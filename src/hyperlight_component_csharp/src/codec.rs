// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! C# types, declarations and encoding for WIT value types.

use hyperlight_component_util::emit::ResolvedBoundVar;
use hyperlight_component_util::etypes::{Defined, FloatWidth, IntWidth, Tyvar, Value, VariantCase};

use crate::names::{Src, camel, case, member, pascal};
use crate::{RT, S};

/// What a type variable reference stands for.
enum Target<'b> {
    /// A declared C# type, by index into `Root::decls`
    Named(usize),
    /// A value type alias, whose definition is relative to the given
    /// `var_offset`
    Alias(Value<'b>, usize),
}

fn target<'b>(s: &S<'_, 'b>, v: &Value<'b>) -> Option<Target<'b>> {
    let Value::Var(Some(Tyvar::Bound(n)), _) = v else {
        return None;
    };
    let ResolvedBoundVar::Definite {
        final_bound_var,
        ty: Defined::Value(def),
    } = s.resolve_bound_var(*n)
    else {
        unreachable!("rejected while collecting");
    };
    let var = s.var_offset + final_bound_var as usize;
    Some(match s.root_mod.decls.iter().position(|d| d.var == var) {
        Some(i) => Target::Named(i),
        None => Target::Alias(def, var + 1),
    })
}

/// Run `f` on an alias definition with its own `var_offset`.
fn alias<'b, R>(s: &mut S<'_, 'b>, offset: usize, f: impl FnOnce(&mut S<'_, 'b>) -> R) -> R {
    let mut s = s.clone();
    s.var_offset = offset;
    f(&mut s)
}

/// The C# type and `WireWriter`/`WireReader` method for a primitive type.
fn primitive(v: &Value) -> Option<(&'static str, &'static str)> {
    Some(match v {
        Value::Bool => ("bool", "Bool"),
        Value::S(IntWidth::I8) => ("sbyte", "S8"),
        Value::U(IntWidth::I8) => ("byte", "U8"),
        Value::S(IntWidth::I16) => ("short", "S16"),
        Value::U(IntWidth::I16) => ("ushort", "U16"),
        Value::S(IntWidth::I32) => ("int", "S32"),
        Value::U(IntWidth::I32) => ("uint", "U32"),
        Value::S(IntWidth::I64) => ("long", "S64"),
        Value::U(IntWidth::I64) => ("ulong", "U64"),
        Value::F(FloatWidth::F32) => ("float", "F32"),
        Value::F(FloatWidth::F64) => ("double", "F64"),
        Value::Char => ("global::System.Text.Rune", "Char"),
        Value::String => ("string", "String"),
        _ => return None,
    })
}

fn is_u8(v: &Value) -> bool {
    matches!(v, Value::U(IntWidth::I8))
}

fn is_option<'b>(s: &mut S<'_, 'b>, v: &Value<'b>) -> bool {
    match (v, target(s, v)) {
        (Value::Option(_), _) => true,
        (_, Some(Target::Alias(def, off))) => alias(s, off, |s| is_option(s, &def)),
        _ => false,
    }
}

/// Whether a value of `v` can hold a list outside a record or variant.
/// Lists compare by reference in C#, so equality of such values goes
/// through `Structural`. Records and variants compare their own lists.
fn contains_list<'b>(s: &mut S<'_, 'b>, v: &Value<'b>) -> bool {
    match v {
        Value::List(_) | Value::FixList(..) => true,
        Value::Option(t) => contains_list(s, t),
        Value::Result(ok, err) => [ok.as_ref(), err.as_ref()]
            .into_iter()
            .flatten()
            .any(|t| contains_list(s, t)),
        Value::Tuple(ts) => ts.iter().any(|t| contains_list(s, t)),
        Value::Var(..) => match target(s, v) {
            Some(Target::Alias(def, off)) => alias(s, off, |s| contains_list(s, &def)),
            _ => false,
        },
        _ => false,
    }
}

/// Whether the C# type of `v` is a value type, which decides how
/// `option<v>` maps to a nullable type.
fn is_value_type<'b>(s: &mut S<'_, 'b>, v: &Value<'b>) -> bool {
    match v {
        Value::String | Value::List(_) | Value::FixList(..) => false,
        Value::Var(..) => match target(s, v) {
            Some(Target::Named(i)) => {
                matches!(s.root_mod.decls[i].value, Value::Enum(_) | Value::Flags(_))
            }
            Some(Target::Alias(def, off)) => alias(s, off, |s| is_value_type(s, &def)),
            None => false,
        },
        _ => true,
    }
}

/// The C# type of `v`.
pub(crate) fn ty<'b>(s: &mut S<'_, 'b>, v: &Value<'b>) -> String {
    if let Some((ty, _)) = primitive(v) {
        return ty.to_string();
    }
    match v {
        Value::Var(..) => match target(s, v) {
            Some(Target::Named(i)) => s.root_mod.type_name(&s.root_mod.decls[i]),
            Some(Target::Alias(def, off)) => alias(s, off, |s| ty(s, &def)),
            None => unreachable!(),
        },
        Value::Tuple(ts) if ts.len() == 1 => {
            format!("global::System.ValueTuple<{}>", ty(s, &ts[0]))
        }
        Value::Tuple(ts) => {
            let types = ts.iter().map(|t| ty(s, t)).collect::<Vec<_>>();
            format!("({})", types.join(", "))
        }
        Value::Option(inner) if is_option(s, inner) => format!("{RT}.Option<{}>", ty(s, inner)),
        Value::Option(inner) => format!("{}?", ty(s, inner)),
        Value::Result(ok, err) => format!(
            "{RT}.Result<{}, {}>",
            ty_or_unit(s, ok.as_ref().as_ref()),
            ty_or_unit(s, err.as_ref().as_ref())
        ),
        Value::List(inner) | Value::FixList(inner, _) if is_u8(inner) => "byte[]".to_string(),
        Value::List(inner) | Value::FixList(inner, _) => format!(
            "global::System.Collections.Generic.IReadOnlyList<{}>",
            ty(s, inner)
        ),
        _ => unreachable!("rejected while collecting"),
    }
}

fn ty_or_unit<'b>(s: &mut S<'_, 'b>, v: Option<&Value<'b>>) -> String {
    v.map_or_else(|| format!("{RT}.Unit"), |v| ty(s, v))
}

/// Emit statements that encode `value` of type `v` into the
/// `WireWriter` named `w`.
pub(crate) fn write<'b>(s: &mut S<'_, 'b>, src: &mut Src, v: &Value<'b>, value: &str, w: &str) {
    if let Some((_, method)) = primitive(v) {
        src.line(format!("{w}.{method}({value});"));
        return;
    }
    match v {
        Value::Var(..) => match target(s, v) {
            Some(Target::Named(i)) => {
                let root = &*s.root_mod;
                src.line(format!(
                    "{}.Write_{}({w}, {value});",
                    root.codec, root.decls[i].mangled
                ));
            }
            Some(Target::Alias(def, off)) => alias(s, off, |s| write(s, src, &def, value, w)),
            None => unreachable!(),
        },
        Value::Tuple(ts) => {
            let t = s.root_mod.temp();
            src.line(format!("var {t} = {value};"));
            for (i, ty) in ts.iter().enumerate() {
                write(s, src, ty, &tuple_item(&t, i), w);
            }
        }
        Value::Option(inner) => {
            let t = s.root_mod.temp();
            src.line(format!("var {t} = {value};"));
            let (has_value, payload) = if is_option(s, inner) || is_value_type(s, inner) {
                (format!("{t}.HasValue"), format!("{t}.Value"))
            } else {
                (format!("{t} is not null"), t.clone())
            };
            src.line(format!("if ({has_value})"));
            src.open();
            src.line(format!("{w}.U8(1);"));
            write(s, src, inner, &payload, w);
            src.close();
            src.line("else");
            src.open();
            src.line(format!("{w}.U8(0);"));
            src.close();
        }
        Value::Result(ok, err) => {
            let t = s.root_mod.temp();
            src.line(format!("var {t} = {value};"));
            src.line(format!("if ({t}.IsOk)"));
            src.open();
            src.line(format!("{w}.U8(0);"));
            if let Some(ok) = ok.as_ref() {
                write(s, src, ok, &format!("{t}.Ok"), w);
            }
            src.close();
            src.line("else");
            src.open();
            src.line(format!("{w}.U8(1);"));
            if let Some(err) = err.as_ref() {
                write(s, src, err, &format!("{t}.Err"), w);
            }
            src.close();
        }
        Value::List(inner) if is_u8(inner) => src.line(format!("{w}.Bytes({value});")),
        Value::FixList(inner, n) if is_u8(inner) => {
            src.line(format!("{w}.FixedBytes({value}, {n});"));
        }
        Value::List(inner) | Value::FixList(inner, _) => {
            let t = s.root_mod.temp();
            src.line(format!("var {t} = {value};"));
            match v {
                Value::FixList(_, n) => {
                    src.line(format!("{RT}.WireWriter.CheckFixedLength({t}, {n});"));
                }
                _ => {
                    src.line(format!(
                        "global::System.ArgumentNullException.ThrowIfNull({t});"
                    ));
                    src.line(format!("{w}.Length({t}.Count);"));
                }
            }
            let e = s.root_mod.temp();
            src.line(format!("foreach (var {e} in {t})"));
            src.open();
            write(s, src, inner, &e, w);
            src.close();
        }
        _ => unreachable!("rejected while collecting"),
    }
}

/// Emit statements that decode a value of type `v` from the
/// `WireReader` named `r`, and return the local holding it.
pub(crate) fn read<'b>(s: &mut S<'_, 'b>, src: &mut Src, v: &Value<'b>, r: &str) -> String {
    if let Value::Var(..) = v
        && let Some(Target::Alias(def, off)) = target(s, v)
    {
        return alias(s, off, |s| read(s, src, &def, r));
    }
    let t = s.root_mod.temp();
    if let Some((_, method)) = primitive(v) {
        src.line(format!("var {t} = {r}.{method}();"));
        return t;
    }
    match v {
        Value::Var(..) => {
            let Some(Target::Named(i)) = target(s, v) else {
                unreachable!()
            };
            let root = &*s.root_mod;
            src.line(format!(
                "var {t} = {}.Read_{}(ref {r});",
                root.codec, root.decls[i].mangled
            ));
        }
        Value::Tuple(ts) => {
            let items = ts.iter().map(|ty| read(s, src, ty, r)).collect::<Vec<_>>();
            if items.len() == 1 {
                src.line(format!("var {t} = new {}({});", ty(s, v), items[0]));
            } else {
                src.line(format!("var {t} = ({});", items.join(", ")));
            }
        }
        Value::Option(inner) => {
            let option_ty = ty(s, v);
            let nested = is_option(s, inner);
            src.line(format!("{option_ty} {t};"));
            src.line(format!("if ({r}.Tag8(2) == 1)"));
            src.open();
            let x = read(s, src, inner, r);
            if nested {
                src.line(format!("{t} = {option_ty}.Some({x});"));
            } else {
                src.line(format!("{t} = {x};"));
            }
            src.close();
            src.line("else");
            src.open();
            if nested {
                src.line(format!("{t} = {option_ty}.None;"));
            } else {
                src.line(format!("{t} = null;"));
            }
            src.close();
        }
        Value::Result(ok, err) => {
            let result_ty = ty(s, v);
            src.line(format!("{result_ty} {t};"));
            src.line(format!("if ({r}.Tag8(2) == 0)"));
            src.open();
            let x = read_or_unit(s, src, ok.as_ref().as_ref(), r);
            src.line(format!("{t} = {result_ty}.FromOk({x});"));
            src.close();
            src.line("else");
            src.open();
            let x = read_or_unit(s, src, err.as_ref().as_ref(), r);
            src.line(format!("{t} = {result_ty}.FromErr({x});"));
            src.close();
        }
        Value::List(inner) if is_u8(inner) => src.line(format!("var {t} = {r}.Bytes();")),
        Value::FixList(inner, n) if is_u8(inner) => {
            src.line(format!("var {t} = {r}.FixedBytes({n});"));
        }
        Value::List(inner) | Value::FixList(inner, _) => {
            let n = s.root_mod.temp();
            // A guest-supplied length is not trusted as a capacity.
            let capacity = match v {
                Value::FixList(_, len) => {
                    src.line(format!("var {n} = {len};"));
                    n.clone()
                }
                _ => {
                    src.line(format!("var {n} = {r}.Length();"));
                    String::new()
                }
            };
            let elem = ty(s, inner);
            src.line(format!(
                "var {t} = new global::System.Collections.Generic.List<{elem}>({capacity});"
            ));
            let i = s.root_mod.temp();
            src.line(format!("for (var {i} = 0; {i} < {n}; {i}++)"));
            src.open();
            let x = read(s, src, inner, r);
            src.line(format!("{t}.Add({x});"));
            src.close();
        }
        _ => unreachable!("rejected while collecting"),
    }
    t
}

fn read_or_unit<'b>(s: &mut S<'_, 'b>, src: &mut Src, v: Option<&Value<'b>>, r: &str) -> String {
    match v {
        Some(v) => read(s, src, v, r),
        None => format!("default({RT}.Unit)"),
    }
}

/// A clone of `s` positioned at the definition of the declared type `i`.
fn at_decl<'c, 'b>(s: &'c mut S<'_, 'b>, i: usize) -> (S<'c, 'b>, Value<'b>, String) {
    let d = &s.root_mod.decls[i];
    let (var, value, name) = (d.var, d.value.clone(), d.name.clone());
    let mut s = s.clone();
    s.var_offset = var + 1;
    (s, value, name)
}

/// Declaration of the record, variant, enum or flags type `i`.
pub(crate) fn emit_decl(s: &mut S<'_, '_>, i: usize) -> Src {
    let (mut s, value, name) = at_decl(s, i);
    let s = &mut s;
    let mut src = Src::default();
    match &value {
        Value::Record(fields) => {
            src.line(format!("public sealed record {name}"));
            src.open();
            for (i, f) in fields.iter().enumerate() {
                if i > 0 {
                    src.line("");
                }
                src.line(format!(
                    "public required {} {} {{ get; init; }}",
                    ty(s, &f.ty),
                    member(f.name.name, &name)
                ));
            }
            let fields = fields
                .iter()
                .map(|f| (member(f.name.name, &name), &f.ty))
                .collect::<Vec<_>>();
            emit_structural_equality(s, &mut src, &name, &fields);
            src.close();
        }
        Value::Variant(cases) => {
            src.line(format!("public abstract record {name}"));
            src.open();
            src.line(format!("private {name}() {{ }}"));
            for c in cases {
                let case_name = case(c.name.name, &name);
                src.line("");
                match &c.ty {
                    Some(t) if contains_list(s, t) => {
                        src.line(format!(
                            "public sealed record {case_name}({} Value) : {name}",
                            ty(s, t)
                        ));
                        src.open();
                        emit_structural_equality(
                            s,
                            &mut src,
                            &case_name,
                            &[("Value".to_string(), t)],
                        );
                        src.close();
                    }
                    Some(t) => src.line(format!(
                        "public sealed record {case_name}({} Value) : {name};",
                        ty(s, t)
                    )),
                    None => src.line(format!("public sealed record {case_name} : {name};")),
                }
            }
            emit_match(s, &mut src, &name, cases);
            src.close();
        }
        Value::Enum(names) => {
            src.line(format!("public enum {name} : uint"));
            src.open();
            for (i, c) in names.iter().enumerate() {
                src.line(format!("{} = {i},", pascal(c.name)));
            }
            src.close();
        }
        Value::Flags(flags) => {
            src.line("[global::System.Flags]");
            src.line(format!("public enum {name} : uint"));
            src.open();
            if flags.iter().all(|f| pascal(f.name) != "None") {
                src.line("None = 0,");
            }
            for (i, f) in flags.iter().enumerate() {
                src.line(format!("{} = 1u << {i},", pascal(f.name)));
            }
            src.close();
        }
        _ => unreachable!("only named types are declared"),
    }
    src
}

/// `Equals` and `GetHashCode` for a sealed record whose `fields` may
/// hold lists, which compare by reference by default.
fn emit_structural_equality<'b>(
    s: &mut S<'_, 'b>,
    src: &mut Src,
    name: &str,
    fields: &[(String, &Value<'b>)],
) {
    let lists = fields
        .iter()
        .map(|(_, ty)| contains_list(s, ty))
        .collect::<Vec<_>>();
    if !lists.contains(&true) {
        return;
    }
    let eqs = fields
        .iter()
        .zip(&lists)
        .map(|((field, t), list)| {
            if *list {
                format!("{RT}.Structural.Equal({field}, other.{field})")
            } else {
                format!(
                    "global::System.Collections.Generic.EqualityComparer<{}>.Default.Equals({field}, other.{field})",
                    ty(s, t)
                )
            }
        })
        .collect::<Vec<_>>();
    src.line("");
    src.line(format!("public bool Equals({name}? other) =>"));
    src.indent_lines(|src| {
        src.line("other is not null");
        for (i, eq) in eqs.iter().enumerate() {
            let end = if i + 1 == eqs.len() { ";" } else { "" };
            src.line(format!("&& {eq}{end}"));
        }
    });
    src.line("");
    src.line("public override int GetHashCode()");
    src.open();
    src.line("var hash = new global::System.HashCode();");
    for ((field, _), list) in fields.iter().zip(&lists) {
        if *list {
            src.line(format!("hash.Add({RT}.Structural.Hash({field}));"));
        } else {
            src.line(format!("hash.Add({field});"));
        }
    }
    src.line("return hash.ToHashCode();");
    src.close();
}

/// `Match` and `Switch`, which take one function per case so that a
/// case added to the WIT breaks every caller at compile time.
fn emit_match<'b>(s: &mut S<'_, 'b>, src: &mut Src, name: &str, cases: &[VariantCase<'b>]) {
    let payloads = cases
        .iter()
        .map(|c| c.ty.as_ref().map(|t| ty(s, t)))
        .collect::<Vec<_>>();
    let handler = |c: &VariantCase, payload: &Option<String>, result: Option<&str>| {
        let ty = match (result, payload) {
            (Some(r), Some(p)) => format!("global::System.Func<{p}, {r}>"),
            (Some(r), None) => format!("global::System.Func<{r}>"),
            (None, Some(p)) => format!("global::System.Action<{p}>"),
            (None, None) => "global::System.Action".to_string(),
        };
        format!("{ty} {}", camel(c.name.name))
    };
    let call = |c: &VariantCase| {
        let case_name = case(c.name.name, name);
        match c.ty {
            Some(_) => (
                format!("{case_name} __c"),
                format!("{}(__c.Value)", camel(c.name.name)),
            ),
            None => (case_name, format!("{}()", camel(c.name.name))),
        }
    };

    src.line("");
    src.line("/// <summary>Calls the function for this case and returns its result.</summary>");
    let params = cases
        .iter()
        .zip(&payloads)
        .map(|(c, p)| handler(c, p, Some("TResult")));
    src.line(format!(
        "public TResult Match<TResult>({}) => this switch",
        params.collect::<Vec<_>>().join(", ")
    ));
    src.open();
    for c in cases {
        let (pattern, invoke) = call(c);
        src.line(format!("{pattern} => {invoke},"));
    }
    src.line("_ => throw new global::System.InvalidOperationException(),");
    src.close_with("};");

    src.line("");
    src.line("/// <summary>Calls the action for this case.</summary>");
    let params = cases
        .iter()
        .zip(&payloads)
        .map(|(c, p)| handler(c, p, None));
    src.line(format!(
        "public void Switch({})",
        params.collect::<Vec<_>>().join(", ")
    ));
    src.open();
    src.line("switch (this)");
    src.open();
    for c in cases {
        let (pattern, invoke) = call(c);
        src.line(format!("case {pattern}:"));
        src.indent_lines(|src| {
            src.line(format!("{invoke};"));
            src.line("break;");
        });
    }
    src.line("default:");
    src.indent_lines(|src| src.line("throw new global::System.InvalidOperationException();"));
    src.close();
    src.close();
}

/// Encode and decode methods for the declared type `i`.
pub(crate) fn emit_type_codec(s: &mut S<'_, '_>, src: &mut Src, i: usize) {
    let full = s.root_mod.type_name(&s.root_mod.decls[i]);
    let mangled = s.root_mod.decls[i].mangled.clone();
    let (mut s, value, name) = at_decl(s, i);
    let s = &mut s;

    src.line(format!(
        "public static void Write_{mangled}({RT}.WireWriter w, {full} v)"
    ));
    src.open();
    match &value {
        Value::Record(fields) => {
            src.line("global::System.ArgumentNullException.ThrowIfNull(v);");
            for f in fields {
                write(
                    s,
                    src,
                    &f.ty,
                    &format!("v.{}", member(f.name.name, &name)),
                    "w",
                );
            }
        }
        Value::Variant(cases) => {
            src.line("switch (v)");
            src.open();
            for (i, c) in cases.iter().enumerate() {
                let case_ty = format!("{full}.{}", case(c.name.name, &name));
                match &c.ty {
                    Some(payload) => {
                        let x = s.root_mod.temp();
                        src.line(format!("case {case_ty} {x}:"));
                        src.indent_lines(|src| {
                            src.line(format!("w.U32({i});"));
                            write(s, src, payload, &format!("{x}.Value"), "w");
                            src.line("break;");
                        });
                    }
                    None => {
                        src.line(format!("case {case_ty}:"));
                        src.indent_lines(|src| {
                            src.line(format!("w.U32({i});"));
                            src.line("break;");
                        });
                    }
                }
            }
            src.line("default:");
            src.indent_lines(|src| {
                src.line(
                    "throw new global::System.ArgumentException($\"unknown case {v}\", nameof(v));",
                );
            });
            src.close();
        }
        Value::Enum(names) => {
            src.line(format!("if ((uint)v >= {})", names.len()));
            src.open();
            src.line("throw new global::System.ArgumentOutOfRangeException(nameof(v));");
            src.close();
            src.line("w.U32((uint)v);");
        }
        Value::Flags(flags) => {
            let mask = flags_mask(flags.len());
            src.line(format!("if (((uint)v & ~{mask}u) != 0)"));
            src.open();
            src.line("throw new global::System.ArgumentOutOfRangeException(nameof(v));");
            src.close();
            src.line(format!("w.Flags((uint)v, {});", flags.len().div_ceil(8)));
        }
        _ => unreachable!("only named types are declared"),
    }
    src.close();

    src.line("");
    src.line(format!(
        "public static {full} Read_{mangled}(ref {RT}.WireReader r)"
    ));
    src.open();
    match &value {
        Value::Record(fields) => {
            let fields = fields
                .iter()
                .map(|f| (member(f.name.name, &name), read(s, src, &f.ty, "r")))
                .collect::<Vec<_>>();
            src.line(format!("return new {full}"));
            src.open();
            for (field, value) in fields {
                src.line(format!("{field} = {value},"));
            }
            src.close_with("};");
        }
        Value::Variant(cases) => {
            src.line(format!("switch (r.Tag32({}))", cases.len()));
            src.open();
            for (i, c) in cases.iter().enumerate() {
                let case_ty = format!("{full}.{}", case(c.name.name, &name));
                src.line(format!("case {i}:"));
                src.open();
                match &c.ty {
                    Some(payload) => {
                        let x = read(s, src, payload, "r");
                        src.line(format!("return new {case_ty}({x});"));
                    }
                    None => src.line(format!("return new {case_ty}();")),
                }
                src.close();
            }
            src.line("default:");
            src.indent_lines(|src| {
                src.line("throw new global::System.InvalidOperationException();");
            });
            src.close();
        }
        Value::Enum(names) => {
            src.line(format!("return ({full})r.Tag32({});", names.len()));
        }
        Value::Flags(flags) => {
            let mask = flags_mask(flags.len());
            src.line(format!(
                "return ({full})(r.Flags({}) & {mask}u);",
                flags.len().div_ceil(8)
            ));
        }
        _ => unreachable!("only named types are declared"),
    }
    src.close();
}

/// Accessor for element `i` of a C# value tuple.
fn tuple_item(tuple: &str, i: usize) -> String {
    format!("{tuple}.Item{}", i + 1)
}

/// Hex literal with the low `count` bits set. WIT flags have at most 32
/// members.
fn flags_mask(count: usize) -> String {
    format!("0x{:X}", u32::MAX >> (32 - count))
}
