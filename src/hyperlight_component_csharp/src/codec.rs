// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! C# types and encoding for WIT value types.

use wit_parser::{Type, TypeDef, TypeDefKind, TypeId};

use crate::names::{Src, camel, case, member, pascal};
use crate::{Gen, RT};

impl Gen<'_> {
    /// Follow type aliases to the defining type.
    fn def(&self, ty: &Type) -> Option<(TypeId, &TypeDef)> {
        let mut ty = *ty;
        loop {
            let Type::Id(id) = ty else {
                return None;
            };
            let def = &self.resolve.types[id];
            match &def.kind {
                TypeDefKind::Type(inner) => ty = *inner,
                _ => return Some((id, def)),
            }
        }
    }

    fn is_option(&self, ty: &Type) -> bool {
        matches!(self.def(ty), Some((_, d)) if matches!(d.kind, TypeDefKind::Option(_)))
    }

    /// Whether a value of `ty` can hold a list outside a record or
    /// variant. Lists compare by reference in C#, so equality of such
    /// values goes through `Structural`. Records and variants compare
    /// their own lists.
    fn contains_list(&self, ty: &Type) -> bool {
        let Some((_, def)) = self.def(ty) else {
            return false;
        };
        match &def.kind {
            TypeDefKind::List(_) | TypeDefKind::FixedLengthList(..) => true,
            TypeDefKind::Option(inner) => self.contains_list(inner),
            TypeDefKind::Result(r) => {
                r.ok.as_ref().is_some_and(|t| self.contains_list(t))
                    || r.err.as_ref().is_some_and(|t| self.contains_list(t))
            }
            TypeDefKind::Tuple(t) => t.types.iter().any(|t| self.contains_list(t)),
            _ => false,
        }
    }

    /// Whether the C# type of `ty` is a value type, which decides how
    /// `option<ty>` maps to a nullable type.
    fn is_value_type(&self, ty: &Type) -> bool {
        match self.def(ty) {
            None => !matches!(ty, Type::String),
            Some((_, def)) => matches!(
                def.kind,
                TypeDefKind::Enum(_)
                    | TypeDefKind::Flags(_)
                    | TypeDefKind::Tuple(_)
                    | TypeDefKind::Option(_)
                    | TypeDefKind::Result(_)
            ),
        }
    }

    /// The C# type of `ty`.
    pub(super) fn ty(&self, ty: &Type) -> String {
        let Some((id, def)) = self.def(ty) else {
            return match ty {
                Type::Bool => "bool",
                Type::U8 => "byte",
                Type::S8 => "sbyte",
                Type::U16 => "ushort",
                Type::S16 => "short",
                Type::U32 => "uint",
                Type::S32 => "int",
                Type::U64 => "ulong",
                Type::S64 => "long",
                Type::F32 => "float",
                Type::F64 => "double",
                Type::Char => "global::System.Text.Rune",
                Type::String => "string",
                Type::ErrorContext | Type::Id(_) => unreachable!("rejected while collecting"),
            }
            .to_string();
        };
        match &def.kind {
            TypeDefKind::Record(_)
            | TypeDefKind::Variant(_)
            | TypeDefKind::Enum(_)
            | TypeDefKind::Flags(_) => self.type_name(id),
            TypeDefKind::Tuple(t) if t.types.len() == 1 => {
                format!("global::System.ValueTuple<{}>", self.ty(&t.types[0]))
            }
            TypeDefKind::Tuple(t) => {
                let types = t.types.iter().map(|t| self.ty(t)).collect::<Vec<_>>();
                format!("({})", types.join(", "))
            }
            TypeDefKind::Option(inner) if self.is_option(inner) => {
                format!("{RT}.Option<{}>", self.ty(inner))
            }
            TypeDefKind::Option(inner) => format!("{}?", self.ty(inner)),
            TypeDefKind::Result(r) => format!(
                "{RT}.Result<{}, {}>",
                self.ty_or_unit(r.ok.as_ref()),
                self.ty_or_unit(r.err.as_ref())
            ),
            TypeDefKind::List(Type::U8) | TypeDefKind::FixedLengthList(Type::U8, _) => {
                "byte[]".to_string()
            }
            TypeDefKind::List(inner) | TypeDefKind::FixedLengthList(inner, _) => format!(
                "global::System.Collections.Generic.IReadOnlyList<{}>",
                self.ty(inner)
            ),
            _ => unreachable!("rejected while collecting"),
        }
    }

    fn ty_or_unit(&self, ty: Option<&Type>) -> String {
        ty.map_or_else(|| format!("{RT}.Unit"), |t| self.ty(t))
    }

    /// Emit statements that encode `value` of type `ty` into the
    /// `WireWriter` named `w`.
    pub(super) fn write(&self, src: &mut Src, ty: &Type, value: &str, w: &str) {
        let Some((id, def)) = self.def(ty) else {
            let method = match ty {
                Type::Bool => "Bool",
                Type::U8 => "U8",
                Type::S8 => "S8",
                Type::U16 => "U16",
                Type::S16 => "S16",
                Type::U32 => "U32",
                Type::S32 => "S32",
                Type::U64 => "U64",
                Type::S64 => "S64",
                Type::F32 => "F32",
                Type::F64 => "F64",
                Type::Char => "Char",
                Type::String => "String",
                Type::ErrorContext | Type::Id(_) => unreachable!("rejected while collecting"),
            };
            src.line(format!("{w}.{method}({value});"));
            return;
        };
        match &def.kind {
            TypeDefKind::Record(_)
            | TypeDefKind::Variant(_)
            | TypeDefKind::Enum(_)
            | TypeDefKind::Flags(_) => {
                src.line(format!(
                    "{}.Write_{}({w}, {value});",
                    self.codec, self.mangled[&id]
                ));
            }
            TypeDefKind::Tuple(t) => {
                let v = self.temp();
                src.line(format!("var {v} = {value};"));
                for (i, ty) in t.types.iter().enumerate() {
                    self.write(src, ty, &tuple_item(&v, i), w);
                }
            }
            TypeDefKind::Option(inner) => {
                let v = self.temp();
                src.line(format!("var {v} = {value};"));
                let (has_value, payload) = if self.is_option(inner) || self.is_value_type(inner) {
                    (format!("{v}.HasValue"), format!("{v}.Value"))
                } else {
                    (format!("{v} is not null"), v.clone())
                };
                src.line(format!("if ({has_value})"));
                src.open();
                src.line(format!("{w}.U8(1);"));
                self.write(src, inner, &payload, w);
                src.close();
                src.line("else");
                src.open();
                src.line(format!("{w}.U8(0);"));
                src.close();
            }
            TypeDefKind::Result(r) => {
                let v = self.temp();
                src.line(format!("var {v} = {value};"));
                src.line(format!("if ({v}.IsOk)"));
                src.open();
                src.line(format!("{w}.U8(0);"));
                if let Some(ty) = &r.ok {
                    self.write(src, ty, &format!("{v}.Ok"), w);
                }
                src.close();
                src.line("else");
                src.open();
                src.line(format!("{w}.U8(1);"));
                if let Some(ty) = &r.err {
                    self.write(src, ty, &format!("{v}.Err"), w);
                }
                src.close();
            }
            TypeDefKind::List(Type::U8) => src.line(format!("{w}.Bytes({value});")),
            TypeDefKind::FixedLengthList(Type::U8, n) => {
                src.line(format!("{w}.FixedBytes({value}, {n});"));
            }
            TypeDefKind::List(inner) | TypeDefKind::FixedLengthList(inner, _) => {
                let v = self.temp();
                src.line(format!("var {v} = {value};"));
                match &def.kind {
                    TypeDefKind::FixedLengthList(_, n) => {
                        src.line(format!("{RT}.WireWriter.CheckFixedLength({v}, {n});"));
                    }
                    _ => {
                        src.line(format!(
                            "global::System.ArgumentNullException.ThrowIfNull({v});"
                        ));
                        src.line(format!("{w}.Length({v}.Count);"));
                    }
                }
                let e = self.temp();
                src.line(format!("foreach (var {e} in {v})"));
                src.open();
                self.write(src, inner, &e, w);
                src.close();
            }
            _ => unreachable!("rejected while collecting"),
        }
    }

    /// Emit statements that decode a value of type `ty` from the
    /// `WireReader` named `r`, and return the local holding it.
    pub(super) fn read(&self, src: &mut Src, ty: &Type, r: &str) -> String {
        let v = self.temp();
        let Some((id, def)) = self.def(ty) else {
            let method = match ty {
                Type::Bool => "Bool",
                Type::U8 => "U8",
                Type::S8 => "S8",
                Type::U16 => "U16",
                Type::S16 => "S16",
                Type::U32 => "U32",
                Type::S32 => "S32",
                Type::U64 => "U64",
                Type::S64 => "S64",
                Type::F32 => "F32",
                Type::F64 => "F64",
                Type::Char => "Char",
                Type::String => "String",
                Type::ErrorContext | Type::Id(_) => unreachable!("rejected while collecting"),
            };
            src.line(format!("var {v} = {r}.{method}();"));
            return v;
        };
        match &def.kind {
            TypeDefKind::Record(_)
            | TypeDefKind::Variant(_)
            | TypeDefKind::Enum(_)
            | TypeDefKind::Flags(_) => {
                src.line(format!(
                    "var {v} = {}.Read_{}(ref {r});",
                    self.codec, self.mangled[&id]
                ));
            }
            TypeDefKind::Tuple(t) => {
                let items = t
                    .types
                    .iter()
                    .map(|ty| self.read(src, ty, r))
                    .collect::<Vec<_>>();
                if items.len() == 1 {
                    src.line(format!("var {v} = new {}({});", self.ty(ty), items[0]));
                } else {
                    src.line(format!("var {v} = ({});", items.join(", ")));
                }
            }
            TypeDefKind::Option(inner) => {
                let (none, some): (String, fn(&str, &str) -> String) = if self.is_option(inner) {
                    (format!("{}.None", self.ty(ty)), |ty, x| {
                        format!("{ty}.Some({x})")
                    })
                } else {
                    ("null".to_string(), |_, x| x.to_string())
                };
                src.line(format!("{} {v};", self.ty(ty)));
                src.line(format!("if ({r}.Tag8(2) == 1)"));
                src.open();
                let x = self.read(src, inner, r);
                src.line(format!("{v} = {};", some(&self.ty(ty), &x)));
                src.close();
                src.line("else");
                src.open();
                src.line(format!("{v} = {none};"));
                src.close();
            }
            TypeDefKind::Result(res) => {
                let t = self.ty(ty);
                src.line(format!("{t} {v};"));
                src.line(format!("if ({r}.Tag8(2) == 0)"));
                src.open();
                let x = self.read_or_unit(src, res.ok.as_ref(), r);
                src.line(format!("{v} = {t}.FromOk({x});"));
                src.close();
                src.line("else");
                src.open();
                let x = self.read_or_unit(src, res.err.as_ref(), r);
                src.line(format!("{v} = {t}.FromErr({x});"));
                src.close();
            }
            TypeDefKind::List(Type::U8) => src.line(format!("var {v} = {r}.Bytes();")),
            TypeDefKind::FixedLengthList(Type::U8, n) => {
                src.line(format!("var {v} = {r}.FixedBytes({n});"));
            }
            TypeDefKind::List(inner) | TypeDefKind::FixedLengthList(inner, _) => {
                let n = self.temp();
                match &def.kind {
                    TypeDefKind::FixedLengthList(_, len) => src.line(format!("var {n} = {len};")),
                    _ => src.line(format!("var {n} = {r}.Length();")),
                }
                src.line(format!(
                    "var {v} = new global::System.Collections.Generic.List<{}>({n});",
                    self.ty(inner)
                ));
                let i = self.temp();
                src.line(format!("for (var {i} = 0; {i} < {n}; {i}++)"));
                src.open();
                let x = self.read(src, inner, r);
                src.line(format!("{v}.Add({x});"));
                src.close();
            }
            _ => unreachable!("rejected while collecting"),
        }
        v
    }

    fn read_or_unit(&self, src: &mut Src, ty: Option<&Type>, r: &str) -> String {
        match ty {
            Some(ty) => self.read(src, ty, r),
            None => format!("default({RT}.Unit)"),
        }
    }

    /// Declaration of a record, variant, enum or flags type.
    pub(super) fn emit_decl(&self, id: TypeId) -> Src {
        let def = &self.resolve.types[id];
        let name = pascal(def.name.as_deref().unwrap());
        let mut src = Src::default();
        src.docs(&def.docs);
        match &def.kind {
            TypeDefKind::Record(r) => {
                src.line(format!("public sealed record {name}"));
                src.open();
                for (i, f) in r.fields.iter().enumerate() {
                    if i > 0 {
                        src.line("");
                    }
                    src.docs(&f.docs);
                    src.line(format!(
                        "public required {} {} {{ get; init; }}",
                        self.ty(&f.ty),
                        member(&f.name, &name)
                    ));
                }
                let fields = r
                    .fields
                    .iter()
                    .map(|f| (member(&f.name, &name), &f.ty))
                    .collect::<Vec<_>>();
                self.emit_structural_equality(&mut src, &name, &fields);
                src.close();
            }
            TypeDefKind::Variant(v) => {
                src.line(format!("public abstract record {name}"));
                src.open();
                src.line(format!("private {name}() {{ }}"));
                for c in &v.cases {
                    let case_name = case(&c.name, &name);
                    src.line("");
                    src.docs(&c.docs);
                    match &c.ty {
                        Some(ty) if self.contains_list(ty) => {
                            src.line(format!(
                                "public sealed record {case_name}({} Value) : {name}",
                                self.ty(ty)
                            ));
                            src.open();
                            self.emit_structural_equality(
                                &mut src,
                                &case_name,
                                &[("Value".to_string(), ty)],
                            );
                            src.close();
                        }
                        Some(ty) => src.line(format!(
                            "public sealed record {case_name}({} Value) : {name};",
                            self.ty(ty)
                        )),
                        None => src.line(format!("public sealed record {case_name} : {name};")),
                    }
                }
                self.emit_match(&mut src, &name, v);
                src.close();
            }
            TypeDefKind::Enum(e) => {
                src.line(format!("public enum {name} : uint"));
                src.open();
                for (i, c) in e.cases.iter().enumerate() {
                    src.docs(&c.docs);
                    src.line(format!("{} = {i},", pascal(&c.name)));
                }
                src.close();
            }
            TypeDefKind::Flags(f) => {
                src.line("[global::System.Flags]");
                src.line(format!("public enum {name} : uint"));
                src.open();
                if f.flags.iter().all(|flag| pascal(&flag.name) != "None") {
                    src.line("None = 0,");
                }
                for (i, flag) in f.flags.iter().enumerate() {
                    src.docs(&flag.docs);
                    src.line(format!("{} = 1u << {i},", pascal(&flag.name)));
                }
                src.close();
            }
            _ => unreachable!("only named types are declared"),
        }
        src
    }

    /// `Equals` and `GetHashCode` for a sealed record whose `fields` may
    /// hold lists, which compare by reference by default.
    fn emit_structural_equality(&self, src: &mut Src, name: &str, fields: &[(String, &Type)]) {
        if !fields.iter().any(|(_, ty)| self.contains_list(ty)) {
            return;
        }
        let eq = |field: &str, ty: &Type| {
            if self.contains_list(ty) {
                format!("{RT}.Structural.Equal({field}, other.{field})")
            } else {
                format!(
                    "global::System.Collections.Generic.EqualityComparer<{}>.Default.Equals({field}, other.{field})",
                    self.ty(ty)
                )
            }
        };
        src.line("");
        src.line(format!("public bool Equals({name}? other) =>"));
        src.indent_lines(|src| {
            src.line("other is not null");
            for (i, (field, ty)) in fields.iter().enumerate() {
                let end = if i + 1 == fields.len() { ";" } else { "" };
                src.line(format!("&& {}{end}", eq(field, ty)));
            }
        });
        src.line("");
        src.line("public override int GetHashCode()");
        src.open();
        src.line("var hash = new global::System.HashCode();");
        for (field, ty) in fields {
            if self.contains_list(ty) {
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
    fn emit_match(&self, src: &mut Src, name: &str, v: &wit_parser::Variant) {
        let handler = |c: &wit_parser::Case, result: Option<&str>| {
            let payload = c.ty.as_ref().map(|ty| self.ty(ty));
            let ty = match (result, payload) {
                (Some(r), Some(p)) => format!("global::System.Func<{p}, {r}>"),
                (Some(r), None) => format!("global::System.Func<{r}>"),
                (None, Some(p)) => format!("global::System.Action<{p}>"),
                (None, None) => "global::System.Action".to_string(),
            };
            format!("{ty} {}", camel(&c.name))
        };
        let call = |c: &wit_parser::Case| {
            let case_name = case(&c.name, name);
            match c.ty {
                Some(_) => (
                    format!("{case_name} __c"),
                    format!("{}(__c.Value)", camel(&c.name)),
                ),
                None => (case_name, format!("{}()", camel(&c.name))),
            }
        };

        src.line("");
        src.line("/// <summary>Calls the function for this case and returns its result.</summary>");
        let params = v.cases.iter().map(|c| handler(c, Some("TResult")));
        src.line(format!(
            "public TResult Match<TResult>({}) => this switch",
            params.collect::<Vec<_>>().join(", ")
        ));
        src.open();
        for c in &v.cases {
            let (pattern, invoke) = call(c);
            src.line(format!("{pattern} => {invoke},"));
        }
        src.line("_ => throw new global::System.InvalidOperationException(),");
        src.close_with("};");

        src.line("");
        src.line("/// <summary>Calls the action for this case.</summary>");
        let params = v.cases.iter().map(|c| handler(c, None));
        src.line(format!(
            "public void Switch({})",
            params.collect::<Vec<_>>().join(", ")
        ));
        src.open();
        src.line("switch (this)");
        src.open();
        for c in &v.cases {
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

    /// The static class with encode and decode methods for every
    /// declared type.
    pub(super) fn emit_codec(&self) -> Src {
        let name = self.codec.rsplit('.').next().unwrap();
        let mut src = Src::default();
        src.line(format!("internal static class {name}"));
        src.open();
        for (i, id) in self.decls.iter().enumerate() {
            if i > 0 {
                src.line("");
            }
            self.emit_type_codec(&mut src, *id);
        }
        src.close();
        src
    }

    fn emit_type_codec(&self, src: &mut Src, id: TypeId) {
        let def = &self.resolve.types[id];
        let ty = self.type_name(id);
        let name = pascal(def.name.as_deref().unwrap());
        let mangled = &self.mangled[&id];

        src.line(format!(
            "public static void Write_{mangled}({RT}.WireWriter w, {ty} v)"
        ));
        src.open();
        match &def.kind {
            TypeDefKind::Record(r) => {
                src.line("global::System.ArgumentNullException.ThrowIfNull(v);");
                for f in &r.fields {
                    self.write(src, &f.ty, &format!("v.{}", member(&f.name, &name)), "w");
                }
            }
            TypeDefKind::Variant(v) => {
                src.line("switch (v)");
                src.open();
                for (i, c) in v.cases.iter().enumerate() {
                    let case_ty = format!("{ty}.{}", case(&c.name, &name));
                    match &c.ty {
                        Some(payload) => {
                            let x = self.temp();
                            src.line(format!("case {case_ty} {x}:"));
                            src.indent_lines(|src| {
                                src.line(format!("w.U32({i});"));
                                self.write(src, payload, &format!("{x}.Value"), "w");
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
            TypeDefKind::Enum(e) => {
                src.line(format!("if ((uint)v >= {})", e.cases.len()));
                src.open();
                src.line("throw new global::System.ArgumentOutOfRangeException(nameof(v));");
                src.close();
                src.line("w.U32((uint)v);");
            }
            TypeDefKind::Flags(f) => {
                let mask = flags_mask(f.flags.len());
                src.line(format!("if (((uint)v & ~{mask}u) != 0)"));
                src.open();
                src.line("throw new global::System.ArgumentOutOfRangeException(nameof(v));");
                src.close();
                src.line(format!("w.Flags((uint)v, {});", f.flags.len().div_ceil(8)));
            }
            _ => unreachable!("only named types are declared"),
        }
        src.close();

        src.line("");
        src.line(format!(
            "public static {ty} Read_{mangled}(ref {RT}.WireReader r)"
        ));
        src.open();
        match &def.kind {
            TypeDefKind::Record(rec) => {
                let fields = rec
                    .fields
                    .iter()
                    .map(|f| (member(&f.name, &name), self.read(src, &f.ty, "r")))
                    .collect::<Vec<_>>();
                src.line(format!("return new {ty}"));
                src.open();
                for (field, value) in fields {
                    src.line(format!("{field} = {value},"));
                }
                src.close_with("};");
            }
            TypeDefKind::Variant(v) => {
                src.line(format!("switch (r.Tag32({}))", v.cases.len()));
                src.open();
                for (i, c) in v.cases.iter().enumerate() {
                    let case_ty = format!("{ty}.{}", case(&c.name, &name));
                    src.line(format!("case {i}:"));
                    src.open();
                    match &c.ty {
                        Some(payload) => {
                            let x = self.read(src, payload, "r");
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
            TypeDefKind::Enum(e) => {
                src.line(format!("return ({ty})r.Tag32({});", e.cases.len()));
            }
            TypeDefKind::Flags(f) => {
                let mask = flags_mask(f.flags.len());
                src.line(format!(
                    "return ({ty})(r.Flags({}) & {mask}u);",
                    f.flags.len().div_ceil(8)
                ));
            }
            _ => unreachable!("only named types are declared"),
        }
        src.close();
    }
}

/// Accessor for element `i` of a C# value tuple.
fn tuple_item(tuple: &str, i: usize) -> String {
    format!("{tuple}.Item{}", i + 1)
}

/// Hex literal with the low `count` bits set. WIT flags have at most 32 members.
fn flags_mask(count: usize) -> String {
    format!("0x{:X}", u32::MAX >> (32 - count))
}
