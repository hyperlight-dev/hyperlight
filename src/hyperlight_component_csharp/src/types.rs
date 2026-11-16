// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Declares a C# type with codec methods for each record, variant, enum
//! and flags type the world uses, and rejects what the bindings do not
//! support.

use hyperlight_component_util::emit::ResolvedBoundVar;
use hyperlight_component_util::etypes::{
    Component, Defined, ExternDecl, ExternDesc, Func, Handleable, Tyvar, Value,
};

use crate::codec::{emit_decl, emit_type_codec};
use crate::names::{Src, pascal};
use crate::{Decl, Error, ResourceDecl, S, error};

/// Walk the imports, then the exports, of the world `ct`.
pub(crate) fn emit_toplevel<'b>(s: &mut S<'_, 'b>, ct: &Component<'b>) -> Result<(), Error> {
    s.var_offset = ct.instance.evars.len();
    for ed in &ct.imports {
        emit_extern_decl(s, ed, true)?;
    }
    s.var_offset = 0;
    for ed in &ct.instance.unqualified.exports {
        emit_extern_decl(s, ed, true)?;
    }

    // World types share the root namespace with the generated classes
    // and the first segment of each interface's namespace.
    let root = &*s.root_mod;
    let world = &root.world_type;
    let mut generated = vec![
        format!("{world}Component"),
        format!("I{world}Imports"),
        format!("{world}Codec"),
        format!("{world}Resources"),
    ];
    for ed in ct.imports.iter().chain(&ct.instance.unqualified.exports) {
        if let ExternDesc::Instance(_) = ed.desc {
            let ns = root.interface_namespace(ed.kebab_name);
            generated.push(ns.split('.').next().unwrap_or_default().to_string());
        }
    }
    if let Some(d) = root
        .decls
        .iter()
        .find(|d| d.world_level && generated.contains(&d.name))
    {
        return Err(error(format!(
            "type '{}' clashes with the generated name {}",
            s.bound_vars[d.var].origin.last_name().unwrap_or_default(),
            d.name
        )));
    }
    if let Some(r) = root.resources.iter().find(|r| {
        root.decls
            .iter()
            .any(|d| d.namespace == r.namespace && d.name == r.name)
            || (r.instance.is_none() && generated.contains(&r.name))
    }) {
        return Err(error(format!(
            "resource '{}' clashes with the generated name {}",
            r.wit_name, r.name
        )));
    }
    Ok(())
}

fn emit_extern_decl<'b>(s: &mut S<'_, 'b>, ed: &ExternDecl<'b>, top: bool) -> Result<(), Error> {
    match &ed.desc {
        ExternDesc::Type(Defined::Handleable(Handleable::Var(Tyvar::Bound(n)))) => visit_var(s, *n),
        ExternDesc::Type(_) => Err(error(format!(
            "type '{}': this kind of type is not supported",
            ed.kebab_name
        ))),
        ExternDesc::Func(f) => visit_func(s, f),
        ExternDesc::Instance(it) if top => {
            for ed in &it.exports {
                emit_extern_decl(s, ed, false)?;
            }
            Ok(())
        }
        _ => Err(error(format!(
            "'{}': nested instances, components and core modules are not supported",
            ed.kebab_name
        ))),
    }
}

fn visit_func<'b>(s: &mut S<'_, 'b>, f: &Func<'b>) -> Result<(), Error> {
    for p in &f.params {
        visit_value(s, &p.ty)?;
    }
    if let Some(ty) = &f.result {
        visit_value(s, ty)?;
    }
    Ok(())
}

/// Check that `v` is supported and declare every type it uses that
/// needs a declaration.
fn visit_value<'b>(s: &mut S<'_, 'b>, v: &Value<'b>) -> Result<(), Error> {
    match v {
        Value::Bool | Value::S(_) | Value::U(_) | Value::F(_) | Value::Char | Value::String => {
            Ok(())
        }
        // The component model forbids these, but the WIT reader does not
        // validate its input.
        Value::FixList(_, 0) => Err(error("fixed-length lists must not be empty")),
        Value::Tuple(ts) if ts.is_empty() => Err(error("tuples must not be empty")),
        Value::List(t) | Value::FixList(t, _) | Value::Option(t) => visit_value(s, t),
        Value::Tuple(ts) => ts.iter().try_for_each(|t| visit_value(s, t)),
        Value::Result(ok, err) => {
            for t in [ok.as_ref(), err.as_ref()].into_iter().flatten() {
                visit_value(s, t)?;
            }
            Ok(())
        }
        Value::Var(Some(Tyvar::Bound(n)), _) => visit_var(s, *n),
        Value::Own(Handleable::Var(Tyvar::Bound(n)))
        | Value::Borrow(Handleable::Var(Tyvar::Bound(n))) => match s.resolve_bound_var(*n) {
            ResolvedBoundVar::Resource { rtidx } => declare_resource(s, rtidx as usize),
            ResolvedBoundVar::Definite { .. } => Err(error("handle to a non-resource type")),
        },
        Value::Own(_) | Value::Borrow(_) => Err(error("unresolved resource type")),
        Value::Record(_) | Value::Variant(_) | Value::Enum(_) | Value::Flags(_) => Err(error(
            "anonymous records, variants, enums and flags are not supported",
        )),
        Value::Var(..) => Err(error("unresolved type variable")),
    }
}

/// Visit the definition of the type variable `n`, and declare it if it is
/// a record, variant, enum or flags type. Its name is assigned before
/// its fields are visited, and its source is written after.
fn visit_var<'b>(s: &mut S<'_, 'b>, n: u32) -> Result<(), Error> {
    let (var, v) = match s.resolve_bound_var(n) {
        ResolvedBoundVar::Definite {
            final_bound_var,
            ty: Defined::Value(v),
        } => (s.var_offset + final_bound_var as usize, v),
        ResolvedBoundVar::Resource { rtidx } => {
            return declare_resource(s, rtidx as usize);
        }
        ResolvedBoundVar::Definite { .. } => {
            return Err(error("non-value type definitions are not supported"));
        }
    };
    if s.root_mod.decl_index(var).is_some() {
        return Ok(());
    }
    let mut s = s.clone();
    s.var_offset = var + 1;
    let fields = match &v {
        Value::Record(fields) => fields.iter().map(|f| &f.ty).collect(),
        Value::Variant(cases) => cases.iter().filter_map(|c| c.ty.as_ref()).collect(),
        Value::Enum(_) | Value::Flags(_) => Vec::new(),
        _ => return visit_value(&mut s, &v),
    };
    let Some(i) = declare(&mut s, var, &v)? else {
        return Ok(());
    };
    for ty in fields {
        visit_value(&mut s, ty)?;
    }
    let ns = s.root_mod.decls[i].namespace.clone();
    let decl = emit_decl(&mut s, i);
    s.root_mod.add(ns, decl);
    let mut methods = Src::default();
    emit_type_codec(&mut s, &mut methods, i);
    s.root_mod.add_codec_methods(methods);
    Ok(())
}

/// Name the C# type for the type variable `var` after the WIT type and
/// interface it comes from, and return its index in `Root::decls`. Return
/// `None` when the type is already declared.
fn declare<'b>(s: &mut S<'_, 'b>, var: usize, v: &Value<'b>) -> Result<Option<usize>, Error> {
    let origin = &s.bound_vars[var].origin;
    let path = origin.path.as_deref().unwrap_or_default();
    let (wit_name, instance) = match path {
        [ty] => (ty.name(), None),
        [ty, instance] => (ty.name(), Some(instance.name())),
        _ => return Err(error("types of nested instances are not supported")),
    };
    // The component model forbids these, but the WIT reader does not
    // validate its input.
    let empty = match v {
        Value::Record(fields) => fields.is_empty(),
        Value::Flags(flags) => flags.is_empty(),
        _ => false,
    };
    if empty {
        return Err(error(format!("type '{wit_name}' must not be empty")));
    }
    if let Value::Flags(flags) = v
        && flags.len() > 32
    {
        return Err(error(format!(
            "type '{wit_name}': flags with more than 32 members are not supported"
        )));
    }
    let root = &mut *s.root_mod;
    let name = pascal(wit_name);
    let (namespace, base) = match instance {
        Some(instance) => {
            let relative = root.interface_namespace(instance);
            let base = format!("{}_{name}", relative.replace('.', "_"));
            (root.qualify(Some(relative)), base)
        }
        None => (root.ns.clone(), name.clone()),
    };
    // A world that imports and exports one interface has a type variable
    // for each copy of its types. Both copies use one C# type. Inline
    // interfaces are distinct even when their names match.
    if let Some(d) = root
        .decls
        .iter_mut()
        .find(|d| d.namespace == namespace && d.name == name)
    {
        if d.instance.as_deref() != instance || !instance.is_some_and(|i| i.contains(':')) {
            return Err(error(format!(
                "type '{wit_name}' clashes with another type named {}.{name}",
                d.namespace
            )));
        }
        d.aliases.push(var);
        return Ok(None);
    }
    let mut mangled = base.clone();
    let mut n = 1;
    while root.decls.iter().any(|d| d.mangled == mangled) {
        n += 1;
        mangled = format!("{base}{n}");
    }
    root.decls.push(Decl {
        var,
        aliases: Vec::new(),
        value: v.clone(),
        namespace,
        name,
        mangled,
        world_level: instance.is_none(),
        instance: instance.map(str::to_string),
    });
    Ok(Some(root.decls.len() - 1))
}

/// Declare the resource introduced by the variable `var`, which the host
/// must define. The Rust host bindings do not support resources the guest
/// defines either.
fn declare_resource(s: &mut S<'_, '_>, var: usize) -> Result<(), Error> {
    if s.root_mod.resource_index(var).is_some() {
        return Ok(());
    }
    let origin = &s.bound_vars[var].origin;
    let path = origin.path.as_deref().unwrap_or_default();
    let (wit_name, instance) = match path {
        [ty] => (ty.name(), None),
        [ty, instance] => (ty.name(), Some(instance.name())),
        _ => return Err(error("resources of nested instances are not supported")),
    };
    if !origin.is_imported() {
        return Err(error(format!(
            "resource '{wit_name}': resources the guest defines are not supported"
        )));
    }
    let root = &mut *s.root_mod;
    let name = format!("I{}", pascal(wit_name));
    let (namespace, base) = match instance {
        Some(instance) => {
            let relative = root.interface_namespace(instance);
            let base = format!("{}_{}", relative.replace('.', "_"), pascal(wit_name));
            (root.qualify(Some(relative)), base)
        }
        None => (root.ns.clone(), pascal(wit_name)),
    };
    let mut table = base.clone();
    let mut n = 1;
    while root.resources.iter().any(|r| r.table == table) {
        n += 1;
        table = format!("{base}{n}");
    }
    root.resources.push(ResourceDecl {
        var,
        wit_name: wit_name.to_string(),
        instance: instance.map(str::to_string),
        namespace,
        name,
        table,
    });
    Ok(())
}
