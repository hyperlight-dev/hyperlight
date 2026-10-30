// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! The host side of a world: interfaces for imports, classes that call
//! exports, and registration of host functions.

use hyperlight_component_util::emit::split_wit_name;
use hyperlight_component_util::etypes::{Component, ExternDecl, ExternDesc, Func, Param};
use hyperlight_component_util::hl::emit_fn_hl_name;

use crate::codec::{read, ty, write};
use crate::names::{Src, camel, member, pascal, string_literal};
use crate::{Error, RT, S, error};

/// Functions of one imported or exported instance, or of the world
/// itself.
struct Group<'c, 'b> {
    /// Instance name, or `None` for functions of the world itself
    instance: Option<&'b str>,
    /// `var_offset` for the function types
    offset: usize,
    functions: Vec<(&'b str, &'c Func<'b>)>,
}

/// A function's role, from its WIT name.
enum Kind<'b> {
    Plain,
    Constructor(&'b str),
    /// Resource and method names
    Method(&'b str, &'b str),
    /// Resource and function names
    Static(&'b str, &'b str),
}

fn kind(name: &str) -> Kind<'_> {
    fn split(rest: &str) -> (&str, &str) {
        rest.split_once('.').unwrap_or((rest, ""))
    }
    if let Some(r) = name.strip_prefix("[constructor]") {
        return Kind::Constructor(r);
    }
    if let Some(rest) = name.strip_prefix("[method]") {
        let (r, f) = split(rest);
        return Kind::Method(r, f);
    }
    if let Some(rest) = name.strip_prefix("[static]") {
        let (r, f) = split(rest);
        return Kind::Static(r, f);
    }
    Kind::Plain
}

fn groups<'c, 'b>(decls: &'c [ExternDecl<'b>], offset: usize) -> Vec<Group<'c, 'b>> {
    let mut groups = Vec::new();
    let mut world = Vec::new();
    for ed in decls {
        match &ed.desc {
            ExternDesc::Instance(it) => {
                let functions = it
                    .exports
                    .iter()
                    .filter_map(|e| match &e.desc {
                        ExternDesc::Func(f) => Some((e.kebab_name, f)),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                if !functions.is_empty() {
                    groups.push(Group {
                        instance: Some(ed.kebab_name),
                        offset,
                        functions,
                    });
                }
            }
            ExternDesc::Func(f) => world.push((ed.kebab_name, f)),
            _ => {}
        }
    }
    if !world.is_empty() {
        groups.push(Group {
            instance: None,
            offset,
            functions: world,
        });
    }
    groups
}

/// Write the interfaces for the imports of the world `ct`, the classes
/// that call its exports, and the component class.
pub(crate) fn emit_toplevel<'b>(s: &mut S<'_, 'b>, ct: &Component<'b>) -> Result<(), Error> {
    let imports = groups(&ct.imports, ct.instance.evars.len());
    let exports = groups(&ct.instance.unqualified.exports, 0);
    check_class_names(s, &imports, &exports)?;
    for i in 0..s.root_mod.resources.len() {
        let src = emit_resource_interface(s, &imports, i);
        let ns = s.root_mod.resources[i].namespace.clone();
        s.root_mod.add(ns, src);
    }
    for group in &imports {
        if let Some(instance) = group.instance {
            let ns = s.root_mod.qualify(s.root_mod.package_namespace(instance));
            let name = import_interface_name(s, group);
            let src = emit_import_interface(s, &name, group);
            s.root_mod.add(ns, src);
        }
    }
    for group in &exports {
        if let Some(instance) = group.instance {
            let ns = s.root_mod.qualify(s.root_mod.package_namespace(instance));
            let name = export_class_name(group);
            let src = emit_export_class(s, &name, group);
            s.root_mod.add(ns, src);
        }
    }
    let src = emit_component(s, &imports, &exports);
    s.root_mod.add(s.root_mod.ns.clone(), src);
    Ok(())
}

/// Reject a generated interface or class whose name a namespace of
/// interface types also takes, which C# cannot compile.
fn check_class_names(s: &S, imports: &[Group], exports: &[Group]) -> Result<(), Error> {
    let root = &*s.root_mod;
    let classes = imports
        .iter()
        .filter(|g| g.instance.is_some())
        .map(|g| qualified_group_type(s, g, import_interface_name(s, g)))
        .chain(
            exports
                .iter()
                .filter(|g| g.instance.is_some())
                .map(|g| qualified_group_type(s, g, export_class_name(g))),
        );
    let namespaces = root
        .decls
        .iter()
        .map(|d| &d.namespace)
        .chain(root.resources.iter().map(|r| &r.namespace))
        .collect::<Vec<_>>();
    for class in classes {
        let class = class.trim_start_matches("global::");
        if namespaces
            .iter()
            .any(|ns| *ns == class || ns.starts_with(&format!("{class}.")))
        {
            return Err(error(format!(
                "generated type {class} clashes with a namespace of the same name"
            )));
        }
    }
    Ok(())
}

fn import_interface_name(s: &S, group: &Group) -> String {
    match group.instance {
        Some(instance) => format!("I{}", pascal(split_wit_name(instance).name)),
        None => format!("I{}Imports", s.root_mod.world_type),
    }
}

fn export_class_name(group: &Group) -> String {
    format!(
        "{}Exports",
        pascal(split_wit_name(group.instance.unwrap()).name)
    )
}

fn qualified_group_type(s: &S, group: &Group, name: String) -> String {
    let ns = match group.instance {
        Some(instance) => s.root_mod.qualify(s.root_mod.package_namespace(instance)),
        None => s.root_mod.ns.clone(),
    };
    format!("global::{ns}.{name}")
}

/// Member names for the instances in `groups`, or `None` for functions of
/// the world itself. A name is qualified with its package when two
/// instances share it or it is in `taken`. Package segments are kept apart
/// with `_` only when the qualified names still clash, as for `a:b-c` and
/// `a-b:c`.
fn group_member_names(s: &S, groups: &[Group], taken: &[String]) -> Vec<Option<String>> {
    let bases = groups
        .iter()
        .map(|g| g.instance.map(|i| pascal(split_wit_name(i).name)))
        .collect::<Vec<_>>();
    let qualified = |instance: &str, base: &str, separator: &str| {
        let package = s.root_mod.package_namespace(instance).unwrap_or_default();
        format!("{}{base}", package.replace('.', separator))
    };
    let names = groups
        .iter()
        .zip(&bases)
        .map(|(g, base)| {
            let (instance, base) = (g.instance?, base.as_deref()?);
            let collides = bases.iter().flatten().filter(|b| *b == base).count() > 1
                || taken.iter().any(|t| t == base);
            Some(if collides {
                qualified(instance, base, "")
            } else {
                base.to_string()
            })
        })
        .collect::<Vec<_>>();
    groups
        .iter()
        .zip(&bases)
        .zip(&names)
        .map(|((g, base), name)| {
            let name = name.as_ref()?;
            if names.iter().flatten().filter(|n| *n == name).count() > 1 {
                Some(qualified(g.instance?, base.as_deref()?, "_"))
            } else {
                Some(name.clone())
            }
        })
        .collect()
}

fn signature<'b>(
    s: &mut S<'_, 'b>,
    group: &Group<'_, 'b>,
    params: &[Param<'b>],
    f: &Func<'b>,
    name: &str,
) -> String {
    let mut s = s.clone();
    s.var_offset = group.offset;
    let params = params
        .iter()
        .map(|p| format!("{} {}", ty(&mut s, &p.ty), camel(p.name.name)))
        .collect::<Vec<_>>()
        .join(", ");
    let result = f.result.as_ref().map_or("void".into(), |t| ty(&mut s, t));
    format!("{result} {name}({params})")
}

fn wire_name(s: &mut S, group: &Group, function: &str) -> String {
    let mut s = s.clone();
    s.cur_instance = group.instance.map(str::to_string);
    emit_fn_hl_name(&s, function)
}

/// A member name of the generated class `class`, escaped if it clashes
/// with the class name, an inherited member, or `RegisterImports` on the
/// component class.
fn class_member(name: &str, class: &str) -> String {
    let name = member(name, class);
    if name == "RegisterImports" {
        format!("{name}_")
    } else {
        name
    }
}

fn emit_import_interface<'b>(s: &mut S<'_, 'b>, name: &str, group: &Group<'_, 'b>) -> Src {
    let mut src = Src::default();
    src.line(format!("public interface {name}"));
    src.open();
    let methods = interface_methods(group, name);
    let mut first = true;
    for ((_, f), method) in group.functions.iter().zip(&methods) {
        let Some(method) = method else {
            continue;
        };
        if !first {
            src.line("");
        }
        first = false;
        src.line(format!("{};", signature(s, group, &f.params, f, method)));
    }
    src.close();
    src
}

/// Method names on the import interface `iface` for the functions of
/// `group`, or `None` for resource methods, which belong to the
/// resource's interface. Constructors are named `New{Resource}` and
/// static functions `{Resource}{Function}`.
fn interface_methods(group: &Group, iface: &str) -> Vec<Option<String>> {
    let mut names = Vec::<Option<String>>::new();
    for (function, _) in &group.functions {
        let mut name = match kind(function) {
            Kind::Plain => member(function, iface),
            Kind::Constructor(r) => member(&format!("new-{r}"), iface),
            Kind::Static(r, f) => member(&format!("{r}-{f}"), iface),
            Kind::Method(..) => {
                names.push(None);
                continue;
            }
        };
        while names.iter().flatten().any(|n| *n == name) {
            name.push('_');
        }
        names.push(Some(name));
    }
    names
}

/// The interface the host implements for resource `i`, with a method for
/// each of the resource's methods.
fn emit_resource_interface<'b>(s: &mut S<'_, 'b>, imports: &[Group<'_, 'b>], i: usize) -> Src {
    let r = &s.root_mod.resources[i];
    let (name, wit_name, instance) = (r.name.clone(), r.wit_name.clone(), r.instance.clone());
    let mut src = Src::default();
    src.line(format!("public interface {name}"));
    src.open();
    if let Some(group) = imports.iter().find(|g| g.instance == instance.as_deref()) {
        let mut first = true;
        for (function, f) in &group.functions {
            if let Kind::Method(resource, method) = kind(function)
                && resource == wit_name
            {
                if !first {
                    src.line("");
                }
                first = false;
                let params = f.params.get(1..).unwrap_or_default();
                let method = member(method, &name);
                src.line(format!("{};", signature(s, group, params, f, &method)));
            }
        }
    }
    src.close();
    src
}

/// Constructor parameters of the classes that call exports.
fn caller_params(s: &S) -> String {
    if s.root_mod.resources.is_empty() {
        format!("{RT}.IGuestCaller caller")
    } else {
        format!(
            "{RT}.IGuestCaller caller, {} resources",
            s.root_mod.resources_class
        )
    }
}

/// An object initializer that gives a reader or writer the resource
/// tables in `resources`, and the current call's scope when `scoped`.
fn context(s: &S, resources: &str, scoped: bool) -> String {
    match (s.root_mod.resources.is_empty(), scoped) {
        (true, _) => String::new(),
        (false, false) => format!(" {{ Resources = {resources} }}"),
        (false, true) => format!(" {{ Resources = {resources}, Scope = __scope }}"),
    }
}

/// Fields and constructor body of a class that calls exports.
fn emit_caller_fields(s: &S, src: &mut Src, class: &str, visibility: &str) {
    src.line(format!("private readonly {RT}.IGuestCaller _caller;"));
    if !s.root_mod.resources.is_empty() {
        src.line(format!(
            "private readonly {} _resources;",
            s.root_mod.resources_class
        ));
    }
    src.line("");
    src.line(format!("{visibility} {class}({})", caller_params(s)));
    src.open();
    src.line("_caller = caller;");
    if !s.root_mod.resources.is_empty() {
        src.line("_resources = resources;");
    }
}

fn emit_export_class<'b>(s: &mut S<'_, 'b>, name: &str, group: &Group<'_, 'b>) -> Src {
    let mut src = Src::default();
    src.line(format!("public sealed class {name}"));
    src.open();
    emit_caller_fields(s, &mut src, name, "internal");
    src.close();
    emit_export_methods(s, &mut src, name, group);
    src.close();
    src
}

fn emit_export_methods<'b>(s: &mut S<'_, 'b>, src: &mut Src, class: &str, group: &Group<'_, 'b>) {
    let resources = !s.root_mod.resources.is_empty();
    for (function, f) in &group.functions {
        src.line("");
        src.line(format!(
            "public {}",
            signature(s, group, &f.params, f, &class_member(function, class))
        ));
        let call = format!(
            "_caller.Call({}, __args)",
            string_literal(&wire_name(s, group, function))
        );
        let mut s = s.clone();
        s.var_offset = group.offset;
        let s = &mut s;
        src.open();
        if resources {
            src.line(format!("var __scope = new {RT}.CallScope();"));
            src.line("try");
            src.open();
        }
        if f.params.is_empty() {
            src.line("var __args = global::System.Array.Empty<byte[]>();");
        } else {
            src.line(format!("var __args = new byte[{}][];", f.params.len()));
        }
        for (i, p) in f.params.iter().enumerate() {
            src.open();
            let init = context(s, "_resources", true);
            src.line(format!("var __w = new {RT}.WireWriter(){init};"));
            write(s, src, &p.ty, &camel(p.name.name), "__w");
            src.line(format!("__args[{i}] = __w.ToArray();"));
            src.close();
        }
        if resources {
            src.line("__scope.Commit();");
        }
        match &f.result {
            Some(t) => {
                let init = context(s, "_resources", false);
                src.line(format!("var __r = new {RT}.WireReader({call}){init};"));
                let value = read(s, src, t, "__r");
                src.line(format!("return {value};"));
            }
            None => src.line(format!("{call};")),
        }
        if resources {
            src.close();
            src.line("finally");
            src.open();
            src.line("__scope.End();");
            src.close();
        }
        src.close();
    }
}

fn emit_component<'b>(
    s: &mut S<'_, 'b>,
    imports: &[Group<'_, 'b>],
    exports: &[Group<'_, 'b>],
) -> Src {
    let world_type = s.root_mod.world_type.clone();
    let name = format!("{world_type}Component");
    let resources = !s.root_mod.resources.is_empty();
    let mut src = Src::default();

    if let Some(group) = imports.iter().find(|g| g.instance.is_none()) {
        let iface = import_interface_name(s, group);
        src.append(emit_import_interface(s, &iface, group));
        src.line("");
    }
    if resources {
        src.append(emit_resources_class(s));
        src.line("");
    }

    src.line(format!("public sealed class {name}"));
    src.open();
    emit_caller_fields(s, &mut src, &name, "public");
    // Functions of the world itself are methods on this class, so the
    // properties for exported interfaces must not take their names.
    let methods = exports
        .iter()
        .filter(|g| g.instance.is_none())
        .flat_map(|g| g.functions.iter().map(|(f, _)| class_member(f, &name)))
        .collect::<Vec<_>>();
    let export_names = group_member_names(s, exports, &methods)
        .into_iter()
        .map(|n| n.map(|n| class_member(&n, &name)))
        .collect::<Vec<_>>();
    let args = if resources {
        "caller, resources"
    } else {
        "caller"
    };
    for (group, prop) in exports.iter().zip(&export_names) {
        if let Some(prop) = prop {
            let class = qualified_group_type(s, group, export_class_name(group));
            src.line(format!("{prop} = new {class}({args});"));
        }
    }
    src.close();
    for (group, prop) in exports.iter().zip(&export_names) {
        if let Some(prop) = prop {
            let class = qualified_group_type(s, group, export_class_name(group));
            src.line("");
            src.line(format!("public {class} {prop} {{ get; }}"));
        }
    }
    if let Some(group) = exports.iter().find(|g| g.instance.is_none()) {
        emit_export_methods(s, &mut src, &name, group);
    }

    // The parameter for functions of the world itself is `world`.
    let taken = imports
        .iter()
        .filter(|g| g.instance.is_none())
        .map(|_| "World".to_string())
        .collect::<Vec<_>>();
    let import_names = group_member_names(s, imports, &taken);
    let params = imports
        .iter()
        .zip(&import_names)
        .map(|(group, base)| {
            let ty = qualified_group_type(s, group, import_interface_name(s, group));
            let mut param = camel(base.as_deref().unwrap_or("world"));
            if param == "registry" {
                param.push('_');
            }
            (ty, param, group)
        })
        .collect::<Vec<_>>();
    src.line("");
    let decls = std::iter::once(format!("{RT}.IHostFunctionRegistry registry"))
        .chain(params.iter().map(|(ty, param, _)| format!("{ty} {param}")))
        .collect::<Vec<_>>()
        .join(", ");
    if resources {
        src.line("/// <summary>");
        src.line("/// Registers the world's imports as host functions. Pass the returned");
        src.line("/// resource tables to the constructor.");
        src.line("/// </summary>");
        src.line(format!(
            "public static {} RegisterImports({decls})",
            s.root_mod.resources_class
        ));
        src.open();
        src.line(format!(
            "var __resources = new {}();",
            s.root_mod.resources_class
        ));
    } else {
        src.line("/// <summary>Registers the world's imports as host functions.</summary>");
        src.line(format!("public static void RegisterImports({decls})"));
        src.open();
    }
    for (_, param, group) in &params {
        let iface = import_interface_name(s, group);
        let methods = interface_methods(group, &iface);
        for ((function, f), method) in group.functions.iter().zip(&methods) {
            let callee = match (kind(function), method) {
                (Kind::Method(resource, m), _) => {
                    Callee::SelfMethod(member(m, &resource_interface(s, group, resource)))
                }
                (_, Some(method)) => Callee::On(param, method.clone()),
                (_, None) => unreachable!("only resource methods have no interface method"),
            };
            emit_registration(s, &mut src, callee, group, function, f);
        }
    }
    if resources {
        src.line("return __resources;");
    }
    src.close();
    src.close();
    src
}

/// The class holding a handle table for each resource.
fn emit_resources_class(s: &S) -> Src {
    let root = &*s.root_mod;
    let name = root.resources_class.rsplit('.').next().unwrap();
    let mut src = Src::default();
    src.line("/// <summary>Handles to host resources that the guest holds.</summary>");
    src.line(format!("public sealed class {name}"));
    src.open();
    src.line(format!("internal {name}()"));
    src.open();
    src.close();
    for r in &root.resources {
        src.line("");
        src.line(format!(
            "internal {RT}.ResourceTable<global::{}.{}> {} {{ get; }} = new();",
            r.namespace, r.name, r.table
        ));
    }
    src.close();
    src
}

/// Name of the interface for the resource `resource` of `group`.
fn resource_interface(s: &S, group: &Group, resource: &str) -> String {
    s.root_mod
        .resources
        .iter()
        .find(|r| r.instance.as_deref() == group.instance && r.wit_name == resource)
        .map(|r| r.name.clone())
        .unwrap()
}

/// What a registered host function calls.
enum Callee<'a> {
    /// A method of an import interface parameter
    On(&'a str, String),
    /// A method of the resource passed as the first argument
    SelfMethod(String),
}

fn emit_registration<'b>(
    s: &mut S<'_, 'b>,
    src: &mut Src,
    callee: Callee,
    group: &Group<'_, 'b>,
    function: &str,
    f: &Func<'b>,
) {
    src.line(format!(
        "registry.Register({}, {}, __args =>",
        string_literal(&wire_name(s, group, function)),
        f.params.len()
    ));
    let mut s = s.clone();
    s.var_offset = group.offset;
    let s = &mut s;
    src.open();
    let mut args = Vec::new();
    for (i, p) in f.params.iter().enumerate() {
        let reader = format!("__r{i}");
        let init = context(s, "__resources", false);
        src.line(format!(
            "var {reader} = new {RT}.WireReader(__args[{i}]){init};"
        ));
        args.push(read(s, src, &p.ty, &reader));
    }
    let call = match callee {
        Callee::On(target, method) => format!("{target}.{method}({})", args.join(", ")),
        Callee::SelfMethod(method) => {
            format!("{}.{method}({})", args[0], args[1..].join(", "))
        }
    };
    match &f.result {
        Some(t) if !s.root_mod.resources.is_empty() => {
            // Undo gifts in the result if encoding it fails.
            src.line(format!("var __ret = {call};"));
            src.line(format!("var __scope = new {RT}.CallScope();"));
            src.line("try");
            src.open();
            let init = context(s, "__resources", true);
            src.line(format!("var __w = new {RT}.WireWriter(){init};"));
            write(s, src, t, "__ret", "__w");
            src.line("__scope.Commit();");
            src.line("return __w.ToArray();");
            src.close();
            src.line("finally");
            src.open();
            src.line("__scope.End();");
            src.close();
        }
        Some(t) => {
            src.line(format!("var __ret = {call};"));
            let init = context(s, "__resources", false);
            src.line(format!("var __w = new {RT}.WireWriter(){init};"));
            write(s, src, t, "__ret", "__w");
            src.line("return __w.ToArray();");
        }
        None => {
            src.line(format!("{call};"));
            src.line("return global::System.Array.Empty<byte>();");
        }
    }
    src.close_with("});");
}
