// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! The host side of a world: interfaces for imports, classes that call
//! exports, and registration of host functions.

use hyperlight_component_util::emit::split_wit_name;
use hyperlight_component_util::etypes::{Component, ExternDecl, ExternDesc, Func};
use hyperlight_component_util::hl::emit_fn_hl_name;

use crate::codec::{read, ty, write};
use crate::names::{Src, camel, member, pascal, string_literal};
use crate::{RT, S};

/// Functions of one imported or exported instance, or of the world
/// itself.
struct Group<'c, 'b> {
    /// Instance name, or `None` for functions of the world itself
    instance: Option<&'b str>,
    /// `var_offset` for the function types
    offset: usize,
    functions: Vec<(&'b str, &'c Func<'b>)>,
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
pub(crate) fn emit_toplevel<'b>(s: &mut S<'_, 'b>, ct: &Component<'b>) {
    let imports = groups(&ct.imports, ct.instance.evars.len());
    let exports = groups(&ct.instance.unqualified.exports, 0);
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

/// Member names for interfaces, qualified with their package when two
/// interfaces share a name.
fn group_member_names(s: &S, groups: &[Group]) -> Vec<String> {
    let bases = groups
        .iter()
        .map(|g| match g.instance {
            Some(instance) => split_wit_name(instance).name.to_string(),
            None => "world".to_string(),
        })
        .collect::<Vec<_>>();
    groups
        .iter()
        .zip(&bases)
        .map(|(g, base)| {
            let collides = bases.iter().filter(|b| *b == base).count() > 1;
            match (g.instance, collides) {
                (Some(instance), true) => format!(
                    "{}{}",
                    s.root_mod
                        .package_namespace(instance)
                        .unwrap_or_default()
                        .replace('.', ""),
                    pascal(base)
                ),
                _ => pascal(base),
            }
        })
        .collect()
}

fn signature<'b>(s: &mut S<'_, 'b>, group: &Group<'_, 'b>, f: &Func<'b>, name: &str) -> String {
    let mut s = s.clone();
    s.var_offset = group.offset;
    let params = f
        .params
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
    for (i, (function, f)) in group.functions.iter().enumerate() {
        if i > 0 {
            src.line("");
        }
        src.line(format!("{};", signature(s, group, f, &pascal(function))));
    }
    src.close();
    src
}

fn emit_export_class<'b>(s: &mut S<'_, 'b>, name: &str, group: &Group<'_, 'b>) -> Src {
    let mut src = Src::default();
    src.line(format!("public sealed class {name}"));
    src.open();
    src.line(format!("private readonly {RT}.IGuestCaller _caller;"));
    src.line("");
    src.line(format!("internal {name}({RT}.IGuestCaller caller)"));
    src.open();
    src.line("_caller = caller;");
    src.close();
    emit_export_methods(s, &mut src, name, group);
    src.close();
    src
}

fn emit_export_methods<'b>(s: &mut S<'_, 'b>, src: &mut Src, class: &str, group: &Group<'_, 'b>) {
    for (function, f) in &group.functions {
        src.line("");
        src.line(format!(
            "public {}",
            signature(s, group, f, &class_member(function, class))
        ));
        let call = format!(
            "_caller.Call({}, __args)",
            string_literal(&wire_name(s, group, function))
        );
        let mut s = s.clone();
        s.var_offset = group.offset;
        let s = &mut s;
        src.open();
        if f.params.is_empty() {
            src.line("var __args = global::System.Array.Empty<byte[]>();");
        } else {
            src.line(format!("var __args = new byte[{}][];", f.params.len()));
        }
        for (i, p) in f.params.iter().enumerate() {
            src.open();
            src.line(format!("var __w = new {RT}.WireWriter();"));
            write(s, src, &p.ty, &camel(p.name.name), "__w");
            src.line(format!("__args[{i}] = __w.ToArray();"));
            src.close();
        }
        match &f.result {
            Some(t) => {
                src.line(format!("var __r = new {RT}.WireReader({call});"));
                let value = read(s, src, t, "__r");
                src.line("__r.End();");
                src.line(format!("return {value};"));
            }
            None => src.line(format!("{call};")),
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
    let mut src = Src::default();

    if let Some(group) = imports.iter().find(|g| g.instance.is_none()) {
        let iface = import_interface_name(s, group);
        src.append(emit_import_interface(s, &iface, group));
        src.line("");
    }

    src.line(format!("public sealed class {name}"));
    src.open();
    src.line(format!("private readonly {RT}.IGuestCaller _caller;"));
    src.line("");
    src.line(format!("public {name}({RT}.IGuestCaller caller)"));
    src.open();
    src.line("_caller = caller;");
    let export_names = group_member_names(s, exports)
        .iter()
        .map(|n| class_member(n, &name))
        .collect::<Vec<_>>();
    for (group, prop) in exports.iter().zip(&export_names) {
        if group.instance.is_some() {
            let class = qualified_group_type(s, group, export_class_name(group));
            src.line(format!("{prop} = new {class}(caller);"));
        }
    }
    src.close();
    for (group, prop) in exports.iter().zip(&export_names) {
        if group.instance.is_some() {
            let class = qualified_group_type(s, group, export_class_name(group));
            src.line("");
            src.line(format!("public {class} {prop} {{ get; }}"));
        }
    }
    if let Some(group) = exports.iter().find(|g| g.instance.is_none()) {
        emit_export_methods(s, &mut src, &name, group);
    }

    let import_names = group_member_names(s, imports);
    let params = imports
        .iter()
        .zip(&import_names)
        .map(|(group, base)| {
            let ty = qualified_group_type(s, group, import_interface_name(s, group));
            let mut param = camel(base);
            if param == "registry" {
                param.push('_');
            }
            (ty, param, group)
        })
        .collect::<Vec<_>>();
    src.line("");
    src.line("/// <summary>Registers the world's imports as host functions.</summary>");
    let decls = std::iter::once(format!("{RT}.IHostFunctionRegistry registry"))
        .chain(params.iter().map(|(ty, param, _)| format!("{ty} {param}")))
        .collect::<Vec<_>>()
        .join(", ");
    src.line(format!("public static void RegisterImports({decls})"));
    src.open();
    for (_, param, group) in &params {
        for (function, f) in &group.functions {
            emit_registration(s, &mut src, param, group, function, f);
        }
    }
    src.close();
    src.close();
    src
}

fn emit_registration<'b>(
    s: &mut S<'_, 'b>,
    src: &mut Src,
    target: &str,
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
        src.line(format!("var {reader} = new {RT}.WireReader(__args[{i}]);"));
        let value = read(s, src, &p.ty, &reader);
        src.line(format!("{reader}.End();"));
        args.push(value);
    }
    let call = format!("{target}.{}({})", pascal(function), args.join(", "));
    match &f.result {
        Some(t) => {
            src.line(format!("var __ret = {call};"));
            src.line(format!("var __w = new {RT}.WireWriter();"));
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
