// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! C# bindings for the host side of a WIT world.
//!
//! The generated code encodes values in the format described in
//! `docs/component-wire-format.md` and calls guest functions through
//! the interfaces in [`RUNTIME_SOURCE`]. It covers every WIT value
//! type. Resources, async functions, futures, streams, maps and flags
//! with more than 32 members are rejected.

mod codec;
mod names;

use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;

use names::{Src, camel, member, pascal, string_literal};
use wit_parser::{
    Function, FunctionKind, InterfaceId, Resolve, Type, TypeDefKind, TypeId, TypeOwner, WorldId,
    WorldItem, WorldKey,
};

/// C# source for the `Hyperlight.Component` namespace that generated
/// bindings depend on.
pub const RUNTIME_SOURCE: &str = include_str!("Runtime.cs");

/// Namespace of [`RUNTIME_SOURCE`].
const RT: &str = "global::Hyperlight.Component";

/// A WIT input the C# bindings cannot be generated for.
#[derive(Debug)]
pub struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

fn error(msg: impl Into<String>) -> Error {
    Error(msg.into())
}

/// Generate C# bindings for a world in the WIT package at `path`.
///
/// `path` is a `.wit` file or a directory, parsed with
/// [`Resolve::push_path`]. `world` selects the world as
/// [`Resolve::select_world`] does. All generated types are placed
/// under `namespace`.
pub fn generate_from_path(
    path: &Path,
    world: Option<&str>,
    namespace: &str,
) -> Result<String, Error> {
    let mut resolve = Resolve::default();
    let (package, _) = resolve
        .push_path(path)
        .map_err(|e| error(format!("failed to parse '{}': {e:#}", path.display())))?;
    let world = resolve
        .select_world(&[package], world)
        .map_err(|e| error(format!("{e:#}")))?;
    generate(&resolve, world, namespace)
}

/// Generate C# bindings for `world`, placing all generated types
/// under `namespace`.
pub fn generate(resolve: &Resolve, world: WorldId, namespace: &str) -> Result<String, Error> {
    if namespace.is_empty()
        || namespace
            .split('.')
            .any(|part| part.is_empty() || !part.chars().all(|c| c.is_alphanumeric() || c == '_'))
    {
        return Err(error(format!("invalid C# namespace '{namespace}'")));
    }
    let mut g = Gen {
        resolve,
        world,
        root: namespace.to_string(),
        codec: String::new(),
        interface_names: HashMap::new(),
        decls: Vec::new(),
        seen: HashSet::new(),
        mangled: HashMap::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        temps: Cell::new(0),
    };
    g.codec = format!(
        "global::{}.{}Codec",
        g.root,
        pascal(&resolve.worlds[world].name)
    );
    g.collect()?;
    Ok(g.emit())
}

/// Functions of one imported or exported world item.
struct Group<'a> {
    /// The interface, or `None` for functions of the world itself
    interface: Option<InterfaceId>,
    /// Instance name in wire function names
    instance: Option<String>,
    functions: Vec<&'a Function>,
}

struct Gen<'a> {
    resolve: &'a Resolve,
    world: WorldId,
    /// Root C# namespace
    root: String,
    /// Fully qualified name of the static class holding codec methods
    codec: String,
    /// Names of interfaces, including anonymous ones named by their
    /// world key
    interface_names: HashMap<InterfaceId, String>,
    /// Records, variants, enums and flags to declare, in WIT order
    decls: Vec<TypeId>,
    seen: HashSet<TypeId>,
    /// Codec method suffix for each declared type
    mangled: HashMap<TypeId, String>,
    imports: Vec<Group<'a>>,
    exports: Vec<Group<'a>>,
    /// Counter for unique local variable names
    temps: Cell<usize>,
}

impl<'a> Gen<'a> {
    fn collect(&mut self) -> Result<(), Error> {
        let world = &self.resolve.worlds[self.world];
        for (key, item) in world.imports.iter().chain(world.exports.iter()) {
            if let (WorldKey::Name(name), WorldItem::Interface { id, .. }) = (key, item) {
                self.interface_names.insert(*id, name.clone());
            }
        }
        for (key, item) in &world.imports {
            if let Some(group) = self.collect_item(key, item)? {
                self.imports.push(group);
            }
        }
        for (key, item) in &world.exports {
            if let Some(group) = self.collect_item(key, item)? {
                self.exports.push(group);
            }
        }
        let world_functions = |groups: &mut Vec<Group<'a>>| {
            let functions = groups
                .iter()
                .filter(|g| g.interface.is_none())
                .flat_map(|g| g.functions.clone())
                .collect::<Vec<_>>();
            groups.retain(|g| g.interface.is_some());
            if !functions.is_empty() {
                groups.push(Group {
                    interface: None,
                    instance: None,
                    functions,
                });
            }
        };
        world_functions(&mut self.imports);
        world_functions(&mut self.exports);

        // World types share the root namespace with the generated classes.
        let world_name = pascal(&world.name);
        let generated = [
            format!("{world_name}Component"),
            format!("I{world_name}Imports"),
            format!("{world_name}Codec"),
        ];
        for id in &self.decls {
            let def = &self.resolve.types[*id];
            let name = pascal(def.name.as_deref().unwrap());
            if matches!(def.owner, TypeOwner::World(_)) && generated.contains(&name) {
                return Err(error(format!(
                    "type '{}' clashes with the generated class {name}",
                    def.name.as_deref().unwrap()
                )));
            }
        }
        Ok(())
    }

    fn collect_item(
        &mut self,
        key: &WorldKey,
        item: &'a WorldItem,
    ) -> Result<Option<Group<'a>>, Error> {
        match item {
            WorldItem::Interface { id, .. } => {
                let iface = &self.resolve.interfaces[*id];
                for ty in iface.types.values() {
                    self.visit(&Type::Id(*ty))?;
                }
                let functions = iface.functions.values().collect::<Vec<_>>();
                for f in &functions {
                    self.visit_function(f)?;
                }
                Ok((!functions.is_empty()).then(|| Group {
                    interface: Some(*id),
                    instance: Some(self.resolve.name_world_key(key)),
                    functions,
                }))
            }
            WorldItem::Function(f) => {
                self.visit_function(f)?;
                Ok(Some(Group {
                    interface: None,
                    instance: None,
                    functions: vec![f],
                }))
            }
            WorldItem::Type { id, .. } => {
                self.visit(&Type::Id(*id))?;
                Ok(None)
            }
        }
    }

    fn visit_function(&mut self, f: &Function) -> Result<(), Error> {
        if !matches!(f.kind, FunctionKind::Freestanding) {
            return Err(error(format!(
                "function '{}': resources and async functions are not supported",
                f.name
            )));
        }
        for p in &f.params {
            self.visit(&p.ty)?;
        }
        if let Some(ty) = &f.result {
            self.visit(ty)?;
        }
        Ok(())
    }

    /// Check that `ty` is supported and record every type it uses
    /// that needs a declaration.
    fn visit(&mut self, ty: &Type) -> Result<(), Error> {
        let id = match ty {
            Type::Id(id) => *id,
            Type::ErrorContext => return Err(error("error-context is not supported")),
            _ => return Ok(()),
        };
        if !self.seen.insert(id) {
            return Ok(());
        }
        let def = &self.resolve.types[id];
        let unsupported = |what: &str| {
            let name = def.name.as_deref().unwrap_or("anonymous type");
            Err(error(format!("type '{name}': {what} are not supported")))
        };
        match &def.kind {
            TypeDefKind::Record(r) => {
                self.declare(id)?;
                for f in &r.fields {
                    self.visit(&f.ty)?;
                }
            }
            TypeDefKind::Variant(v) => {
                self.declare(id)?;
                for c in &v.cases {
                    if let Some(ty) = &c.ty {
                        self.visit(ty)?;
                    }
                }
            }
            TypeDefKind::Enum(_) => self.declare(id)?,
            TypeDefKind::Flags(f) => {
                if f.flags.len() > 32 {
                    return unsupported("flags with more than 32 members");
                }
                self.declare(id)?;
            }
            TypeDefKind::Tuple(t) => {
                for ty in &t.types {
                    self.visit(ty)?;
                }
            }
            TypeDefKind::Option(ty)
            | TypeDefKind::List(ty)
            | TypeDefKind::FixedLengthList(ty, _)
            | TypeDefKind::Type(ty) => self.visit(ty)?,
            TypeDefKind::Result(r) => {
                if let Some(ty) = &r.ok {
                    self.visit(ty)?;
                }
                if let Some(ty) = &r.err {
                    self.visit(ty)?;
                }
            }
            TypeDefKind::Resource | TypeDefKind::Handle(_) => return unsupported("resources"),
            TypeDefKind::Future(_) | TypeDefKind::Stream(_) => {
                return unsupported("futures and streams");
            }
            TypeDefKind::Map(..) => return unsupported("maps"),
            TypeDefKind::Unknown => return unsupported("unresolved types"),
        }
        Ok(())
    }

    fn declare(&mut self, id: TypeId) -> Result<(), Error> {
        let def = &self.resolve.types[id];
        let name = def
            .name
            .as_deref()
            .ok_or_else(|| error("anonymous record, variant, enum or flags"))?;
        let namespace = match def.owner {
            TypeOwner::Interface(i) => self.interface_namespace(i).replace('.', "_"),
            TypeOwner::World(_) => String::new(),
            TypeOwner::None => return Err(error(format!("type '{name}' has no owner"))),
        };
        let base = if namespace.is_empty() {
            pascal(name)
        } else {
            format!("{namespace}_{}", pascal(name))
        };
        let mut mangled = base.clone();
        let mut n = 1;
        while self.mangled.values().any(|m| *m == mangled) {
            n += 1;
            mangled = format!("{base}{n}");
        }
        self.mangled.insert(id, mangled);
        self.decls.push(id);
        Ok(())
    }

    /// Namespace of the types of an interface, relative to the root
    /// namespace, e.g. `Wasi.Http.Types`.
    fn interface_namespace(&self, id: InterfaceId) -> String {
        let name = pascal(&self.interface_name(id));
        match self.package_namespace(id) {
            Some(pkg) => format!("{pkg}.{name}"),
            None => name,
        }
    }

    /// Namespace of an interface's package relative to the root
    /// namespace, e.g. `Wasi.Http`. The version is added, e.g.
    /// `Wasi.Http.V0_2_0`, when the WIT has the package at several versions.
    fn package_namespace(&self, id: InterfaceId) -> Option<String> {
        let pkg = self.resolve.interfaces[id].package?;
        let name = &self.resolve.packages[pkg].name;
        let mut ns = format!("{}.{}", pascal(&name.namespace), pascal(&name.name));
        let versions = self
            .resolve
            .packages
            .iter()
            .filter(|(_, p)| p.name.namespace == name.namespace && p.name.name == name.name)
            .count();
        if let Some(version) = name.version.as_ref().filter(|_| versions > 1) {
            let version = version
                .to_string()
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect::<String>();
            ns.push_str(&format!(".V{version}"));
        }
        Some(ns)
    }

    fn interface_name(&self, id: InterfaceId) -> String {
        self.resolve.interfaces[id]
            .name
            .clone()
            .or_else(|| self.interface_names.get(&id).cloned())
            .unwrap_or_else(|| format!("interface{}", id.index()))
    }

    fn qualify(&self, relative: Option<String>) -> String {
        match relative {
            Some(ns) => format!("{}.{ns}", self.root),
            None => self.root.clone(),
        }
    }

    /// Fully qualified C# name of a declared type.
    fn type_name(&self, id: TypeId) -> String {
        let def = &self.resolve.types[id];
        let ns = match def.owner {
            TypeOwner::Interface(i) => self.qualify(Some(self.interface_namespace(i))),
            _ => self.root.clone(),
        };
        format!("global::{ns}.{}", pascal(def.name.as_deref().unwrap()))
    }

    fn temp(&self) -> String {
        let n = self.temps.get();
        self.temps.set(n + 1);
        format!("__t{n}")
    }

    fn emit(&self) -> String {
        let mut blocks: Vec<(String, Src)> = Vec::new();
        let mut block = |ns: String, src: Src| match blocks.iter_mut().find(|(n, _)| *n == ns) {
            Some((_, existing)) => {
                existing.line("");
                existing.append(src);
            }
            None => blocks.push((ns, src)),
        };

        for id in &self.decls {
            let def = &self.resolve.types[*id];
            let ns = match def.owner {
                TypeOwner::Interface(i) => self.qualify(Some(self.interface_namespace(i))),
                _ => self.root.clone(),
            };
            block(ns, self.emit_decl(*id));
        }
        for group in &self.imports {
            if let Some(id) = group.interface {
                block(
                    self.qualify(self.package_namespace(id)),
                    self.emit_import_interface(&self.import_interface_name(group), group),
                );
            }
        }
        for group in &self.exports {
            if let Some(id) = group.interface {
                block(
                    self.qualify(self.package_namespace(id)),
                    self.emit_export_class(&self.export_class_name(group), group),
                );
            }
        }
        block(self.root.clone(), self.emit_component());
        block(self.root.clone(), self.emit_codec());

        let world = &self.resolve.worlds[self.world];
        let world_id = match world.package {
            Some(pkg) => format!("{}/{}", self.resolve.packages[pkg].name, world.name),
            None => world.name.clone(),
        };
        let mut out = Src::default();
        out.line("// <auto-generated>");
        out.line(format!(
            "// Generated by hyperlight-component-csharp from WIT world {world_id}."
        ));
        out.line("// </auto-generated>");
        out.line("");
        out.line("#nullable enable");
        for (ns, src) in blocks {
            out.line("");
            out.line(format!("namespace {ns}"));
            out.open();
            out.append(src);
            out.close();
        }
        out.into_string()
    }

    fn import_interface_name(&self, group: &Group) -> String {
        match group.interface {
            Some(id) => format!("I{}", pascal(&self.interface_name(id))),
            None => format!("I{}Imports", pascal(&self.resolve.worlds[self.world].name)),
        }
    }

    fn export_class_name(&self, group: &Group) -> String {
        format!(
            "{}Exports",
            pascal(&self.interface_name(group.interface.unwrap()))
        )
    }

    fn qualified_group_type(&self, group: &Group, name: String) -> String {
        let ns = match group.interface {
            Some(id) => self.qualify(self.package_namespace(id)),
            None => self.root.clone(),
        };
        format!("global::{ns}.{name}")
    }

    /// Member names for interfaces, qualified with their package when
    /// two interfaces share a name.
    fn group_member_names(&self, groups: &[Group]) -> Vec<String> {
        let bases = groups
            .iter()
            .map(|g| match g.interface {
                Some(id) => self.interface_name(id),
                None => "world".to_string(),
            })
            .collect::<Vec<_>>();
        groups
            .iter()
            .zip(&bases)
            .map(|(g, base)| {
                let collides = bases.iter().filter(|b| *b == base).count() > 1;
                match (g.interface, collides) {
                    (Some(id), true) => format!(
                        "{}{}",
                        self.package_namespace(id)
                            .unwrap_or_default()
                            .replace('.', ""),
                        pascal(base)
                    ),
                    _ => pascal(base),
                }
            })
            .collect()
    }

    fn signature(&self, f: &Function, name: &str) -> String {
        let params = f
            .params
            .iter()
            .map(|p| format!("{} {}", self.ty(&p.ty), camel(&p.name)))
            .collect::<Vec<_>>()
            .join(", ");
        let result = f.result.as_ref().map_or("void".into(), |t| self.ty(t));
        format!("{result} {name}({params})")
    }

    fn wire_name(group: &Group, f: &Function) -> String {
        match &group.instance {
            Some(instance) => format!("{instance}#{}", f.name),
            None => f.name.clone(),
        }
    }

    fn emit_import_interface(&self, name: &str, group: &Group) -> Src {
        let mut src = Src::default();
        if let Some(id) = group.interface {
            src.docs(&self.resolve.interfaces[id].docs);
        }
        src.line(format!("public interface {name}"));
        src.open();
        for (i, f) in group.functions.iter().enumerate() {
            if i > 0 {
                src.line("");
            }
            src.docs(&f.docs);
            src.line(format!("{};", self.signature(f, &pascal(&f.name))));
        }
        src.close();
        src
    }

    fn emit_export_class(&self, name: &str, group: &Group) -> Src {
        let mut src = Src::default();
        if let Some(id) = group.interface {
            src.docs(&self.resolve.interfaces[id].docs);
        }
        src.line(format!("public sealed class {name}"));
        src.open();
        src.line(format!("private readonly {RT}.IGuestCaller _caller;"));
        src.line("");
        src.line(format!("internal {name}({RT}.IGuestCaller caller)"));
        src.open();
        src.line("_caller = caller;");
        src.close();
        self.emit_export_methods(&mut src, name, group);
        src.close();
        src
    }

    fn emit_export_methods(&self, src: &mut Src, class: &str, group: &Group) {
        for f in &group.functions {
            src.line("");
            src.docs(&f.docs);
            src.line(format!(
                "public {}",
                self.signature(f, &member(&f.name, class))
            ));
            src.open();
            if f.params.is_empty() {
                src.line("var __args = global::System.Array.Empty<byte[]>();");
            } else {
                src.line(format!("var __args = new byte[{}][];", f.params.len()));
            }
            for (i, p) in f.params.iter().enumerate() {
                src.open();
                src.line(format!("var __w = new {RT}.WireWriter();"));
                self.write(src, &p.ty, &camel(&p.name), "__w");
                src.line(format!("__args[{i}] = __w.ToArray();"));
                src.close();
            }
            let call = format!(
                "_caller.Call({}, __args)",
                string_literal(&Self::wire_name(group, f))
            );
            match &f.result {
                Some(ty) => {
                    src.line(format!("var __r = new {RT}.WireReader({call});"));
                    let value = self.read(src, ty, "__r");
                    src.line("__r.End();");
                    src.line(format!("return {value};"));
                }
                None => src.line(format!("{call};")),
            }
            src.close();
        }
    }

    fn emit_component(&self) -> Src {
        let world = &self.resolve.worlds[self.world];
        let name = format!("{}Component", pascal(&world.name));
        let mut src = Src::default();

        if let Some(group) = self.imports.iter().find(|g| g.interface.is_none()) {
            src.append(self.emit_import_interface(&self.import_interface_name(group), group));
            src.line("");
        }

        src.docs(&world.docs);
        src.line(format!("public sealed class {name}"));
        src.open();
        src.line(format!("private readonly {RT}.IGuestCaller _caller;"));
        src.line("");
        src.line(format!("public {name}({RT}.IGuestCaller caller)"));
        src.open();
        src.line("_caller = caller;");
        let export_names = self.group_member_names(&self.exports);
        for (group, prop) in self.exports.iter().zip(&export_names) {
            if group.interface.is_some() {
                let class = self.qualified_group_type(group, self.export_class_name(group));
                src.line(format!("{prop} = new {class}(caller);"));
            }
        }
        src.close();
        for (group, prop) in self.exports.iter().zip(&export_names) {
            if let Some(id) = group.interface {
                let class = self.qualified_group_type(group, self.export_class_name(group));
                src.line("");
                src.docs(&self.resolve.interfaces[id].docs);
                src.line(format!("public {class} {prop} {{ get; }}"));
            }
        }
        if let Some(group) = self.exports.iter().find(|g| g.interface.is_none()) {
            self.emit_export_methods(&mut src, &name, group);
        }

        let import_names = self.group_member_names(&self.imports);
        let params = self
            .imports
            .iter()
            .zip(&import_names)
            .map(|(group, base)| {
                let ty = self.qualified_group_type(group, self.import_interface_name(group));
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
            for f in &group.functions {
                self.emit_registration(&mut src, param, group, f);
            }
        }
        src.close();
        src.close();
        src
    }

    fn emit_registration(&self, src: &mut Src, target: &str, group: &Group, f: &Function) {
        src.line(format!(
            "registry.Register({}, {}, __args =>",
            string_literal(&Self::wire_name(group, f)),
            f.params.len()
        ));
        src.open();
        let mut args = Vec::new();
        for (i, p) in f.params.iter().enumerate() {
            let reader = format!("__r{i}");
            src.line(format!("var {reader} = new {RT}.WireReader(__args[{i}]);"));
            let value = self.read(src, &p.ty, &reader);
            src.line(format!("{reader}.End();"));
            args.push(value);
        }
        let call = format!("{target}.{}({})", pascal(&f.name), args.join(", "));
        match &f.result {
            Some(ty) => {
                src.line(format!("var __ret = {call};"));
                src.line(format!("var __w = new {RT}.WireWriter();"));
                self.write(src, ty, "__ret", "__w");
                src.line("return __w.ToArray();");
            }
            None => {
                src.line(format!("{call};"));
                src.line("return global::System.Array.Empty<byte>();");
            }
        }
        src.close_with("});");
    }
}

#[cfg(test)]
mod tests;
