// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! C# bindings for the host side of a WIT world.
//!
//! The generator walks the elaborated component type from
//! [`hyperlight_component_util`], which the Rust bindings also use. The
//! generated code encodes values in the format described in
//! `docs/component-wire-format.md` and calls guest functions through the
//! interfaces in [`RUNTIME_SOURCE`]. It covers every WIT value type and
//! resources the host defines. Resources the guest defines, async
//! functions, futures, streams, maps and flags with more than 32 members
//! are rejected.

mod codec;
mod host;
mod names;
mod types;

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::path::Path;

use hyperlight_component_util::emit::{State, split_wit_name};
use hyperlight_component_util::etypes::{Component, ExternDesc, Value};
use hyperlight_component_util::util::{WitSource, read_wit_type};
use names::{Src, pascal};

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

/// Generate C# bindings for a world in the `.wit` file or directory at
/// `path`. A relative `path` is resolved against `CARGO_MANIFEST_DIR` when
/// set, and the working directory otherwise. See [`generate`] for `world`
/// and `namespace`.
pub fn generate_from_path(
    path: &Path,
    world: Option<&str>,
    namespace: &str,
) -> Result<String, Error> {
    generate(WitSource::Wit(path.to_path_buf()), world, namespace)
}

/// Generate C# bindings for the world named `world` in `source`, or its
/// last world. All generated types are placed under `namespace`.
///
/// # Panics
///
/// If `source` cannot be read or elaborated, as the bindgen macros do.
pub fn generate(source: WitSource, world: Option<&str>, namespace: &str) -> Result<String, Error> {
    if !namespace.split('.').all(names::is_identifier) {
        return Err(error(format!("invalid C# namespace '{namespace}'")));
    }
    let world = world.map(str::to_string);
    read_wit_type(source, world, |name, ct| emit(&name, ct, namespace))
}

type S<'a, 'b> = State<'a, 'b, Root<'b>>;

fn emit(name: &str, ct: &Component<'_>, namespace: &str) -> Result<String, Error> {
    let mut root = Root::new(namespace, name, ct);
    // Export types refer to the existential variables, then the
    // universal ones. Import types refer to the universal ones.
    let mut bound_vars = ct
        .instance
        .evars
        .iter()
        .rev()
        .chain(ct.uvars.iter().rev())
        .cloned()
        .collect::<VecDeque<_>>();
    let mut vars_needs_vars = VecDeque::new();
    let mut s = State::new(
        &mut root,
        &mut bound_vars,
        &mut vars_needs_vars,
        false,
        false,
    );
    types::emit_toplevel(&mut s, ct)?;
    host::emit_toplevel(&mut s, ct)?;
    Ok(root.render())
}

/// A record, variant, enum or flags type declared in C#.
struct Decl<'b> {
    /// Absolute index of the type variable that defines it
    var: usize,
    /// Other type variables for the same WIT type, from a second copy of
    /// its interface
    aliases: Vec<usize>,
    /// Definition, relative to the variables after `var`
    value: Value<'b>,
    /// Fully qualified C# namespace
    namespace: String,
    name: String,
    /// Suffix of its codec methods
    mangled: String,
    /// Whether the world declares it outside any interface
    world_level: bool,
    /// Instance whose type it is, which identifies the WIT type with
    /// its name
    instance: Option<String>,
}

/// A resource type the host defines. The host implements its C#
/// interface, and the guest holds its values by handle.
struct ResourceDecl {
    /// Absolute index of the type variable that introduces it
    var: usize,
    /// WIT name of the resource
    wit_name: String,
    /// Instance that defines it, or `None` for the world itself
    instance: Option<String>,
    /// Fully qualified C# namespace
    namespace: String,
    /// C# interface name, e.g. `IFields`
    name: String,
    /// Name of its handle table in the resources class
    table: String,
}

/// The C# source for one world, grouped by namespace, and the names of
/// its declared types.
pub(crate) struct Root<'b> {
    /// Root C# namespace
    ns: String,
    /// WIT name of the world
    world: String,
    /// C# name of the world, e.g. `Wire` for `test:wire/wire@0.1.0`
    world_type: String,
    /// Fully qualified name of the static class holding codec methods
    codec: String,
    /// Fully qualified name of the class holding resource tables
    resources_class: String,
    decls: Vec<Decl<'b>>,
    resources: Vec<ResourceDecl>,
    /// `namespace:package` names the world uses at several versions
    versioned: HashSet<String>,
    /// Package namespaces and version of the world, which also hold
    /// its inline interfaces
    world_package: (Vec<String>, String),
    /// Counter for unique local variable names
    temps: usize,
    /// Source of each namespace, in the order first written
    namespaces: Vec<(String, Src)>,
    /// Methods of the codec class
    codec_methods: Src,
}

impl<'b> Root<'b> {
    fn new(ns: &str, world: &str, ct: &Component<'_>) -> Self {
        let wn = split_wit_name(world);
        let world_type = pascal(wn.name);
        let world_package = (
            wn.namespaces
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>(),
            wn._version.join("@"),
        );
        let mut versions = HashMap::<String, HashSet<String>>::new();
        for ed in ct.imports.iter().chain(&ct.instance.unqualified.exports) {
            if let ExternDesc::Instance(_) = ed.desc {
                let (namespaces, version) = package(&world_package, ed.kebab_name);
                if !namespaces.is_empty() {
                    versions
                        .entry(namespaces.join(":"))
                        .or_default()
                        .insert(version);
                }
            }
        }
        Root {
            ns: ns.to_string(),
            world: world.to_string(),
            codec: format!("global::{ns}.{world_type}Codec"),
            resources_class: format!("global::{ns}.{world_type}Resources"),
            world_type,
            decls: Vec::new(),
            resources: Vec::new(),
            versioned: versions
                .into_iter()
                .filter(|(_, v)| v.len() > 1)
                .map(|(k, _)| k)
                .collect(),
            world_package,
            temps: 0,
            namespaces: Vec::new(),
            codec_methods: Src::default(),
        }
    }

    /// Append a declaration to the namespace `ns`.
    fn add(&mut self, ns: String, src: Src) {
        match self.namespaces.iter_mut().find(|(n, _)| *n == ns) {
            Some((_, existing)) => {
                existing.line("");
                existing.append(src);
            }
            None => self.namespaces.push((ns, src)),
        }
    }

    fn add_codec_methods(&mut self, src: Src) {
        if !self.codec_methods.is_empty() {
            self.codec_methods.line("");
        }
        self.codec_methods.append(src);
    }

    fn render(mut self) -> String {
        let name = self.codec.rsplit('.').next().unwrap().to_string();
        let mut codec = Src::default();
        codec.line(format!("internal static class {name}"));
        codec.open();
        codec.append(std::mem::take(&mut self.codec_methods));
        codec.close();
        self.add(self.ns.clone(), codec);

        let mut out = Src::default();
        out.line("// <auto-generated>");
        out.line(format!(
            "// Generated by hyperlight-component-csharp from WIT world {}.",
            self.world
        ));
        out.line("// </auto-generated>");
        out.line("");
        out.line("#nullable enable");
        for (ns, src) in self.namespaces {
            out.line("");
            out.line(format!("namespace {ns}"));
            out.open();
            out.append(src);
            out.close();
        }
        out.into_string()
    }

    /// Namespace of an instance's package relative to the root namespace,
    /// e.g. `Wasi.Http`. The version is added, e.g. `Wasi.Http.V0_2_0`,
    /// when the world uses the package at several versions.
    fn package_namespace(&self, instance: &str) -> Option<String> {
        let (namespaces, version) = package(&self.world_package, instance);
        if namespaces.is_empty() {
            return None;
        }
        let mut ns = namespaces
            .iter()
            .map(|n| pascal(n))
            .collect::<Vec<_>>()
            .join(".");
        if self.versioned.contains(&namespaces.join(":")) {
            let version = version
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect::<String>();
            ns.push_str(&format!(".V{version}"));
        }
        Some(ns)
    }

    /// Namespace of an instance's types relative to the root namespace,
    /// e.g. `Wasi.Http.Types`.
    fn interface_namespace(&self, instance: &str) -> String {
        let name = pascal(split_wit_name(instance).name);
        match self.package_namespace(instance) {
            Some(pkg) => format!("{pkg}.{name}"),
            None => name,
        }
    }

    fn qualify(&self, relative: Option<String>) -> String {
        match relative {
            Some(ns) => format!("{}.{ns}", self.ns),
            None => self.ns.clone(),
        }
    }

    fn temp(&mut self) -> String {
        self.temps += 1;
        format!("__t{}", self.temps - 1)
    }

    /// Index in `decls` of the type declared for the variable `var`.
    fn decl_index(&self, var: usize) -> Option<usize> {
        self.decls
            .iter()
            .position(|d| d.var == var || d.aliases.contains(&var))
    }

    /// Fully qualified C# name of a declared type.
    fn type_name(&self, d: &Decl) -> String {
        format!("global::{}.{}", d.namespace, d.name)
    }

    /// Index in `resources` of the resource introduced by the variable `var`.
    fn resource_index(&self, var: usize) -> Option<usize> {
        self.resources.iter().position(|r| r.var == var)
    }

    /// Expression for the table of resource `i`, given an expression for
    /// the resources object.
    fn resource_table(&self, i: usize, resources: &str) -> String {
        format!(
            "(({}){resources}!).{}",
            self.resources_class, self.resources[i].table
        )
    }
}

/// Package namespaces and version of an instance. Inline interfaces
/// belong to the world's package.
fn package(world_package: &(Vec<String>, String), instance: &str) -> (Vec<String>, String) {
    let wn = split_wit_name(instance);
    if wn.namespaces.is_empty() {
        return world_package.clone();
    }
    (
        wn.namespaces.iter().map(|n| n.to_string()).collect(),
        wn._version.join("@"),
    )
}

#[cfg(test)]
mod tests;
