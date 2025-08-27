/*
Copyright 2025 The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */

//! A bunch of utilities used by the actual code emit functions
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::vec::Vec;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::Ident;

use crate::etypes::{BoundedTyvar, Defined, Handleable, ImportExport, TypeBound, Tyvar};

/// A representation of a trait definition that we will eventually
/// emit. This is used to allow easily adding onto the trait each time
/// we see an extern decl.
#[derive(Debug, Default)]
pub struct Trait {
    /// A set of supertrait constraints, each associated with a
    /// bindings module path
    pub supertraits: BTreeMap<Vec<Ident>, TokenStream>,
    /// Keep track for each type variable of:
    /// - The identifier that we use for it in the generated source
    /// - Whether it comes from a component type variable, and if so,
    ///   which one. (Most do; the I: Imports on the main component
    ///   trait is the main one that doesn't).
    /// - Whether there are any bounds on it
    pub tvs: BTreeMap<Ident, (Option<u32>, TokenStream)>,
    /// Raw tokens of the contents of the trait
    pub items: TokenStream,
}
impl Trait {
    pub fn new() -> Self {
        Self {
            supertraits: BTreeMap::new(),
            tvs: BTreeMap::new(),
            items: TokenStream::new(),
        }
    }
    /// Collect the component tyvar indices that correspond to the
    /// type variables on this trait.
    ///
    /// Precondition: all of the type
    /// variables on this trait do correspond to component variables.
    pub fn tv_idxs(&self) -> Vec<u32> {
        self.tvs.iter().map(|(_, (n, _))| n.unwrap()).collect()
    }
    /// See [`State::adjust_vars`].
    pub fn adjust_vars(&mut self, n: u32) {
        for (_, (v, _)) in self.tvs.iter_mut() {
            if let Some(v) = v.as_mut() {
                *v += n;
            }
        }
    }
    /// Build a token stream of all type variables and trait bounds on
    /// them, e.g. what you would put "inside" the <> in trait T<...>.
    pub fn tv_toks_inner(&mut self) -> TokenStream {
        let tvs = self
            .tvs
            .iter()
            .map(|(k, (_, v))| {
                let colon = if v.is_empty() {
                    quote! {}
                } else {
                    quote! { : }
                };
                quote! { #k #colon #v }
            })
            .collect::<Vec<_>>();
        quote! { #(#tvs),* }
    }
    /// Build a token stream for the type variable part of the trait
    /// declaration
    pub fn tv_toks(&mut self) -> TokenStream {
        if !self.tvs.is_empty() {
            let toks = self.tv_toks_inner();
            quote! { <#toks> }
        } else {
            quote! {}
        }
    }
    /// Build a token stream for this entire trait definition
    pub fn into_tokens(&mut self, n: Ident) -> TokenStream {
        let trait_colon = if !self.supertraits.is_empty() {
            quote! { : }
        } else {
            quote! {}
        };
        let supertraits = self
            .supertraits
            .iter()
            .map(|(is, ts)| {
                quote! { #(#is)::*#ts }
            })
            .collect::<Vec<_>>();
        let tvs = self.tv_toks();
        let items = &self.items;
        quote! {
            pub trait #n #tvs #trait_colon #(#supertraits)+* { #items }
        }
    }
}

/// A representation of a module definition that we will eventually
/// emit. This is used to allow easily adding onto the module each time
/// we see a relevant decl.
#[derive(Debug, Default)]
pub struct Mod {
    pub submods: BTreeMap<Ident, Mod>,
    pub items: TokenStream,
    pub traits: BTreeMap<Ident, Trait>,
    pub impls: BTreeMap<(Vec<Ident>, Ident), TokenStream>,
}
impl Mod {
    pub fn empty() -> Self {
        Self {
            submods: BTreeMap::new(),
            items: TokenStream::new(),
            traits: BTreeMap::new(),
            impls: BTreeMap::new(),
        }
    }
    /// Get a reference to a sub-module, creating it if necessary
    pub fn submod<'a>(&'a mut self, i: Ident) -> &'a mut Self {
        self.submods.entry(i).or_insert(Self::empty())
    }
    /// Get an immutable reference to a sub-module
    ///
    /// Precondition: the named submodule must already exist
    pub fn submod_immut<'a>(&'a self, i: Ident) -> &'a Self {
        &self.submods[&i]
    }
    /// Get a reference to a trait definition in this module, creating
    /// it if necessary
    pub fn r#trait<'a>(&'a mut self, i: Ident) -> &'a mut Trait {
        self.traits.entry(i).or_default()
    }
    /// Get an immutable reference to a trait definition in this module
    ///
    /// Precondition: the named trait must already exist
    pub fn trait_immut<'a>(&'a self, i: Ident) -> &'a Trait {
        &self.traits[&i]
    }
    /// Get a reference to an impl block that is in this module,
    /// creating it if necessary.
    ///
    /// Currently, we don't track much information about these, so
    /// it's just a mutable token stream.
    pub fn r#impl<'a>(&'a mut self, t: Vec<Ident>, i: Ident) -> &'a mut TokenStream {
        self.impls.entry((t, i)).or_default()
    }
    /// See [`State::adjust_vars`].
    pub fn adjust_vars(&mut self, n: u32) {
        self.submods
            .iter_mut()
            .map(|(_, m)| m.adjust_vars(n))
            .for_each(drop);
        self.traits
            .iter_mut()
            .map(|(_, t)| t.adjust_vars(n))
            .for_each(drop);
    }
    /// Build a token stream for this entire module
    pub fn into_tokens(self) -> TokenStream {
        let mut tt = TokenStream::new();
        for (k, v) in self.submods {
            let vt = v.into_tokens();
            tt.extend(quote! {
                pub mod #k { #vt }
            });
        }
        for (n, mut t) in self.traits {
            tt.extend(t.into_tokens(n));
        }
        tt.extend(self.items);
        for ((ns, i), t) in self.impls {
            tt.extend(quote! {
                impl #(#ns)::* for #i { #t }
            })
        }
        tt
    }
}

/// A whole grab-bag of useful state to have while emitting Rust
#[derive(Debug)]
pub struct State<'a, 'b> {
    /// A pointer to a [`Mod`] that everything we emit will end up in
    pub root_mod: &'a mut Mod,
    /// A cursor to the current submodule (under [`State::root_mod`]),
    /// where decls that we are looking at right now should end up
    pub mod_cursor: Vec<Ident>,
    /// If we are currently processing decls that should end up inside
    /// a trait (representing an instance or a resource), this names
    /// the trait where they should end up.
    pub cur_trait: Option<Ident>,
    /// We use a "helper module" for auxiliary definitions: for
    /// example, an instance represented by `InstanceTrait` would end
    /// up with nominal definitions for its nontrivial types in
    /// `instance_trait::Type`.  This keeps track of the name of that
    /// module, if it presently exists.
    pub cur_helper_mod: Option<Ident>,
    /// Whether the trait/type definition that we are currently
    /// emitting is in the helper module or the main module
    /// corresponding directly to the wit package. This is important
    /// to get references to other types correct.
    pub is_helper: bool,
    /// All the bound variables in the component type that we are
    /// currently processing
    pub bound_vars: &'a mut VecDeque<BoundedTyvar<'b>>,
    /// An offset into bound_vars from which any variable indices we
    /// see in the source component type will be resolved; used to
    /// deal with the fact that when we recurse down into a type in
    /// the Eq bound of a type variable, its variables are offset from
    /// ours (since we use de Bruijn indices).
    pub var_offset: usize,
    /// A path through instance import/export names from the root
    /// component type to the type we are currently processing. This
    /// is used with [`crate::etypes::TyvarOrigin`] to decide whether
    /// a type variable we encounter is "locally defined", i.e. should
    /// have a type definition emitted for it in this module.
    pub origin: Vec<ImportExport<'b>>,
    /// A set of type variables that we encountered while emitting the
    /// type bound for a type variable.
    pub cur_needs_vars: Option<&'a mut BTreeSet<u32>>,
    /// A map from type variables to the type variables used in their
    /// bounds, used to ensure that we are parametrized over the
    /// things we need to be
    pub vars_needs_vars: &'a mut VecDeque<BTreeSet<u32>>,
    /// The Rust type parameter used to represent the type that
    /// implements the imports of a component
    pub import_param_var: Option<Ident>,
    /// The Rust type parameter used to represent the current Rust
    /// state type
    pub self_param_var: Option<Ident>,
    /// Whether we are emitting an implementation of the component
    /// interfaces, or just the types of the interface
    pub is_impl: bool,
    /// A namespace path and a name representing the Rust trait
    /// generated for the root component that we started codegen from
    pub root_component_name: Option<(TokenStream, &'a str)>,
    /// Whether we are generating code for the Hyperlight host or the
    /// Hyperlight guest
    pub is_guest: bool,
    /// A temporary hack to enable some special cases used by the
    /// wasmtime guest emit. When that is refactored to use the host
    /// guest emit, this can go away.
    pub is_wasmtime_guest: bool,
}

/// Create a State with all of its &mut references pointing to
/// sensible things, run a function that emits code into the state,
/// and then generate a token stream representing everything emitted
pub fn run_state<'b, F: for<'a> FnMut(&mut State<'a, 'b>)>(
    is_guest: bool,
    is_wasmtime_guest: bool,
    mut f: F,
) -> TokenStream {
    let mut root_mod = Mod::empty();
    let mut bound_vars = std::collections::VecDeque::new();
    let mut vars_needs_vars = std::collections::VecDeque::new();
    {
        let mut state = State::new(
            &mut root_mod,
            &mut bound_vars,
            &mut vars_needs_vars,
            is_guest,
            is_wasmtime_guest,
        );
        f(&mut state);
    }
    root_mod.into_tokens()
}

impl<'a, 'b> State<'a, 'b> {
    pub fn new(
        root_mod: &'a mut Mod,
        bound_vars: &'a mut VecDeque<BoundedTyvar<'b>>,
        vars_needs_vars: &'a mut VecDeque<BTreeSet<u32>>,
        is_guest: bool,
        is_wasmtime_guest: bool,
    ) -> Self {
        Self {
            root_mod,
            mod_cursor: Vec::new(),
            cur_trait: None,
            cur_helper_mod: None,
            is_helper: false,
            bound_vars,
            var_offset: 0,
            origin: Vec::new(),
            cur_needs_vars: None,
            vars_needs_vars,
            import_param_var: None,
            self_param_var: None,
            is_impl: false,
            root_component_name: None,
            is_guest,
            is_wasmtime_guest,
        }
    }
    pub fn clone<'c>(&'c mut self) -> State<'c, 'b> {
        State {
            root_mod: self.root_mod,
            mod_cursor: self.mod_cursor.clone(),
            cur_trait: self.cur_trait.clone(),
            cur_helper_mod: self.cur_helper_mod.clone(),
            is_helper: self.is_helper,
            bound_vars: self.bound_vars,
            var_offset: self.var_offset,
            origin: self.origin.clone(),
            cur_needs_vars: self.cur_needs_vars.as_deref_mut(),
            vars_needs_vars: self.vars_needs_vars,
            import_param_var: self.import_param_var.clone(),
            self_param_var: self.self_param_var.clone(),
            is_impl: self.is_impl,
            root_component_name: self.root_component_name.clone(),
            is_guest: self.is_guest,
            is_wasmtime_guest: self.is_wasmtime_guest,
        }
    }
    /// Obtain a reference to the [`Mod`] that we are currently
    /// generating code in, creating it if necessary
    pub fn cur_mod<'c>(&'c mut self) -> &'c mut Mod {
        let mut m: &'c mut Mod = self.root_mod;
        for i in &self.mod_cursor {
            m = m.submod(i.clone());
        }
        if self.is_helper {
            m = m.submod(self.cur_helper_mod.clone().unwrap());
        }
        m
    }
    /// Obtain an immutable reference to the [`Mod`] that we are
    /// currently generating code in.
    ///
    /// Precondition: the module must already exist
    pub fn cur_mod_immut<'c>(&'c self) -> &'c Mod {
        let mut m: &'c Mod = self.root_mod;
        for i in &self.mod_cursor {
            m = m.submod_immut(i.clone());
        }
        if self.is_helper {
            m = m.submod_immut(self.cur_helper_mod.clone().unwrap());
        }
        m
    }
    /// Copy the state, changing its module cursor to emit code into a
    /// different module
    pub fn with_cursor<'c>(&'c mut self, cursor: Vec<Ident>) -> State<'c, 'b> {
        let mut s = self.clone();
        s.mod_cursor = cursor;
        s
    }
    /// Copy the state, replacing its [`State::cur_needs_vars`] reference,
    /// allowing a caller to capture the vars referenced by any emit
    /// run with the resultant state
    pub fn with_needs_vars<'c>(&'c mut self, needs_vars: &'c mut BTreeSet<u32>) -> State<'c, 'b> {
        let mut s = self.clone();
        s.cur_needs_vars = Some(needs_vars);
        s
    }
    /// Record that an emit sequence needed a var, given an absolute
    /// index for the var (i.e. ignoring [`State::var_offset`])
    pub fn need_noff_var(&mut self, n: u32) {
        self.cur_needs_vars.as_mut().map(|vs| vs.insert(n));
    }
    /// Use the [`State::cur_needs_vars`] map to populate
    /// [`State::vars_needs_vars`] for a var that we presumably just
    /// finished emitting a bound for
    pub fn record_needs_vars(&mut self, n: u32) {
        let un = n as usize;
        if self.vars_needs_vars.len() < un + 1 {
            self.vars_needs_vars.resize(un + 1, BTreeSet::new());
        }
        let Some(ref mut cnvs) = self.cur_needs_vars else {
            return;
        };
        log::debug!("debug varref: recording {:?} for var {:?}", cnvs.iter(), un);
        self.vars_needs_vars[un].extend(cnvs.iter());
    }
    /// Get a list of all the variables needed by a var, given its absolute
    /// index (i.e. ignoring [`State::var_offset`])
    pub fn get_noff_var_refs(&mut self, n: u32) -> BTreeSet<u32> {
        let un = n as usize;
        if self.vars_needs_vars.len() < un + 1 {
            return BTreeSet::new();
        };
        log::debug!(
            "debug varref: looking up {:?} for var {:?}",
            self.vars_needs_vars[un].iter(),
            un
        );
        self.vars_needs_vars[un].clone()
    }
    /// Find the exported name which gave rise to a component type
    /// variable, given its absolute index (i.e. ignoring
    /// [`State::var_offset`])
    pub fn noff_var_id(&self, n: u32) -> Ident {
        let Some(n) = self.bound_vars[n as usize].origin.last_name() else {
            panic!("missing origin on tyvar in rust emit")
        };
        kebab_to_type(n)
    }
    /// Copy the state, changing it to emit into the helper module of
    /// the current trait
    pub fn helper<'c>(&'c mut self) -> State<'c, 'b> {
        let mut s = self.clone();
        s.is_helper = true;
        s
    }
    /// Construct a namespace token stream that can be emitted in the
    /// current module to refer to a name in the root module
    pub fn root_path(&self) -> TokenStream {
        if self.is_impl {
            return TokenStream::new();
        }
        let mut s = self
            .mod_cursor
            .iter()
            .map(|_| quote! { super })
            .collect::<Vec<_>>();
        if self.is_helper {
            s.push(quote! { super });
        }
        quote! { #(#s::)* }
    }
    /// Construct a namespace token stream that can be emitted in the
    /// current module to refer to a name in the helper module
    pub fn helper_path(&self) -> TokenStream {
        if self.is_impl {
            let c = &self.mod_cursor;
            let helper = self.cur_helper_mod.clone().unwrap();
            let h = if !self.is_helper {
                quote! { #helper:: }
            } else {
                TokenStream::new()
            };
            quote! { #(#c::)*#h }
        } else if self.is_helper {
            quote! { self:: }
        } else {
            let helper = self.cur_helper_mod.clone().unwrap();
            quote! { #helper:: }
        }
    }
    /// Emit a namespace token stream that can be emitted in the root
    /// module to refer to the current trait
    pub fn cur_trait_path(&self) -> TokenStream {
        let tns = &self.mod_cursor;
        let tid = self.cur_trait.clone().unwrap();
        quote! { #(#tns::)* #tid }
    }
    /// Add a supertrait constraint referring to a trait in the helper
    /// module; primarily used to add a constraint for the trait
    /// representing a resource type.
    pub fn add_helper_supertrait(&mut self, r: Ident) {
        let (Some(t), Some(hm)) = (self.cur_trait.clone(), &self.cur_helper_mod.clone()) else {
            panic!("invariant violation")
        };
        self.cur_mod()
            .r#trait(t)
            .supertraits
            .insert(vec![hm.clone(), r], TokenStream::new());
    }
    /// Obtain a reference to the [`Trait`] that we are currently
    /// generating code in, creating it if necessary.
    ///
    /// Precondition: we are currently generating code in a trait
    /// (i.e. [`State::cur_trait`] is not [`None`])
    pub fn cur_trait<'c>(&'c mut self) -> &'c mut Trait {
        let n = self.cur_trait.as_ref().unwrap().clone();
        self.cur_mod().r#trait(n)
    }
    /// Obtain an immutable reference to the [`Trait`] that we are
    /// currently generating code in.
    ///
    /// Precondition: we are currently generating code in a trait
    /// (i.e. [`State::cur_trait`] is not [`None`]), and that trait has
    /// already been created
    pub fn cur_trait_immut<'c>(&'c self) -> &'c Trait {
        let n = self.cur_trait.as_ref().unwrap().clone();
        self.cur_mod_immut().trait_immut(n)
    }
    /// Obtain a reference to the trait at the given module path and
    /// name from the root module, creating it and any named modules
    /// if necessary
    pub fn r#trait<'c>(&'c mut self, namespace: &'c [Ident], name: Ident) -> &'c mut Trait {
        let mut m: &'c mut Mod = self.root_mod;
        for i in namespace {
            m = m.submod(i.clone());
        }
        m.r#trait(name)
    }
    /// Add an import/export to [`State::origin`], reflecting that we are now
    /// looking at code underneath it
    pub fn push_origin<'c>(&'c mut self, is_export: bool, name: &'b str) -> State<'c, 'b> {
        let mut s = self.clone();
        s.origin.push(if is_export {
            ImportExport::Export(name)
        } else {
            ImportExport::Import(name)
        });
        s
    }
    /// Find out if a [`Defined`] type is actually a reference to a
    /// locally defined type variable, returning its index and bound
    /// if it is
    pub fn is_var_defn(&self, t: &Defined<'b>) -> Option<(u32, TypeBound<'b>)> {
        match t {
            Defined::Handleable(Handleable::Var(tv)) => match tv {
                Tyvar::Bound(n) => {
                    let bv = &self.bound_vars[self.var_offset + (*n as usize)];
                    log::debug!("checking an origin {:?} {:?}", bv.origin, self.origin);
                    if bv.origin.matches(self.origin.iter()) {
                        Some((*n, bv.bound.clone()))
                    } else {
                        None
                    }
                }
                Tyvar::Free(_) => panic!("free tyvar in finished type"),
            },
            _ => None,
        }
    }
    /// Find out if a variable is locally-defined given its absolute
    /// index, returning its origin and bound if it is
    pub fn is_noff_var_local<'c>(
        &'c self,
        n: u32,
    ) -> Option<(Vec<ImportExport<'c>>, TypeBound<'a>)> {
        let bv = &self.bound_vars[n as usize];
        bv.origin
            .is_local(self.origin.iter())
            .map(|path| (path, bv.bound.clone()))
    }
    /// Obtain an immutable reference to the trait at the specified
    /// namespace path, either from the root module (if `absolute`)
    /// is true, or from the current module
    ///
    /// Precondition: all named traits/modules must exist
    pub fn resolve_trait_immut(&self, absolute: bool, path: &[Ident]) -> &Trait {
        log::debug!("resolving trait {:?} {:?}", absolute, path);
        let mut m = if absolute {
            &*self.root_mod
        } else {
            self.cur_mod_immut()
        };
        for x in &path[0..path.len() - 1] {
            m = &m.submods[x];
        }
        &m.traits[&path[path.len() - 1]]
    }
    /// Shift all of the type variable indices over, because we have
    /// gone under some binders.  Used when we switch from looking at
    /// a component's import types (where type idxs are de Bruijn into
    /// the component's uvar list) to a component's export types
    /// (where type idx are de Bruijn first into the evar list and
    /// then the uvar list, as we go under the existential binders).
    pub fn adjust_vars(&mut self, n: u32) {
        self.vars_needs_vars
            .iter_mut()
            .enumerate()
            .for_each(|(i, vs)| {
                *vs = vs.iter().map(|v| v + n).collect();
                log::debug!("updated {:?} to {:?}", i, *vs);
            });
        for _ in 0..n {
            self.vars_needs_vars.push_front(BTreeSet::new());
        }
        self.root_mod.adjust_vars(n);
    }
    /// Resolve a type variable as far as possible: either this ends
    /// up with a definition, in which case, let's get that, or it
    /// ends up with a resource type, in which case we return the
    /// resource index
    pub fn resolve_tv(&self, n: u32) -> (u32, Option<Defined<'b>>) {
        let m = n + self.var_offset as u32;
        match &self.bound_vars[m as usize].bound {
            TypeBound::Eq(Defined::Handleable(Handleable::Var(Tyvar::Bound(nn)))) => {
                self.resolve_tv(n + 1 + nn)
            }
            TypeBound::Eq(t) => (n, Some(t.clone())),
            TypeBound::SubResource => (m, None),
        }
    }
    /// Construct a namespace path referring to the resource trait for
    /// a resource with the given name
    pub fn resource_trait_path(&self, r: Ident) -> Vec<Ident> {
        let mut path = self.mod_cursor.clone();
        let helper = self
            .cur_helper_mod
            .as_ref()
            .expect("There should always be a helper mod to hold a resource trait")
            .clone();
        path.push(helper);
        path.push(r);
        path
    }
}

/// A parsed representation of a WIT name, containing package
/// namespaces, an actual name, and possibly a SemVer version
#[derive(Debug, Clone)]
pub struct WitName<'a> {
    pub namespaces: Vec<&'a str>,
    pub name: &'a str,
    pub _version: Vec<&'a str>,
}
impl<'a> WitName<'a> {
    /// Extract a list of Rust module names corresponding to the WIT
    /// namespace/package
    pub fn namespace_idents(&self) -> Vec<Ident> {
        self.namespaces
            .iter()
            .map(|x| kebab_to_namespace(x))
            .collect::<Vec<_>>()
    }
    /// Extract a token stream representing the Rust namespace path
    /// corresponding to the WIT namespace/package
    pub fn namespace_path(&self) -> TokenStream {
        let ns = self.namespace_idents();
        quote! { #(#ns)::* }
    }
}
/// Parse a kebab-name as a WIT name
pub fn split_wit_name(n: &str) -> WitName {
    let mut namespaces = Vec::new();
    let mut colon_components = n.split(':').rev();
    let last = colon_components.next().unwrap();
    namespaces.extend(colon_components.rev());
    let mut slash_components = last.split('/').rev();
    let mut versioned_name = slash_components.next().unwrap().split('@');
    let name = versioned_name.next().unwrap();
    namespaces.extend(slash_components.rev());
    WitName {
        namespaces,
        name,
        _version: versioned_name.collect(),
    }
}

fn kebab_to_snake(n: &str) -> Ident {
    if n == "self" {
        return format_ident!("self_");
    }
    let mut ret = String::new();
    for c in n.chars() {
        if c == '-' {
            ret.push('_');
            continue;
        }
        ret.push(c);
    }
    format_ident!("r#{}", ret)
}

fn kebab_to_camel(n: &str) -> Ident {
    let mut word_start = true;
    let mut ret = String::new();
    for c in n.chars() {
        if c == '-' {
            word_start = true;
            continue;
        }
        if word_start {
            ret.extend(c.to_uppercase())
        } else {
            ret.push(c)
        };
        word_start = false;
    }
    format_ident!("{}", ret)
}

/// Convert a kebab name to something suitable for use as a
/// (value-level) variable
pub fn kebab_to_var(n: &str) -> Ident {
    kebab_to_snake(n)
}
/// Convert a kebab name to something suitable for use as a
/// type constructor
pub fn kebab_to_cons(n: &str) -> Ident {
    kebab_to_camel(n)
}
/// Convert a kebab name to something suitable for use as a getter
/// function name
pub fn kebab_to_getter(n: &str) -> Ident {
    kebab_to_snake(n)
}
/// Convert a kebab name to something suitable for use as a type name
pub fn kebab_to_type(n: &str) -> Ident {
    kebab_to_camel(n)
}
/// Convert a kebab name to something suitable for use as a module
/// name/namespace path entry
pub fn kebab_to_namespace(n: &str) -> Ident {
    kebab_to_snake(n)
}
/// From a kebab name for a Component, derive something suitable for
/// use as the name of the imports trait for that component
pub fn kebab_to_imports_name(trait_name: &str) -> Ident {
    format_ident!("{}Imports", kebab_to_type(trait_name))
}
/// From a kebab name for a Component, derive something suitable for
/// use as the name of the imports trait for that component
pub fn kebab_to_exports_name(trait_name: &str) -> Ident {
    format_ident!("{}Exports", kebab_to_type(trait_name))
}

/// The kinds of names that a function associated with a resource in
/// WIT can have
pub enum ResourceItemName {
    Constructor,
    Method(Ident),
    Static(Ident),
}

/// The kinds of names that a function in WIT can have
pub enum FnName {
    Associated(Ident, ResourceItemName),
    Plain(Ident),
}
/// Parse a kebab-name as a WIT function name, figuring out if it is
/// associated with a resource
pub fn kebab_to_fn(n: &str) -> FnName {
    if let Some(n) = n.strip_prefix("[constructor]") {
        return FnName::Associated(kebab_to_type(n), ResourceItemName::Constructor);
    }
    if let Some(n) = n.strip_prefix("[method]") {
        let mut i = n.split('.');
        let r = i.next().unwrap();
        let n = i.next().unwrap();
        return FnName::Associated(
            kebab_to_type(r),
            ResourceItemName::Method(kebab_to_snake(n)),
        );
    }
    if let Some(n) = n.strip_prefix("[static]") {
        let mut i = n.split('.');
        let r = i.next().unwrap();
        let n = i.next().unwrap();
        return FnName::Associated(
            kebab_to_type(r),
            ResourceItemName::Static(kebab_to_snake(n)),
        );
    }
    FnName::Plain(kebab_to_snake(n))
}
