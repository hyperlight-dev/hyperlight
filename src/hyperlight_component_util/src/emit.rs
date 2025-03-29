use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::vec::Vec;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::Ident;

use crate::dbg_println;
use crate::etypes::{BoundedTyvar, Defined, Handleable, ImportExport, TypeBound, Tyvar};

#[derive(Debug)]
pub struct Trait {
    pub supertraits: BTreeMap<Vec<Ident>, TokenStream>,
    pub tvs: BTreeMap<Ident, (Option<u32>, TokenStream)>,
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
    pub fn tv_idxs(&self) -> Vec<u32> {
        self.tvs.iter().map(|(_, (n, _))| n.unwrap()).collect()
    }
    pub fn adjust_vars(&mut self, n: u32) {
        for (_, (v, _)) in self.tvs.iter_mut() {
            v.as_mut().map(|v| *v += n);
        }
    }
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
    pub fn tv_toks(&mut self) -> TokenStream {
        if self.tvs.len() > 0 {
            let toks = self.tv_toks_inner();
            quote! { <#toks> }
        } else {
            quote! {}
        }
    }
    pub fn emit(&mut self, n: Ident) -> TokenStream {
        let trait_colon = if self.supertraits.len() > 0 {
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

#[derive(Debug)]
pub struct Mod {
    pub submods: BTreeMap<Ident, Mod>,
    pub items: TokenStream,
    pub traits: BTreeMap<Ident, Trait>,
}
impl Mod {
    pub fn empty() -> Self {
        Self {
            submods: BTreeMap::new(),
            items: TokenStream::new(),
            traits: BTreeMap::new(),
        }
    }
    pub fn submod<'a>(&'a mut self, i: Ident) -> &'a mut Self {
        self.submods.entry(i).or_insert(Self::empty())
    }
    pub fn submod_immut<'a>(&'a self, i: Ident) -> &'a Self {
        &self.submods[&i]
    }
    pub fn r#trait<'a>(&'a mut self, i: Ident) -> &'a mut Trait {
        self.traits.entry(i).or_insert(Trait::new())
    }
    pub fn trait_immut<'a>(&'a self, i: Ident) -> &'a Trait {
        &self.traits[&i]
    }
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
    pub fn into_tokens(self) -> TokenStream {
        let mut tt = TokenStream::new();
        for (k, v) in self.submods {
            let vt = v.into_tokens();
            tt.extend(quote! {
                pub mod #k { #vt }
            });
        }
        for (n, mut t) in self.traits {
            tt.extend(t.emit(n));
        }
        tt.extend(self.items);
        tt
    }
}

#[derive(Debug)]
pub struct State<'a, 'b> {
    pub root_mod: &'a mut Mod,
    pub mod_cursor: Vec<Ident>,
    pub cur_trait: Option<Ident>,
    pub cur_helper_mod: Option<Ident>,
    pub is_helper: bool,
    pub bound_vars: &'a mut VecDeque<BoundedTyvar<'b>>,
    pub var_offset: usize,
    pub origin: Vec<ImportExport<'b>>,
    pub cur_needs_vars: Option<&'a mut BTreeSet<u32>>,
    pub vars_needs_vars: &'a mut VecDeque<BTreeSet<u32>>,
    pub helper_type_name: Option<Ident>,
    pub import_param_var: Option<Ident>,
    pub self_param_var: Option<Ident>,
    pub is_impl: bool,
    pub root_component_name: Option<(TokenStream, &'a str)>,
    pub is_guest: bool,
}

pub fn run_state<'b, F: for<'a> FnMut(&mut State<'a, 'b>)>(
    is_guest: bool,
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
            helper_type_name: None,
            import_param_var: None,
            self_param_var: None,
            is_impl: false,
            root_component_name: None,
            is_guest,
        }
    }
    pub fn clone<'c>(&'c mut self) -> State<'c, 'b> {
        State {
            root_mod: &mut self.root_mod,
            mod_cursor: self.mod_cursor.clone(),
            cur_trait: self.cur_trait.clone(),
            cur_helper_mod: self.cur_helper_mod.clone(),
            is_helper: self.is_helper,
            bound_vars: &mut self.bound_vars,
            var_offset: self.var_offset,
            origin: self.origin.clone(),
            cur_needs_vars: self.cur_needs_vars.as_mut().map(|v| &mut **v),
            vars_needs_vars: &mut self.vars_needs_vars,
            helper_type_name: self.helper_type_name.clone(),
            import_param_var: self.import_param_var.clone(),
            self_param_var: self.self_param_var.clone(),
            is_impl: self.is_impl,
            root_component_name: self.root_component_name.clone(),
            is_guest: self.is_guest,
        }
    }
    pub fn cur_mod<'c>(&'c mut self) -> &'c mut Mod {
        let mut m: &'c mut Mod = &mut self.root_mod;
        for i in &self.mod_cursor {
            m = m.submod(i.clone());
        }
        if self.is_helper {
            m = m.submod(self.cur_helper_mod.clone().unwrap());
        }
        m
    }
    pub fn cur_mod_immut<'c>(&'c self) -> &'c Mod {
        let mut m: &'c Mod = &self.root_mod;
        for i in &self.mod_cursor {
            m = m.submod_immut(i.clone());
        }
        if self.is_helper {
            m = m.submod_immut(self.cur_helper_mod.clone().unwrap());
        }
        m
    }
    pub fn with_cursor<'c>(&'c mut self, cursor: Vec<Ident>) -> State<'c, 'b> {
        let mut s = self.clone();
        s.mod_cursor = cursor;
        s
    }
    pub fn with_needs_vars<'c>(&'c mut self, needs_vars: &'c mut BTreeSet<u32>) -> State<'c, 'b> {
        let mut s = self.clone();
        s.cur_needs_vars = Some(needs_vars);
        s
    }
    pub fn need_noff_var(&mut self, n: u32) {
        self.cur_needs_vars.as_mut().map(|vs| vs.insert(n));
    }
    pub fn record_needs_vars(&mut self, n: u32) {
        let un = n as usize;
        if self.vars_needs_vars.len() < un + 1 {
            self.vars_needs_vars.resize(un + 1, BTreeSet::new());
        }
        let Some(ref mut cnvs) = self.cur_needs_vars else {
            return;
        };
        dbg_println!("debug varref: recording {:?} for var {:?}", cnvs.iter(), un);
        self.vars_needs_vars[un].extend(cnvs.iter());
    }
    pub fn get_noff_var_refs(&mut self, n: u32) -> BTreeSet<u32> {
        let un = n as usize;
        if self.vars_needs_vars.len() < un + 1 {
            return BTreeSet::new();
        };
        dbg_println!(
            "debug varref: looking up {:?} for var {:?}",
            self.vars_needs_vars[un].iter(),
            un
        );
        self.vars_needs_vars[un].clone()
    }
    pub fn noff_var_id(&self, n: u32) -> Ident {
        let Some(n) = self.bound_vars[n as usize].origin.last_name() else {
            panic!("missing origin on tyvar in rust emit")
        };
        kebab_to_type(n)
    }
    pub fn helper<'c>(&'c mut self) -> State<'c, 'b> {
        let mut s = self.clone();
        s.is_helper = true;
        s
    }
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
    pub fn cur_trait_path(&self) -> TokenStream {
        let tns = &self.mod_cursor;
        let tid = self.cur_trait.clone().unwrap();
        quote! { #(#tns::)* #tid }
    }
    pub fn add_helper_supertrait(&mut self, r: Ident) {
        let (Some(t), Some(hm)) = (self.cur_trait.clone(), &self.cur_helper_mod.clone()) else {
            panic!("invariant violation")
        };
        self.cur_mod()
            .r#trait(t)
            .supertraits
            .insert(vec![hm.clone(), r], TokenStream::new());
    }
    pub fn cur_trait<'c>(&'c mut self) -> &'c mut Trait {
        let n = self.cur_trait.as_ref().unwrap().clone();
        self.cur_mod().r#trait(n)
    }
    pub fn cur_trait_immut<'c>(&'c self) -> &'c Trait {
        let n = self.cur_trait.as_ref().unwrap().clone();
        self.cur_mod_immut().trait_immut(n)
    }
    pub fn r#trait<'c>(&'c mut self, namespace: &'c [Ident], name: Ident) -> &'c mut Trait {
        let mut m: &'c mut Mod = &mut self.root_mod;
        for i in namespace {
            m = m.submod(i.clone());
        }
        m.r#trait(name)
    }
    pub fn push_origin<'c>(&'c mut self, is_export: bool, name: &'b str) -> State<'c, 'b> {
        let mut s = self.clone();
        s.origin.push(if is_export {
            ImportExport::Export(name)
        } else {
            ImportExport::Import(name)
        });
        s
    }
    pub fn is_var_defn(&self, t: &Defined<'b>) -> Option<(u32, TypeBound<'b>)> {
        match t {
            Defined::Handleable(Handleable::Var(tv)) => match tv {
                Tyvar::Bound(n) => {
                    let bv = &self.bound_vars[self.var_offset + (*n as usize)];
                    dbg_println!("checking an origin {:?} {:?}", bv.origin, self.origin);
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
    pub fn is_noff_var_local<'c>(
        &'c self,
        n: u32,
    ) -> Option<(Vec<ImportExport<'c>>, TypeBound<'a>)> {
        let bv = &self.bound_vars[n as usize];
        if let Some(path) = bv.origin.is_local(self.origin.iter()) {
            Some((path, bv.bound.clone()))
        } else {
            None
        }
    }
    pub fn resolve_trait_immut(&self, absolute: bool, path: &[Ident]) -> &Trait {
        dbg_println!("resolving trait {:?} {:?}", absolute, path);
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
    pub fn adjust_vars(&mut self, n: u32) {
        let _ = self
            .vars_needs_vars
            .iter_mut()
            .enumerate()
            .map(|(i, vs)| {
                *vs = vs.iter().map(|v| v + n).collect();
                dbg_println!("updated {:?} to {:?}", i, *vs);
            })
            .collect::<()>();
        for _ in 0..n {
            self.vars_needs_vars.push_front(BTreeSet::new());
        }
        self.root_mod.adjust_vars(n);
    }
    /// either this ends up with a definition, in which case, let's get that,
    /// or it ends up with a resource type
    pub fn resolve_tv(&self, n: u32) -> (u32, Option<Defined<'b>>) {
        match &self.bound_vars[self.var_offset + n as usize].bound {
            TypeBound::Eq(Defined::Handleable(Handleable::Var(Tyvar::Bound(nn)))) => {
                self.resolve_tv(n + 1 + nn)
            }
            TypeBound::Eq(t) => (n, Some(t.clone())),
            TypeBound::SubResource => (n, None),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WitName<'a> {
    pub namespaces: Vec<&'a str>,
    pub name: &'a str,
    pub _version: Vec<&'a str>,
}
impl<'a> WitName<'a> {
    pub fn namespace_idents(&self) -> Vec<Ident> {
        self.namespaces
            .iter()
            .map(|x| format_ident!("{}", x))
            .collect::<Vec<_>>()
    }
    pub fn namespace_path(&self) -> TokenStream {
        let ns = self.namespace_idents();
        quote! { #(#ns)::* }
    }
}
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

pub fn kebab_to_var(n: &str) -> Ident {
    kebab_to_snake(n)
}
pub fn kebab_to_cons(n: &str) -> Ident {
    kebab_to_camel(n)
}
pub fn kebab_to_getter(n: &str) -> Ident {
    kebab_to_snake(n)
}

pub enum ResourceItemName {
    Constructor,
    Method(Ident),
    Static(Ident),
}

pub enum FnName {
    Associated(Ident, ResourceItemName),
    Plain(Ident),
}
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

pub fn kebab_to_type(n: &str) -> Ident {
    kebab_to_camel(n)
}

pub fn kebab_to_namespace(n: &str) -> Ident {
    kebab_to_snake(n)
}
