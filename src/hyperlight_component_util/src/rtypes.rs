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

//! The Rust representation of a component type (etype)

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::vec::Vec;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::Ident;

use crate::emit::{
    FnName, ResourceItemName, State, WitName, kebab_to_cons, kebab_to_exports_name, kebab_to_fn,
    kebab_to_getter, kebab_to_imports_name, kebab_to_namespace, kebab_to_type, kebab_to_var,
    split_wit_name,
};
use crate::etypes::{
    Component, Defined, ExternDecl, ExternDesc, Func, Handleable, ImportExport, Instance, Param,
    Result, TypeBound, Tyvar, Value,
};

/// When referring to an instance or resource trait, emit a token
/// stream that instantiates any types it is parametrized by with our
/// own best understanding of how to name the relevant type variables
fn emit_tvis(s: &mut State, tvs: Vec<u32>) -> TokenStream {
    let tvs = tvs
        .iter()
        .map(|tv| emit_var_ref(s, &Tyvar::Bound(*tv)))
        .collect::<Vec<_>>();
    if !tvs.is_empty() {
        quote! { <#(#tvs),*> }
    } else {
        TokenStream::new()
    }
}

/// Emit a token stream that references the type of a particular resource
///
/// - `n`: the absolute index (i.e. ignoring [`State::var_offset`]) of
///   the component tyvar being referenced
/// - `path`: the origin path between the module where we are and the
///   module where the resource is defined.  The existence of this
///   path implies that the var is "locally defined".
fn emit_resource_ref(s: &mut State, n: u32, path: Vec<ImportExport>) -> TokenStream {
    // todo: when the guest codegen is split into generic and wasm,
    // this can go away, since an appropriate impl for the imports
    // trait will be there
    if s.is_guest && s.is_impl {
        // Morally, this should check that the var is imported, but
        // that information is gone by now (in the common prefix of
        // the path that was chopped off), and we won't support
        // resources exported from the guest until this whole special
        // case is gone, so ignore it.
        let id = format_ident!("HostResource{}", n);
        return quote! { #id };
    }
    // There is always at least one element in the path, which names
    // the thing we are referring to
    let rtrait = kebab_to_type(path[path.len() - 1].name());

    // Deal specially with being in the local instance, where there is
    // no instance type & so it is not easy to resolve the
    // path-from-the-root to the resource type trait in question
    if path.len() == 1 {
        let helper = s.cur_helper_mod.clone().unwrap();
        let rtrait = kebab_to_type(path[0].name());
        let t = s.resolve_trait_immut(false, &[helper.clone(), rtrait.clone()]);
        let tvis = emit_tvis(s, t.tv_idxs());
        let mut sv = quote! { Self };
        if let Some(s) = &s.self_param_var {
            sv = quote! { #s };
        };
        return quote! { <#sv as #helper::#rtrait #tvis>::T };
    };

    // Generally speaking, the structure that we expect to see in
    // `path` ends in an instance that exports the resource type,
    // followed by the resource type itself. We locate the resource
    // trait by using that final instance name directly; any other
    // names are just used to get to the type that implements it
    let instance = path[path.len() - 2].name();
    let iwn = split_wit_name(instance);
    let extras = path[0..path.len() - 2]
        .iter()
        .map(|p| {
            let wn = split_wit_name(p.name());
            kebab_to_type(wn.name)
        })
        .collect::<Vec<_>>();
    let extras = quote! { #(#extras::)* };
    let rp = s.root_path();
    let tns = iwn.namespace_path();
    let instance_mod = kebab_to_namespace(iwn.name);
    let instance_type = kebab_to_type(iwn.name);
    let mut sv = quote! { Self };
    if path[path.len() - 2].imported() {
        if let Some(iv) = &s.import_param_var {
            sv = quote! { #iv }
        };
    } else if let Some(s) = &s.self_param_var {
        sv = quote! { #s }
    };
    let mut trait_path = Vec::new();
    trait_path.extend(iwn.namespace_idents());
    trait_path.push(instance_mod.clone());
    trait_path.push(rtrait.clone());
    let t = s.resolve_trait_immut(true, &trait_path);
    let tvis = emit_tvis(s, t.tv_idxs());
    quote! { <#sv::#extras #instance_type as #rp #tns::#instance_mod::#rtrait #tvis>::T }
}

/// Try to find a way to refer to the given type variable from the
/// current module/trait. If this fails, the type must be coming from
/// a sibling package, so we will have to emit a parametrization that
/// the root (or at least someone higher up the tree) can instantiate.
/// - `n`: the absolute index (i.e. ignoring [`State::var_offset`]) of
///   the component tyvar being referenced
fn try_find_local_var_id(
    s: &mut State,
    // this should be an absolute var number (no noff)
    n: u32,
) -> Option<TokenStream> {
    if let Some((path, bound)) = s.is_noff_var_local(n) {
        let var_is_helper = match bound {
            TypeBound::Eq(_) => true,
            TypeBound::SubResource => false,
        };
        if !var_is_helper {
            // it is a resource type
            if s.is_helper {
                // but we're in that resource type, so that's ok
                if path.len() == 1 && s.cur_trait == Some(kebab_to_type(path[0].name())) {
                    return Some(quote! { Self::T });
                }
                // otherwise, there is no way to reference that from here
                return None;
            } else {
                let mut path_strs = vec!["".to_string(); path.len()];
                for (i, p) in path.iter().enumerate() {
                    path_strs[i] = p.name().to_string();
                }
                let path = path
                    .into_iter()
                    .enumerate()
                    .map(|(i, p)| match p {
                        ImportExport::Import(_) => ImportExport::Import(&path_strs[i]),
                        ImportExport::Export(_) => ImportExport::Export(&path_strs[i]),
                    })
                    .collect::<Vec<_>>();
                return Some(emit_resource_ref(s, n, path));
            }
        }
        log::debug!("path is {:?}\n", path);
        let mut path = path.iter().rev();
        let name = kebab_to_type(path.next().unwrap().name());
        let owner = path.next();
        if let Some(owner) = owner {
            // if we have an instance type, use it
            let wn = split_wit_name(owner.name());
            let rp = s.root_path();
            let tns = wn.namespace_path();
            let helper = kebab_to_namespace(wn.name);
            Some(quote! { #rp #tns::#helper::#name })
        } else {
            let hp = s.helper_path();
            Some(quote! { #hp #name })
        }
    } else {
        None
    }
}

/// Emit a token stream that references the given type variable in a
/// type context, either directly if it is locally defined or by
/// adding a parameter to the current type/trait/etc if necessary.
/// - `tv`: the variable to reference
///
/// Precondition: `tv` must be a [`Tyvar::Bound`] tyvar
pub fn emit_var_ref(s: &mut State, tv: &Tyvar) -> TokenStream {
    let Tyvar::Bound(n) = tv else {
        panic!("free tyvar in rust emit")
    };
    emit_var_ref_noff(s, n + s.var_offset as u32, false)
}
/// Emit a token stream that references the given type variable in a
/// value context (e.g. a constructor), either directly if it is
/// locally defined or by adding a parameter to the current
/// type/trait/etc if necessary.
/// - `tv`: the variable to reference
///
/// Precondition: `tv` must be a [`Tyvar::Bound`] tyvar
pub fn emit_var_ref_value(s: &mut State, tv: &Tyvar) -> TokenStream {
    let Tyvar::Bound(n) = tv else {
        panic!("free tyvar in rust emit")
    };
    emit_var_ref_noff(s, n + s.var_offset as u32, true)
}
/// Emit a token stream that references the given bound type variable,
/// either directly if it is locally defined or by adding a parameter
/// to the current type/trait/etc if necessary.
/// - `n`: the absolute index (i.e. ignoring [`State::var_offset`]) of
///   the bound variable being referenced
/// - `is_value`: whether this is a value (e.g. constructor) or type context.
pub fn emit_var_ref_noff(s: &mut State, n: u32, is_value: bool) -> TokenStream {
    log::debug!("var_ref {:?} {:?}", &s.bound_vars[n as usize], s.origin);
    // if the variable was defined locally, try to reference it directly
    let id = try_find_local_var_id(s, n);
    let id = match id {
        Some(id) => {
            // if we are referencing the local one, we need to give it
            // the variables it wants
            let vs = s.get_noff_var_refs(n);
            let vs = vs
                .iter()
                .map(|n| emit_var_ref_noff(s, *n, false))
                .collect::<Vec<_>>();
            let vs_toks = if !vs.is_empty() {
                if is_value {
                    quote! { ::<#(#vs),*> }
                } else {
                    quote! { <#(#vs),*> }
                }
            } else {
                TokenStream::new()
            };

            quote! { #id #vs_toks }
        }
        None => {
            // otherwise, record that whatever type is referencing it needs to
            // have it in scope
            s.need_noff_var(n);
            let id = s.noff_var_id(n);
            quote! { #id }
        }
    };
    quote! { #id }
}

/// Format the name of the rust type corresponding to a component
/// numeric type.
///
/// Precondition: `vt` is a numeric type (`S`, `U`, `F`)
pub fn numeric_rtype(vt: &Value) -> (Ident, u8) {
    match vt {
        Value::S(w) => (format_ident!("i{}", w.width()), w.width()),
        Value::U(w) => (format_ident!("u{}", w.width()), w.width()),
        Value::F(w) => (format_ident!("f{}", w.width()), w.width()),
        _ => panic!("numeric_rtype: internal invariant violation"),
    }
}

/// Emit a Rust type corresponding to a given value type. The
/// resultant token stream will parse as a Rust type.
///
/// Precondition: `vt` is an inline-able value type.
pub fn emit_value(s: &mut State, vt: &Value) -> TokenStream {
    match vt {
        Value::Bool => quote! { bool },
        Value::S(_) | Value::U(_) | Value::F(_) => {
            let (id, _) = numeric_rtype(vt);
            quote! { #id }
        }
        Value::Char => quote! { char },
        Value::String => quote! { alloc::string::String },
        Value::List(vt) => {
            let vt = emit_value(s, vt);
            quote! { alloc::vec::Vec<#vt> }
        }
        Value::Record(_) => panic!("record not at top level of valtype"),
        Value::Tuple(vts) => {
            let vts = vts.iter().map(|vt| emit_value(s, vt)).collect::<Vec<_>>();
            quote! { (#(#vts),*) }
        }
        Value::Flags(_) => panic!("flags not at top level of valtype"),
        Value::Variant(_) => panic!("flags not at top level of valtype"),
        Value::Enum(_) => panic!("enum not at top level of valtype"),
        Value::Option(vt) => {
            let vt = emit_value(s, vt);
            quote! { ::core::option::Option<#vt> }
        }
        Value::Result(vt1, vt2) => {
            let unit = Value::Tuple(Vec::new());
            let vt1 = emit_value(s, vt1.as_ref().as_ref().unwrap_or(&unit));
            let vt2 = emit_value(s, vt2.as_ref().as_ref().unwrap_or(&unit));
            quote! { ::core::result::Result<#vt1, #vt2> }
        }
        Value::Own(ht) => match ht {
            Handleable::Resource(_) => panic!("bare resource in type"),
            Handleable::Var(tv) => {
                if s.is_guest {
                    let wrap = if s.is_wasmtime_guest {
                        |toks| quote! { ::wasmtime::component::Resource<#toks> }
                    } else {
                        |toks| toks
                    };
                    if !s.is_impl {
                        wrap(emit_var_ref(s, tv))
                    } else {
                        let n = crate::hl::resolve_handleable_to_resource(s, ht);
                        log::debug!("resolved ht to r (4) {:?} {:?}", ht, n);
                        let id = format_ident!("HostResource{}", n);
                        wrap(quote! { #id })
                    }
                } else {
                    emit_var_ref(s, tv)
                }
            }
        },
        Value::Borrow(ht) => match ht {
            Handleable::Resource(_) => panic!("bare resource in type"),
            Handleable::Var(tv) => {
                if s.is_guest {
                    let wrap = if s.is_wasmtime_guest {
                        |toks| quote! { ::wasmtime::component::Resource<#toks> }
                    } else {
                        |toks| quote! { &#toks }
                    };
                    if !s.is_impl {
                        wrap(emit_var_ref(s, tv))
                    } else {
                        let n = crate::hl::resolve_handleable_to_resource(s, ht);
                        log::debug!("resolved ht to r (5) {:?} {:?}", ht, n);
                        let id = format_ident!("HostResource{}", n);
                        wrap(quote! { #id })
                    }
                } else {
                    let vr = emit_var_ref(s, tv);
                    quote! { ::hyperlight_common::resource::BorrowedResourceGuard<#vr> }
                }
            }
        },
        Value::Var(Some(tv), _) => emit_var_ref(s, tv),
        Value::Var(None, _) => panic!("value type with recorded but unknown var"),
    }
}

/// Emit a Rust type corresponding to a given toplevel value type. The
/// resultant token stream will parse as a Rust type declaration that
/// defines a type named `id`.
fn emit_value_toplevel(s: &mut State, v: Option<u32>, id: Ident, vt: &Value) -> TokenStream {
    let is_wasmtime_guest = s.is_wasmtime_guest;
    match vt {
        Value::Record(rfs) => {
            let (vs, toks) = gather_needed_vars(s, v, |s| {
                let rfs = rfs
                    .iter()
                    .map(|rf| {
                        let orig_name = rf.name.name;
                        let id = kebab_to_var(orig_name);
                        let derives = if s.is_wasmtime_guest {
                            quote! { #[component(name = #orig_name)] }
                        } else {
                            TokenStream::new()
                        };
                        let ty = emit_value(s, &rf.ty);
                        quote! { #derives pub #id: #ty }
                    })
                    .collect::<Vec<_>>();
                quote! { #(#rfs),* }
            });
            let vs = emit_type_defn_var_list(s, vs);
            let derives = if s.is_wasmtime_guest {
                quote! {
                    #[derive(::wasmtime::component::ComponentType)]
                    #[derive(::wasmtime::component::Lift)]
                    #[derive(::wasmtime::component::Lower)]
                    #[component(record)]
                }
            } else {
                TokenStream::new()
            };
            quote! {
                #derives
                #[derive(Debug)]
                pub struct #id #vs { #toks }
            }
        }
        Value::Flags(ns) => {
            let (vs, toks) = gather_needed_vars(s, v, |_| {
                let ns = ns
                    .iter()
                    .map(|n| {
                        let orig_name = n.name;
                        let id = kebab_to_var(orig_name);
                        quote! { pub #id: bool }
                    })
                    .collect::<Vec<_>>();
                quote! { #(#ns),* }
            });
            let vs = emit_type_defn_var_list(s, vs);
            quote! {
                #[derive(Debug, Clone, PartialEq)]
                pub struct #id #vs { #toks }
            }
        }
        Value::Variant(vcs) => {
            let (vs, toks) = gather_needed_vars(s, v, |s| {
                let vcs = vcs
                    .iter()
                    .map(|vc| {
                        let orig_name = vc.name.name;
                        let id = kebab_to_cons(orig_name);
                        let derives = if s.is_wasmtime_guest {
                            quote! { #[component(name = #orig_name)] }
                        } else {
                            TokenStream::new()
                        };
                        match &vc.ty {
                            Some(ty) => {
                                let ty = emit_value(s, ty);
                                quote! { #derives #id(#ty) }
                            }
                            None => quote! { #derives #id },
                        }
                    })
                    .collect::<Vec<_>>();
                quote! { #(#vcs),* }
            });
            let vs = emit_type_defn_var_list(s, vs);
            let derives = if s.is_wasmtime_guest {
                quote! {
                    #[derive(::wasmtime::component::ComponentType)]
                    #[derive(::wasmtime::component::Lift)]
                    #[derive(::wasmtime::component::Lower)]
                    #[component(variant)]
                }
            } else {
                TokenStream::new()
            };
            quote! {
                #derives
                #[derive(Debug)]
                pub enum #id #vs { #toks }
            }
        }
        Value::Enum(ns) => {
            let (vs, toks) = gather_needed_vars(s, v, |_| {
                let ns = ns
                    .iter()
                    .map(|n| {
                        let orig_name = n.name;
                        let id = kebab_to_cons(orig_name);
                        let derives = if is_wasmtime_guest {
                            quote! { #[component(name = #orig_name)] }
                        } else {
                            TokenStream::new()
                        };
                        quote! { #derives #id }
                    })
                    .collect::<Vec<_>>();
                quote! { #(#ns),* }
            });
            let vs = emit_type_defn_var_list(s, vs);
            let derives = if s.is_wasmtime_guest {
                quote! {
                    #[derive(::wasmtime::component::ComponentType)]
                    #[derive(::wasmtime::component::Lift)]
                    #[derive(::wasmtime::component::Lower)]
                    #[component(enum)]
                    #[repr(u8)] // todo: should this always be u8?
                }
            } else {
                TokenStream::new()
            };
            quote! {
                #derives
                #[derive(Debug, Copy, Clone, PartialEq)]
                pub enum #id #vs { #toks }
            }
        }
        _ => emit_type_alias(s, v, id, |s| emit_value(s, vt)),
    }
}

/// Emit a Rust type corresponding to a defined type. The token stream
/// will parse as a Rust type declaration that defines a type named `id`.
///
/// Precondition: `dt` is not an instance or component, which we
/// cannot deal with as first-class at the moment, or a bare resource
/// type.
fn emit_defined(s: &mut State, v: Option<u32>, id: Ident, dt: &Defined) -> TokenStream {
    match dt {
        // the lack of trait aliases makes emitting a name for an
        // instance/component difficult in rust
        Defined::Instance(_) | Defined::Component(_) => TokenStream::new(),
        // toplevel vars should have been handled elsewhere
        Defined::Handleable(Handleable::Resource(_)) => panic!("bare resource in type"),
        Defined::Handleable(Handleable::Var(tv)) => {
            emit_type_alias(s, v, id, |s| emit_var_ref(s, tv))
        }
        Defined::Value(vt) => emit_value_toplevel(s, v, id, vt),
        Defined::Func(ft) => emit_type_alias(s, v, id, |s| emit_func(s, ft)),
    }
}

/// Emit a Rust argument declaration, suitable for placing in the
/// argument list of a function, for a given component function type
/// parameter.
pub fn emit_func_param(s: &mut State, p: &Param) -> TokenStream {
    let name = kebab_to_var(p.name.name);
    let ty = emit_value(s, &p.ty);
    quote! { #name: #ty }
}

/// Emit a Rust version of a component function return type.
///
/// Precondition: the result type must only be a named result if there
/// are no names in it (i.e. a unit type)
pub fn emit_func_result(s: &mut State, r: &Result) -> TokenStream {
    match r {
        Result::Unnamed(vt) => emit_value(s, vt),
        Result::Named(rs) if rs.is_empty() => quote! { () },
        _ => panic!("multiple named function results are not currently supported"),
    }
}

/// Emit a Rust typeversion of a component function type. This is only
/// used for defining certain type aliases of functions, and so it
/// truly is a Rust type-level function type, not a value-level
/// declaration.
fn emit_func(s: &mut State, ft: &Func) -> TokenStream {
    let params = ft
        .params
        .iter()
        .map(|p| emit_func_param(s, p))
        .collect::<Vec<_>>();
    let result = emit_func_result(s, &ft.result);
    quote! { fn(#(#params),*) -> #result }
}

/// Gather the vars that are referenced when running `f`. If `v` is
/// [`Some(vn)`], also record this as the set of vars needed by the
/// bound tyvar with absolute index `vn`.
fn gather_needed_vars<F: Fn(&mut State) -> TokenStream>(
    s: &mut State,
    v: Option<u32>,
    f: F,
) -> (BTreeSet<u32>, TokenStream) {
    let mut needs_vars = BTreeSet::new();
    let mut sv = s.with_needs_vars(&mut needs_vars);
    let toks = f(&mut sv);
    if let Some(vn) = v {
        sv.record_needs_vars(vn);
    }
    drop(sv);
    (needs_vars, toks)
}
/// Emit a Rust type parameter list that can be affixed to a type
/// definition, given a set `vs` of the component-level bound tyvars
/// that the type references but are not locally-defined.
fn emit_type_defn_var_list(s: &mut State, vs: BTreeSet<u32>) -> TokenStream {
    if vs.is_empty() {
        TokenStream::new()
    } else {
        let vs = vs
            .iter()
            .map(|n| {
                if s.is_guest {
                    let t = s.noff_var_id(*n);
                    quote! { #t: 'static }
                } else {
                    let t = s.noff_var_id(*n);
                    quote! { #t }
                }
            })
            .collect::<Vec<_>>();
        quote! { <#(#vs),*> }
    }
}
/// Emit a type alias declaration, allowing one to name an anonymous
/// Rust type without creating a new nominal type.
///
/// - `v`: If [`Some(vn)`], the component-level bound tyvar absolute
///   index that this declaration corresponds to
/// - `id`: The name of the alias to produce
/// - `f`: A function which produces a token stream that parses as a
///   Rust type, to use as the body of the alias
fn emit_type_alias<F: Fn(&mut State) -> TokenStream>(
    s: &mut State,
    v: Option<u32>,
    id: Ident,
    f: F,
) -> TokenStream {
    let (vs, toks) = gather_needed_vars(s, v, f);
    let vs = emit_type_defn_var_list(s, vs);
    quote! { pub type #id #vs = #toks; }
}

/// Emit (via returning) a Rust trait item corresponding to this
/// extern decl
fn emit_extern_decl<'a, 'b, 'c>(
    is_export: bool,
    s: &'c mut State<'a, 'b>,
    ed: &'c ExternDecl<'b>,
) -> TokenStream {
    log::debug!("  emitting decl {:?}", ed.kebab_name);
    match &ed.desc {
        ExternDesc::CoreModule(_) => panic!("core module (im/ex)ports are not supported"),
        ExternDesc::Func(ft) => {
            let mut s = s.push_origin(is_export, ed.kebab_name);
            match kebab_to_fn(ed.kebab_name) {
                FnName::Plain(n) => {
                    let params = ft
                        .params
                        .iter()
                        .map(|p| emit_func_param(&mut s, p))
                        .collect::<Vec<_>>();
                    let result = emit_func_result(&mut s, &ft.result);
                    quote! {
                        fn #n(&mut self, #(#params),*) -> #result;
                    }
                }
                FnName::Associated(r, n) => {
                    let mut s = s.helper();
                    s.cur_trait = Some(r.clone());
                    let mut needs_vars = BTreeSet::new();
                    let mut sv = s.with_needs_vars(&mut needs_vars);
                    let params = ft
                        .params
                        .iter()
                        .map(|p| emit_func_param(&mut sv, p))
                        .collect::<Vec<_>>();
                    match n {
                        ResourceItemName::Constructor => {
                            sv.cur_trait().items.extend(quote! {
                                fn new(&mut self, #(#params),*) -> Self::T;
                            });
                        }
                        ResourceItemName::Method(n) => {
                            let result = emit_func_result(&mut sv, &ft.result);
                            sv.cur_trait().items.extend(quote! {
                                fn #n(&mut self, #(#params),*) -> #result;
                            });
                        }
                        ResourceItemName::Static(n) => {
                            let result = emit_func_result(&mut sv, &ft.result);
                            sv.cur_trait().items.extend(quote! {
                                fn #n(&mut self, #(#params),*) -> #result;
                            });
                        }
                    }
                    for v in needs_vars {
                        let id = s.noff_var_id(v);
                        s.cur_trait().tvs.insert(id, (Some(v), TokenStream::new()));
                    }
                    quote! {}
                }
            }
        }
        ExternDesc::Type(t) => {
            fn go_defined<'a, 'b, 'c>(
                s: &'c mut State<'a, 'b>,
                ed: &'c ExternDecl<'b>,
                t: &'c Defined<'b>,
                v: Option<u32>,
            ) -> TokenStream {
                let id = kebab_to_type(ed.kebab_name);
                let mut s = s.helper();

                let t = emit_defined(&mut s, v, id, t);
                s.cur_mod().items.extend(t);
                TokenStream::new()
            }
            let edn: &'b str = ed.kebab_name;
            let mut s: State<'_, 'b> = s.push_origin(is_export, edn);
            if let Some((n, bound)) = s.is_var_defn(t) {
                match bound {
                    TypeBound::Eq(t) => {
                        // ensure that when go_defined() looks up vars
                        // that might occur in the type, they resolve
                        // properly
                        let noff = s.var_offset as u32 + n;
                        s.var_offset += n as usize + 1;
                        go_defined(&mut s, ed, &t, Some(noff))
                    }
                    TypeBound::SubResource => {
                        let rn = kebab_to_type(ed.kebab_name);
                        s.add_helper_supertrait(rn.clone());
                        let mut s = s.helper();
                        s.cur_trait = Some(rn.clone());
                        s.cur_trait().items.extend(quote! {
                            type T: ::core::marker::Send;
                        });
                        quote! {}
                    }
                }
            } else {
                go_defined(&mut s, ed, t, None)
            }
        }
        ExternDesc::Instance(it) => {
            let mut s = s.push_origin(is_export, ed.kebab_name);
            let wn = split_wit_name(ed.kebab_name);
            emit_instance(&mut s, wn.clone(), it);

            let nsids = wn.namespace_idents();
            let repr = s.r#trait(&nsids, kebab_to_type(wn.name));
            let vs = if !repr.tvs.is_empty() {
                let vs = repr.tvs.clone();
                let tvs = vs
                    .iter()
                    .map(|(_, (tv, _))| emit_var_ref(&mut s, &Tyvar::Bound(tv.unwrap())));
                quote! { <#(#tvs),*> }
            } else {
                TokenStream::new()
            };

            let getter = kebab_to_getter(wn.name);
            let rp = s.root_path();
            let tns = wn.namespace_path();
            let tn = kebab_to_type(wn.name);
            quote! {
                type #tn: #rp #tns::#tn #vs;
                fn #getter(&mut self) -> impl ::core::borrow::BorrowMut<Self::#tn>;
            }
        }
        ExternDesc::Component(_) => {
            panic!("nested components not yet supported in rust bindings");
        }
    }
}

/// Emit (via mutating `s`) a Rust trait declaration corresponding to
/// this instance type
fn emit_instance<'a, 'b, 'c>(s: &'c mut State<'a, 'b>, wn: WitName, it: &'c Instance<'b>) {
    log::debug!("emitting instance {:?}", wn);
    let mut s = s.with_cursor(wn.namespace_idents());

    let name = kebab_to_type(wn.name);

    s.cur_helper_mod = Some(kebab_to_namespace(wn.name));
    s.cur_trait = Some(name.clone());
    if !s.cur_trait().items.is_empty() {
        // Temporary hack: we have visited this wit:package/instance
        // before, so bail out instead of adding duplicates of
        // everything. Since we don't really have strong semantic
        // guarantees that the exact same contents will be in each
        // occurrence of a wit:package/instance (and indeed they may
        // well be stripped down to the essentials in each
        // occurrence), this is NOT sound, and will need to be
        // revisited.  The correct approach here is to change
        // emit_extern_decl to create function/resource items in a
        // Trait that can be merged properly, instead of directly
        // emitting tokens.
        return;
    }

    let mut needs_vars = BTreeSet::new();
    let mut sv = s.with_needs_vars(&mut needs_vars);

    let exports = it
        .exports
        .iter()
        .map(|ed| emit_extern_decl(true, &mut sv, ed))
        .collect::<Vec<_>>();

    // instantiations for the supertraits

    let mut stvs = BTreeMap::new();
    let _ = sv.cur_trait(); // make sure it exists
    let t = sv.cur_trait_immut();
    for (ti, _) in t.supertraits.iter() {
        let t = sv.resolve_trait_immut(false, ti);
        stvs.insert(ti.clone(), t.tv_idxs());
    }
    // hack to make the local-definedness check work properly, since
    // it usually should ignore the last origin component
    sv.origin.push(ImportExport::Export("self"));
    let mut stis = BTreeMap::new();
    for (id, tvs) in stvs.into_iter() {
        stis.insert(id, emit_tvis(&mut sv, tvs));
    }
    for (id, ts) in stis.into_iter() {
        sv.cur_trait().supertraits.get_mut(&id).unwrap().extend(ts);
    }

    drop(sv);
    log::debug!("after exports, ncur_needs_vars is {:?}", needs_vars);
    for v in needs_vars {
        let id = s.noff_var_id(v);
        s.cur_trait().tvs.insert(id, (Some(v), TokenStream::new()));
    }

    s.cur_trait().items.extend(quote! { #(#exports)* });
}

/// Emit (via mutating `s`) a set of Rust trait declarations
/// corresponding to this component. This includes an `Imports` and an
/// `Exports` trait, as well as a main trait with an `instantiate()`
/// function that maps from an implementer of the imports to an
/// implementor of the exports
fn emit_component<'a, 'b, 'c>(s: &'c mut State<'a, 'b>, wn: WitName, ct: &'c Component<'b>) {
    let mut s = s.with_cursor(wn.namespace_idents());

    let base_name = kebab_to_type(wn.name);

    s.cur_helper_mod = Some(kebab_to_namespace(wn.name));

    let import_name = kebab_to_imports_name(wn.name);
    *s.bound_vars = ct
        .uvars
        .iter()
        .rev()
        .map(Clone::clone)
        .collect::<VecDeque<_>>();
    s.cur_trait = Some(import_name.clone());
    let imports = ct
        .imports
        .iter()
        .map(|ed| emit_extern_decl(false, &mut s, ed))
        .collect::<Vec<TokenStream>>();
    s.cur_trait().items.extend(quote! { #(#imports)* });

    s.adjust_vars(ct.instance.evars.len() as u32);

    s.import_param_var = Some(format_ident!("I"));

    let export_name = kebab_to_exports_name(wn.name);
    *s.bound_vars = ct
        .instance
        .evars
        .iter()
        .rev()
        .chain(ct.uvars.iter().rev())
        .map(Clone::clone)
        .collect::<VecDeque<_>>();
    s.cur_trait = Some(export_name.clone());
    let exports = ct
        .instance
        .unqualified
        .exports
        .iter()
        .map(|ed| emit_extern_decl(true, &mut s, ed))
        .collect::<Vec<_>>();
    s.cur_trait().tvs.insert(
        format_ident!("I"),
        (None, quote! { #import_name + ::core::marker::Send }),
    );
    s.cur_trait().items.extend(quote! { #(#exports)* });

    s.cur_helper_mod = None;
    s.cur_trait = None;

    s.cur_mod().items.extend(quote! {
        pub trait #base_name {
            type Exports<I: #import_name + ::core::marker::Send>: #export_name<I>;
            // todo: can/should this 'static bound be avoided?
            // it is important right now because this is closed over in host functions
            fn instantiate<I: #import_name + ::core::marker::Send + 'static>(self, imports: I) -> Self::Exports<I>;
        }
    });
}

/// See [`emit_component`]
pub fn emit_toplevel<'a, 'b, 'c>(s: &'c mut State<'a, 'b>, n: &str, ct: &'c Component<'b>) {
    let wn = split_wit_name(n);
    emit_component(s, wn, ct);
}
