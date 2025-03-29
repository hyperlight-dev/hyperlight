//! The Rust representation of a component type (etype)

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::vec::Vec;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::Ident;

use crate::dbg_println;
use crate::emit::{
    kebab_to_cons, kebab_to_fn, kebab_to_getter, kebab_to_namespace, kebab_to_type, kebab_to_var,
    split_wit_name, FnName, ResourceItemName, State, WitName,
};
use crate::etypes::{
    Component, Defined, ExternDecl, ExternDesc, Func, Handleable, ImportExport, Instance, Param,
    Result, TypeBound, Tyvar, Value,
};

/// type variable instantiations
fn emit_tvis(s: &mut State, tvs: Vec<u32>) -> TokenStream {
    let tvs = tvs
        .iter()
        .map(|tv| emit_var_ref(s, &Tyvar::Bound(*tv)))
        .collect::<Vec<_>>();
    if tvs.len() > 0 {
        quote! { <#(#tvs),*> }
    } else {
        TokenStream::new()
    }
}

fn emit_resource_ref(
    s: &mut State,
    n: u32,
    path: Vec<ImportExport>,
    _bound: TypeBound,
) -> TokenStream {
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
        let t = s.resolve_trait_immut(false, &vec![helper.clone(), rtrait.clone()]);
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
    } else {
        if let Some(s) = &s.self_param_var {
            sv = quote! { #s }
        };
    };
    let mut trait_path = Vec::new();
    trait_path.extend(iwn.namespace_idents());
    trait_path.push(instance_mod.clone());
    trait_path.push(rtrait.clone());
    let t = s.resolve_trait_immut(true, &trait_path);
    let tvis = emit_tvis(s, t.tv_idxs());
    quote! { <#sv::#extras #instance_type as #rp #tns::#instance_mod::#rtrait #tvis>::T }
}

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
                return Some(emit_resource_ref(s, n, path, bound));
            }
        }
        dbg_println!("path is {:?}\n", path);
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

pub fn emit_var_ref(s: &mut State, tv: &Tyvar) -> TokenStream {
    let Tyvar::Bound(n) = tv else {
        panic!("free tyvar in rust emit")
    };
    emit_var_ref_noff(s, n + s.var_offset as u32, false)
}
pub fn emit_var_ref_value(s: &mut State, tv: &Tyvar) -> TokenStream {
    let Tyvar::Bound(n) = tv else {
        panic!("free tyvar in rust emit")
    };
    emit_var_ref_noff(s, n + s.var_offset as u32, true)
}
pub fn emit_var_ref_noff(s: &mut State, n: u32, is_value: bool) -> TokenStream {
    dbg_println!("var_ref {:?} {:?}", &s.bound_vars[n as usize], s.origin);
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

/// Invariant: `vt` is a numeric type (`S`, `U`, `F`)
pub fn numeric_rtype(vt: &Value) -> (Ident, u8) {
    match vt {
        Value::S(w) => (format_ident!("s{}", w.width()), w.width()),
        Value::U(w) => (format_ident!("u{}", w.width()), w.width()),
        Value::F(w) => (format_ident!("f{}", w.width()), w.width()),
        _ => panic!("numeric_rtype"),
    }
}

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
                    if !s.is_impl {
                        let vr = emit_var_ref(s, tv);
                        quote! { ::wasmtime::component::Resource<#vr> }
                    } else {
                        let n = crate::hl::resolve_handleable_to_resource(s, ht);
                        dbg_println!("resolved ht to r (4) {:?} {:?}", ht, n);
                        let id = format_ident!("HostResource{}", n);
                        quote! { ::wasmtime::component::Resource<#id> }
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
                    if !s.is_impl {
                        let vr = emit_var_ref(s, tv);
                        quote! { ::wasmtime::component::Resource<#vr> }
                    } else {
                        let n = crate::hl::resolve_handleable_to_resource(s, ht);
                        dbg_println!("resolved ht to r (5) {:?} {:?}", ht, n);
                        let id = format_ident!("HostResource{}", n);
                        quote! { ::wasmtime::component::Resource<#id> }
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
fn emit_value_toplevel(s: &mut State, v: Option<u32>, id: Ident, vt: &Value) -> TokenStream {
    let is_guest = s.is_guest;
    match vt {
        Value::Record(rfs) => {
            let (vs, toks) = gather_needed_vars(s, v, |mut s| {
                let rfs = rfs
                    .iter()
                    .map(|rf| {
                        let orig_name = rf.name.name;
                        let id = kebab_to_var(orig_name);
                        let derives = if is_guest {
                            quote! { #[component(name = #orig_name)] }
                        } else {
                            TokenStream::new()
                        };
                        let ty = emit_value(&mut s, &rf.ty);
                        quote! { #derives pub #id: #ty }
                    })
                    .collect::<Vec<_>>();
                quote! { #(#rfs),* }
            });
            let vs = emit_type_defn_var_list(s, vs);
            let derives = if is_guest {
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
                pub struct #id #vs { #toks }
            }
        }
        Value::Variant(vcs) => {
            let (vs, toks) = gather_needed_vars(s, v, |mut s| {
                let vcs = vcs
                    .iter()
                    .map(|vc| {
                        let orig_name = vc.name.name;
                        let id = kebab_to_cons(orig_name);
                        let derives = if is_guest {
                            quote! { #[component(name = #orig_name)] }
                        } else {
                            TokenStream::new()
                        };
                        match &vc.ty {
                            Some(ty) => {
                                let ty = emit_value(&mut s, ty);
                                quote! { #derives #id(#ty) }
                            }
                            None => quote! { #derives #id },
                        }
                    })
                    .collect::<Vec<_>>();
                quote! { #(#vcs),* }
            });
            let vs = emit_type_defn_var_list(s, vs);
            let derives = if is_guest {
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
                        let derives = if is_guest {
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
            let derives = if is_guest {
                quote! {
                    #[derive(::wasmtime::component::ComponentType)]
                    #[derive(::wasmtime::component::Lift)]
                    #[derive(::wasmtime::component::Lower)]
                    #[derive(::core::clone::Clone)]
                    #[derive(::core::marker::Copy)]
                    #[component(enum)]
                    #[repr(u8)] // todo: should this always be u8?
                }
            } else {
                TokenStream::new()
            };
            quote! {
                #derives
                pub enum #id #vs { #toks }
            }
        }
        _ => emit_type_alias(s, v, id, |s| emit_value(s, vt)),
    }
}

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

pub fn emit_func_param(s: &mut State, p: &Param) -> TokenStream {
    let name = kebab_to_var(p.name.name);
    let ty = emit_value(s, &p.ty);
    quote! { #name: #ty }
}

pub fn emit_func_result(s: &mut State, r: &Result) -> TokenStream {
    match r {
        Result::Unnamed(vt) => emit_value(s, vt),
        Result::Named(rs) if rs.len() == 0 => quote! { () },
        _ => panic!("multiple named function results are not currently supported"),
    }
}

fn emit_func(s: &mut State, ft: &Func) -> TokenStream {
    let params = ft
        .params
        .iter()
        .map(|p| emit_func_param(s, p))
        .collect::<Vec<_>>();
    let result = emit_func_result(s, &ft.result);
    quote! { fn(#(#params),*) -> #result }
}

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

fn emit_extern_decl<'a, 'b, 'c>(
    is_export: bool,
    s: &'c mut State<'a, 'b>,
    ed: &'c ExternDecl<'b>,
) -> TokenStream {
    dbg_println!("  emitting decl {:?}", ed.kebab_name);
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
                    match n {
                        ResourceItemName::Constructor => {
                            sv.cur_trait().items.extend(quote! {
                                fn new(&mut self) -> Self::T;
                            });
                        }
                        ResourceItemName::Method(n) => {
                            let params = ft
                                .params
                                .iter()
                                .map(|p| emit_func_param(&mut sv, p))
                                .collect::<Vec<_>>();
                            let result = emit_func_result(&mut sv, &ft.result);
                            sv.cur_trait().items.extend(quote! {
                                fn #n(&mut self, #(#params),*) -> #result;
                            });
                        }
                        ResourceItemName::Static(n) => {
                            let params = ft
                                .params
                                .iter()
                                .map(|p| emit_func_param(&mut sv, p))
                                .collect::<Vec<_>>();
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

                s.helper_type_name = Some(id.clone());
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

fn emit_instance<'a, 'b, 'c>(s: &'c mut State<'a, 'b>, wn: WitName, it: &'c Instance<'b>) {
    dbg_println!("emitting instance {:?}", wn);
    let mut s = s.with_cursor(wn.namespace_idents());

    let name = kebab_to_type(wn.name);

    s.cur_helper_mod = Some(kebab_to_namespace(wn.name));
    s.cur_trait = Some(name.clone());
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
    dbg_println!("after exports, ncur_needs_vars is {:?}", needs_vars);
    for v in needs_vars {
        let id = s.noff_var_id(v);
        s.cur_trait().tvs.insert(id, (Some(v), TokenStream::new()));
    }

    s.cur_trait().items.extend(quote! { #(#exports)* });
}

fn emit_component<'a, 'b, 'c>(s: &'c mut State<'a, 'b>, wn: WitName, ct: &'c Component<'b>) {
    let mut s = s.with_cursor(wn.namespace_idents());

    let base_name = kebab_to_type(wn.name);

    s.cur_helper_mod = Some(kebab_to_namespace(wn.name));

    let import_name = format_ident!("{}Imports", base_name);
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

    let export_name = format_ident!("{}Exports", base_name);
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

pub fn emit_toplevel<'a, 'b, 'c>(s: &'c mut State<'a, 'b>, n: &str, ct: &'c Component<'b>) {
    let wn = split_wit_name(n);
    emit_component(s, wn, ct);
}
