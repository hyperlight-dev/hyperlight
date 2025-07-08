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

use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};

use crate::emit::{
    FnName, ResourceItemName, State, WitName, kebab_to_exports_name, kebab_to_fn, kebab_to_getter,
    kebab_to_imports_name, kebab_to_namespace, kebab_to_type, kebab_to_var, split_wit_name,
};
use crate::etypes::{Component, ExternDecl, ExternDesc, Instance, Tyvar};
use crate::hl::{
    emit_fn_hl_name, emit_hl_marshal_param, emit_hl_marshal_result, emit_hl_unmarshal_param,
    emit_hl_unmarshal_result,
};
use crate::{resource, rtypes};

/// Emit (via returning) code to be added to an `impl <instance trait>
/// for Guest {}` declaration that implements this extern declaration
/// in terms of Hyperlight guest calls
fn emit_export_extern_decl<'a, 'b, 'c>(
    s: &'c mut State<'a, 'b>,
    ed: &'c ExternDecl<'b>,
) -> TokenStream {
    match &ed.desc {
        ExternDesc::CoreModule(_) => panic!("core module (im/ex)ports are not supported"),
        ExternDesc::Func(ft) => {
            match kebab_to_fn(ed.kebab_name) {
                FnName::Plain(n) => {
                    let param_decls = ft
                        .params
                        .iter()
                        .map(|p| rtypes::emit_func_param(s, p))
                        .collect::<Vec<_>>();
                    let result_decl = rtypes::emit_func_result(s, &ft.result);
                    let hln = emit_fn_hl_name(s, ed.kebab_name);
                    let ret = format_ident!("ret");
                    let marshal = ft
                        .params
                        .iter()
                        .map(|p| emit_hl_marshal_param(s, kebab_to_var(p.name.name), &p.ty))
                        .collect::<Vec<_>>();
                    let unmarshal = emit_hl_unmarshal_result(s, ret.clone(), &ft.result);
                    quote! {
                        fn #n(&mut self, #(#param_decls),*) -> #result_decl {
                            let #ret = ::hyperlight_host::sandbox::Callable::call::<::std::vec::Vec::<u8>>(&mut self.sb,
                                #hln,
                                (#(#marshal,)*)
                            );
                            let ::std::result::Result::Ok(#ret) = #ret else { panic!("bad return from guest {:?}", #ret) };
                            #[allow(clippy::unused_unit)]
                            #unmarshal
                        }
                    }
                }
                FnName::Associated(_, _) =>
                // this can be fixed when the guest wasm and
                // general macros are split
                {
                    panic!("guest resources are not currently supported")
                }
            }
        }
        ExternDesc::Type(_) => {
            // no runtime representation is needed for types
            quote! {}
        }
        ExternDesc::Instance(it) => {
            let wn = split_wit_name(ed.kebab_name);
            emit_export_instance(s, wn.clone(), it);

            let getter = kebab_to_getter(wn.name);
            let tn = kebab_to_type(wn.name);
            quote! {
                type #tn = Self;
                #[allow(refining_impl_trait)]
                fn #getter<'a>(&'a mut self) -> &'a mut Self {
                    self
                }
            }
        }
        ExternDesc::Component(_) => {
            panic!("nested components not yet supported in rust bindings");
        }
    }
}

/// Emit (via mutating `s`) an `impl <instance trait> for Host {}`
/// declaration that implements this exported instance in terms of
/// hyperlight guest calls
fn emit_export_instance<'a, 'b, 'c>(s: &'c mut State<'a, 'b>, wn: WitName, it: &'c Instance<'b>) {
    let mut s = s.with_cursor(wn.namespace_idents());
    s.cur_helper_mod = Some(kebab_to_namespace(wn.name));

    let exports = it
        .exports
        .iter()
        .map(|ed| emit_export_extern_decl(&mut s, ed))
        .collect::<Vec<_>>();

    let ns = wn.namespace_path();
    let nsi = wn.namespace_idents();
    let trait_name = kebab_to_type(wn.name);
    let r#trait = s.r#trait(&nsi, trait_name.clone());
    let tvs = r#trait
        .tvs
        .iter()
        .map(|(_, (tv, _))| tv.unwrap())
        .collect::<Vec<_>>();
    let tvs = tvs
        .iter()
        .map(|tv| rtypes::emit_var_ref(&mut s, &Tyvar::Bound(*tv)))
        .collect::<Vec<_>>();
    let (root_ns, root_base_name) = s.root_component_name.unwrap();
    let wrapper_name = kebab_to_wrapper_name(root_base_name);
    let imports_name = kebab_to_imports_name(root_base_name);
    s.root_mod.items.extend(quote! {
        impl<I: #root_ns::#imports_name, S: ::hyperlight_host::sandbox::Callable> #ns::#trait_name <#(#tvs),*> for #wrapper_name<I, S> {
            #(#exports)*
        }
    });
}

/// Keep track of how to get the portion of the state that corresponds
/// to the instance that we are presently emitting
#[derive(Clone)]
struct SelfInfo {
    orig_id: Ident,
    type_id: Vec<Ident>,
    outer_id: Ident,
    inner_preamble: TokenStream,
    inner_id: Ident,
}
impl SelfInfo {
    fn new(orig_id: Ident) -> Self {
        let outer_id = format_ident!("captured_{}", orig_id);
        let inner_id = format_ident!("slf");
        SelfInfo {
            orig_id,
            type_id: vec![format_ident!("I")],
            inner_preamble: quote! {
                let mut #inner_id = #outer_id.lock().unwrap();
                let mut #inner_id = ::std::ops::DerefMut::deref_mut(&mut #inner_id);
            },
            outer_id,
            inner_id,
        }
    }
    /// Adjust a [`SelfInfo`] to get the portion of the state for the
    /// current instance via calling the given getter
    fn with_getter(&self, tp: TokenStream, type_name: Ident, getter: Ident) -> Self {
        let mut toks = self.inner_preamble.clone();
        let id = self.inner_id.clone();
        let mut type_id = self.type_id.clone();
        toks.extend(quote! {
            let mut #id = #tp::#getter(::std::borrow::BorrowMut::<#(#type_id)::*>::borrow_mut(&mut #id));
        });
        type_id.push(type_name);
        SelfInfo {
            orig_id: self.orig_id.clone(),
            type_id,
            outer_id: self.outer_id.clone(),
            inner_preamble: toks,
            inner_id: id,
        }
    }
}

/// Emit (via returning) code to register this particular extern definition with
/// Hyperlight as a host function
///
/// - `get_self`: a [`SelfInfo`] that details how to get from the root
///   component implementation's state to the state for the
///   implementation of this instance.
fn emit_import_extern_decl<'a, 'b, 'c>(
    s: &'c mut State<'a, 'b>,
    get_self: SelfInfo,
    ed: &'c ExternDecl<'b>,
) -> TokenStream {
    match &ed.desc {
        ExternDesc::CoreModule(_) => panic!("core module (im/ex)ports are not supported"),
        ExternDesc::Func(ft) => {
            let hln = emit_fn_hl_name(s, ed.kebab_name);
            log::debug!("providing host function {}", hln);
            let (pds, pus) = ft
                .params
                .iter()
                .map(|p| {
                    let id = kebab_to_var(p.name.name);
                    (
                        quote! { #id: ::std::vec::Vec<u8> },
                        emit_hl_unmarshal_param(s, id, &p.ty),
                    )
                })
                .unzip::<_, _, Vec<_>, Vec<_>>();
            let tp = s.cur_trait_path();
            let callname = match kebab_to_fn(ed.kebab_name) {
                FnName::Plain(n) => quote! { #tp::#n },
                FnName::Associated(r, m) => {
                    let hp = s.helper_path();
                    match m {
                        ResourceItemName::Constructor => quote! { #hp #r::new },
                        ResourceItemName::Method(mn) => quote! { #hp #r::#mn },
                        ResourceItemName::Static(mn) => quote! { #hp #r::#mn },
                    }
                }
            };
            let SelfInfo {
                orig_id,
                type_id,
                outer_id,
                inner_preamble,
                inner_id,
            } = get_self;
            let ret = format_ident!("ret");
            let marshal_result = emit_hl_marshal_result(s, ret.clone(), &ft.result);
            quote! {
                let #outer_id = #orig_id.clone();
                let captured_rts = rts.clone();
                sb.register_host_function(#hln, move |#(#pds),*| {
                    let mut rts = captured_rts.lock().unwrap();
                    #inner_preamble
                    let #ret = #callname(
                        ::std::borrow::BorrowMut::<#(#type_id)::*>::borrow_mut(
                            &mut #inner_id
                        ),
                        #(#pus),*
                    );
                    Ok(#marshal_result)
                })
                .unwrap();
            }
        }
        ExternDesc::Type(_) => {
            // no runtime representation is needed for types
            quote! {}
        }
        ExternDesc::Instance(it) => {
            let mut s = s.clone();
            let wn = split_wit_name(ed.kebab_name);
            let type_name = kebab_to_type(wn.name);
            let getter = kebab_to_getter(wn.name);
            let tp = s.cur_trait_path();
            let get_self = get_self.with_getter(tp, type_name, getter); //quote! { #get_self let mut slf = &mut #tp::#getter(&mut *slf); };
            emit_import_instance(&mut s, get_self, wn.clone(), it)
        }
        ExternDesc::Component(_) => {
            panic!("nested components not yet supported in rust bindings");
        }
    }
}

/// Emit (via returning) code to register each export of the given
/// instance with Hyperlight as a host function.
///
/// - `get_self`: a [`SelfInfo`] that details how to get from the root
///   component implementation's state to the state for the
///   implementation of this instance. This should already have been
///   updated for this instance by the caller!
fn emit_import_instance<'a, 'b, 'c>(
    s: &'c mut State<'a, 'b>,
    get_self: SelfInfo,
    wn: WitName,
    it: &'c Instance<'b>,
) -> TokenStream {
    let mut s = s.with_cursor(wn.namespace_idents());
    s.cur_helper_mod = Some(kebab_to_namespace(wn.name));
    s.cur_trait = Some(kebab_to_type(wn.name));

    let imports = it
        .exports
        .iter()
        .map(|ed| emit_import_extern_decl(&mut s, get_self.clone(), ed))
        .collect::<Vec<_>>();

    quote! { #(#imports)* }
}

/// From a kebab name for a Component, derive something suitable for
/// use as the name of the wrapper struct that will implement its
/// exports in terms of guest function calls.
fn kebab_to_wrapper_name(trait_name: &str) -> Ident {
    format_ident!("{}Sandbox", kebab_to_type(trait_name))
}

/// Emit (via mutating `s`):
/// - a resource table for each resource exported by this component
/// - a wrapper type encapsulating a sandbox and a wrapper table that
///   implements the relevant export trait
/// - an implementation of the component trait itself for Hyperlight's
///   `UninitializedSandbox` that makes it easy to instantiate
fn emit_component<'a, 'b, 'c>(s: &'c mut State<'a, 'b>, wn: WitName, ct: &'c Component<'b>) {
    let mut s = s.with_cursor(wn.namespace_idents());
    let ns = wn.namespace_path();
    let r#trait = kebab_to_type(wn.name);
    let import_trait = kebab_to_imports_name(wn.name);
    let export_trait = kebab_to_exports_name(wn.name);
    let wrapper_name = kebab_to_wrapper_name(wn.name);
    let import_id = format_ident!("imports");

    let rtsid = format_ident!("{}Resources", r#trait);
    s.import_param_var = Some(format_ident!("I"));
    resource::emit_tables(
        &mut s,
        rtsid.clone(),
        quote! { #ns::#import_trait },
        None,
        false,
    );

    s.var_offset = ct.instance.evars.len();
    s.cur_trait = Some(import_trait.clone());
    let imports = ct
        .imports
        .iter()
        .map(|ed| emit_import_extern_decl(&mut s, SelfInfo::new(import_id.clone()), ed))
        .collect::<Vec<_>>();
    s.var_offset = 0;

    s.root_component_name = Some((ns.clone(), wn.name));
    s.cur_trait = Some(export_trait.clone());
    s.import_param_var = Some(format_ident!("I"));
    let exports = ct
        .instance
        .unqualified
        .exports
        .iter()
        .map(|ed| emit_export_extern_decl(&mut s, ed))
        .collect::<Vec<_>>();

    s.root_mod.items.extend(quote! {
        pub struct #wrapper_name<T: #ns::#import_trait, S: ::hyperlight_host::sandbox::Callable> {
            pub(crate) sb: S,
            pub(crate) rt: ::std::sync::Arc<::std::sync::Mutex<#rtsid<T>>>,
        }
        pub(crate) fn register_host_functions<I: #ns::#import_trait + ::std::marker::Send + 'static, S: ::hyperlight_host::func::Registerable>(sb: &mut S, i: I) -> ::std::sync::Arc<::std::sync::Mutex<#rtsid<I>>> {
            let rts = ::std::sync::Arc::new(::std::sync::Mutex::new(#rtsid::new()));
            let #import_id = ::std::sync::Arc::new(::std::sync::Mutex::new(i));
            #(#imports)*
            rts
        }
        impl<I: #ns::#import_trait + ::std::marker::Send, S: ::hyperlight_host::sandbox::Callable> #ns::#export_trait<I> for #wrapper_name<I, S> {
            #(#exports)*
        }
        impl #ns::#r#trait for ::hyperlight_host::sandbox::UninitializedSandbox {
            type Exports<I: #ns::#import_trait + ::std::marker::Send> = #wrapper_name<I, ::hyperlight_host::sandbox::initialized_multi_use::MultiUseSandbox>;
            fn instantiate<I: #ns::#import_trait + ::std::marker::Send + 'static>(mut self, i: I) -> Self::Exports<I> {
                let rts = register_host_functions(&mut self, i);
                let noop = ::core::default::Default::default();
                let sb = self.evolve(noop).unwrap();
                #wrapper_name {
                    sb,
                    rt: rts,
                }
            }
        }
    });
}

/// See [`emit_component`]
pub fn emit_toplevel<'a, 'b, 'c>(s: &'c mut State<'a, 'b>, n: &str, ct: &'c Component<'b>) {
    s.is_impl = true;
    log::debug!("\n\n=== starting host emit ===\n");
    let wn = split_wit_name(n);
    emit_component(s, wn, ct)
}
