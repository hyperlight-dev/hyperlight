// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use crate::emit::{
    FnName, ResourceItemName, State, WitName, find_colliding_import_names, import_member_names,
    kebab_to_exports_name, kebab_to_fn, kebab_to_getter, kebab_to_imports_name, kebab_to_namespace,
    kebab_to_type, kebab_to_var, split_wit_name,
};
use crate::etypes::{Component, Defined, ExternDecl, ExternDesc, Handleable, Instance, Tyvar};
use crate::hl::{
    emit_fn_hl_name, emit_hl_marshal_param, emit_hl_marshal_result, emit_hl_unmarshal_param,
    emit_hl_unmarshal_result,
};
use crate::{resource, rtypes};

/// Emit (mostly via returning) code to be added to an `impl <instance
/// trait> for Host {}` declaration that implements this extern
/// declaration in terms of Hyperlight host calls.
///
/// For functions associated with a resource, this will instead mutate
/// `s` to directly add them to the resource trait implementation and
/// return an empty token stream.
fn emit_import_extern_decl<'a, 'b, 'c>(
    s: &'c mut State<'a, 'b>,
    ed: &'c ExternDecl<'b>,
) -> TokenStream {
    match &ed.desc {
        ExternDesc::CoreModule(_) => panic!("core module (im/ex)ports are not supported"),
        ExternDesc::Func(ft) => {
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
                .map(|p| {
                    let me = emit_hl_marshal_param(s, kebab_to_var(p.name.name), &p.ty);
                    quote! { args.push(::hyperlight_common::flatbuffer_wrappers::function_types::ParameterValue::VecBytes(#me)); }
                })
                .collect::<Vec<_>>();
            let unmarshal = emit_hl_unmarshal_result(s, ret.clone(), &ft.result);
            let fnname = kebab_to_fn(ed.kebab_name);
            let n = match &fnname {
                FnName::Plain(n) => quote! { #n },
                FnName::Associated(_, m) => match m {
                    ResourceItemName::Constructor => quote! { new },
                    ResourceItemName::Method(mn) => quote! { #mn },
                    ResourceItemName::Static(mn) => quote! { #mn },
                },
            };
            let decl = if ft.async_ {
                quote! {
                    async fn #n(slf: ::hyperlight_common::access::SyncHandle<Self>, #(#param_decls),*) -> #result_decl {
                        let mut args = ::alloc::vec::Vec::new();
                        #(#marshal)*
                        let #ret = ::hyperlight_guest_bin::host_comm::call_host_function_async::<::alloc::vec::Vec<u8>>(
                            #hln,
                            Some(args),
                            ::hyperlight_common::flatbuffer_wrappers::function_types::ReturnType::VecBytes,
                        ).await;
                        let ::core::result::Result::Ok(#ret) = #ret else { panic!("bad return from guest {:?}", #ret) };
                        #[allow(clippy::unused_unit)]
                        #unmarshal
                    }
                }
            } else {
                quote! {
                    fn #n(&mut self, #(#param_decls),*) -> #result_decl {
                        let mut args = ::alloc::vec::Vec::new();
                        #(#marshal)*
                        let #ret = ::hyperlight_guest_bin::host_comm::call_host_function::<::alloc::vec::Vec<u8>>(
                            #hln,
                            Some(args),
                            ::hyperlight_common::flatbuffer_wrappers::function_types::ReturnType::VecBytes,
                        );
                        let ::core::result::Result::Ok(#ret) = #ret else { panic!("bad return from guest {:?}", #ret) };
                        #[allow(clippy::unused_unit)]
                        #unmarshal
                    }
                }
            };
            match fnname {
                FnName::Plain(_) => decl,
                FnName::Associated(r, _) => {
                    // if a resource type could depend on another
                    // tyvar, there might be some complexities
                    // here, but that is not the case at the
                    // moment.
                    let path = s.resource_trait_path(r);
                    s.root_mod
                        .r#impl(path, format_ident!("Host"))
                        .1
                        .extend(decl);
                    TokenStream::new()
                }
            }
        }
        ExternDesc::Type(t) => match t {
            Defined::Handleable(Handleable::Var(Tyvar::Bound(b))) => {
                // only resources need something emitted
                let noff = (s.var_offset as u32 + b) as usize;
                let crate::etypes::TypeBound::SubResource = &s.bound_vars[noff].bound else {
                    return quote! {};
                };
                let rtid = format_ident!("HostResource{}", noff);
                let path = s.resource_trait_path(kebab_to_type(ed.kebab_name));
                let r#impl = s.root_mod.r#impl(path, format_ident!("Host"));
                r#impl.0 = quote! { <::hyperlight_common::component::Negative> };
                r#impl.1.extend(quote! {
                    type T = #rtid;
                });
                TokenStream::new()
            }
            _ => quote! {},
        },
        ExternDesc::Instance(it) => {
            let wn = split_wit_name(ed.kebab_name);
            emit_import_instance(s, wn.clone(), it);

            let (tn, getter) = import_member_names(&wn, &s.colliding_import_names);
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
/// declaration that implements this imported instance in terms of
/// hyperlight host calls
fn emit_import_instance<'a, 'b, 'c>(s: &'c mut State<'a, 'b>, wn: WitName, it: &'c Instance<'b>) {
    let mut s = s.with_instance(&wn);
    s.cur_helper_mod = Some(kebab_to_namespace(wn.name));

    let imports = it
        .exports
        .iter()
        .map(|ed| emit_import_extern_decl(&mut s, ed))
        .collect::<Vec<_>>();

    let trait_path = wn
        .namespace_idents()
        .iter()
        .chain(&[kebab_to_type(wn.name)])
        .cloned()
        .collect::<Vec<_>>();
    let trait_ref = rtypes::trait_ref(&mut s, rtypes::EmitPositivity::Opposite, true, &trait_path);
    s.root_mod.items.extend(quote! {
        impl #trait_ref for Host {
            #(#imports)*
        }
    });
}

/// Emit (via returning) code to register this particular extern
/// definition with Hyperlight as a callable function.
fn emit_export_extern_decl<'a, 'b, 'c>(
    mut s: &'c mut State<'a, 'b>,
    path: Vec<WitName>,
    ed: &'c ExternDecl<'b>,
) -> TokenStream {
    match &ed.desc {
        ExternDesc::CoreModule(_) => panic!("core module (im/ex)ports are not supported"),
        ExternDesc::Func(ft) => {
            let fname = emit_fn_hl_name(s, ed.kebab_name);
            let n = match kebab_to_fn(ed.kebab_name) {
                FnName::Plain(n) => n,
                FnName::Associated(_, _) => {
                    panic!("resources exported from wasm not yet supported")
                }
            };
            let pts = ft.params.iter().map(|_| quote! { ::hyperlight_common::flatbuffer_wrappers::function_types::ParameterType::VecBytes }).collect::<Vec<_>>();
            let (pds, pus) = ft.params.iter().enumerate()
                .map(|(i, p)| {
                    let id = kebab_to_var(p.name.name);
                    let pd = quote! { let ::hyperlight_common::flatbuffer_wrappers::function_types::ParameterValue::VecBytes(#id) = &fc.parameters.as_ref().unwrap()[#i] else { panic!("invariant violation: host passed non-VecBytes core hyperlight argument"); }; };
                    let pu = emit_hl_unmarshal_param(s, id, &p.ty);
                    (pd, pu)
                })
                .unzip::<_, _, Vec<_>, Vec<_>>();
            let get_instance = path
                .iter()
                .skip(1)
                .map(|wn| {
                    let n = kebab_to_getter(wn.name);
                    // TODO: Check that name resolution here works
                    // properly with nested instances (not yet supported
                    // in WIT, so we need to use a raw component type to
                    // check)
                    quote! {
                        let mut state = state.#n();
                        let state = ::core::borrow::BorrowMut::borrow_mut(&mut state);
                    }
                })
                .collect::<Vec<_>>();
            let export_trait = kebab_to_exports_name(&path[0].name);
            let export_trait_ns = path[0].namespace_path();
            let export_trait_ref = quote! { #export_trait_ns::#export_trait<::hyperlight_common::component::Positive, Host> };
            let (get_type, _) = path
                .iter()
                .skip(1)
                .fold((quote! { T }, export_trait_ref), |(inner_type, inner_trait_ref), wn| {
                    // todo: dedup with similar logic in host.rs
                    let trait_path = wn
                        .namespace_idents()
                        .iter()
                        .chain(&[kebab_to_type(wn.name)])
                        .cloned()
                        .collect::<Vec<_>>();
                    let trait_ref =
                        rtypes::trait_ref(&mut s, rtypes::EmitPositivity::Opposite, true, &trait_path);
                    let n = kebab_to_type(wn.name);
                    // TODO: Check that name resolution here works
                    // properly with nested instances (not yet supported
                    // in WIT, so we need to use a raw component type to
                    // check)
                    (quote! {
                        <#inner_type as #inner_trait_ref>::#n
                    }, trait_ref)
                });
            let real_result_type = rtypes::emit_func_result(s, &ft.result);
            let ret = format_ident!("ret");
            let marshal_result = emit_hl_marshal_result(s, ret.clone(), &ft.result);
            let trait_path = s.cur_trait_path();
            if ft.async_ {
                return quote! {
                    fn #n<T: Guest>(fc: ::hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall) -> alloc::boxed::Box<dyn core::future::Future<Output = ::hyperlight_guest::error::Result<::hyperlight_common::flatbuffer_wrappers::function_types::ReturnValue>>> {
                        struct GuestFunctionFuture<T: Guest, F: ::core::future::Future> {
                            // todo: remove the need for the extra Pin<Box<>>
                            future: ::core::pin::Pin<::alloc::boxed::Box<F>>,
                            handle: ::hyperlight_common::access::SyncHandle<#get_type>,
                        }
                        impl<T: Guest, F: ::core::future::Future<Output = #real_result_type>> ::core::future::Future for GuestFunctionFuture<T, F> {
                            type Output = ::hyperlight_guest::error::Result<::hyperlight_common::flatbuffer_wrappers::function_types::ReturnValue>;
                            fn poll(mut self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
                                <T as Guest>::with_guest_state(|state| {
                                    #(#get_instance)*
                                    let slf = &mut *self;
                                    slf.handle.with(state, || {
                                        match slf.future.as_mut().poll(cx) {
                                            core::task::Poll::Ready(#ret) => {
                                                core::task::Poll::Ready(::core::result::Result::Ok(::hyperlight_common::flatbuffer_wrappers::function_types::ReturnValue::VecBytes(#marshal_result)))
                                            },
                                            core::task::Poll::Pending => core::task::Poll::Pending,
                                        }
                                    })
                                })
                            }
                        }
                        let sync_handle: ::hyperlight_common::access::SyncHandle<#get_type> = ::hyperlight_common::access::SyncHandle::new();
                        #(#pds)*
                        ::alloc::boxed::Box::new(GuestFunctionFuture::<T, _> {
                            future: ::alloc::boxed::Box::into_pin(::alloc::boxed::Box::new(#trait_path::#n(sync_handle.clone(), #(#pus,)*))),
                            handle: sync_handle,
                        })
                    }
                    ::hyperlight_guest_bin::guest_function::register::register_function_async(
                        ::hyperlight_guest_bin::guest_function::definition::GuestFunctionDefinition::new(
                            ::alloc::string::ToString::to_string(#fname),
                            ::alloc::vec![#(#pts),*],
                            ::hyperlight_common::flatbuffer_wrappers::function_types::ReturnType::VecBytes,
                            #n::<T>
                        )
                    );
                };
            }

            let (async_, await_, register_function, with_guest_state) = if ft.async_ {
                (quote! { async }, quote! { .await }, quote! { register_function_async }, quote! { with_async_guest_state })
            } else {
                (quote! { }, quote! { }, quote! { register_function }, quote! { with_guest_state})
            };
            quote! {
                #async_ fn #n<T: Guest>(fc: ::hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall) -> ::hyperlight_guest::error::Result<::hyperlight_common::flatbuffer_wrappers::function_types::ReturnValue> {
                    <T as Guest>::#with_guest_state(#async_ |state| {
                        #(#pds)*
                        #(#get_instance)*
                        let #ret = #trait_path::#n(state, #(#pus,)*) #await_;
                        ::core::result::Result::Ok(::hyperlight_common::flatbuffer_wrappers::function_types::ReturnValue::VecBytes(#marshal_result))
                    }) #await_
                }
                ::hyperlight_guest_bin::guest_function::register::#register_function(
                    ::hyperlight_guest_bin::guest_function::definition::GuestFunctionDefinition::new(
                        ::alloc::string::ToString::to_string(#fname),
                        ::alloc::vec![#(#pts),*],
                        ::hyperlight_common::flatbuffer_wrappers::function_types::ReturnType::VecBytes,
                        #n::<T>
                    )
                );
            }
        }
        ExternDesc::Type(_) => {
            // no runtime representation is needed for types
            quote! {}
        }
        ExternDesc::Instance(it) => {
            let wn = split_wit_name(ed.kebab_name);
            let mut path = path.clone();
            path.push(wn.clone());
            emit_export_instance(s, wn.clone(), path, it)
        }
        ExternDesc::Component(_) => {
            panic!("nested components not yet supported in rust bindings");
        }
    }
}

/// Emit (via returning) code to register each export of the given
/// instance with Hyperlight as a callable function.
///
/// - `path`: the instance path (from the root component) where this
///   definition may be found, used to locate the correct component of
///   the guest state. This should already have been updated for this
///   instance by the caller!
fn emit_export_instance<'a, 'b, 'c>(
    s: &'c mut State<'a, 'b>,
    wn: WitName,
    path: Vec<WitName>,
    it: &'c Instance<'b>,
) -> TokenStream {
    let mut s = s.with_instance(&wn);
    s.cur_helper_mod = Some(kebab_to_namespace(wn.name));
    s.cur_trait = Some(kebab_to_type(wn.name));
    let exports = it
        .exports
        .iter()
        .map(|ed| emit_export_extern_decl(&mut s, path.clone(), ed))
        .collect::<Vec<_>>();
    quote! { #(#exports)* }
}

/// Emit (via mutating `s`):
/// - a resource table for each resource exported by this component
/// - impl T for Host for each relevant trait T
///
/// Emit (via returning):
/// - Hyperlight guest function ABI wrapper for each guest function
/// - Hyperlight guest function register calls for each guest function
fn emit_component<'a, 'b, 'c>(
    s: &'c mut State<'a, 'b>,
    wn: WitName,
    ct: &'c Component<'b>,
) -> TokenStream {
    let mut s = s.with_cursor(wn.namespace_idents());
    let ns = wn.namespace_path();
    let r#trait = kebab_to_type(wn.name);
    let import_trait = kebab_to_imports_name(wn.name);
    let export_trait = kebab_to_exports_name(wn.name);
    s.positivity_param = Some(quote! { ::hyperlight_common::component::Positive });
    // We don't set s.self_param_var or s.import_param_var at all
    // here, because they are currently obviated by the (s.is_guest &&
    // s.is_impl) hack in rtypes::emit_resource_ref. For when we
    // eventually do:
    //
    // See Note [Origin paths and self parameters in impl codegen for higher-order components]
    // in emit.rs
    s.colliding_import_names = find_colliding_import_names(&ct.imports);

    let rtsid = format_ident!("{}Resources", r#trait);
    resource::emit_tables(
        &mut s,
        rtsid.clone(),
        quote! { #ns::#import_trait<::hyperlight_common::component::Negative> + ::core::marker::Send + 'static },
        Some(quote! { #ns::#export_trait<::hyperlight_common::component::Positive, I> }),
        true,
    );
    s.root_mod
        .items
        .extend(s.bound_vars.iter().enumerate().map(|(i, _)| {
            let id = format_ident!("HostResource{}", i);
            quote! {
                pub struct #id { rep: u32 }
            }
        }));

    s.var_offset = ct.instance.evars.len();
    s.cur_trait = Some(import_trait.clone());
    let imports = ct
        .imports
        .iter()
        .map(|ed| emit_import_extern_decl(&mut s, ed))
        .collect::<Vec<_>>();
    s.var_offset = 0;
    s.positivity_param = Some(quote! { ::hyperlight_common::component::Positive });
    // We don't set s.self_param_var or s.import_param_var at all
    // here, because it is currently obviated by the (s.is_guest &&
    // s.is_impl) hack in rtypes::emit_resource_ref. For when we
    // eventually do:
    //
    // See Note [Origin paths and self parameters in impl codegen for higher-order components]
    // in emit.rs
    s.cur_trait = Some(export_trait.clone());
    let exports = ct
        .instance
        .unqualified
        .exports
        .iter()
        .map(|ed| emit_export_extern_decl(&mut s, vec![wn.clone()], ed))
        .collect::<Vec<_>>();

    s.root_mod.items.extend(quote! {
        impl #ns::#import_trait<::hyperlight_common::component::Negative> for Host {
            #(#imports)*
        }
    });
    quote! {
        #(#exports)*
    }
}

/// In addition to the items emitted by [`emit_component`], mutate `s`
/// to emit:
/// - a dummy `Host` type to reflect host functions
/// - a toplevel `Guest` trait that can be implemented to provide access to
///   any guest state
/// - a `hyperlight_guest_init` function that registers all guest
/// - functions when given a type that implements the `Guest` trait
pub fn emit_toplevel<'a, 'b, 'c>(s: &'c mut State<'a, 'b>, n: &str, ct: &'c Component<'b>) {
    s.is_impl = true;
    tracing::debug!("\n\n=== starting guest emit ===\n");
    let wn = split_wit_name(n);

    let ns = wn.namespace_path();
    let export_trait = kebab_to_exports_name(wn.name);

    let tokens = emit_component(s, wn, ct);

    s.root_mod.items.extend(quote! {
        pub struct Host {}

        /// Because Hyperlight guest functions can't close over any
        /// state, this function is used on each guest call to acquire
        /// any state that the guest functions might need.
        pub trait Guest: #ns::#export_trait<::hyperlight_common::component::Positive, Host> + 'static {
            fn with_guest_state<R, F: FnOnce(&mut Self) -> R>(f: F) -> R;
            //async fn with_async_guest_state<R: ::core::future::Future, F: for<'a> FnOnce(&'a Self) -> R>(f: F) -> R::Output;
        }
        /// Register all guest functions.
        pub fn hyperlight_guest_init<T: Guest>() {
            //let GUEST: ::hyperlight_common::access::SyncHandle<T> = ::hyperlight_common::access::SyncHandle::<T>::new();
            #tokens
        }
    });
}
