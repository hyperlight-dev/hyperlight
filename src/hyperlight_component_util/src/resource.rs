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

use crate::emit::State;
use crate::etypes::{TypeBound, Tyvar};
use crate::rtypes::emit_var_ref;

/// Emit a structure definition for a resource table that keeps track
/// of resources lent/borrowed/given/taken to/from the other side of
/// the Hyperlight boundary.
/// - `rtsid`: The name of the struct to create
/// - `bound`: a bound to be used for a phantom type variable that
///   records the fact that these resource tables are only valid for a
///   component that has been instantiated with a particular
///   implementation of its imports
/// - `sv`: optionally a bound to be used for a phantom type variable
///   that records the fact that these resource tables are only valid
///   for a particular implementation of a component
pub fn emit_tables<'a, 'b, 'c>(
    s: &'c mut State<'a, 'b>,
    rtsid: Ident,
    bound: TokenStream,
    sv: Option<TokenStream>,
    is_guest: bool,
) {
    let vs = s.bound_vars.clone();
    let (fields, inits) = vs
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let field_name = format_ident!("resource{}", i);
            let alloc_ns = if s.is_guest {
                quote! { ::alloc }
            } else {
                quote! { ::std }
            };
            match v.bound {
                TypeBound::Eq(_) => (quote! { #field_name: () }, quote! { #field_name: () }),
                TypeBound::SubResource => {
                    if v.origin.is_imported() ^ is_guest {
                        let t = emit_var_ref(s, &Tyvar::Bound(i as u32));
                        (
                            quote! {
                                #field_name: #alloc_ns::collections::VecDeque<
                                ::hyperlight_common::resource::ResourceEntry<#t>
                                >
                            },
                            quote! { #field_name: #alloc_ns::collections::VecDeque::new() },
                        )
                    } else {
                        // we don't need to keep track of anything for
                        // resources owned by the other side
                        (
                            quote! {
                                #field_name: ()
                            },
                            quote! { #field_name: () },
                        )
                    }
                }
            }
        })
        .unzip::<_, _, Vec<_>, Vec<_>>();
    let (sv, svs, sphantom, sphantominit) = if let Some(sv) = sv {
        (
            quote! { , S: #sv },
            quote! { , S },
            quote! { _phantomS: ::core::marker::PhantomData<S>, },
            quote! { _phantomS: ::core::marker::PhantomData, },
        )
    } else {
        (
            TokenStream::new(),
            TokenStream::new(),
            TokenStream::new(),
            TokenStream::new(),
        )
    };
    s.root_mod.items.extend(quote! {
        pub(crate) struct #rtsid<I: #bound #sv> {
            #(#fields,)*
            _phantomI: ::core::marker::PhantomData<I>,
            #sphantom
        }
        impl<I: #bound #sv> #rtsid<I #svs> {
            pub(crate) fn new() -> Self {
                #rtsid {
                    #(#inits,)*
                    _phantomI: ::core::marker::PhantomData,
                    #sphantominit
                }
            }
        }
    });
}
