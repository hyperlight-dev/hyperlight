use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};

use crate::emit::State;
use crate::etypes::{TypeBound, Tyvar};
use crate::rtypes::emit_var_ref;

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
                    if v.origin.is_imported() && !is_guest {
                        let t = emit_var_ref(s, &Tyvar::Bound(i as u32));
                        (
                            quote! {
                                #field_name: #alloc_ns::collections::VecDeque<
                                ::hyperlight_common::resource::ResourceEntry<#t>
                                >
                            },
                            quote! { #field_name: #alloc_ns::collections::VecDeque::new() },
                        )
                    } else if !v.origin.is_imported() && is_guest {
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
            fn new() -> Self {
                #rtsid {
                    #(#inits,)*
                    _phantomI: ::core::marker::PhantomData,
                    #sphantominit
                }
            }
        }
    });
}
