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

use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use quote::quote;
use syn::parse::{Error, Parse, ParseStream, Result};
use syn::spanned::Spanned as _;
use syn::{ForeignItemFn, ItemFn, LitStr, Pat, parse_macro_input};

enum NameArg {
    None,
    Name(LitStr),
}

impl Parse for NameArg {
    fn parse(input: ParseStream) -> Result<Self> {
        if input.is_empty() {
            return Ok(NameArg::None);
        }
        let name: LitStr = input.parse()?;
        if !input.is_empty() {
            return Err(Error::new(input.span(), "expected a single identifier"));
        }
        Ok(NameArg::Name(name))
    }
}

#[proc_macro_attribute]
pub fn guest_function(attr: TokenStream, item: TokenStream) -> TokenStream {
    let crate_name =
        crate_name("hyperlight-guest-bin").expect("hyperlight-guest-bin must be a dependency");
    let crate_name = match crate_name {
        FoundCrate::Itself => quote! {crate},
        FoundCrate::Name(name) => {
            let ident = syn::Ident::new(&name, proc_macro2::Span::call_site());
            quote! {::#ident}
        }
    };

    let fn_declaration = parse_macro_input!(item as ItemFn);

    let ident = fn_declaration.sig.ident.clone();

    let exported_name = match parse_macro_input!(attr as NameArg) {
        NameArg::None => quote! { stringify!(#ident) },
        NameArg::Name(name) => quote! { #name },
    };

    if let Some(syn::FnArg::Receiver(arg)) = fn_declaration.sig.inputs.first() {
        return Error::new(
            arg.span(),
            "Receiver (self) argument is not allowed in guest functions",
        )
        .to_compile_error()
        .into();
    }

    if fn_declaration.sig.asyncness.is_some() {
        return Error::new(
            fn_declaration.sig.asyncness.span(),
            "Async functions are not allowed in guest functions",
        )
        .to_compile_error()
        .into();
    }

    let output = quote! {
        #fn_declaration

        const _: () = {
            #[#crate_name::__private::linkme::distributed_slice(#crate_name::__private::GUEST_FUNCTION_INIT)]
            #[linkme(crate = #crate_name::__private::linkme)]
            static REGISTRATION: fn() = || {
                hyperlight_guest_bin::guest_function::register::register_fn(#exported_name, #ident);
            };
        };
    };

    output.into()
}

#[proc_macro_attribute]
pub fn host_function(attr: TokenStream, item: TokenStream) -> TokenStream {
    let crate_name =
        crate_name("hyperlight-guest-bin").expect("hyperlight-guest-bin must be a dependency");
    let crate_name = match crate_name {
        FoundCrate::Itself => quote! {crate},
        FoundCrate::Name(name) => {
            let ident = syn::Ident::new(&name, proc_macro2::Span::call_site());
            quote! {::#ident}
        }
    };

    let fn_declaration = parse_macro_input!(item as ForeignItemFn);

    let ForeignItemFn {
        attrs,
        vis,
        sig,
        semi_token: _,
    } = fn_declaration;

    let ident = sig.ident.clone();

    let exported_name = match parse_macro_input!(attr as NameArg) {
        NameArg::None => quote! { stringify!(#ident) },
        NameArg::Name(name) => quote! { #name },
    };

    let mut args = vec![];
    for arg in sig.inputs.iter() {
        match arg {
            syn::FnArg::Receiver(_) => {
                return Error::new(
                    arg.span(),
                    "Receiver (self) argument is not allowed in guest functions",
                )
                .to_compile_error()
                .into();
            }
            syn::FnArg::Typed(arg) => {
                let Pat::Ident(pat) = *arg.pat.clone() else {
                    return Error::new(
                        arg.span(),
                        "Only named arguments are allowed in host functions",
                    )
                    .to_compile_error()
                    .into();
                };

                if !pat.attrs.is_empty() {
                    return Error::new(
                        arg.span(),
                        "Attributes are not allowed on host function arguments",
                    )
                    .to_compile_error()
                    .into();
                }

                if pat.by_ref.is_some() {
                    return Error::new(
                        arg.span(),
                        "By-ref arguments are not allowed in host functions",
                    )
                    .to_compile_error()
                    .into();
                }

                if pat.mutability.is_some() {
                    return Error::new(
                        arg.span(),
                        "Mutable arguments are not allowed in host functions",
                    )
                    .to_compile_error()
                    .into();
                }

                if pat.subpat.is_some() {
                    return Error::new(
                        arg.span(),
                        "Sub-patterns are not allowed in host functions",
                    )
                    .to_compile_error()
                    .into();
                }

                let ident = pat.ident.clone();

                args.push(quote! { #ident });
            }
        }
    }

    let ret: proc_macro2::TokenStream = match &sig.output {
        syn::ReturnType::Default => quote! { quote! { () } },
        syn::ReturnType::Type(_, ty) => {
            quote! { #ty }
        }
    };

    let output = quote! {
        #(#attrs)* #vis #sig {
            use #crate_name::__private::{ResultType, HyperlightGuestError};
            use #crate_name::host_comm::call_host;
            <#ret as ResultType<HyperlightGuestError>>::from_result(call_host(#exported_name, (#(#args,)*)))
        }
    };

    output.into()
}
