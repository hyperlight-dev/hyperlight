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

/// Represents the optional name argument for the guest_function and host_function macros.
enum NameArg {
    None,
    Name(LitStr),
}

impl Parse for NameArg {
    fn parse(input: ParseStream) -> Result<Self> {
        // accepts either nothing or a single string literal
        // anything else is an error
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

/// Attribute macro to mark a function as a guest function.
/// This will register the function so that it can be called by the host.
///
/// If a name is provided as an argument, that name will be used to register the function.
/// Otherwise, the function's identifier will be used.
///
/// The function arguments must be supported parameter types, and the return type must be
/// a supported return type or a `Result<T, HyperlightGuestError>` with T being a supported
/// return type.
///
/// # Note
/// The function will be registered with the host at program initialization regardless of
/// the visibility modifier used (e.g., `pub`, `pub(crate)`, etc.).
/// This means that a private functions can be called by the host from beyond its normal
/// visibility scope.
///
/// # Example
/// ```ignore
/// use hyperlight_guest_bin::guest_function;
/// #[guest_function]
/// fn my_guest_function(arg1: i32, arg2: String) -> i32 {
///     arg1 + arg2.len() as i32
/// }
/// ```
///
/// or with a custom name:
/// ```ignore
/// use hyperlight_guest_bin::guest_function;
/// #[guest_function("custom_name")]
/// fn my_guest_function(arg1: i32, arg2: String) -> i32 {
///     arg1 + arg2.len() as i32
/// }
/// ```
///
/// or with a Result return type:
/// ```ignore
/// use hyperlight_guest_bin::guest_function;
/// use hyperlight_guest::bail;
/// #[guest_function]
/// fn my_guest_function(arg1: i32, arg2: String) -> Result<i32, HyperlightGuestError> {
///     bail!("An error occurred");
/// }
/// ```
#[proc_macro_attribute]
pub fn guest_function(attr: TokenStream, item: TokenStream) -> TokenStream {
    // Obtain the crate name for hyperlight-guest-bin
    let crate_name =
        crate_name("hyperlight-guest-bin").expect("hyperlight-guest-bin must be a dependency");
    let crate_name = match crate_name {
        FoundCrate::Itself => quote! {crate},
        FoundCrate::Name(name) => {
            let ident = syn::Ident::new(&name, proc_macro2::Span::call_site());
            quote! {::#ident}
        }
    };

    // Parse the function definition that we will be working with, and
    // early return if parsing as `ItemFn` fails.
    let fn_declaration = parse_macro_input!(item as ItemFn);

    // Obtain the name of the function being decorated.
    let ident = fn_declaration.sig.ident.clone();

    // Determine the name used to register the function, either
    // the provided name or the function's identifier.
    let exported_name = match parse_macro_input!(attr as NameArg) {
        NameArg::None => quote! { stringify!(#ident) },
        NameArg::Name(name) => quote! { #name },
    };

    // Small sanity checks to improve error messages.
    // These checks are not strictly necessary, as the generated code
    // would fail to compile anyway (due to the trait bounds of `register_fn`),
    // but they provide better feedback to the user of the macro.

    // Check that there are no receiver arguments (i.e., `self`, `&self`, `Box<Self>`, etc).
    if let Some(syn::FnArg::Receiver(arg)) = fn_declaration.sig.inputs.first() {
        return Error::new(
            arg.span(),
            "Receiver (self) argument is not allowed in guest functions",
        )
        .to_compile_error()
        .into();
    }

    // Check that the function is not async.
    if fn_declaration.sig.asyncness.is_some() {
        return Error::new(
            fn_declaration.sig.asyncness.span(),
            "Async functions are not allowed in guest functions",
        )
        .to_compile_error()
        .into();
    }

    // The generated code will replace the decorated code, so we need to
    // include the original function declaration in the output.
    let output = quote! {
        #fn_declaration

        const _: () = {
            // Add the function registration in the GUEST_FUNCTION_INIT distributed slice
            // so that it can be registered at program initialization
            #[#crate_name::__private::linkme::distributed_slice(#crate_name::__private::GUEST_FUNCTION_INIT)]
            #[linkme(crate = #crate_name::__private::linkme)]
            static REGISTRATION: fn() = || {
                #crate_name::guest_function::register::register_fn(#exported_name, #ident);
            };
        };
    };

    output.into()
}

/// Attribute macro to mark a function as a host function.
/// This will generate a function that calls the host function with the same name.
///
/// If a name is provided as an argument, that name will be used to call the host function.
/// Otherwise, the function's identifier will be used.
///
/// The function arguments must be supported parameter types, and the return type must be
/// a supported return type or a `Result<T, HyperlightGuestError>` with T being a supported
/// return type.
///
/// # Panic
/// If the return type is not a Result, the generated function will panic if the host function
/// returns an error.
///
/// # Example
/// ```ignore
/// use hyperlight_guest_bin::host_function;
/// #[host_function]
/// fn my_host_function(arg1: i32, arg2: String) -> i32;
/// ```
///
/// or with a custom name:
/// ```ignore
/// use hyperlight_guest_bin::host_function;
/// #[host_function("custom_name")]
/// fn my_host_function(arg1: i32, arg2: String) -> i32;
/// ```
///
/// or with a Result return type:
/// ```ignore
/// use hyperlight_guest_bin::host_function;
/// use hyperlight_guest::error::HyperlightGuestError;
/// #[host_function]
/// fn my_host_function(arg1: i32, arg2: String) -> Result<i32, HyperlightGuestError>;
/// ```
#[proc_macro_attribute]
pub fn host_function(attr: TokenStream, item: TokenStream) -> TokenStream {
    // Obtain the crate name for hyperlight-guest-bin
    let crate_name =
        crate_name("hyperlight-guest-bin").expect("hyperlight-guest-bin must be a dependency");
    let crate_name = match crate_name {
        FoundCrate::Itself => quote! {crate},
        FoundCrate::Name(name) => {
            let ident = syn::Ident::new(&name, proc_macro2::Span::call_site());
            quote! {::#ident}
        }
    };

    // Parse the function declaration that we will be working with, and
    // early return if parsing as `ForeignItemFn` fails.
    // A function declaration without a body is a foreign item function, as that's what
    // you would use when declaring an FFI function.
    let fn_declaration = parse_macro_input!(item as ForeignItemFn);

    // Destructure the foreign item function to get its components.
    let ForeignItemFn {
        attrs,
        vis,
        sig,
        semi_token: _,
    } = fn_declaration;

    // Obtain the name of the function being decorated.
    let ident = sig.ident.clone();

    // Determine the name used to call the host function, either
    // the provided name or the function's identifier.
    let exported_name = match parse_macro_input!(attr as NameArg) {
        NameArg::None => quote! { stringify!(#ident) },
        NameArg::Name(name) => quote! { #name },
    };

    // Build the list of argument identifiers to pass to the call_host function.
    // While doing that, also do some sanity checks to improve error messages.
    // These checks are not strictly necessary, as the generated code would fail
    // to compile anyway due to either:
    // * the trait bounds of `call_host`
    // * the generated code having invalid syntax
    // but they provide better feedback to the user of the macro, especially in
    // the case of invalid syntax.
    let mut args = vec![];
    for arg in sig.inputs.iter() {
        match arg {
            // Reject receiver arguments (i.e., `self`, `&self`, `Box<Self>`, etc).
            syn::FnArg::Receiver(_) => {
                return Error::new(
                    arg.span(),
                    "Receiver (self) argument is not allowed in guest functions",
                )
                .to_compile_error()
                .into();
            }
            syn::FnArg::Typed(arg) => {
                // A typed argument: `name: Type`
                // Technically, the `name` part can be any pattern, e.g., destructuring patterns
                // like `(a, b): (i32, u64)`, but we only allow simple identifiers here
                // to keep things simple.

                // Reject anything that is not a simple identifier.
                let Pat::Ident(pat) = *arg.pat.clone() else {
                    return Error::new(
                        arg.span(),
                        "Only named arguments are allowed in host functions",
                    )
                    .to_compile_error()
                    .into();
                };

                // Reject any argument with attributes, e.g., `#[cfg(feature = "gdb")] name: Type`
                if !pat.attrs.is_empty() {
                    return Error::new(
                        arg.span(),
                        "Attributes are not allowed on host function arguments",
                    )
                    .to_compile_error()
                    .into();
                }

                // Reject any argument passed by reference
                if pat.by_ref.is_some() {
                    return Error::new(
                        arg.span(),
                        "By-ref arguments are not allowed in host functions",
                    )
                    .to_compile_error()
                    .into();
                }

                // Reject any mutable argument, e.g., `mut name: Type`
                if pat.mutability.is_some() {
                    return Error::new(
                        arg.span(),
                        "Mutable arguments are not allowed in host functions",
                    )
                    .to_compile_error()
                    .into();
                }

                // Reject any sub-patterns
                if pat.subpat.is_some() {
                    return Error::new(
                        arg.span(),
                        "Sub-patterns are not allowed in host functions",
                    )
                    .to_compile_error()
                    .into();
                }

                let ident = pat.ident.clone();

                // All checks passed, add the identifier to the argument list.
                args.push(quote! { #ident });
            }
        }
    }

    // Determine the return type of the function.
    // If the return type is not specified, it is `()`.
    let ret: proc_macro2::TokenStream = match &sig.output {
        syn::ReturnType::Default => quote! { quote! { () } },
        syn::ReturnType::Type(_, ty) => {
            quote! { #ty }
        }
    };

    // Take the parts of the function declaration and generate a function definition
    // matching the provided declaration, but with a body that calls the host function.
    let output = quote! {
        #(#attrs)* #vis #sig {
            use #crate_name::__private::FromResult;
            use #crate_name::host_comm::call_host;
            <#ret as FromResult>::from_result(call_host(#exported_name, (#(#args,)*)))
        }
    };

    output.into()
}
