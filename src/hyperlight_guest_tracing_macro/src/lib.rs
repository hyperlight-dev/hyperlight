/*
Copyright 2025  The Hyperlight Authors.

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
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::{ItemFn, Lit, parse_macro_input};

/// A procedural macro attribute for tracing function calls.
/// Usage:
/// ```rust
/// #[trace_function]
/// fn my_function() {
/// //     // Function body
/// }
/// ```
///
/// This macro will create a trace record when the function is called, if the `trace_guest`
/// feature is enabled.
///
/// The trace record will contain the function name as a string.
/// Note: This macro is intended to be used with the `hyperlight_guest_tracing` crate.
#[proc_macro_attribute]
pub fn trace_function(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(item as ItemFn);

    let fn_name = &input_fn.sig.ident;
    let fn_name_str = fn_name.to_string();
    let fn_vis = &input_fn.vis;
    let fn_sig = &input_fn.sig;
    let fn_block = &input_fn.block;
    let fn_attrs = &input_fn.attrs;
    let fn_output = &input_fn.sig.output;

    let expanded = match fn_output {
        syn::ReturnType::Default => {
            // No return value (unit)
            quote! {
                #(#fn_attrs)*
                #fn_vis #fn_sig {
                    #[cfg(feature = "trace_guest")]
                    hyperlight_guest_tracing::create_trace_record(concat!("> ", #fn_name_str));
                    // Call the original function body
                    #fn_block
                    #[cfg(feature = "trace_guest")]
                    hyperlight_guest_tracing::create_trace_record(concat!("< ", #fn_name_str));
                }
            }
        }
        syn::ReturnType::Type(_, _) => {
            // Has a return value
            quote! {
                #(#fn_attrs)*
                #fn_vis #fn_sig {
                    #[cfg(feature = "trace_guest")]
                    hyperlight_guest_tracing::create_trace_record(concat!("> ", #fn_name_str));
                    let __trace_result = (|| #fn_block )();
                    #[cfg(feature = "trace_guest")]
                    hyperlight_guest_tracing::create_trace_record(concat!("< ", #fn_name_str));
                    __trace_result
                }
            }
        }
    };

    TokenStream::from(expanded)
}

/// Input structure for the trace macro
struct TraceInput {
    message: Lit,
}

impl Parse for TraceInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(TraceInput {
            message: input.parse()?,
        })
    }
}

/// This macro creates a trace record with a message.
///
/// Usage:
/// ```rust
/// trace!("message");
/// ```
#[proc_macro]
pub fn trace(input: TokenStream) -> TokenStream {
    // Convert to proc_macro2::TokenStream for parsing
    let input2: proc_macro2::TokenStream = input.clone().into();

    // Try to parse as message
    if let Ok(parsed) = syn::parse2::<TraceInput>(input2) {
        let trace_message = match parsed.message {
            Lit::Str(lit_str) => lit_str.value(),
            _ => "expression".to_string(),
        };

        let expanded = quote! {
            {
                #[cfg(feature = "trace_guest")]
                hyperlight_guest_tracing::create_trace_record(#trace_message);
            }
        };

        return TokenStream::from(expanded);
    }

    // Fallback: treat the entire input as an expression with default message
    let expanded = quote! {
        {
            #[cfg(feature = "trace_guest")]
            hyperlight_guest_tracing::create_trace_record("expression");
        }
    };

    TokenStream::from(expanded)
}

/// This macro flushes the trace buffer, sending any remaining trace records to the host.
///
/// Usage:
/// ```rust
/// flush!();
/// ```
#[proc_macro]
pub fn flush(_input: TokenStream) -> TokenStream {
    let expanded = quote! {
        {
            #[cfg(feature = "trace_guest")]
            hyperlight_guest_tracing::flush_trace_buffer();
        }
    };

    TokenStream::from(expanded)
}
