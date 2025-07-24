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
use syn::{ItemFn, parse_macro_input};

/// A procedural macro attribute for tracing function calls.
/// Usage:
/// ```rust
/// #[hyperlight_guest_tracing_macro::trace_function]
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

    // Compose entry/exit messages
    let entry_msg = format!("> {}", fn_name_str);
    let exit_msg = format!("< {}", fn_name_str);

    let expanded = match fn_output {
        syn::ReturnType::Default => {
            // No return value (unit)
            quote! {
                #(#fn_attrs)*
                #fn_vis #fn_sig {
                    #[cfg(feature = "trace_guest")]
                    const _: () = assert!(
                        #entry_msg.len() <= hyperlight_guest_tracing::MAX_TRACE_MSG_LEN,
                        "Trace message exceeds the maximum bytes length",
                    );
                    #[cfg(feature = "trace_guest")]
                    ::hyperlight_guest_tracing::create_trace_record(#entry_msg);
                    // Call the original function body
                    #fn_block
                    #[cfg(feature = "trace_guest")]
                    ::hyperlight_guest_tracing::create_trace_record(#exit_msg);
                }
            }
        }
        syn::ReturnType::Type(_, _) => {
            // Has a return value
            quote! {
                #(#fn_attrs)*
                #fn_vis #fn_sig {
                    #[cfg(feature = "trace_guest")]
                    const _: () = assert!(
                        #entry_msg.len() <= hyperlight_guest_tracing::MAX_TRACE_MSG_LEN,
                        "Trace message exceeds the maximum bytes length",
                    );
                    #[cfg(feature = "trace_guest")]
                    ::hyperlight_guest_tracing::create_trace_record(#entry_msg);
                    let __trace_result = (|| #fn_block )();
                    #[cfg(feature = "trace_guest")]
                    ::hyperlight_guest_tracing::create_trace_record(#exit_msg);
                    __trace_result
                }
            }
        }
    };

    TokenStream::from(expanded)
}

// Input structure for the trace macro
struct TraceMacroInput {
    message: syn::Lit,
    statement: Option<proc_macro2::TokenStream>,
}

impl syn::parse::Parse for TraceMacroInput {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let message: syn::Lit = input.parse()?;
        if !matches!(message, syn::Lit::Str(_)) {
            return Err(input.error("first argument to trace! must be a string literal"));
        }

        let statement = if input.peek(syn::Token![,]) {
            let _: syn::Token![,] = input.parse()?;
            Some(input.parse()?)
        } else {
            None
        };
        Ok(TraceMacroInput { message, statement })
    }
}

/// This macro creates a trace record with a message, or traces a block with entry/exit records.
///
/// Usage:
/// ```rust
/// use hyperlight_guest_tracing_macro::trace;
/// trace!("message");
/// trace!("message", { /* block of code */ });
/// ```
///
/// When called with an expression or statement as the second argument, it is wrapped in a block,
/// entry and exit trace records are created at the start and end of block, and the result of the block is returned.
///
/// # Examples
///
/// ## Basic usage: trace with message only
///
/// ```
/// use hyperlight_guest_tracing_macro::trace;
/// trace!("hello");
/// ```
///
/// ## Trace with a block, returning a value
///
/// ```
/// use hyperlight_guest_tracing_macro::trace;
/// let x = trace!("block", { 42 });
/// assert_eq!(x, 42);
/// ```
///
/// ## Trace with a block using local variables
///
/// ```
/// use hyperlight_guest_tracing_macro::trace;
/// let y = 10;
/// let z = trace!("sum", { y + 5 });
/// assert_eq!(z, 15);
/// ```
///
/// ## Trace with a block that returns a reference
///
/// ```
/// use hyperlight_guest_tracing_macro::trace;
/// let s = String::from("abc");
/// let r: &str = trace!("ref", { &s });
/// assert_eq!(r, "abc");
/// ```
///
/// ## Control flow: `return` inside the block returns from the function
///
/// ```
/// use hyperlight_guest_tracing_macro::trace;
/// fn foo() -> i32 {
///     let _ = trace!("fail", {
///         // This return only exits the closure, not the function `foo`.
///         return 42;
///     });
///     assert!(false, "This should not be reached");
/// }
/// ```
///
/// ## Control flow: `break` inside the block exits the outer loop
///
/// ```
/// use hyperlight_guest_tracing_macro::trace;
/// let mut x = 0;
/// for i in 1..3 {
///     x = i;
///     let _ = trace!("msg", {
///         // This break should exit the loop.
///         break;
///     });
/// }
/// assert_eq!(x, 1, "Loop should break after the first iteration");
/// ```
#[proc_macro]
pub fn trace(input: TokenStream) -> TokenStream {
    let parsed = syn::parse_macro_input!(input as TraceMacroInput);
    let trace_message = match parsed.message {
        syn::Lit::Str(ref lit_str) => lit_str.value(),
        _ => unreachable!(),
    };
    if let Some(statement) = parsed.statement {
        let entry_msg = format!("+ {}", trace_message);
        let exit_msg = format!("- {}", trace_message);
        let expanded = quote! {
            {
                #[cfg(feature = "trace_guest")]
                const _: () = assert!(
                    #entry_msg.len() <= hyperlight_guest_tracing::MAX_TRACE_MSG_LEN,
                    "Trace message exceeds the maximum bytes length",
                );
                #[cfg(feature = "trace_guest")]
                ::hyperlight_guest_tracing::create_trace_record(#entry_msg);
                let __trace_result = #statement;
                #[cfg(feature = "trace_guest")]
                ::hyperlight_guest_tracing::create_trace_record(#exit_msg);
                __trace_result
            }
        };
        TokenStream::from(expanded)
    } else {
        let expanded = quote! {
            {
                #[cfg(feature = "trace_guest")]
                const _: () = assert!(
                    #trace_message.len() <= hyperlight_guest_tracing::MAX_TRACE_MSG_LEN,
                    "Trace message exceeds the maximum bytes length",
                );
                #[cfg(feature = "trace_guest")]
                ::hyperlight_guest_tracing::create_trace_record(#trace_message);
            }
        };
        TokenStream::from(expanded)
    }
}

/// This macro flushes the trace buffer, sending any remaining trace records to the host.
///
/// Usage:
/// ```rust
/// hyperlight_guest_tracing_macro::flush!();
/// ```
#[proc_macro]
pub fn flush(_input: TokenStream) -> TokenStream {
    let expanded = quote! {
        {
            #[cfg(feature = "trace_guest")]
            ::hyperlight_guest_tracing::flush_trace_buffer();
        }
    };

    TokenStream::from(expanded)
}
