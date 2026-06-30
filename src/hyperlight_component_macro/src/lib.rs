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

//! # Component-model bindgen macros
//!
//! These macros make it easy to use Wasm Component Model types
//! (e.g. those described by WIT) to describe the interface between a
//! Hyperlight host and guest.
//!
//! For both host and guest bindings, bindings generation takes in WIT
//! source input (`*.wit` files or WIT package directories) or a
//! wasm-encoded WIT package. Wasm input should have roughly the
//! structure of a binary-encoded WIT (in particular, component
//! import/export kebab-names should have `wit:package/name` namespace
//! structure, and the same two-level convention for wrapping a
//! component type into an actual component should be adhered to).
//!
//! Both macros can take explicit `wit:`, `wasm:`, or `inline:` inputs. WIT file
//! paths may also be WIT package directories with `deps/`; inline WIT does not
//! resolve external dependencies. For compatibility, a bare string literal,
//! `path:` option, or `$WIT_WORLD` is treated as wasm-encoded WIT. Relative paths
//! are resolved relative to `$CARGO_MANIFEST_DIR`.
//!
//! ## Debugging
//!
//! The generated code can be examined by setting the environment
//! variable `$HYPERLIGHT_COMPONENT_MACRO_DEBUG=/path/to/file.rs`,
//! which will result in the generated code being written to that
//! file, which is then included back into the Rust source.
//!
//! The macros also can be configured to output a great deal of debug
//! information about the internal elaboration and codegen
//! phases. This is logged via the `log` and `env_logger` crates, so
//! setting `RUST_LOG=debug` before running the compiler should
//! suffice to produce this output.

extern crate proc_macro;

use hyperlight_component_util::*;
use syn::parse::{Parse, ParseStream};
use syn::{Ident, LitStr, Result, Token};

/// Create host bindings for the WIT world or wasm component type in the file
/// passed in (or `$WIT_WORLD`, if nothing is passed in). This will
/// produce all relevant types and trait implementations for the
/// component type, as well as functions allowing the component to be
/// instantiated inside a sandbox.
///
/// This includes both a primitive `register_host_functions`, which can
/// be used to directly register the host functions on any sandbox
/// (and which can easily be used with Hyperlight-Wasm), as well as an
/// `instantiate()` method on the component trait that makes
/// instantiating the sandbox particularly ergonomic in core
/// Hyperlight.
#[proc_macro]
pub fn host_bindgen(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let _ = env_logger::try_init();
    let parsed_bindgen_input = syn::parse_macro_input!(input as BindgenInputParams);
    let BindgenInputParams { world_name, source } = parsed_bindgen_input;
    let source = source_or_env(source);

    util::read_wit_type(source, world_name, |kebab_name, ct| {
        let decls = emit::run_state(false, false, |s| {
            rtypes::emit_toplevel(s, &kebab_name, ct);
            host::emit_toplevel(s, &kebab_name, ct);
        });
        util::emit_decls(decls).into()
    })
}

/// Create the hyperlight_guest_init() function (which should be
/// called in hyperlight_main()) for the WIT world or wasm component type in the
/// file passed in (or `$WIT_WORLD`, if nothing is passed in). This
/// function registers Hyperlight functions for component exports
/// (which are implemented by calling into the trait provided) and
/// implements the relevant traits for a trivial Host type (by calling
/// into the Hyperlight host).
#[proc_macro]
pub fn guest_bindgen(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let _ = env_logger::try_init();
    let parsed_bindgen_input = syn::parse_macro_input!(input as BindgenInputParams);
    let BindgenInputParams { world_name, source } = parsed_bindgen_input;
    let source = source_or_env(source);

    util::read_wit_type(source, world_name, |kebab_name, ct| {
        let decls = emit::run_state(true, false, |s| {
            // Emit type/trait definitions for all instances in the world
            rtypes::emit_toplevel(s, &kebab_name, ct);
            // Emit the host/guest function registrations
            guest::emit_toplevel(s, &kebab_name, ct);
        });
        // Use util::emit_decls() to choose between emitting the token
        // stream directly and emitting an include!() pointing at a
        // temporary file, depending on whether the user has requested
        // a debug temporary file be created.
        util::emit_decls(decls).into()
    })
}

#[derive(Debug)]
struct BindgenInputParams {
    world_name: Option<String>,
    source: Option<util::WitSource>,
}

fn source_or_env(source: Option<util::WitSource>) -> util::WitSource {
    source.unwrap_or_else(|| {
        util::WitSource::Wasm(std::path::PathBuf::from(
            std::env::var_os("WIT_WORLD")
                .expect("WIT_WORLD must be set when bindgen input is omitted"),
        ))
    })
}

fn unknown_key_error(key: &Ident) -> syn::Error {
    syn::Error::new(
        key.span(),
        format!(
            "unknown parameter '{}'; expected 'path', 'wit', 'wasm', 'inline', 'world', or 'world_name'",
            key
        ),
    )
}

fn source_from_key(key: &Ident, value: LitStr) -> Result<util::WitSource> {
    match key.to_string().as_str() {
        "path" => Ok(util::WitSource::Wasm(std::path::PathBuf::from(
            value.value(),
        ))),
        "wit" => Ok(util::WitSource::Wit(std::path::PathBuf::from(
            value.value(),
        ))),
        "wasm" => Ok(util::WitSource::Wasm(std::path::PathBuf::from(
            value.value(),
        ))),
        "inline" => Ok(util::WitSource::Inline(value.value())),
        _ => Err(unknown_key_error(key)),
    }
}

impl Parse for BindgenInputParams {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut source = None;
        let mut world_name = None;

        if input.peek(syn::token::Brace) {
            let content;
            syn::braced!(content in input);

            // Parse key-value pairs inside the braces
            while !content.is_empty() {
                let key: Ident = content.parse()?;
                content.parse::<Token![:]>()?;

                match key.to_string().as_str() {
                    "world" | "world_name" => {
                        let value: LitStr = content.parse()?;
                        world_name = Some(value.value());
                    }
                    "path" | "wit" | "wasm" | "inline" => {
                        let value: LitStr = content.parse()?;
                        if source.is_some() {
                            return Err(syn::Error::new(
                                key.span(),
                                "only one input source may be specified",
                            ));
                        }
                        source = Some(source_from_key(&key, value)?);
                    }
                    _ => return Err(unknown_key_error(&key)),
                }
                // Parse optional comma
                if content.peek(Token![,]) {
                    content.parse::<Token![,]>()?;
                }
            }
        } else if input.peek(Ident) {
            let key: Ident = input.parse()?;
            input.parse::<Token![:]>()?;
            let value: LitStr = input.parse()?;
            match key.to_string().as_str() {
                "world" | "world_name" => world_name = Some(value.value()),
                "path" | "wit" | "wasm" | "inline" => {
                    source = Some(source_from_key(&key, value)?);
                }
                _ => return Err(unknown_key_error(&key)),
            }
        } else {
            let option_path_litstr = input.parse::<Option<syn::LitStr>>()?;
            if let Some(concrete_path) = option_path_litstr {
                source = Some(util::WitSource::Wasm(std::path::PathBuf::from(
                    concrete_path.value(),
                )));
            }
        }
        Ok(Self { world_name, source })
    }
}
