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
//! For both host and guest bindings, bindings generation takes in a
//! binary-encoded wasm component, which should have roughly the
//! structure of a binary-encoded WIT (in particular, component
//! import/export kebab-names should have `wit:package/name` namespace
//! structure, and the same two-level convention for wrapping a
//! component type into an actual component should be adhered to). If
//! you are using WIT as the input, it is easy to build such a file
//! via `wasm-tools component wit -w -o file.wasm file.wit`.
//!
//! Both macros can take the path to such a file as a parameter, or,
//! if one is not provided, will fall back to using the path in the
//! environment variable `$WIT_WORLD`. A relative path provided either way
//! will be resolved relative to `$CARGO_MANIFEST_DIR`.
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

/// Create host bindings for the wasm component type in the file
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
    let path: Option<syn::LitStr> = syn::parse_macro_input!(input as Option<syn::LitStr>);
    let path = path
        .map(|x| x.value().into())
        .unwrap_or_else(|| std::env::var_os("WIT_WORLD").unwrap());
    util::read_wit_type_from_file(path, |kebab_name, ct| {
        let decls = emit::run_state(false, false, |s| {
            rtypes::emit_toplevel(s, &kebab_name, ct);
            host::emit_toplevel(s, &kebab_name, ct);
        });
        util::emit_decls(decls).into()
    })
}

#[proc_macro]
pub fn host_bindgen2(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let _ = env_logger::try_init();

    let parsed_bindgen_input = syn::parse_macro_input!(input as BindgenInputParams);

    eprintln!("WE GET BACK FROM THE PARSING");
    eprintln!("{:?}", parsed_bindgen_input);

    let path = parsed_bindgen_input.path.unwrap_or_else(|| {
        let wit_world_env = std::env::var_os("WIT_WORLD");

        if let Some(env) = wit_world_env {
            std::path::PathBuf::from(env)
        } else {
            std::path::PathBuf::new()
        }
    });

    let world_name = parsed_bindgen_input.world_name;

    // what do we do, do we disturb the function signature or
    // put this world_name as an env or a rust static variable.
    // keeping as a rust static variable seems to be an appropriate
    // choice. frequently changing the OS env will be stupid

    eprintln!("PATH = {:?} \n WORLD_NAME = {:?}", path.clone().into_os_string(), world_name.clone());
    

    util::read_world_from_file_1(
        path.into_os_string(),
        world_name,
        |kebab_name, ct: &etypes::Component<'_>| {
            let decls = emit::run_state(false, false, |s| {
                rtypes::emit_toplevel(s, &kebab_name, ct);
                host::emit_toplevel(s, &kebab_name, ct);
            });
            util::emit_decls(decls).into()
        },
    )
}

/// Create the hyperlight_guest_init() function (which should be
/// called in hyperlight_main()) for the wasm component type in the
/// file passed in (or `$WIT_WORLD`, if nothing is passed in). This
/// function registers Hyperlight functions for component exports
/// (which are implemented by calling into the trait provided) and
/// implements the relevant traits for a trivial Host type (by calling
/// into the Hyperlight host).
#[proc_macro]
pub fn guest_bindgen(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let _ = env_logger::try_init();
    let path: Option<syn::LitStr> = syn::parse_macro_input!(input as Option<syn::LitStr>);
    let path = path
        .map(|x| x.value().into())
        .unwrap_or_else(|| std::env::var_os("WIT_WORLD").unwrap());
    util::read_wit_type_from_file(path, |kebab_name, ct| {
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
    path: Option<std::path::PathBuf>,
}

impl Parse for BindgenInputParams {
    fn parse(input: ParseStream) -> Result<Self> {
        let content;
        syn::braced!(content in input);
        eprintln!("Content = \n {:?}", content);

        let mut world_name = None;
        let mut path = None;

        // Parse key-value pairs inside the braces
        while !content.is_empty() {
            let key: Ident = content.parse()?;
            content.parse::<Token![:]>()?;

            match key.to_string().as_str() {
                "world_name" => {
                    let value: LitStr = content.parse()?;
                    world_name = Some(value.value());
                }
                "path" => {
                    let value: LitStr = content.parse()?;
                    path = Some(std::path::PathBuf::from(value.value()));
                }
                _ => {
                    return Err(syn::Error::new(key.span(), format!("Unknown key: {}", key)));
                }
            }

            // Parse optional comma
            if content.peek(Token![,]) {
                content.parse::<Token![,]>()?;
            }
        }
        Ok(Self { world_name, path })
    }
}
