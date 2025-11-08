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

//! General utilities for bindgen macros
use crate::etypes;

/// Read and parse a WIT type encapsulated in a wasm file from the
/// given filename, relative to the cargo manifest directory.
pub fn read_wit_type_from_file<R, F: FnMut(String, &etypes::Component) -> R>(
    filename: impl AsRef<std::ffi::OsStr>,
    world_name: Option<String>,
    mut cb: F,
) -> R {
    let path = std::path::Path::new(&filename);
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest_dir = std::path::Path::new(&manifest_dir);
    let path = manifest_dir.join(path);

    let bytes = std::fs::read(path).unwrap();
    let i = wasmparser::Parser::new(0).parse_all(&bytes);
    let ct = crate::component::read_component_single_exported_type(i, world_name);

    // because of the two-level encapsulation scheme, we need to look
    // for the single export of the component type that we just read
    if !ct.uvars.is_empty()
        || !ct.imports.is_empty()
        || !ct.instance.evars.is_empty()
        || ct.instance.unqualified.exports.len() != 1
    {
        panic!("malformed component type container for wit type");
    };
    let export = &ct.instance.unqualified.exports[0];
    use etypes::ExternDesc;
    let ExternDesc::Component(ct) = &export.desc else {
        panic!("malformed component type container: does not contain component type");
    };
    log::debug!("hcm: considering component type {:?}", ct);
    cb(export.kebab_name.to_string(), ct)
}

/// Deal with `$HYPERLIGHT_COMPONENT_MACRO_DEBUG`: if it is present,
/// save the given token stream (representing the result of
/// macroexpansion) to the debug file and then return the token stream
pub fn emit_decls(decls: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
    if let Ok(dbg_out) = std::env::var("HYPERLIGHT_COMPONENT_MACRO_DEBUG") {
        if let Ok(file) = syn::parse2(decls.clone()) {
            std::fs::write(&dbg_out, prettyplease::unparse(&file)).unwrap();
        } else {
            let decls = format!("{}", &decls);
            std::fs::write(&dbg_out, &decls).unwrap();
        }
        quote::quote! { include!(#dbg_out); }
    } else {
        decls
    }
}
