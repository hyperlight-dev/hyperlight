// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

//! General utilities for bindgen macros
use crate::etypes;

/// Input accepted by component bindgen.
#[derive(Debug)]
pub enum WitSource {
    Wasm(std::path::PathBuf),
    Wat(std::path::PathBuf),
    Wit(std::path::PathBuf),
    Inline(String),
}

impl WitSource {
    fn encode(self) -> Vec<u8> {
        match self {
            Self::Wasm(path) => {
                let path = manifest_path(&path);
                let bytes = std::fs::read(&path).unwrap_or_else(|err| {
                    panic!(
                        "failed to read wasm-encoded WIT input '{}': {err}",
                        path.display()
                    )
                });
                if !wasmparser::Parser::is_component(&bytes) {
                    panic!(
                        "wasm-encoded WIT input '{}' is not a wasm component",
                        path.display()
                    );
                }
                bytes
            }
            Self::Wat(path) => {
                let path = manifest_path(&path);
                let bytes = wat::parse_file(&path).unwrap_or_else(|err| {
                    panic!("failed to read wat input '{}': {err:#}", path.display());
                });
                if !wasmparser::Parser::is_component(&bytes) {
                    panic!("wat input '{}' is not a wasm component", path.display());
                }
                bytes
            }
            Self::Wit(path) => {
                let path = manifest_path(&path);
                let mut resolve = wit_parser::Resolve::default();
                let (package, _) = resolve.push_path(&path).unwrap_or_else(|err| {
                    panic!("failed to parse WIT input '{}': {err:#}", path.display())
                });

                wit_component::encode(&resolve, package).unwrap_or_else(|err| {
                    panic!(
                        "failed to encode WIT input '{}' as a wasm component type: {err:#}",
                        path.display()
                    )
                })
            }
            Self::Inline(contents) => {
                match wat::Detect::from_bytes(&contents) {
                    wat::Detect::WasmBinary => {
                        panic!("inline component type looks like a binary!")
                    }
                    wat::Detect::WasmText => {
                        let bytes = wat::parse_str(&contents).unwrap_or_else(|err| {
                            panic!("failed to read inline wat input: {err:#}")
                        });
                        if !wasmparser::Parser::is_component(&bytes) {
                            panic!("inline wat input is not a wasm component");
                        }
                        bytes
                    }
                    wat::Detect::Unknown => {
                        // It's probably WIT
                        let mut resolve = wit_parser::Resolve::default();
                        let package =
                            resolve
                                .push_str("inline.wit", &contents)
                                .unwrap_or_else(|err| {
                                    panic!("failed to parse inline WIT input: {err:#}")
                                });
                        wit_component::encode(&resolve, package).unwrap_or_else(|err| {
                            panic!("failed to encode inline WIT input as a wasm component type: {err:#}")
                        })
                    }
                }
            }
        }
    }
}

fn manifest_path(path: &std::path::Path) -> std::path::PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    std::path::Path::new(&manifest_dir).join(path)
}

/// Read and parse a WIT type from a supported bindgen input.
pub fn read_wit_type<R, F: FnMut(String, &etypes::Component) -> R>(
    source: WitSource,
    world_name: Option<String>,
    mut cb: F,
) -> R {
    let bytes = source.encode();
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
    tracing::debug!("hcm: considering component type {:?}", ct);
    cb(export.kebab_name.to_string(), ct)
}

/// Read and parse a wasm-encoded WIT file, relative to the cargo manifest
/// directory.
pub fn read_wit_type_from_file<R, F: FnMut(String, &etypes::Component) -> R>(
    filename: impl AsRef<std::ffi::OsStr>,
    world_name: Option<String>,
    cb: F,
) -> R {
    let src = WitSource::Wasm(std::path::PathBuf::from(filename.as_ref()));
    read_wit_type(src, world_name, cb)
}

/// Deal with `$HYPERLIGHT_COMPONENT_MACRO_DEBUG`: if it is present,
/// save the given token stream (representing the result of
/// macroexpansion) to the debug file and then return the token stream
pub fn emit_decls(decls: proc_macro2::TokenStream, for_kebab: &str) -> proc_macro2::TokenStream {
    if let Ok(dbg_out) = std::env::var("HYPERLIGHT_COMPONENT_MACRO_DEBUG") {
        let fs_safe = for_kebab.replace("/", "_");
        #[cfg(windows)]
        let fs_safe = fs_safe.replace(":", "+");
        let dbg_out = dbg_out.replace("#", &fs_safe);
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
