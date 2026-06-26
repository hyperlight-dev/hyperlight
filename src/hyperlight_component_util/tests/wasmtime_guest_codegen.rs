/*
Copyright 2026 The Hyperlight Authors.

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

use std::path::{Path, PathBuf};

use hyperlight_component_util::etypes::{
    Defined, ExternDesc, Handleable, ImportExport, TypeBound, Tyvar, Value,
};
use hyperlight_component_util::{emit, guest, rtypes, util};

fn fixture_path(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn encode_wit_fixture_to_wasm(path: &Path) -> PathBuf {
    let mut resolve = wit_parser::Resolve::default();
    let (package, _) = resolve
        .push_path(path)
        .expect("WIT fixture should parse successfully");
    let wasm = wit_component::encode(&resolve, package).expect("WIT fixture should encode");
    let wasm_path = std::env::temp_dir().join(format!(
        "hyperlight-component-util-{}-wit-fixture.wasm",
        std::process::id()
    ));
    std::fs::write(&wasm_path, wasm).expect("temporary wasm fixture should be written");
    wasm_path
}

#[test]
fn wasmtime_guest_codegen_emits_wasmtime_flags_macro() {
    let generated = util::read_wit_type(
        util::WitSource::Wit(PathBuf::from("../tests/rust_guests/witguest/guest.wit")),
        None,
        |kebab_name, ct| {
            // Mirrors the hyperlight-wasm guest-bindgen expansion path:
            // https://github.com/hyperlight-dev/hyperlight-wasm/blob/81e72f5920ebc23584097abfe24d05a40bf084cc/src/hyperlight_wasm_macro/src/lib.rs#L37-L38
            emit::run_state(true, true, |s| {
                rtypes::emit_toplevel(s, &kebab_name, ct);
                guest::emit_toplevel(s, &kebab_name, ct);
            })
        },
    );
    let generated: syn::File = syn::parse2(generated).expect("generated Rust should parse");
    let generated = prettyplease::unparse(&generated);

    assert!(generated.contains("::wasmtime::component::flags! {"));
    assert!(generated.contains("Smallflags {"));
    assert!(generated.contains("\"flag-a\""));
    assert!(generated.contains("const FLAG_A;"));
    assert!(generated.contains("\"flag-b\""));
    assert!(generated.contains("const FLAG_B;"));
    assert!(generated.contains("\"flag-c\""));
    assert!(generated.contains("const FLAG_C;"));
    assert!(!generated.contains("pub flag_a: bool"));
    assert!(!generated.contains("pub flag_b: bool"));
    assert!(!generated.contains("pub flag_c: bool"));
}

#[test]
fn read_wit_type_accepts_wasm_encoded_wit() {
    let wasm_path =
        encode_wit_fixture_to_wasm(&fixture_path("../tests/rust_guests/witguest/guest.wit"));
    let kebab_name = util::read_wit_type(
        util::WitSource::Wasm(wasm_path.clone()),
        None,
        |kebab_name, ct| {
            assert!(!ct.imports.is_empty() || !ct.instance.unqualified.exports.is_empty());
            kebab_name
        },
    );
    std::fs::remove_file(wasm_path).expect("temporary wasm fixture should be removed");

    assert_eq!(kebab_name, "test:wit/test");
}

#[test]
fn read_wit_type_resolves_wit_package_deps() {
    util::read_wit_type(
        util::WitSource::Wit(PathBuf::from("../tests/rust_guests/witguest/with-deps")),
        None,
        |kebab_name, ct| {
            assert_eq!(kebab_name, "test:with-deps/with-deps");
            let shared_types = ct
                .imports
                .iter()
                .find(|import| import.kebab_name == "deps:shared/types")
                .expect("dependency interface should be imported");

            let ExternDesc::Instance(shared_types) = &shared_types.desc else {
                panic!("dependency import should be an interface instance");
            };
            let dep_record = shared_types
                .exports
                .iter()
                .find(|export| export.kebab_name == "dep-record")
                .expect("dependency interface type should be resolved");
            let ExternDesc::Type(Defined::Handleable(Handleable::Var(Tyvar::Bound(0)))) =
                &dep_record.desc
            else {
                panic!("dependency type should resolve to an imported type variable");
            };
            let TypeBound::Eq(Defined::Value(Value::Record(fields))) = &ct.uvars[0].bound else {
                panic!("dependency type variable should be bound to the resolved record");
            };
            assert_eq!(
                ct.uvars[0].origin.path.as_deref(),
                Some(
                    [
                        ImportExport::Export("dep-record"),
                        ImportExport::Import("deps:shared/types")
                    ]
                    .as_slice()
                )
            );
            assert_eq!(fields.len(), 1);
            assert_eq!(fields[0].name.name, "value");
            assert!(matches!(fields[0].ty, Value::String));
        },
    );
}

#[test]
fn read_wit_type_accepts_inline_wit() {
    let kebab_name = util::read_wit_type(
        util::WitSource::Inline(
            r#"
                package test:inline-bindgen;

                world inline-world {
                    export types;
                }

                interface types {
                    record inline-record {
                        value: string,
                    }
                }
            "#
            .to_string(),
        ),
        Some("inline-world".to_string()),
        |kebab_name, ct| {
            assert!(
                ct.instance
                    .unqualified
                    .exports
                    .iter()
                    .any(|export| export.kebab_name == "test:inline-bindgen/types")
            );
            kebab_name
        },
    );

    assert_eq!(kebab_name, "test:inline-bindgen/inline-world");
}
