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

use hyperlight_component_util::{emit, guest, rtypes, util};

#[test]
fn wasmtime_guest_codegen_emits_wasmtime_flags_macro() {
    let generated = util::read_wit_type_from_file(
        "../tests/rust_guests/witguest/interface.wasm",
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
