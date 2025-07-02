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

#![allow(clippy::disallowed_macros)]

use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
use hyperlight_host::sandbox_state::transition::Noop;
use hyperlight_host::{GuestBinary, MultiUseSandbox, UninitializedSandbox};
use hyperlight_testing::simdguest_as_string;

/// Helper function to create a sandbox for SIMD tests
fn create_simd_sandbox() -> MultiUseSandbox {
    UninitializedSandbox::new(
        GuestBinary::FilePath(simdguest_as_string().expect("simdguest binary missing")),
        None,
    )
    .unwrap()
    .evolve(Noop::default())
    .unwrap()
}

/// Test SSE (Streaming SIMD Extensions) feature
#[test]
fn sse_feature() {
    let mut sbox = create_simd_sandbox();
    let result = sbox
        .call_guest_function_by_name::<bool>("test_sse", ())
        .expect("test_sse should succeed");
    assert!(result, "SSE feature should return true");
}

/// Test SSE2 (Streaming SIMD Extensions 2) feature
#[test]
fn sse2_feature() {
    let mut sbox = create_simd_sandbox();
    let result = sbox
        .call_guest_function_by_name::<bool>("test_sse2", ())
        .expect("test_sse2 should succeed");
    assert!(result, "SSE2 feature should return true");
}

/// Test SSE3 (Streaming SIMD Extensions 3) feature
#[test]
fn sse3_feature() {
    let mut sbox = create_simd_sandbox();
    let result = sbox
        .call_guest_function_by_name::<bool>("test_sse3", ())
        .expect("test_sse3 should succeed");
    assert!(result, "SSE3 feature should return true");
}

/// Test SSSE3 (Supplemental Streaming SIMD Extensions 3) feature
#[test]
fn ssse3_feature() {
    let mut sbox = create_simd_sandbox();
    let result = sbox
        .call_guest_function_by_name::<bool>("test_ssse3", ())
        .expect("test_ssse3 should succeed");
    assert!(result, "SSSE3 feature should return true");
}

/// Test SSE4.1 (Streaming SIMD Extensions 4.1) feature
#[test]
fn sse4_1_feature() {
    let mut sbox = create_simd_sandbox();
    let result = sbox
        .call_guest_function_by_name::<bool>("test_sse4_1", ())
        .expect("test_sse4_1 should succeed");
    assert!(result, "SSE4.1 feature should return true");
}

/// Test SSE4.2 (Streaming SIMD Extensions 4.2) feature
#[test]
fn sse4_2_feature() {
    let mut sbox = create_simd_sandbox();
    let result = sbox
        .call_guest_function_by_name::<bool>("test_sse4_2", ())
        .expect("test_sse4_2 should succeed");
    assert!(result, "SSE4.2 feature should return true");
}

/// Test AVX (Advanced Vector Extensions) feature
#[test]
fn avx_feature() {
    let mut sbox = create_simd_sandbox();
    let result = sbox
        .call_guest_function_by_name::<bool>("test_avx", ())
        .expect("test_avx should succeed");
    assert!(result, "AVX feature should return true");
}

/// Test AVX2 (Advanced Vector Extensions 2) feature
#[test]
fn avx2_feature() {
    let mut sbox = create_simd_sandbox();
    let result = sbox
        .call_guest_function_by_name::<bool>("test_avx2", ())
        .expect("test_avx2 should succeed");
    assert!(result, "AVX2 feature should return true");
}
