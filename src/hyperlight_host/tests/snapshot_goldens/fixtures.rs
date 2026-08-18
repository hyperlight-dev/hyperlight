// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

//! Canonical fixture builders. These define exactly what bytes a
//! goldens push contains. Any change here is a snapshot content
//! change and requires a goldens regen.

use std::path::PathBuf;
use std::sync::Arc;

use hyperlight_host::func::Registerable;
use hyperlight_host::sandbox::snapshot::Snapshot;
use hyperlight_host::{HostFunctions, MultiUseSandbox, SandboxBuilder};
use hyperlight_testing::simple_guest_as_pathbuf;

/// Heap pattern length used by the golden. Small enough to
/// stay cheap, large enough to exercise non-trivial heap state.
pub(crate) const HEAP_PATTERN_LEN: u64 = 1024;

/// Value the captured `COUNTER` static must hold in the golden.
/// Set by `AddToStatic(CALL_COUNTER_BUMP)` at generate time.
pub(crate) const CALL_COUNTER_BUMP: i32 = 42;

/// Canonical builder configuration used to produce the goldens.
/// Layout knobs are deliberately bumped away from defaults so any
/// silent arithmetic change in `SandboxMemoryLayout::new` shifts at
/// least one region between generate-time and load-time.
fn golden_builder() -> SandboxBuilder {
    SandboxBuilder::new()
        .input_data_size(64 * 1024)
        .output_data_size(64 * 1024)
        .heap_size(256 * 1024)
        .scratch_size(512 * 1024)
}

fn simpleguest_path() -> PathBuf {
    simple_guest_as_pathbuf()
}

pub(crate) fn generate() -> Arc<Snapshot> {
    let mut funcs = HostFunctions::default();
    register_host_echo_fns(&mut funcs);
    let mut sbox = golden_builder()
        .host_functions(funcs)
        .build_from_file(simpleguest_path())
        .expect("build golden sandbox");
    run_canonical_calls(&mut sbox);
    sbox.snapshot().expect("snapshot")
}

/// Deterministic sequence of guest calls that mutate captured state
/// before snapshotting. Each call lands a specific bit of state
/// (BSS, heap, host-call wiring) that one of the per-surface
/// checks then asserts on after the golden is loaded.
fn run_canonical_calls(sbox: &mut MultiUseSandbox) {
    let bumped: i32 = sbox
        .call("AddToStatic", CALL_COUNTER_BUMP)
        .expect("AddToStatic");
    assert_eq!(bumped, CALL_COUNTER_BUMP);

    let _: () = sbox
        .call("AllocAndWritePattern", HEAP_PATTERN_LEN)
        .expect("AllocAndWritePattern");

    // Drive every host fn once so the captured host_function_details
    // blob has known signatures and dispatch regressions surface at
    // generate time.
    sbox.call::<i32>("RoundTripHostI32", 1234i32)
        .expect("RTH i32");
    sbox.call::<u32>("RoundTripHostU32", 4321u32)
        .expect("RTH u32");
    sbox.call::<i64>("RoundTripHostI64", -42i64)
        .expect("RTH i64");
    sbox.call::<u64>("RoundTripHostU64", 1u64 << 40)
        .expect("RTH u64");
    sbox.call::<f32>("RoundTripHostF32", 3.5f32)
        .expect("RTH f32");
    sbox.call::<f64>("RoundTripHostF64", -2.25f64)
        .expect("RTH f64");
    sbox.call::<bool>("RoundTripHostBool", true)
        .expect("RTH bool");
    sbox.call::<String>("RoundTripHostString", "hi".to_string())
        .expect("RTH string");
    sbox.call::<Vec<u8>>("RoundTripHostVecBytes", vec![1u8, 2, 3])
        .expect("RTH vec");
    sbox.call::<()>("RoundTripHostNoOp", ()).expect("RTH noop");
}

/// Register the `HostEcho*` family used by the golden. Used at
/// both generate and load time so the registered set matches the
/// captured `host_function_details`.
pub(crate) fn register_host_echo_fns<R: Registerable>(r: &mut R) {
    r.register_host_function("HostEchoI32", |v: i32| Ok(v))
        .unwrap();
    r.register_host_function("HostEchoU32", |v: u32| Ok(v))
        .unwrap();
    r.register_host_function("HostEchoI64", |v: i64| Ok(v))
        .unwrap();
    r.register_host_function("HostEchoU64", |v: u64| Ok(v))
        .unwrap();
    r.register_host_function("HostEchoF32", |v: f32| Ok(v))
        .unwrap();
    r.register_host_function("HostEchoF64", |v: f64| Ok(v))
        .unwrap();
    r.register_host_function("HostEchoBool", |v: bool| Ok(v))
        .unwrap();
    r.register_host_function("HostEchoString", |v: String| Ok(v))
        .unwrap();
    r.register_host_function("HostEchoVecBytes", |v: Vec<u8>| Ok(v))
        .unwrap();
    r.register_host_function("HostNoOp", || Ok(())).unwrap();
}
