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

//! Canonical fixture builders. These define exactly what bytes a
//! goldens push contains. Any change here is a snapshot content
//! change and requires a goldens regen.

use std::sync::Arc;

use hyperlight_host::func::Registerable;
use hyperlight_host::sandbox::SandboxConfiguration;
use hyperlight_host::sandbox::snapshot::Snapshot;
use hyperlight_host::sandbox::uninitialized::GuestEnvironment;
use hyperlight_host::{GuestBinary, MultiUseSandbox, UninitializedSandbox};
use hyperlight_testing::simple_guest_as_string;

/// Init data bytes baked into the init golden. Loaded back via
/// `ReadFromUserMemory` to assert byte-for-byte round-trip.
pub const INIT_DATA: &[u8] = b"hyperlight-snapshot-golden-init-data\0";

/// Heap pattern length used by the call golden. Small enough to
/// stay cheap, large enough to exercise non-trivial heap state.
pub const HEAP_PATTERN_LEN: u64 = 1024;

/// Value the captured `COUNTER` static must hold in the call
/// golden. Set by `AddToStatic(CALL_COUNTER_BUMP)` at generate
/// time.
pub const CALL_COUNTER_BUMP: i32 = 42;

/// Canonical `SandboxConfiguration` used to produce the goldens.
/// Layout knobs are deliberately bumped away from defaults so any
/// silent arithmetic change in `SandboxMemoryLayout::new` shifts at
/// least one region between generate-time and load-time.
fn golden_config() -> SandboxConfiguration {
    let mut cfg = SandboxConfiguration::default();
    cfg.set_input_data_size(64 * 1024);
    cfg.set_output_data_size(64 * 1024);
    cfg.set_heap_size(256 * 1024);
    cfg.set_scratch_size(512 * 1024);
    cfg
}

fn simpleguest_path() -> String {
    simple_guest_as_string().expect("simpleguest_path")
}

pub fn generate(kind: crate::platform::Kind) -> Arc<Snapshot> {
    match kind {
        crate::platform::Kind::Init => generate_init(),
        crate::platform::Kind::Call => generate_call(),
    }
}

pub fn generate_init() -> Arc<Snapshot> {
    let env = GuestEnvironment::new(GuestBinary::FilePath(simpleguest_path()), Some(INIT_DATA));
    Arc::new(Snapshot::from_env(env, golden_config()).expect("Snapshot::from_env (init)"))
}

pub fn generate_call() -> Arc<Snapshot> {
    let mut u = UninitializedSandbox::new(
        GuestBinary::FilePath(simpleguest_path()),
        Some(golden_config()),
    )
    .expect("UninitializedSandbox::new");
    register_host_echo_fns(&mut u);
    let mut sbox = u.evolve().expect("evolve");
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
    // blob has known signatures, and any regression in host-dispatch
    // surfaces at generate time rather than only during golden load.
    let _: i32 = sbox.call("RoundTripHostI32", 1234i32).expect("RTH i32");
    let _: u32 = sbox.call("RoundTripHostU32", 4321u32).expect("RTH u32");
    let _: i64 = sbox.call("RoundTripHostI64", -42i64).expect("RTH i64");
    let _: u64 = sbox.call("RoundTripHostU64", 1u64 << 40).expect("RTH u64");
    let _: f32 = sbox.call("RoundTripHostF32", 3.5f32).expect("RTH f32");
    let _: f64 = sbox.call("RoundTripHostF64", -2.25f64).expect("RTH f64");
    let _: bool = sbox.call("RoundTripHostBool", true).expect("RTH bool");
    let _: String = sbox
        .call("RoundTripHostString", "hi".to_string())
        .expect("RTH string");
    let _: Vec<u8> = sbox
        .call("RoundTripHostVecBytes", vec![1u8, 2, 3])
        .expect("RTH vec");
}

/// Register the `HostEcho*` family used by the call golden. Same
/// helper is used both at generate time (against
/// `UninitializedSandbox`) and at load time (against
/// `HostFunctions`) so the registered set matches the captured
/// `host_function_details`.
pub fn register_host_echo_fns<R: Registerable>(r: &mut R) {
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
}
