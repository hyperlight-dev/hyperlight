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

//! Functional checks against goldens loaded from the on-disk cache.
//!
//! Each check runs against a fresh `MultiUseSandbox` built from
//! the golden for `Check::kind`, so checks are independent and
//! one failure does not poison the next.
//!
//! Adding coverage: write a `fn(&mut MultiUseSandbox) -> Result<(),
//! String>` and add one row to `CHECKS`.

use std::sync::Arc;

use hyperlight_host::sandbox::snapshot::Snapshot;
use hyperlight_host::{HostFunctions, MultiUseSandbox};

use crate::fixtures::{CALL_COUNTER_BUMP, HEAP_PATTERN_LEN, INIT_DATA, register_host_echo_fns};
use crate::platform::Kind;

pub struct Check {
    pub name: &'static str,
    pub kind: Kind,
    pub run: fn(&mut MultiUseSandbox) -> Result<(), String>,
}

pub const CHECKS: &[Check] = &[
    Check {
        name: "init/basic_call",
        kind: Kind::Init,
        run: init_basic_call,
    },
    Check {
        name: "init/data_round_trip",
        kind: Kind::Init,
        run: init_data_round_trip,
    },
    Check {
        name: "init/custom_layout_works",
        kind: Kind::Init,
        run: init_custom_layout_works,
    },
    Check {
        name: "call/captured_bss",
        kind: Kind::Call,
        run: call_captured_bss,
    },
    Check {
        name: "call/captured_heap_pattern",
        kind: Kind::Call,
        run: call_captured_heap_pattern,
    },
    Check {
        name: "call/guest_types_round_trip",
        kind: Kind::Call,
        run: call_guest_types_round_trip,
    },
    Check {
        name: "call/host_round_trips",
        kind: Kind::Call,
        run: call_host_round_trips,
    },
    Check {
        name: "call/chained_snapshot",
        kind: Kind::Call,
        run: call_chained_snapshot,
    },
];

// -----------------------------------------------------------------
// init
// -----------------------------------------------------------------

/// Loaded init golden answers a basic call and observes a clean
/// BSS. Covers the header layout, layout arithmetic, PEB contents,
/// the dispatch port, the initialise entry convention, and BSS init.
fn init_basic_call(sbox: &mut MultiUseSandbox) -> Result<(), String> {
    let value: i32 = sbox
        .call("GetStatic", ())
        .map_err(|e| format!("GetStatic: {e}"))?;
    if value != 0 {
        return Err(format!("fresh init must observe BSS == 0, got {value}"));
    }
    Ok(())
}

/// `INIT_DATA` survives the snapshot round-trip with permissions
/// intact. The guest's `ReadFromUserMemory` returns the captured
/// bytes; a mismatch indicates silent corruption of the init_data
/// region.
fn init_data_round_trip(sbox: &mut MultiUseSandbox) -> Result<(), String> {
    let bytes: Vec<u8> = sbox
        .call(
            "ReadFromUserMemory",
            (INIT_DATA.len() as u64, INIT_DATA.to_vec()),
        )
        .map_err(|e| format!("ReadFromUserMemory: {e}"))?;
    if bytes != INIT_DATA {
        return Err(format!(
            "captured init_data did not round-trip byte-for-byte (len={})",
            bytes.len(),
        ));
    }
    Ok(())
}

/// Any silent shift in `SandboxMemoryLayout::new` arithmetic with
/// the non-default sizes from `golden_config` would land the PEB or
/// scratch buffers at the wrong addresses; an `Echo` would then
/// fail.
fn init_custom_layout_works(sbox: &mut MultiUseSandbox) -> Result<(), String> {
    let got: String = sbox
        .call("Echo", "custom-layout".to_string())
        .map_err(|e| format!("Echo: {e}"))?;
    if got != "custom-layout" {
        return Err(format!("Echo returned {got:?}"));
    }
    Ok(())
}

// -----------------------------------------------------------------
// call
// -----------------------------------------------------------------

/// Captured BSS restores exactly: `COUNTER == CALL_COUNTER_BUMP`.
/// Covers the dispatch convention, sregs apply, page-table
/// relocation, captured stack/BSS.
fn call_captured_bss(sbox: &mut MultiUseSandbox) -> Result<(), String> {
    let value: i32 = sbox
        .call("GetStatic", ())
        .map_err(|e| format!("GetStatic: {e}"))?;
    if value != CALL_COUNTER_BUMP {
        return Err(format!(
            "captured COUNTER expected {CALL_COUNTER_BUMP}, got {value}",
        ));
    }
    Ok(())
}

/// Captured heap state restores exactly: the pinned `Vec<u8>`
/// pattern produced by `AllocAndWritePattern` survives across
/// save/load.
fn call_captured_heap_pattern(sbox: &mut MultiUseSandbox) -> Result<(), String> {
    let got: Vec<u8> = sbox
        .call("ReadPattern", ())
        .map_err(|e| format!("ReadPattern: {e}"))?;
    let expected: Vec<u8> = (0..HEAP_PATTERN_LEN as usize)
        .map(|i| (i & 0xff) as u8)
        .collect();
    if got != expected {
        return Err(format!(
            "captured heap pattern mismatch (got len {} expected len {})",
            got.len(),
            expected.len(),
        ));
    }
    Ok(())
}

/// Guest-call wire format for every primitive parameter and return
/// type. Each loop asserts an `EchoT` round-trips. Float NaN goes
/// through `is_nan` since `NaN != NaN`.
fn call_guest_types_round_trip(sbox: &mut MultiUseSandbox) -> Result<(), String> {
    macro_rules! echo {
        ($name:expr, $ty:ty, $values:expr) => {{
            for &v in $values.iter() {
                let got: $ty = sbox
                    .call($name, v)
                    .map_err(|e| format!("{}({:?}): {e}", $name, v))?;
                if got != v {
                    return Err(format!("{}({:?}) returned {:?}", $name, v, got));
                }
            }
        }};
    }
    echo!("EchoI32", i32, [i32::MIN, -1, 0, 1, i32::MAX]);
    echo!("EchoU32", u32, [0u32, 1, u32::MAX]);
    echo!("EchoI64", i64, [i64::MIN, -1, 0, 1, i64::MAX]);
    echo!("EchoU64", u64, [0u64, 1, u64::MAX]);
    echo!(
        "EchoFloat",
        f32,
        [
            0.0f32,
            -1.5,
            1.5,
            f32::MIN,
            f32::MAX,
            f32::INFINITY,
            f32::NEG_INFINITY,
        ]
    );
    let got: f32 = sbox
        .call("EchoFloat", f32::NAN)
        .map_err(|e| format!("EchoFloat(NaN): {e}"))?;
    if !got.is_nan() {
        return Err(format!("EchoFloat(NaN) returned {got}"));
    }
    echo!(
        "EchoDouble",
        f64,
        [
            0.0f64,
            -1.5,
            1.5,
            f64::MIN,
            f64::MAX,
            f64::INFINITY,
            f64::NEG_INFINITY,
        ]
    );
    let got: f64 = sbox
        .call("EchoDouble", f64::NAN)
        .map_err(|e| format!("EchoDouble(NaN): {e}"))?;
    if !got.is_nan() {
        return Err(format!("EchoDouble(NaN) returned {got}"));
    }
    echo!("EchoBool", bool, [false, true]);

    for v in [String::new(), "hello".to_string(), "héllo 🌍".to_string()] {
        let got: String = sbox
            .call("Echo", v.clone())
            .map_err(|e| format!("Echo({v:?}): {e}"))?;
        if got != v {
            return Err(format!("Echo({v:?}) returned {got:?}"));
        }
    }
    for v in [
        Vec::<u8>::new(),
        vec![0u8, 1, 2, 3, 0xff],
        (0..256u32).map(|i| (i & 0xff) as u8).collect::<Vec<u8>>(),
    ] {
        let got: Vec<u8> = sbox
            .call("GetSizePrefixedBuffer", v.clone())
            .map_err(|e| format!("GetSizePrefixedBuffer(len={}): {e}", v.len()))?;
        if got != v {
            return Err(format!(
                "GetSizePrefixedBuffer(len={}) did not round-trip",
                v.len(),
            ));
        }
    }
    let _: () = sbox.call("NoOp", ()).map_err(|e| format!("NoOp: {e}"))?;
    let mixed: i32 = sbox
        .call(
            "PrintElevenArgs",
            (
                "a".to_string(),
                1i32,
                2i64,
                "b".to_string(),
                "c".to_string(),
                true,
                false,
                3u32,
                4u64,
                5i32,
                6.5f32,
            ),
        )
        .map_err(|e| format!("PrintElevenArgs: {e}"))?;
    if mixed < 0 {
        return Err(format!("PrintElevenArgs returned {mixed}"));
    }
    Ok(())
}

/// Host-call wire format for every primitive parameter and return
/// type. Each `RoundTripHostT` invokes the matching `HostEchoT` on
/// the registered host-fn set.
fn call_host_round_trips(sbox: &mut MultiUseSandbox) -> Result<(), String> {
    macro_rules! rt {
        ($name:expr, $ty:ty, $value:expr) => {{
            let v: $ty = $value;
            let got: $ty = sbox
                .call($name, v.clone())
                .map_err(|e| format!("{}({:?}): {e}", $name, v))?;
            if got != v {
                return Err(format!("{}({:?}) returned {:?}", $name, v, got));
            }
        }};
    }
    rt!("RoundTripHostI32", i32, -7);
    rt!("RoundTripHostU32", u32, 0xdead_beef);
    rt!("RoundTripHostI64", i64, i64::MIN);
    rt!("RoundTripHostU64", u64, u64::MAX);
    rt!("RoundTripHostF32", f32, -1.25);
    rt!("RoundTripHostF64", f64, 1234.5);
    rt!("RoundTripHostBool", bool, false);
    rt!("RoundTripHostString", String, "round-trip".to_string());
    rt!("RoundTripHostVecBytes", Vec<u8>, vec![0u8, 1, 2, 3, 0xff]);
    Ok(())
}

/// Snapshot-from-loaded-snapshot path. Mutates state on the loaded
/// call golden, takes a fresh snapshot, round-trips it through an
/// OCI layout on disk, and asserts the mutation survives.
fn call_chained_snapshot(sbox: &mut MultiUseSandbox) -> Result<(), String> {
    let val: i32 = sbox
        .call("AddToStatic", 5i32)
        .map_err(|e| format!("AddToStatic: {e}"))?;
    if val != CALL_COUNTER_BUMP + 5 {
        return Err(format!(
            "AddToStatic returned {val}, expected {}",
            CALL_COUNTER_BUMP + 5,
        ));
    }
    let snap = sbox
        .snapshot()
        .map_err(|e| format!("take chained snapshot: {e}"))?;

    let tmp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let layout = tmp.path().join("chained");
    let tag = "chained";
    snap.to_oci(&layout, tag)
        .map_err(|e| format!("to_oci: {e}"))?;

    let loaded = Snapshot::from_oci(&layout, tag).map_err(|e| format!("from_oci: {e}"))?;
    let mut funcs = HostFunctions::default();
    register_host_echo_fns(&mut funcs);
    let mut sbox2 = MultiUseSandbox::from_snapshot(Arc::new(loaded), funcs, None)
        .map_err(|e| format!("from_snapshot: {e}"))?;
    let val: i32 = sbox2
        .call("GetStatic", ())
        .map_err(|e| format!("GetStatic on chained: {e}"))?;
    if val != CALL_COUNTER_BUMP + 5 {
        return Err(format!(
            "chained snapshot observed COUNTER={val}, expected {}",
            CALL_COUNTER_BUMP + 5,
        ));
    }
    Ok(())
}
