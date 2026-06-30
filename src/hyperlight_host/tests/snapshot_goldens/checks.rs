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

//! Functional checks against goldens loaded from the on-disk goldens
//! directory.
//!
//! Each check builds its own `MultiUseSandbox` from the golden with
//! `GoldenTest::load_sandbox`, so checks are independent and one
//! failure does not poison the next. See `docs/snapshot-versioning.md`
//! for how to add a check.

use std::path::Path;
use std::sync::Arc;

use hyperlight_host::sandbox::snapshot::{OciTag, Snapshot};
use hyperlight_host::{HostFunctions, MultiUseSandbox};

use crate::fixtures::{CALL_COUNTER_BUMP, HEAP_PATTERN_LEN, register_host_echo_fns};

/// A staged golden handed to a check. The check builds sandboxes from
/// it with `load_sandbox`, as many as it needs.
pub(crate) struct GoldenTest<'a> {
    dir: &'a Path,
    tag: &'a str,
}

impl<'a> GoldenTest<'a> {
    pub(crate) fn new(dir: &'a Path, tag: &'a str) -> Self {
        Self { dir, tag }
    }

    /// The on-disk OCI Image Layout directory of the golden.
    pub(crate) fn dir(&self) -> &Path {
        self.dir
    }

    /// The golden's OCI tag.
    pub(crate) fn tag(&self) -> &str {
        self.tag
    }

    /// Load the golden into a fresh sandbox with the checks' host
    /// functions registered.
    pub(crate) fn load_sandbox(&self) -> Result<MultiUseSandbox, String> {
        let reference = OciTag::new(self.tag())
            .map_err(|e| format!("invalid golden tag {}: {e}", self.tag()))?;
        let snap = Snapshot::checked_load(self.dir(), reference)
            .map_err(|e| format!("Snapshot::checked_load({}): {e}", self.tag()))?;
        let mut funcs = HostFunctions::default();
        register_host_echo_fns(&mut funcs);
        MultiUseSandbox::from_snapshot(Arc::new(snap), funcs, None)
            .map_err(|e| format!("MultiUseSandbox::from_snapshot({}): {e}", self.tag()))
    }
}

pub(crate) struct Check {
    pub(crate) name: &'static str,
    /// The lowest ABI major this check runs against. A check reads
    /// state that `generate()` writes, so it runs only against a golden
    /// whose major is at or above `since_abi`. Set it to the current
    /// `SNAPSHOT_ABI_VERSION` when adding a check. See
    /// `docs/snapshot-versioning.md`.
    pub(crate) since_abi_major: u32,
    pub(crate) run: fn(&GoldenTest) -> Result<(), String>,
}

pub(crate) const CHECKS: &[Check] = &[
    Check {
        name: "captured_bss",
        since_abi_major: 1,
        run: captured_bss,
    },
    Check {
        name: "captured_heap_pattern",
        since_abi_major: 1,
        run: captured_heap_pattern,
    },
    Check {
        name: "guest_types_round_trip",
        since_abi_major: 1,
        run: guest_types_round_trip,
    },
    Check {
        name: "host_round_trips",
        since_abi_major: 1,
        run: host_round_trips,
    },
    Check {
        name: "chained_snapshot",
        since_abi_major: 1,
        run: chained_snapshot,
    },
];

/// Captured BSS restores exactly: `COUNTER == CALL_COUNTER_BUMP`.
/// Covers the dispatch convention, sregs apply, page-table
/// relocation, captured stack/BSS.
fn captured_bss(golden: &GoldenTest) -> Result<(), String> {
    let mut sbox = golden.load_sandbox()?;
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
fn captured_heap_pattern(golden: &GoldenTest) -> Result<(), String> {
    let mut sbox = golden.load_sandbox()?;
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
fn guest_types_round_trip(golden: &GoldenTest) -> Result<(), String> {
    let mut sbox = golden.load_sandbox()?;
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
fn host_round_trips(golden: &GoldenTest) -> Result<(), String> {
    let mut sbox = golden.load_sandbox()?;
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
    let _: () = sbox
        .call("RoundTripHostNoOp", ())
        .map_err(|e| format!("RoundTripHostNoOp: {e}"))?;
    Ok(())
}

/// Snapshot-from-loaded-snapshot path. Mutates state on the loaded
/// golden, takes a fresh snapshot, round-trips it through an
/// OCI layout on disk, and asserts the mutation survives.
fn chained_snapshot(golden: &GoldenTest) -> Result<(), String> {
    let mut sbox = golden.load_sandbox()?;
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
    let tag = OciTag::new("chained").map_err(|e| format!("tag: {e}"))?;
    snap.save(&layout, &tag).map_err(|e| format!("save: {e}"))?;

    let loaded = Snapshot::checked_load(&layout, tag).map_err(|e| format!("checked_load: {e}"))?;
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
