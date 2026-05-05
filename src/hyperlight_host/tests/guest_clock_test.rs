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

//! Integration tests for the paravirtualized guest clock, only compiled
//! when the `enable_guest_clock` feature is enabled on `hyperlight-host`.
#![cfg(all(feature = "enable_guest_clock", target_arch = "x86_64"))]

use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub mod common;
use crate::common::with_rust_sandbox;
/// Minimum real wait used by the monotonic advance test. Chosen large
/// enough to dwarf any plausible CI scheduling jitter but small enough
/// not to slow the test suite down noticeably.
const MONOTONIC_ADVANCE_SLEEP: Duration = Duration::from_millis(50);

/// Minimum real wait used by the restore-doesn't-freeze-wall-clock test.
/// Must be comfortably larger than `WALL_CLOCK_ADVANCE_TOLERANCE` below.
const RESTORE_SLEEP: Duration = Duration::from_millis(200);

/// Allowed "play" when comparing post-restore wall-clock time against the
/// host's notion of now. Accounts for the guest call round-trip plus any
/// CI jitter. Kept generous because the test only needs to prove that
/// the clock was re-stamped, not that it is sub-millisecond accurate.
const WALL_CLOCK_ADVANCE_TOLERANCE: Duration = Duration::from_millis(500);

/// How long to sit idle after sandbox creation in the no-drift test below.
/// Long enough that any constant offset between guest and host wall
/// clocks (e.g. from a stale `boot_time_ns` calibration) dominates over
/// scheduling jitter.
const IDLE_BEFORE_FIRST_CALL: Duration = Duration::from_secs(2);

/// Tight tolerance used by the no-drift test.
///
/// The host computes `boot_time_ns = wall_now - monotonic_now`
/// back-to-back in `arm_clock` (where `monotonic_now` comes from
/// `KVM_GET_CLOCK` on KVM, or `HV_REGISTER_TIME_REF_COUNT` on
/// Hyper-V). On KVM, `KVM_GET_CLOCK` can disagree with the live
/// pvclock page by up to ~13ms (observed on WSL2; root cause
/// uncertain — may be smaller on bare metal). The 20ms tolerance
/// accommodates this while still catching formula bugs (e.g.
/// omitting the monotonic subtraction produces ~100ms+ drift).
const WALL_CLOCK_TIGHT_TOLERANCE: Duration = Duration::from_millis(20);

#[test]
fn clock_is_available_under_enable_guest_clock() {
    with_rust_sandbox(|mut sbox| {
        let available: i32 = sbox.call("ClockIsAvailable", ()).unwrap();
        assert_eq!(available, 1, "guest clock should be armed by the host");
    });
}

#[test]
fn monotonic_time_advances_across_calls() {
    with_rust_sandbox(|mut sbox| {
        let first: i64 = sbox.call("GetMonotonicTimeNs", ()).unwrap();
        assert!(first >= 0, "guest reported clock unavailable: {first}");

        thread::sleep(MONOTONIC_ADVANCE_SLEEP);

        let second: i64 = sbox.call("GetMonotonicTimeNs", ()).unwrap();
        assert!(second >= 0, "guest reported clock unavailable: {second}");

        let delta_ns = second - first;
        assert!(
            delta_ns >= MONOTONIC_ADVANCE_SLEEP.as_nanos() as i64 / 2,
            "monotonic clock did not advance enough: first={first} second={second} \
             delta_ns={delta_ns}"
        );
    });
}

#[test]
fn wall_clock_tracks_host_wall_clock() {
    with_rust_sandbox(|mut sbox| {
        let guest_ns: i64 = sbox.call("GetWallClockTimeNs", ()).unwrap();
        assert!(
            guest_ns >= 0,
            "guest reported wall-clock unavailable: {guest_ns}"
        );

        let host_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i64;

        let skew_ns = (host_ns - guest_ns).abs();
        assert!(
            skew_ns < WALL_CLOCK_ADVANCE_TOLERANCE.as_nanos() as i64,
            "guest wall-clock differs from host by {skew_ns} ns \
             (guest={guest_ns}, host={host_ns})"
        );
    });
}

/// Snapshot / restore must re-stamp the host's `boot_time_ns` so the guest
/// sees real elapsed wall-clock time across the restore rather than a
/// frozen instant from when the snapshot was taken.
#[test]
fn wall_clock_advances_across_snapshot_restore() {
    with_rust_sandbox(|mut sbox| {
        let snapshot = sbox.snapshot().unwrap();

        let before: i64 = sbox.call("GetWallClockTimeNs", ()).unwrap();
        assert!(
            before >= 0,
            "guest reported wall-clock unavailable: {before}"
        );

        thread::sleep(RESTORE_SLEEP);
        sbox.restore(snapshot).unwrap();

        let after: i64 = sbox.call("GetWallClockTimeNs", ()).unwrap();
        assert!(after >= 0, "guest reported wall-clock unavailable: {after}");

        let advance_ns = after - before;
        // Allow half the sleep to cover scheduling jitter on the low end;
        // on the high end, real elapsed time plus the guest-call overhead
        // is fine.
        assert!(
            advance_ns >= RESTORE_SLEEP.as_nanos() as i64 / 2,
            "wall-clock did not advance across snapshot/restore: \
             before={before} after={after} advance_ns={advance_ns}"
        );
    });
}

/// Diagnostic for the `boot_time_ns` calibration formula.
///
/// `arm_clock` stamps `boot_time_ns` and the guest computes
/// `wall = boot_time_ns + monotonic_time_ns()`. For that to match the
/// host's wall clock, `boot_time_ns` must be `wall_at_arm - monotonic_at_arm`
/// — i.e. the Unix-epoch origin of the monotonic clock — not just
/// `wall_at_arm`. If the host stamps the latter, the guest's wall clock
/// is offset ahead of the host by exactly the value of the underlying
/// paravirt counter at arm time, which on a host with non-trivial
/// uptime (or any KVM partition where `system_time` is host-wide) can
/// be arbitrarily large.
///
/// This test waits for a real interval after sandbox creation before
/// the first guest call, then requires the guest's reported wall clock
/// to match the host's within a tight tolerance. The existing
/// [`wall_clock_tracks_host_wall_clock`] test uses a 500 ms tolerance
/// and reads immediately, both of which can mask a small constant
/// offset. This one will not.
#[test]
fn wall_clock_does_not_drift_after_idle() {
    with_rust_sandbox(|mut sbox| {
        thread::sleep(IDLE_BEFORE_FIRST_CALL);

        let guest_ns: i64 = sbox.call("GetWallClockTimeNs", ()).unwrap();
        assert!(
            guest_ns >= 0,
            "guest reported wall-clock unavailable: {guest_ns}"
        );

        let host_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i64;

        let skew_ns = (host_ns - guest_ns).abs();
        assert!(
            skew_ns < WALL_CLOCK_TIGHT_TOLERANCE.as_nanos() as i64,
            "guest wall-clock skew of {skew_ns} ns exceeds tolerance of {tol} ns \
             after {idle:?} idle — likely a `boot_time_ns` calibration bug \
             (guest={guest_ns}, host={host_ns})",
            tol = WALL_CLOCK_TIGHT_TOLERANCE.as_nanos(),
            idle = IDLE_BEFORE_FIRST_CALL,
        );
    });
}
