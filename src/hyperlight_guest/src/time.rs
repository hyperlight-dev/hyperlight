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

//! Low-level guest time functions using the paravirtualized clock.
//!
//! This module provides low-level functions to read time without VM exits by
//! consulting the shared clock page populated by the host. The page lives at
//! a fixed, compile-time-known guest-virtual address inside the scratch
//! region (see [`hyperlight_common::layout::clock_page_gva`]), so no
//! per-sandbox discovery data — such as a PEB field — is required.
//!
//! # For most users
//!
//! Use [`hyperlight_guest_bin::time`] instead, which provides a
//! `std::time`-compatible API (`SystemTime`, `Instant`) built on top of the
//! free functions here.
//!
//! # Supported clock sources
//!
//! - **KVM pvclock** — used when running under KVM.
//! - **Hyper-V Reference TSC** — used when running under MSHV or WHP.
//!
//! Which one is active is decided by the host and advertised by the
//! `clock_type` field in the scratch bookkeeping page. When the host is built
//! without the `enable_guest_clock` feature the field reads back as
//! [`ClockType::None`] and every function in this module returns `None`.
//!
//! # Concurrency invariant (current)
//!
//! In the current Hyperlight execution model the guest vCPU runs only
//! while the host thread is blocked inside the vCPU run call: the host
//! writes the clock page **before** entering the guest and cannot mutate
//! it while the guest reads. There is therefore no concurrent writer in
//! practice and the seqlock retry, the acquire fences, and the per-field
//! `read_volatile`s will never actually fire at runtime today.
//!
//! These primitives are kept anyway because: (1) they future-proof
//! against multi-vCPU sandboxes, async host-side clock updates, or
//! live migration; and (2) by never creating a `&T` over
//! hypervisor-mutable memory we satisfy Rust's aliasing rules
//! unconditionally.

use core::sync::atomic::{AtomicU64, Ordering, fence};

use hyperlight_common::layout::{
    SCRATCH_TOP_BOOT_TIME_NS_OFFSET, SCRATCH_TOP_CLOCK_TYPE_OFFSET, clock_page_gva,
};
use hyperlight_common::time::{
    ClockType, HvReferenceTscPage, KvmPvclockVcpuTimeInfo, PVCLOCK_TSC_STABLE_BIT,
};

/// The guest-virtual address of the top of scratch memory. The
/// bookkeeping fields (`clock_type`, `boot_time_ns`, etc.) are stored
/// as negative offsets from this address.
const SCRATCH_TOP_GVA: u64 = hyperlight_common::layout::MAX_GVA as u64 + 1;

/// Error type for clock validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockValidationError {
    /// Clock is not configured. Either the host was built without the
    /// `enable_guest_clock` feature, or the bookkeeping page contains an unknown
    /// discriminant that we treat as "unavailable" out of caution.
    NotConfigured,
    /// KVM pvclock does not have `PVCLOCK_TSC_STABLE_BIT` set. This
    /// indicates the TSC is not stable across vCPUs on this host.
    KvmTscNotStable,
    /// Hyper-V Reference TSC page has `tsc_sequence == 0`, which in the
    /// TLFS is the host's "fall back to MSR" sentinel. MSR reads require a
    /// VM exit which is not available from a Hyperlight guest, so this is
    /// reported as an error rather than retried.
    HyperVTscSequenceZero,
}

/// Read the `clock_type` field from the scratch bookkeeping page.
#[inline]
fn read_clock_type() -> ClockType {
    // SAFETY: the bookkeeping page at the top of scratch is always mapped
    // RW; reads of any 8-byte aligned u64 inside it are well-defined.
    // Zero-initialised memory decodes to `ClockType::None`.
    let ptr = (SCRATCH_TOP_GVA - SCRATCH_TOP_CLOCK_TYPE_OFFSET) as *const u64;
    let raw = unsafe { core::ptr::read_volatile(ptr) };
    ClockType::from(raw)
}

/// Read the `boot_time_ns` field from the scratch bookkeeping page.
#[inline]
fn read_boot_time_ns() -> u64 {
    // SAFETY: see `read_clock_type`.
    let ptr = (SCRATCH_TOP_GVA - SCRATCH_TOP_BOOT_TIME_NS_OFFSET) as *const u64;
    unsafe { core::ptr::read_volatile(ptr) }
}

/// Returns `true` when the host has armed a paravirtualized clock for this
/// sandbox. Cheap - just a single read of the bookkeeping field.
#[inline]
pub fn is_available() -> bool {
    !matches!(read_clock_type(), ClockType::None)
}

/// Validate that the paravirtualized clock is properly configured and stable.
///
/// This is an optional defense-in-depth check a guest can make once during
/// initialisation. The host should have already verified invariant TSC
/// support when enabling the feature; this catches accidental
/// misconfiguration.
pub fn validate_clock() -> Result<(), ClockValidationError> {
    match read_clock_type() {
        ClockType::KvmPvclock => {
            // SAFETY: the clock page is mapped read/write into the guest's
            // scratch region for the lifetime of the sandbox, and a
            // `KvmPvclockVcpuTimeInfo` (32 bytes) fits at offset 0. We use
            // raw-pointer `read_volatile` instead of materialising a
            // `&KvmPvclockVcpuTimeInfo` so the reader stays sound under
            // Rust's aliasing rules even if a future Hyperlight execution
            // model lets the host mutate this page concurrently with the
            // guest. See module-level "Concurrency invariant" note.
            let ptr = clock_page_gva() as *const KvmPvclockVcpuTimeInfo;
            let flags = unsafe { core::ptr::read_volatile(&raw const (*ptr).flags) };
            if (flags & PVCLOCK_TSC_STABLE_BIT) == 0 {
                return Err(ClockValidationError::KvmTscNotStable);
            }
            Ok(())
        }
        ClockType::HyperVReferenceTsc => {
            // SAFETY: as above. `HvReferenceTscPage` fills the full 4 KiB
            // page; we only read the `tsc_sequence` header field here.
            let ptr = clock_page_gva() as *const HvReferenceTscPage;
            let seq = unsafe { core::ptr::read_volatile(&raw const (*ptr).tsc_sequence) };
            if seq == 0 {
                return Err(ClockValidationError::HyperVTscSequenceZero);
            }
            Ok(())
        }
        ClockType::None => Err(ClockValidationError::NotConfigured),
    }
}

/// Read the CPU's Time Stamp Counter.
#[inline]
fn rdtsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: RDTSC is unprivileged on x86_64 and always present on
        // CPUs that support the paravirtualized clock (host-verified
        // invariant TSC).
        unsafe { core::arch::x86_64::_rdtsc() }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0 // TSC not available on non-x86_64 architectures.
    }
}

/// Maximum number of retries when the hypervisor is concurrently updating
/// the paravirtualized clock page.
///
/// Both the KVM pvclock and Hyper-V Reference TSC protocols use a
/// seqlock-style mechanism: the hypervisor bumps a sequence/version counter
/// before and after mutating the page, and readers must retry if they
/// observe an in-progress or changed counter. Mutations are extremely
/// short, so a small retry cap is plenty; the hypervisor's design assumes
/// the client spin-retries rather than falling back to an MSR (which would
/// force a VM exit and defeat the whole point of the paravirtualized
/// clock).
const CLOCK_SEQLOCK_MAX_RETRIES: u32 = 100;

/// Read time from the KVM pvclock structure.
///
/// Uses the seqlock-style protocol described in
/// <https://docs.kernel.org/virt/kvm/x86/msr.html#pvclock>: the host sets
/// `version` to an odd value before mutating and to a new even value
/// afterwards; readers retry while `version` is odd or changes across the
/// read. We cap retries with [`CLOCK_SEQLOCK_MAX_RETRIES`] so that a
/// pathologically churning host can't make us spin forever.
fn read_kvm_pvclock() -> Option<u64> {
    // SAFETY: see `validate_clock` for the mapping invariant. Today the
    // host cannot mutate this page while the guest is running (single
    // vCPU, host-then-guest scheduling), so the seqlock loop and the
    // volatile loads are not strictly required for correctness right now.
    // We keep the upstream pvclock contract verbatim so that:
    //   (a) the reader is sound under Rust's aliasing rules regardless of
    //       what the host is doing — no `&T` is ever taken over this
    //       memory; and
    //   (b) no behavioural change is needed when Hyperlight gains
    //       multi-vCPU sandboxes or async host-side clock updates.
    let ptr = clock_page_gva() as *const KvmPvclockVcpuTimeInfo;

    for _ in 0..CLOCK_SEQLOCK_MAX_RETRIES {
        let version1 = unsafe { core::ptr::read_volatile(&raw const (*ptr).version) };
        if version1 & 1 != 0 {
            core::hint::spin_loop();
            continue; // Update in progress.
        }

        // Pair with the hypervisor's write barrier between the version bump
        // and the payload write. On x86_64 an Acquire fence is free (no
        // instruction emitted), but we keep it for correctness under the
        // memory model.
        fence(Ordering::Acquire);

        let tsc_timestamp = unsafe { core::ptr::read_volatile(&raw const (*ptr).tsc_timestamp) };
        let system_time = unsafe { core::ptr::read_volatile(&raw const (*ptr).system_time) };
        let tsc_to_system_mul =
            unsafe { core::ptr::read_volatile(&raw const (*ptr).tsc_to_system_mul) };
        let tsc_shift = unsafe { core::ptr::read_volatile(&raw const (*ptr).tsc_shift) };

        fence(Ordering::Acquire);

        let version2 = unsafe { core::ptr::read_volatile(&raw const (*ptr).version) };
        if version1 != version2 {
            core::hint::spin_loop();
            continue; // Data changed mid-read.
        }

        let tsc_now = rdtsc();
        let tsc_delta = tsc_now.wrapping_sub(tsc_timestamp);

        // KVM pvclock scaler, per
        // <https://docs.kernel.org/virt/kvm/x86/msr.html#pvclock>:
        // `ns = (tsc_delta * tsc_to_system_mul) >> (32 - tsc_shift)`.
        // We clamp the right-shift count to `[0, 63]` so
        // buggy host cannot induce UB / panic via an out-of-range shift;
        // values outside the documented `tsc_shift ∈ [-31, 31]` band
        // produce non-meaningful timings, but the reader stays sound.
        let raw_shift = 32i32 - tsc_shift as i32;
        let shift = raw_shift.clamp(0, 63) as u32;
        let ns_delta = ((tsc_delta as u128 * tsc_to_system_mul as u128) >> shift) as u64;

        return Some(system_time.wrapping_add(ns_delta));
    }

    None
}

/// Read time from the Hyper-V Reference TSC page.
///
/// Uses the seqlock-style protocol described in TLFS §12.7. A sequence of
/// 0 is a persistent "fall back to MSR" signal from the host; we return
/// `None` without retrying because MSR reads require a VM exit that is
/// unavailable inside a Hyperlight guest.
fn read_hv_reference_tsc() -> Option<u64> {
    // SAFETY: see `read_kvm_pvclock` for the aliasing / volatile rationale.
    let ptr = clock_page_gva() as *const HvReferenceTscPage;

    for _ in 0..CLOCK_SEQLOCK_MAX_RETRIES {
        let seq1 = unsafe { core::ptr::read_volatile(&raw const (*ptr).tsc_sequence) };
        if seq1 == 0 {
            return None; // Persistent MSR-fallback sentinel.
        }

        fence(Ordering::Acquire);

        let tsc_scale = unsafe { core::ptr::read_volatile(&raw const (*ptr).tsc_scale) };
        let tsc_offset = unsafe { core::ptr::read_volatile(&raw const (*ptr).tsc_offset) };

        fence(Ordering::Acquire);

        let seq2 = unsafe { core::ptr::read_volatile(&raw const (*ptr).tsc_sequence) };
        if seq1 != seq2 {
            core::hint::spin_loop();
            continue; // Host updated the page mid-read.
        }

        let tsc_now = rdtsc();

        // Hyper-V Reference TSC formula (TLFS §12.7):
        //   `time_100ns = ((tsc * scale) >> 64) + offset`
        // The high 64 bits of a 128-bit multiply give the scaled value.
        // We use `checked_add_signed` on the offset addition: an overflow
        // here would mean the host's `tsc_offset` is so far out of band
        // that `time_100ns` cannot be represented, which we treat as
        // "clock unavailable" rather than retrying — the offset is
        // host-written and stable, so retrying cannot rescue it.
        let scaled = ((tsc_now as u128 * tsc_scale as u128) >> 64) as u64;
        let time_100ns = scaled.checked_add_signed(tsc_offset)?;

        return time_100ns.checked_mul(100);
    }

    None
}

/// The raw pvclock value from the previous [`monotonic_time_ns`] read: the
/// baseline the next read compares against. It is updated on **every** read,
/// so it can step *down* once on a cross-partition restore — it is not a
/// "max ever", which is why `monotonic_time_ns` stores `raw` unconditionally.
///
/// This and [`MONO_OFFSET`] must live in `.bss` (the guest's snapshot
/// region), never in scratch: on restore the host replaces the snapshot
/// region with the snapshot's contents but *zeroes* scratch, so keeping them
/// here means they come back at their snapshot-time values. In scratch they
/// would be wiped to 0 and the monotonic guard would silently break.
///
/// Used to spot a backward jump when a snapshot is restored into a new
/// partition whose clock starts lower: the next [`monotonic_time_ns`] sees
/// `raw < RAW_BASELINE` and folds the old baseline into [`MONO_OFFSET`] (see
/// [`monotonic_fixup`]). The fixup is lazy — no host→guest restore hook is
/// required.
static RAW_BASELINE: AtomicU64 = AtomicU64::new(0);

/// Cumulative offset folded into raw pvclock reads to preserve monotonicity
/// across cross-partition restores. Also `.bss` — see [`RAW_BASELINE`] for
/// why. On each backward jump the previous baseline is added, so reported
/// time never decreases.
static MONO_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Decide the monotonic-offset update for a freshly read `raw` clock value.
///
/// Given the previous `baseline` (the prior raw read) and offset, returns
/// `(new_offset, reported)`. If `raw < baseline` the underlying clock jumped
/// backward (a snapshot was restored into a partition whose clock starts
/// lower), so the old baseline is folded into the offset to keep the
/// reported value non-decreasing; otherwise the offset is unchanged. The
/// caller stores `raw` as the new baseline.
///
/// Pulled out as a function so the backward-jump logic can be unit
/// tested without a live hypervisor clock.
fn monotonic_fixup(raw: u64, baseline: u64, offset: u64) -> (u64, u64) {
    let offset = if raw < baseline {
        offset.wrapping_add(baseline)
    } else {
        offset
    };
    (offset, raw.wrapping_add(offset))
}

/// Read the raw monotonic value from the hypervisor without any
/// offset adjustment.
fn raw_monotonic_ns() -> Option<u64> {
    match read_clock_type() {
        ClockType::KvmPvclock => read_kvm_pvclock(),
        ClockType::HyperVReferenceTsc => read_hv_reference_tsc(),
        ClockType::None => None,
    }
}

/// Monotonic time in nanoseconds.
///
/// The value is an absolute counter derived from the hypervisor's time
/// base (kvmclock on KVM, partition reference time on Hyper-V). It is
/// monotonically increasing and suitable for measuring elapsed time
/// between two reads.
///
/// If a snapshot is restored into a **new** partition whose raw clock
/// starts from a lower value, an offset is applied so the returned
/// value never goes backward. Within a single partition epoch, diffs
/// between consecutive reads reflect real elapsed time. Across a
/// cross-partition restore the diff includes a synthetic gap (the
/// baseline carried over from the old partition) — safe for timeouts and
/// deadlines, but not an accurate measure of freeze duration (use
/// wall-clock time for that).
///
/// Returns `None` if the clock is not configured, or if the retry cap
/// was exhausted (the caller may retry).
pub fn monotonic_time_ns() -> Option<u64> {
    let raw = raw_monotonic_ns()?;

    // Keep monotonicity across cross-partition snapshot restores: if the
    // hypervisor's raw counter jumped backward, fold the old baseline into
    // the offset. `RAW_BASELINE` / `MONO_OFFSET` live in BSS so the snapshot
    // restores them (see their docs); the decision is computed by
    // `monotonic_fixup` so it can be unit-tested without a live clock.
    let baseline = RAW_BASELINE.load(Ordering::Relaxed);
    let offset = MONO_OFFSET.load(Ordering::Relaxed);
    let (new_offset, reported) = monotonic_fixup(raw, baseline, offset);
    RAW_BASELINE.store(raw, Ordering::Relaxed);
    MONO_OFFSET.store(new_offset, Ordering::Relaxed);
    Some(reported)
}

/// Wall-clock time in nanoseconds since the Unix epoch.
///
/// Returns `None` if:
/// - The clock is not configured (`clock_type == None`).
/// - `boot_time_ns` has not been stamped yet (it is zero before
///   `arm_clock` runs). On some backends the host's monotonic clock
///   source is unreliable until after the first vCPU run, so
///   wall clock is unavailable during `hyperlight_main` (init).
///   Monotonic time works fine during init. Wall clock becomes
///   available on the first dispatch call.
/// - The underlying monotonic read fails.
///
/// The host computes `boot_time_ns` as the Unix-epoch origin of the
/// monotonic clock (`wall_now - monotonic_now`, sampled back-to-back
/// in `arm_clock`) and stamps it into the scratch bookkeeping page. The
/// guest simply adds its live raw monotonic reading to recover wall time.
///
/// This host-side computation is necessary because Hyper-V has no
/// guest-accessible wall-clock register (unlike KVM's
/// `MSR_KVM_WALL_CLOCK_NEW`). We use the same host-computed approach
/// on all backends for uniformity.
pub fn wall_clock_time_ns() -> Option<u64> {
    // Use the *raw* monotonic value, never the offset-adjusted
    // `monotonic_time_ns()`: `boot_time_ns` is calibrated by the host
    // against the raw clock, so folding `MONO_OFFSET` in here would push
    // wall time into the future after a cross-partition restore. The split
    // is pinned by `wall_time_from`, whose signature can't see the offset.
    let raw = raw_monotonic_ns()?;
    wall_time_from(read_boot_time_ns(), raw)
}

/// Combine the host-stamped `boot_time_ns` (the Unix-epoch origin of the
/// monotonic clock) with a **raw** monotonic reading to recover wall time.
///
/// Takes the raw counter by design — never the offset-adjusted
/// [`monotonic_time_ns`] value. `boot_time_ns` is calibrated by the host
/// against the raw clock, so feeding the offset-adjusted reading in here
/// would shift wall time into the future by [`MONO_OFFSET`] after a
/// cross-partition restore. This signature deliberately cannot see the offset.
///
/// Returns `None` when `boot_time_ns` is still 0 — the host hasn't stamped it
/// yet (scratch is zero-initialised) — rather than a nonsense value.
fn wall_time_from(boot_time_ns: u64, raw_ns: u64) -> Option<u64> {
    if boot_time_ns == 0 {
        return None;
    }
    Some(boot_time_ns.wrapping_add(raw_ns))
}

/// Monotonic time in microseconds.
///
/// See [`monotonic_time_ns`] for details on the time base.
pub fn monotonic_time_us() -> Option<u64> {
    monotonic_time_ns().map(|ns| ns / 1_000)
}

/// Wall-clock time as `(seconds, sub-second nanoseconds)` since the Unix
/// epoch. Shape matches a POSIX `timespec`.
pub fn wall_clock_time() -> Option<(u64, u32)> {
    let ns = wall_clock_time_ns()?;
    let secs = ns / 1_000_000_000;
    let nsecs = (ns % 1_000_000_000) as u32;
    Some((secs, nsecs))
}

#[cfg(test)]
mod tests {
    use super::{monotonic_fixup, wall_time_from};

    #[test]
    fn forward_progress_leaves_offset_untouched() {
        // Normal advance within one partition: offset stays put.
        assert_eq!(monotonic_fixup(200, 100, 0), (0, 200));
        // First-ever read (baseline == 0).
        assert_eq!(monotonic_fixup(500, 0, 0), (0, 500));
        // Equal is not "backward": no offset bump.
        assert_eq!(monotonic_fixup(100, 100, 0), (0, 100));
    }

    #[test]
    fn backward_jump_folds_old_baseline_into_offset() {
        // Restored into a partition whose raw clock starts lower (50 < 1000):
        // fold the old baseline (1000) into the offset.
        assert_eq!(monotonic_fixup(50, 1000, 0), (1000, 1050));
        // Forward reads afterward keep the accumulated offset.
        assert_eq!(monotonic_fixup(60, 50, 1000), (1000, 1060));
        // A second cross-partition restore stacks another mark on top.
        assert_eq!(monotonic_fixup(20, 50, 1000), (1050, 1070));
    }

    #[test]
    fn reported_time_never_decreases_across_a_restore() {
        // Climb in partition 1, then "restore" into a lower-clock partition 2
        // (snapshot/restore brings `baseline`/`offset` back to their
        // snapshot-time values) and keep climbing. Reported time must never
        // regress.
        let mut baseline = 0u64;
        let mut offset = 0u64;
        let mut last = 0u64;
        // P1 climb, then the drop to 5 models the cross-partition restore.
        for raw in [10u64, 250, 1000, 5, 30, 800] {
            let (new_offset, reported) = monotonic_fixup(raw, baseline, offset);
            assert!(
                reported >= last,
                "monotonic violated: raw={raw} reported={reported} last={last}"
            );
            baseline = raw;
            offset = new_offset;
            last = reported;
        }
    }

    #[test]
    fn wall_time_uses_raw_not_the_monotonic_offset() {
        // After a cross-partition restore the monotonic path carries a
        // non-zero offset, but wall time must come from the RAW counter:
        // `boot_time_ns` is calibrated against raw, so folding the offset in
        // would shove wall time into the future. `wall_time_from` can't even
        // see the offset — this pins that.
        let boot = 1_000_000u64;
        let raw = 500u64;
        // A backward jump (restore into a lower-clock partition) inflates the
        // monotonic offset; the offset-adjusted reading would be 10_500.
        let (offset, monotonic) = monotonic_fixup(raw, 10_000, 0);
        assert_eq!((offset, monotonic), (10_000, 10_500));
        // Wall is computed from raw, so it ignores that offset…
        assert_eq!(wall_time_from(boot, raw), Some(1_000_500));
        // …and must not equal what the offset-adjusted reading would give.
        assert_ne!(
            wall_time_from(boot, raw),
            Some(boot.wrapping_add(monotonic))
        );
    }

    #[test]
    fn wall_time_is_none_until_boot_time_is_stamped() {
        // boot_time_ns == 0 => host hasn't calibrated yet => unavailable.
        assert_eq!(wall_time_from(0, 12_345), None);
        // Once stamped, it's just boot + raw.
        assert_eq!(wall_time_from(1, 0), Some(1));
        assert_eq!(wall_time_from(100, 25), Some(125));
    }
}
