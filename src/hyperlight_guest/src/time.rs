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

use core::sync::atomic::{Ordering, fence};

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

/// Monotonic time in nanoseconds.
///
/// The value is an absolute counter from the hypervisor's time base
/// (kvmclock on KVM, partition reference time on Hyper-V). It is
/// monotonically increasing and suitable for measuring elapsed time
/// between two reads, but its epoch is unspecified — do not assume
/// it starts at zero when the sandbox is created.
///
/// Returns `None` if the clock is not configured, or if the retry cap was
/// exhausted (the caller may retry).
pub fn monotonic_time_ns() -> Option<u64> {
    match read_clock_type() {
        ClockType::KvmPvclock => read_kvm_pvclock(),
        ClockType::HyperVReferenceTsc => read_hv_reference_tsc(),
        ClockType::None => None,
    }
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
/// guest simply adds its live monotonic reading to recover wall time.
///
/// This host-side computation is necessary because Hyper-V has no
/// guest-accessible wall-clock register (unlike KVM's
/// `MSR_KVM_WALL_CLOCK_NEW`). We use the same host-computed approach
/// on all backends for uniformity.
pub fn wall_clock_time_ns() -> Option<u64> {
    let monotonic = monotonic_time_ns()?;
    let boot_time = read_boot_time_ns();
    // boot_time_ns == 0 means the host hasn't stamped it yet
    // (scratch memory is zero-initialised). Return None rather
    // than returning a nonsense value.
    if boot_time == 0 {
        return None;
    }
    Some(boot_time.wrapping_add(monotonic))
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
