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

//! Paravirtualized clock structures shared between host and guest.
//!
//! Guests can read time without a VM exit by consulting a shared memory page
//! that the hypervisor updates. The page is placed in the sandbox's scratch
//! region (see [`crate::layout::SCRATCH_TOP_CLOCK_PAGE_OFFSET`]), so it is
//! not included in sandbox snapshots.
//!
//! # Layout
//!
//! The clock page (4 KiB) is 100% hypervisor-owned:
//!
//! ```text
//! clock page (offset -0x3000 from scratch top):
//!   0x0000 ..        : hypervisor calibration data
//!                       - KVM:     KvmPvclockVcpuTimeInfo (32 bytes)
//!                       - Hyper-V: HvReferenceTscPage     (4096 bytes)
//! ```
//!
//! Hyperlight's own metadata lives in the bookkeeping page at the top
//! of scratch (separate from the clock page), so a future TLFS
//! extension of the reserved region cannot clobber it:
//!
//! ```text
//! bookkeeping page (top of scratch, offset -0x08..-0x30):
//!   -0x28 : clock_type    (u64, ClockType discriminant)
//!   -0x30 : boot_time_ns  (u64, Unix-epoch origin of monotonic clock)
//! ```

/// KVM pvclock flag: TSC is stable and synchronized across vCPUs.
///
/// When this bit is set in [`KvmPvclockVcpuTimeInfo::flags`], the TSC is
/// guaranteed to be monotonic and synchronized across all vCPUs, even when
/// migrating between physical CPUs on the same host.
///
/// Reference: Linux kernel `arch/x86/include/asm/pvclock-abi.h`.
pub const PVCLOCK_TSC_STABLE_BIT: u8 = 1 << 0;

/// KVM pvclock structure (defined by KVM ABI).
///
/// The host writes to this structure, and the guest reads it to compute the
/// current time in nanoseconds.
///
/// Reference: Linux kernel `arch/x86/include/asm/pvclock.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmPvclockVcpuTimeInfo {
    /// Version counter — odd means update in progress. Guest must re-read
    /// if this changes during read.
    pub version: u32,
    pub pad0: u32,
    /// TSC value when `system_time` was captured.
    pub tsc_timestamp: u64,
    /// System time in nanoseconds at `tsc_timestamp`.
    pub system_time: u64,
    /// Multiplier for TSC → nanoseconds conversion.
    pub tsc_to_system_mul: u32,
    /// Shift for TSC → nanoseconds conversion (can be negative).
    pub tsc_shift: i8,
    /// Flags (e.g. [`PVCLOCK_TSC_STABLE_BIT`]).
    pub flags: u8,
    pub pad: [u8; 2],
}

/// Hyper-V Reference TSC page structure (defined by Hyper-V ABI).
///
/// Used by both MSHV (Linux) and WHP (Windows). Time is in 100-nanosecond
/// intervals.
///
/// Reference: Hyper-V TLFS §12.7.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HvReferenceTscPage {
    /// Sequence counter. A value of 0 means the host is directing the guest
    /// to fall back to an MSR read; the guest must also re-read if this
    /// changes during a read.
    pub tsc_sequence: u32,
    pub reserved1: u32,
    /// Scale factor for TSC → time conversion.
    /// Formula: `time = (tsc * tsc_scale) >> 64 + tsc_offset` (in 100 ns).
    pub tsc_scale: u64,
    /// Offset to add after scaling (in 100 ns units).
    pub tsc_offset: i64,
    /// Rest of the 4 KiB page is reserved by the TLFS.
    pub reserved2: [u64; 509],
}

/// Type of paravirtualized clock configured for the guest.
///
/// This is the value written by the host at
/// [`crate::layout::SCRATCH_TOP_CLOCK_TYPE_OFFSET`] in the scratch
/// bookkeeping page.
/// The guest treats any value other than the two supported variants as
/// [`ClockType::None`] — this means a misbehaving host that writes garbage
/// to the bookkeeping page simply ends up advertising "no clock", rather than
/// causing the guest to misinterpret the calibration header.
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockType {
    /// No clock configured — time functions return `None` / zero.
    None = 0,
    /// KVM pvclock (Linux KVM hypervisor).
    KvmPvclock = 1,
    /// Hyper-V Reference TSC (MSHV on Linux, WHP on Windows).
    HyperVReferenceTsc = 2,
}

impl From<u64> for ClockType {
    fn from(value: u64) -> Self {
        match value {
            1 => ClockType::KvmPvclock,
            2 => ClockType::HyperVReferenceTsc,
            _ => ClockType::None,
        }
    }
}

impl From<ClockType> for u64 {
    fn from(value: ClockType) -> Self {
        value as u64
    }
}

// Compile-time size invariants. These layouts are dictated by the hypervisor
// ABI (KVM pvclock, Hyper-V TLFS §12.7) — a size mismatch is a programming
// error that must surface at build time.
const _: () = {
    assert!(core::mem::size_of::<KvmPvclockVcpuTimeInfo>() == 32);
    assert!(core::mem::size_of::<HvReferenceTscPage>() == 4096);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_type_conversion_round_trips() {
        assert_eq!(ClockType::from(0u64), ClockType::None);
        assert_eq!(ClockType::from(1u64), ClockType::KvmPvclock);
        assert_eq!(ClockType::from(2u64), ClockType::HyperVReferenceTsc);
    }

    #[test]
    fn clock_type_conversion_unknown_is_none() {
        // A host that writes an unrecognised value must be treated as
        // "clock unavailable", not as an opportunity to misinterpret.
        assert_eq!(ClockType::from(3u64), ClockType::None);
        assert_eq!(ClockType::from(u64::MAX), ClockType::None);
    }
}
