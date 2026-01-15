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
//! These structures enable guests to read time without VM exits by using
//! shared memory pages that the hypervisor updates.

/// KVM pvclock structure (defined by KVM ABI).
///
/// The host writes to this structure, and the guest reads it to compute
/// the current time in nanoseconds.
///
/// Reference: Linux kernel `arch/x86/include/asm/pvclock.h`
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmPvclockVcpuTimeInfo {
    /// Version counter - odd means update in progress.
    /// Guest must re-read if this changes during read.
    pub version: u32,
    pub pad0: u32,
    /// TSC value when `system_time` was captured.
    pub tsc_timestamp: u64,
    /// System time in nanoseconds at `tsc_timestamp`.
    pub system_time: u64,
    /// Multiplier for TSC -> nanoseconds conversion.
    pub tsc_to_system_mul: u32,
    /// Shift for TSC -> nanoseconds conversion (can be negative).
    pub tsc_shift: i8,
    /// Flags (e.g., TSC stable bit).
    pub flags: u8,
    pub pad: [u8; 2],
}

/// Hyper-V Reference TSC page structure (defined by Hyper-V ABI).
///
/// Used by both MSHV (Linux) and WHP (Windows).
/// Time is in 100-nanosecond intervals.
///
/// Reference: Hyper-V TLFS (Top Level Functional Specification)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HvReferenceTscPage {
    /// Sequence counter. If 0, guest must fall back to MSR read.
    /// Guest must re-read if this changes during read.
    pub tsc_sequence: u32,
    pub reserved1: u32,
    /// Scale factor for TSC -> time conversion.
    /// Formula: time = (tsc * tsc_scale) >> 64
    pub tsc_scale: u64,
    /// Offset to add after scaling (in 100ns units).
    pub tsc_offset: i64,
    /// Rest of the 4KB page is reserved.
    pub reserved2: [u64; 509],
}

/// Type of paravirtualized clock configured for the guest.
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockType {
    /// No clock configured - time functions will return None.
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

/// Clock region in the PEB (Process Environment Block).
///
/// Contains a pointer to the clock page and metadata needed to
/// compute wall-clock time.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GuestClockRegion {
    /// Guest virtual address of the clock page.
    /// 0 if clock is not configured.
    pub clock_page_ptr: u64,
    /// Type of clock (see [`ClockType`]).
    pub clock_type: u64,
    /// UTC time in nanoseconds since Unix epoch (1970-01-01 00:00:00 UTC)
    /// at the moment the sandbox was created.
    ///
    /// Wall-clock time = boot_time_ns + monotonic_time_ns
    pub boot_time_ns: u64,
    /// UTC offset in seconds at the time the sandbox was created.
    ///
    /// This captures the host's timezone offset from UTC. Positive values are
    /// east of UTC (e.g., +3600 for UTC+1), negative values are west (e.g.,
    /// -18000 for UTC-5/EST).
    ///
    /// Local time = wall_clock_time + utc_offset_seconds * 1_000_000_000
    pub utc_offset_seconds: i32,
    /// Padding to maintain 8-byte alignment.
    _padding: u32,
}

impl Default for GuestClockRegion {
    fn default() -> Self {
        Self {
            clock_page_ptr: 0,
            clock_type: ClockType::None as u64,
            boot_time_ns: 0,
            utc_offset_seconds: 0,
            _padding: 0,
        }
    }
}

impl GuestClockRegion {
    /// Creates a new `GuestClockRegion` with the specified parameters.
    pub fn new(
        clock_page_ptr: u64,
        clock_type: ClockType,
        boot_time_ns: u64,
        utc_offset_seconds: i32,
    ) -> Self {
        Self {
            clock_page_ptr,
            clock_type: clock_type as u64,
            boot_time_ns,
            utc_offset_seconds,
            _padding: 0,
        }
    }

    /// Returns true if a clock is configured.
    pub fn is_available(&self) -> bool {
        self.clock_page_ptr != 0 && self.clock_type != ClockType::None as u64
    }

    /// Returns the clock type.
    pub fn get_clock_type(&self) -> ClockType {
        ClockType::from(self.clock_type)
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::*;

    #[test]
    fn test_kvm_pvclock_size() {
        // KVM pvclock struct must be exactly 32 bytes
        assert_eq!(size_of::<KvmPvclockVcpuTimeInfo>(), 32);
    }

    #[test]
    fn test_hv_reference_tsc_size() {
        // Hyper-V reference TSC page must be exactly 4KB
        assert_eq!(size_of::<HvReferenceTscPage>(), 4096);
    }

    #[test]
    fn test_guest_clock_region_size() {
        // GuestClockRegion should be 32 bytes (4 x u64 equivalent: 3 x u64 + i32 + u32)
        assert_eq!(size_of::<GuestClockRegion>(), 32);
    }

    #[test]
    fn test_clock_type_conversion() {
        assert_eq!(ClockType::from(0u64), ClockType::None);
        assert_eq!(ClockType::from(1u64), ClockType::KvmPvclock);
        assert_eq!(ClockType::from(2u64), ClockType::HyperVReferenceTsc);
        assert_eq!(ClockType::from(99u64), ClockType::None);
    }

    #[test]
    fn test_guest_clock_region_default() {
        let region = GuestClockRegion::default();
        assert!(!region.is_available());
        assert_eq!(region.get_clock_type(), ClockType::None);
    }
}
