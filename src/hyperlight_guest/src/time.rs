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

//! Low-level guest time functions using paravirtualized clock.
//!
//! This module provides low-level functions to read time without VM exits by using
//! the shared clock page configured by the hypervisor. These functions require an
//! explicit `GuestHandle` reference.
//!
//! # For most users
//!
//! Use [`hyperlight_guest_bin::time`] instead, which provides a `std::time`-compatible
//! API with `SystemTime` and `Instant` types that don't require passing a handle.
//!
//! # Supported Clock Types
//!
//! - **KVM pvclock**: Used when running under KVM hypervisor
//! - **Hyper-V Reference TSC**: Used when running under MSHV or WHP
//!
//! # Usage
//!
//! ```ignore
//! use hyperlight_guest::time::{monotonic_time_ns, wall_clock_time_ns};
//!
//! // Get time since sandbox creation (monotonic)
//! if let Some(ns) = monotonic_time_ns(guest_handle) {
//!     // ns is nanoseconds since sandbox started
//! }
//!
//! // Get wall-clock time (UTC)
//! if let Some(ns) = wall_clock_time_ns(guest_handle) {
//!     // ns is nanoseconds since Unix epoch (1970-01-01 00:00:00 UTC)
//! }
//! ```

use core::sync::atomic::{Ordering, compiler_fence};

use hyperlight_common::mem::HyperlightPEB;
use hyperlight_common::time::{
    ClockType, GuestClockRegion, HvReferenceTscPage, KvmPvclockVcpuTimeInfo,
};

use crate::guest_handle::handle::GuestHandle;

/// Read the CPU's Time Stamp Counter (TSC).
///
/// This is a monotonically increasing counter that increments at the CPU's
/// base frequency.
#[inline]
fn rdtsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let lo: u32;
        let hi: u32;
        // SAFETY: RDTSC is always available on x86_64
        unsafe {
            core::arch::asm!(
                "rdtsc",
                out("eax") lo,
                out("edx") hi,
                options(nostack, nomem, preserves_flags)
            );
        }
        ((hi as u64) << 32) | (lo as u64)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0 // TSC not available on non-x86_64 architectures
    }
}

/// Read time from KVM pvclock structure.
///
/// Returns nanoseconds since the clock was initialized, or None if
/// the clock data is invalid or being updated.
fn read_kvm_pvclock(clock_page_ptr: u64) -> Option<u64> {
    // SAFETY: clock_page_ptr was set by the host and points to valid memory
    let pvclock = unsafe { &*(clock_page_ptr as *const KvmPvclockVcpuTimeInfo) };

    // Read version - odd means update in progress
    let version1 = unsafe { core::ptr::read_volatile(&pvclock.version) };
    if version1 & 1 != 0 {
        return None; // Update in progress, retry later
    }

    compiler_fence(Ordering::Acquire);

    // Read clock data
    let tsc_timestamp = pvclock.tsc_timestamp;
    let system_time = pvclock.system_time;
    let tsc_to_system_mul = pvclock.tsc_to_system_mul;
    let tsc_shift = pvclock.tsc_shift;

    compiler_fence(Ordering::Acquire);

    // Check version again - must match
    let version2 = unsafe { core::ptr::read_volatile(&pvclock.version) };
    if version1 != version2 {
        return None; // Data changed during read, retry later
    }

    // Get current TSC
    let tsc_now = rdtsc();

    // Calculate elapsed TSC ticks
    let tsc_delta = tsc_now.wrapping_sub(tsc_timestamp);

    // Convert TSC delta to nanoseconds
    // Formula: ns = (tsc_delta * tsc_to_system_mul) >> (32 - tsc_shift)
    // But tsc_shift can be negative, so we need to handle both cases
    let ns_delta = if tsc_shift >= 0 {
        ((tsc_delta as u128 * tsc_to_system_mul as u128) >> (32 - tsc_shift as u32)) as u64
    } else {
        ((tsc_delta as u128 * tsc_to_system_mul as u128) >> (32 + (-tsc_shift) as u32)) as u64
    };

    Some(system_time.wrapping_add(ns_delta))
}

/// Read time from Hyper-V Reference TSC page.
///
/// Returns nanoseconds since the clock was initialized, or None if
/// the clock data is invalid.
fn read_hv_reference_tsc(clock_page_ptr: u64) -> Option<u64> {
    // SAFETY: clock_page_ptr was set by the host and points to valid memory
    let tsc_page = unsafe { &*(clock_page_ptr as *const HvReferenceTscPage) };

    // Read sequence - 0 means fallback to MSR (not supported in guest)
    let seq1 = unsafe { core::ptr::read_volatile(&tsc_page.tsc_sequence) };
    if seq1 == 0 {
        return None; // Must use MSR fallback, not available in guest
    }

    compiler_fence(Ordering::Acquire);

    // Read clock data
    let tsc_scale = tsc_page.tsc_scale;
    let tsc_offset = tsc_page.tsc_offset;

    compiler_fence(Ordering::Acquire);

    // Check sequence again
    let seq2 = unsafe { core::ptr::read_volatile(&tsc_page.tsc_sequence) };
    if seq1 != seq2 {
        return None; // Data changed during read, retry later
    }

    // Get current TSC
    let tsc_now = rdtsc();

    // Calculate time in 100ns units
    // Formula: time_100ns = ((tsc * scale) >> 64) + offset
    let scaled = ((tsc_now as u128 * tsc_scale as u128) >> 64) as i64;
    let time_100ns = scaled.wrapping_add(tsc_offset);

    if time_100ns < 0 {
        return None; // Invalid time
    }

    // Convert 100ns units to nanoseconds
    Some((time_100ns as u64) * 100)
}

/// Get the guest clock region from the PEB.
fn get_clock_region(peb: *mut HyperlightPEB) -> Option<&'static GuestClockRegion> {
    if peb.is_null() {
        return None;
    }
    // SAFETY: PEB pointer is valid if not null, set during guest init
    let peb_ref = unsafe { &*peb };
    Some(&peb_ref.guest_clock)
}

/// Get monotonic time in nanoseconds since the sandbox was created.
///
/// This time is monotonically increasing and suitable for measuring
/// elapsed time. It does not represent wall-clock time.
///
/// # Arguments
/// * `handle` - The guest handle containing the PEB pointer
///
/// # Returns
/// * `Some(ns)` - Nanoseconds since sandbox creation
/// * `None` - Clock not configured or read failed (caller should retry)
///
/// # Example
/// ```ignore
/// let start = monotonic_time_ns(handle).unwrap_or(0);
/// // ... do work ...
/// let end = monotonic_time_ns(handle).unwrap_or(0);
/// let elapsed_ns = end - start;
/// ```
pub fn monotonic_time_ns(handle: &GuestHandle) -> Option<u64> {
    let peb = handle.peb()?;
    let clock_region = get_clock_region(peb)?;

    if !clock_region.is_available() {
        return None;
    }

    match clock_region.get_clock_type() {
        ClockType::KvmPvclock => read_kvm_pvclock(clock_region.clock_page_ptr),
        ClockType::HyperVReferenceTsc => read_hv_reference_tsc(clock_region.clock_page_ptr),
        ClockType::None => None,
    }
}

/// Get wall-clock time in nanoseconds since the Unix epoch.
///
/// Returns the current UTC time as nanoseconds since 1970-01-01 00:00:00 UTC.
/// This is computed by adding the boot time (when sandbox was created) to
/// the monotonic time.
///
/// # Arguments
/// * `handle` - The guest handle containing the PEB pointer
///
/// # Returns
/// * `Some(ns)` - Nanoseconds since Unix epoch (UTC)
/// * `None` - Clock not configured or read failed (caller should retry)
///
/// # Example
/// ```ignore
/// if let Some(ns) = wall_clock_time_ns(handle) {
///     let secs = ns / 1_000_000_000;
///     let nsecs = ns % 1_000_000_000;
///     // secs is Unix timestamp, nsecs is sub-second nanoseconds
/// }
/// ```
pub fn wall_clock_time_ns(handle: &GuestHandle) -> Option<u64> {
    let peb = handle.peb()?;
    let clock_region = get_clock_region(peb)?;

    if !clock_region.is_available() {
        return None;
    }

    let monotonic = monotonic_time_ns(handle)?;
    Some(clock_region.boot_time_ns.wrapping_add(monotonic))
}

/// Get monotonic time in microseconds since the sandbox was created.
///
/// Convenience function that returns time in microseconds instead of nanoseconds.
///
/// # Arguments
/// * `handle` - The guest handle containing the PEB pointer
///
/// # Returns
/// * `Some(us)` - Microseconds since sandbox creation
/// * `None` - Clock not configured or read failed
pub fn monotonic_time_us(handle: &GuestHandle) -> Option<u64> {
    monotonic_time_ns(handle).map(|ns| ns / 1_000)
}

/// Get wall-clock time as seconds and nanoseconds since Unix epoch.
///
/// Returns a tuple of (seconds, nanoseconds) suitable for use with
/// `timespec` structures or similar APIs.
///
/// # Arguments
/// * `handle` - The guest handle containing the PEB pointer
///
/// # Returns
/// * `Some((secs, nsecs))` - Seconds and sub-second nanoseconds since Unix epoch
/// * `None` - Clock not configured or read failed
pub fn wall_clock_time(handle: &GuestHandle) -> Option<(u64, u32)> {
    let ns = wall_clock_time_ns(handle)?;
    let secs = ns / 1_000_000_000;
    let nsecs = (ns % 1_000_000_000) as u32;
    Some((secs, nsecs))
}

/// Check if the paravirtualized clock is available.
///
/// # Arguments
/// * `handle` - The guest handle containing the PEB pointer
///
/// # Returns
/// * `true` - Clock is configured and available
/// * `false` - Clock is not configured
pub fn is_clock_available(handle: &GuestHandle) -> bool {
    handle
        .peb()
        .and_then(get_clock_region)
        .is_some_and(|r| r.is_available())
}

/// Get the UTC offset in seconds at sandbox creation time.
///
/// Returns the timezone offset that was captured when the sandbox was created.
/// This represents the host's local timezone offset from UTC at that moment.
///
/// Positive values are east of UTC (e.g., +3600 for UTC+1), negative values
/// are west (e.g., -18000 for UTC-5/EST).
///
/// # Arguments
/// * `handle` - The guest handle containing the PEB pointer
///
/// # Returns
/// * `Some(offset)` - Seconds offset from UTC
/// * `None` - Clock not configured
///
/// # Example
/// ```ignore
/// if let Some(offset) = utc_offset_seconds(handle) {
///     // Get local time from wall clock time
///     let wall_ns = wall_clock_time_ns(handle).unwrap_or(0);
///     let local_ns = wall_ns.wrapping_add((offset as i64 * 1_000_000_000) as u64);
/// }
/// ```
pub fn utc_offset_seconds(handle: &GuestHandle) -> Option<i32> {
    let peb = handle.peb()?;
    let clock_region = get_clock_region(peb)?;

    if !clock_region.is_available() {
        return None;
    }

    Some(clock_region.utc_offset_seconds)
}

/// Get local time in nanoseconds since the Unix epoch.
///
/// Returns the current local time as nanoseconds since 1970-01-01 00:00:00 UTC,
/// adjusted for the host's timezone offset at sandbox creation time.
///
/// Note: This uses a static timezone offset captured at sandbox creation.
/// It does not account for DST changes that might occur during the sandbox
/// lifetime.
///
/// # Arguments
/// * `handle` - The guest handle containing the PEB pointer
///
/// # Returns
/// * `Some(ns)` - Nanoseconds since Unix epoch in local time
/// * `None` - Clock not configured or read failed
pub fn local_time_ns(handle: &GuestHandle) -> Option<u64> {
    let wall_ns = wall_clock_time_ns(handle)?;
    let offset = utc_offset_seconds(handle)?;
    // Add offset (can be negative, so we use wrapping_add with cast)
    Some(wall_ns.wrapping_add((offset as i64 * 1_000_000_000) as u64))
}

// ============================================================================
// Date/time calculation utilities - shared between guest crates
//
// These functions provide pure date/time calculations that don't depend on
// any clock source. They are shared between hyperlight_guest_bin (Rust API)
// and hyperlight_guest_capi (C API).
// ============================================================================

// Time constants
/// Seconds per day (86400).
pub(crate) const SECS_PER_DAY: i64 = 86400;
/// Seconds per hour (3600).
pub(crate) const SECS_PER_HOUR: i64 = 3600;
/// Seconds per minute (60).
pub(crate) const SECS_PER_MINUTE: i64 = 60;
/// Nanoseconds per second (1,000,000,000).
pub const NANOS_PER_SEC: u64 = 1_000_000_000;

// Calendar constants for date calculations
const DAYS_FROM_YEAR_0_TO_1970: i32 = 719528;
const DAYS_PER_400_YEAR_CYCLE: i32 = 146097;
const DAYS_PER_100_YEAR_CYCLE: i32 = 36524;
const DAYS_PER_4_YEAR_CYCLE: i32 = 1461;
const DAYS_PER_YEAR: i32 = 365;
const DAYS_PER_LEAP_YEAR: i32 = 366;

/// Returns true if the given year is a leap year.
#[inline]
#[must_use]
pub(crate) const fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Returns the number of days in a month (1-12).
///
/// Returns 0 for invalid month values (outside 1-12).
#[inline]
#[must_use]
pub const fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        1 => 31,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        3 => 31,
        4 => 30,
        5 => 31,
        6 => 30,
        7 => 31,
        8 => 31,
        9 => 30,
        10 => 31,
        11 => 30,
        12 => 31,
        _ => 0,
    }
}

/// Returns the day of week for a date.
///
/// # Arguments
/// * `year` - The year
/// * `month` - Month (1-12)
/// * `day` - Day of month (1-31)
///
/// # Returns
/// Day of week where Monday = 0, Sunday = 6
#[inline]
#[must_use]
pub fn day_of_week_monday(year: i32, month: u8, day: u8) -> u8 {
    let h = zeller_congruence(year, month, day);
    // Convert Zeller's result (0=Sat, 1=Sun, ..., 6=Fri) to Monday=0
    match h {
        0 => 5, // Sat
        1 => 6, // Sun
        2 => 0, // Mon
        3 => 1, // Tue
        4 => 2, // Wed
        5 => 3, // Thu
        6 => 4, // Fri
        _ => 0,
    }
}

/// Returns the day of week for a date (POSIX style).
///
/// # Arguments
/// * `year` - The year
/// * `month` - Month (1-12)
/// * `day` - Day of month (1-31)
///
/// # Returns
/// Day of week where Sunday = 0, Saturday = 6 (POSIX tm_wday convention)
#[inline]
#[must_use]
pub fn day_of_week_sunday(year: i32, month: u8, day: u8) -> u8 {
    let h = zeller_congruence(year, month, day);
    // Convert Zeller's result (0=Sat, 1=Sun, ..., 6=Fri) to Sunday=0
    match h {
        0 => 6, // Sat
        1 => 0, // Sun
        2 => 1, // Mon
        3 => 2, // Tue
        4 => 3, // Wed
        5 => 4, // Thu
        6 => 5, // Fri
        _ => 0,
    }
}

/// Zeller's congruence algorithm for calculating day of week.
///
/// Returns a value 0-6 where:
/// - 0 = Saturday
/// - 1 = Sunday
/// - 2 = Monday
/// - 3 = Tuesday
/// - 4 = Wednesday
/// - 5 = Thursday
/// - 6 = Friday
#[inline]
fn zeller_congruence(year: i32, month: u8, day: u8) -> u8 {
    // Adjust for Zeller's: treat Jan/Feb as months 13/14 of previous year
    let (y, m) = if month < 3 {
        (year - 1, month as i32 + 12)
    } else {
        (year, month as i32)
    };

    let q = day as i32;
    let k = y % 100;
    let j = y / 100;

    // Zeller's formula
    let h = (q + (13 * (m + 1)) / 5 + k + k / 4 + j / 4 - 2 * j) % 7;
    ((h + 7) % 7) as u8 // Ensure positive
}

/// Returns the day of year (1-366) for a date.
///
/// # Arguments
/// * `year` - The year (for leap year calculation)
/// * `month` - Month (1-12)
/// * `day` - Day of month (1-31)
#[inline]
#[must_use]
pub fn day_of_year(year: i32, month: u8, day: u8) -> u16 {
    let mut doy = day as u16;
    for m in 1..month {
        doy += days_in_month(year, m) as u16;
    }
    doy
}

/// Converts Unix timestamp (seconds since epoch) to date/time components.
///
/// # Arguments
/// * `secs` - Seconds since Unix epoch (1970-01-01 00:00:00 UTC)
///
/// # Returns
/// Tuple of (year, month, day, hour, minute, second)
/// - year: Full year (e.g., 2026)
/// - month: 1-12
/// - day: 1-31
/// - hour: 0-23
/// - minute: 0-59
/// - second: 0-59
#[must_use]
pub fn timestamp_to_datetime(secs: i64) -> (i32, u8, u8, u8, u8, u8) {
    // Handle time of day
    let time_of_day = secs.rem_euclid(SECS_PER_DAY) as u32;
    let hour = (time_of_day / SECS_PER_HOUR as u32) as u8;
    let minute = ((time_of_day % SECS_PER_HOUR as u32) / SECS_PER_MINUTE as u32) as u8;
    let second = (time_of_day % SECS_PER_MINUTE as u32) as u8;

    // Calculate days since epoch (can be negative)
    let mut days = secs.div_euclid(SECS_PER_DAY) as i32;

    // Add days from 1970 to year 0 for easier calculation
    days += DAYS_FROM_YEAR_0_TO_1970;

    // Calculate year using the 400-year cycle
    let cycles_400 = days.div_euclid(DAYS_PER_400_YEAR_CYCLE);
    days = days.rem_euclid(DAYS_PER_400_YEAR_CYCLE);

    let mut year = cycles_400 * 400;

    // 100-year cycles within 400-year cycle
    let cycles_100 = (days / DAYS_PER_100_YEAR_CYCLE).min(3);
    days -= cycles_100 * DAYS_PER_100_YEAR_CYCLE;
    year += cycles_100 * 100;

    // 4-year cycles
    let cycles_4 = days / DAYS_PER_4_YEAR_CYCLE;
    days -= cycles_4 * DAYS_PER_4_YEAR_CYCLE;
    year += cycles_4 * 4;

    // Remaining years within the 4-year cycle
    // The first year of the 4-year cycle is a leap year (366 days),
    // remaining years have 365 days each
    if days >= DAYS_PER_LEAP_YEAR {
        // Past the leap year
        days -= DAYS_PER_LEAP_YEAR;
        year += 1;
        let years_remaining = (days / DAYS_PER_YEAR).min(2);
        days -= years_remaining * DAYS_PER_YEAR;
        year += years_remaining;
    }

    // days is now day of year (0-indexed)
    let doy = days as u16;

    // Find month and day using days_in_month
    let mut month = 1u8;
    let mut remaining = doy as i32;

    while remaining >= days_in_month(year, month) as i32 {
        remaining -= days_in_month(year, month) as i32;
        month += 1;
    }

    let day = (remaining + 1) as u8;

    (year, month, day, hour, minute, second)
}

/// Converts date/time components to Unix timestamp (seconds since epoch).
///
/// # Arguments
/// * `year` - Full year (e.g., 2026)
/// * `month` - Month (1-12)
/// * `day` - Day of month (1-31)
/// * `hour` - Hour (0-23)
/// * `minute` - Minute (0-59)
/// * `second` - Second (0-59)
///
/// # Returns
/// Seconds since Unix epoch (1970-01-01 00:00:00 UTC), or `None` if any
/// input is invalid (month outside 1-12, day outside 1-31, etc.)
#[must_use]
pub fn datetime_to_timestamp(
    year: i32,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
) -> Option<i64> {
    // Validate inputs
    if month == 0 || month > 12 {
        return None;
    }
    if day == 0 || day > 31 {
        return None;
    }
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    // Validate day for the specific month
    if day > days_in_month(year, month) {
        return None;
    }

    // Days from year 0 to the given year
    let y = year - 1;
    let mut days = y * 365 + y / 4 - y / 100 + y / 400;

    // Add days for completed months
    for m in 1..month {
        days += days_in_month(year, m) as i32;
    }

    // Add days in current month
    days += (day - 1) as i32;

    // Subtract days from year 0 to 1970
    days -= DAYS_FROM_YEAR_0_TO_1970;

    // Convert to seconds
    let secs = days as i64 * SECS_PER_DAY
        + hour as i64 * SECS_PER_HOUR
        + minute as i64 * SECS_PER_MINUTE
        + second as i64;
    Some(secs)
}
