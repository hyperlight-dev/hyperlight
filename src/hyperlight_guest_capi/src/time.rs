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

//! C API for time functions.
//!
//! Provides POSIX-compatible `gettimeofday` and `clock_gettime` functions
//! using the paravirtualized clock.

use core::ffi::c_int;

use hyperlight_guest::time::{monotonic_time_ns, utc_offset_seconds, wall_clock_time_ns};
use hyperlight_guest_bin::GUEST_HANDLE;

/// POSIX timeval structure.
#[repr(C)]
pub struct timeval {
    /// Seconds since Unix epoch.
    pub tv_sec: i64,
    /// Microseconds (0-999999).
    pub tv_usec: i64,
}

/// POSIX timespec structure.
#[repr(C)]
pub struct timespec {
    /// Seconds since Unix epoch (for wall clock) or since boot (for monotonic).
    pub tv_sec: i64,
    /// Nanoseconds (0-999999999).
    pub tv_nsec: i64,
}

/// POSIX timezone structure (deprecated, included for compatibility).
///
/// The `tz_minuteswest` and `tz_dsttime` fields can be populated using the
/// `utc_offset_seconds` value from the clock region, which captures the host's
/// timezone offset at sandbox creation time.
#[repr(C)]
pub struct timezone {
    /// Minutes west of Greenwich.
    pub tz_minuteswest: c_int,
    /// Type of DST correction.
    pub tz_dsttime: c_int,
}

// Clock IDs for clock_gettime
/// System-wide real-time clock (wall clock).
pub const CLOCK_REALTIME: c_int = 0;
/// Monotonic clock that cannot be set.
pub const CLOCK_MONOTONIC: c_int = 1;
/// High-resolution per-process timer from the CPU (not supported).
pub const CLOCK_PROCESS_CPUTIME_ID: c_int = 2;
/// Thread-specific CPU-time clock (not supported).
pub const CLOCK_THREAD_CPUTIME_ID: c_int = 3;
/// Like CLOCK_MONOTONIC but includes time spent in suspend.
pub const CLOCK_BOOTTIME: c_int = 7;
/// Faster but less precise version of CLOCK_REALTIME.
pub const CLOCK_REALTIME_COARSE: c_int = 5;
/// Faster but less precise version of CLOCK_MONOTONIC.
pub const CLOCK_MONOTONIC_COARSE: c_int = 6;

/// Get the current wall-clock time (UTC).
///
/// This is a POSIX-compatible implementation of `gettimeofday(2)`.
/// Returns UTC time as seconds since 1970-01-01 00:00:00.
///
/// # Arguments
/// * `tv` - Pointer to a `timeval` struct to fill with the current time.
/// * `tz` - Optional pointer to a `timezone` struct. If provided, will be
///   populated with the timezone offset that was captured at sandbox creation.
///   Note: The `tz_dsttime` field is always set to 0 (DST info not available).
///
/// # Returns
/// * `0` on success
/// * `-1` on error (clock not available or null pointer)
///
/// # Safety
/// The `tv` and `tz` pointers must be valid and properly aligned if not null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gettimeofday(tv: *mut timeval, tz: *mut timezone) -> c_int {
    if tv.is_null() {
        return -1;
    }

    // SAFETY: GUEST_HANDLE is initialized during entrypoint, we are single-threaded
    #[allow(static_mut_refs)]
    let handle = unsafe { &GUEST_HANDLE };

    match wall_clock_time_ns(handle) {
        Some(ns) => {
            let secs = (ns / 1_000_000_000) as i64;
            let usecs = ((ns % 1_000_000_000) / 1_000) as i64;

            // SAFETY: Caller guarantees tv is valid
            unsafe {
                (*tv).tv_sec = secs;
                (*tv).tv_usec = usecs;
            }

            // Populate timezone if requested
            if !tz.is_null() {
                let offset_secs = utc_offset_seconds(handle).unwrap_or(0);
                // Convert seconds east of UTC to minutes west of UTC
                let minutes_west = -(offset_secs / 60) as c_int;
                // SAFETY: Caller guarantees tz is valid if not null
                unsafe {
                    (*tz).tz_minuteswest = minutes_west;
                    (*tz).tz_dsttime = 0; // DST info not available
                }
            }

            0
        }
        None => -1,
    }
}

/// Get the time of a specified clock.
///
/// This is a POSIX-compatible implementation of `clock_gettime(2)`.
///
/// # Supported Clocks
/// * `CLOCK_REALTIME` / `CLOCK_REALTIME_COARSE` - Wall-clock time (UTC, seconds since 1970-01-01 00:00:00)
/// * `CLOCK_MONOTONIC` / `CLOCK_MONOTONIC_COARSE` / `CLOCK_BOOTTIME` - Time since sandbox creation
///
/// # Unsupported Clocks (return -1)
/// * `CLOCK_PROCESS_CPUTIME_ID` - Process CPU time not available
/// * `CLOCK_THREAD_CPUTIME_ID` - Thread CPU time not available
///
/// # Arguments
/// * `clk_id` - The clock to query.
/// * `tp` - Pointer to a `timespec` struct to fill with the current time.
///
/// # Returns
/// * `0` on success
/// * `-1` on error (invalid clock ID, clock not available, or null pointer)
///
/// # Safety
/// The `tp` pointer must be valid and properly aligned if not null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clock_gettime(clk_id: c_int, tp: *mut timespec) -> c_int {
    if tp.is_null() {
        return -1;
    }

    // SAFETY: GUEST_HANDLE is initialized during entrypoint, we are single-threaded
    #[allow(static_mut_refs)]
    let handle = unsafe { &GUEST_HANDLE };

    let ns_result = match clk_id {
        CLOCK_REALTIME | CLOCK_REALTIME_COARSE => wall_clock_time_ns(handle),
        CLOCK_MONOTONIC | CLOCK_MONOTONIC_COARSE | CLOCK_BOOTTIME => monotonic_time_ns(handle),
        // CPU time clocks are not supported in the guest
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => return -1,
        _ => return -1, // Invalid clock ID
    };

    match ns_result {
        Some(ns) => {
            let secs = (ns / 1_000_000_000) as i64;
            let nsecs = (ns % 1_000_000_000) as i64;

            // SAFETY: Caller guarantees tp is valid
            unsafe {
                (*tp).tv_sec = secs;
                (*tp).tv_nsec = nsecs;
            }
            0
        }
        None => -1,
    }
}

/// Get the resolution (precision) of a specified clock.
///
/// This is a POSIX-compatible implementation of `clock_getres(2)`.
///
/// # Arguments
/// * `clk_id` - The clock to query.
/// * `res` - Pointer to a `timespec` struct to fill with the resolution.
///
/// # Returns
/// * `0` on success
/// * `-1` on error (invalid clock ID or null pointer)
///
/// # Safety
/// The `res` pointer must be valid and properly aligned if not null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clock_getres(clk_id: c_int, res: *mut timespec) -> c_int {
    // Validate clock ID - only supported clocks
    match clk_id {
        CLOCK_REALTIME
        | CLOCK_REALTIME_COARSE
        | CLOCK_MONOTONIC
        | CLOCK_MONOTONIC_COARSE
        | CLOCK_BOOTTIME => {}
        // CPU time clocks are not supported
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => return -1,
        _ => return -1,
    }

    if res.is_null() {
        // POSIX allows res to be NULL, just validate clock ID
        return 0;
    }

    // Return fixed 1ns resolution
    // SAFETY: Caller guarantees res is valid
    unsafe {
        (*res).tv_sec = 0;
        (*res).tv_nsec = 1;
    }
    0
}

/// Get the current time in seconds since Unix epoch.
///
/// This is a simplified time function compatible with C's `time()`.
///
/// # Arguments
/// * `tloc` - Optional pointer to store the time. Can be NULL.
///
/// # Returns
/// * Seconds since Unix epoch on success
/// * `-1` on error (clock not available)
///
/// # Safety
/// If `tloc` is not null, it must be valid and properly aligned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn time(tloc: *mut i64) -> i64 {
    // SAFETY: GUEST_HANDLE is initialized during entrypoint, we are single-threaded
    #[allow(static_mut_refs)]
    let handle = unsafe { &GUEST_HANDLE };

    match wall_clock_time_ns(handle) {
        Some(ns) => {
            let secs = (ns / 1_000_000_000) as i64;
            if !tloc.is_null() {
                // SAFETY: Caller guarantees tloc is valid if not null
                unsafe {
                    *tloc = secs;
                }
            }
            secs
        }
        None => -1,
    }
}

/// Get the UTC offset in seconds that was captured at sandbox creation.
///
/// This returns the host's local timezone offset from UTC. Positive values
/// are east of UTC (e.g., +3600 for UTC+1), negative values are west (e.g.,
/// -18000 for UTC-5/EST).
///
/// # Arguments
/// * `offset` - Pointer to store the UTC offset in seconds.
///
/// # Returns
/// * `0` on success
/// * `-1` on error (clock not available or null pointer)
///
/// # Safety
/// The `offset` pointer must be valid and properly aligned if not null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hl_get_utc_offset(offset: *mut c_int) -> c_int {
    if offset.is_null() {
        return -1;
    }

    // SAFETY: GUEST_HANDLE is initialized during entrypoint, we are single-threaded
    #[allow(static_mut_refs)]
    let handle = unsafe { &GUEST_HANDLE };

    match utc_offset_seconds(handle) {
        Some(secs) => {
            // SAFETY: Caller guarantees offset is valid
            unsafe {
                *offset = secs;
            }
            0
        }
        None => -1,
    }
}

// ============================================================================
// Broken-down time (struct tm) and related functions
// ============================================================================

/// POSIX tm structure for broken-down time.
///
/// This structure is compatible with the standard C `struct tm`.
#[repr(C)]
pub struct tm {
    /// Seconds after the minute (0-60, 60 for leap second)
    pub tm_sec: c_int,
    /// Minutes after the hour (0-59)
    pub tm_min: c_int,
    /// Hours since midnight (0-23)
    pub tm_hour: c_int,
    /// Day of the month (1-31)
    pub tm_mday: c_int,
    /// Months since January (0-11)
    pub tm_mon: c_int,
    /// Years since 1900
    pub tm_year: c_int,
    /// Days since Sunday (0-6, Sunday = 0)
    pub tm_wday: c_int,
    /// Days since January 1 (0-365)
    pub tm_yday: c_int,
    /// Daylight Saving Time flag (positive if DST, 0 if not, negative if unknown)
    pub tm_isdst: c_int,
}

/// Convert a timestamp to broken-down UTC time.
///
/// This is a POSIX-compatible implementation of `gmtime_r(3)`.
///
/// # Arguments
/// * `timep` - Pointer to a time_t (seconds since Unix epoch).
/// * `result` - Pointer to a `tm` struct to fill with the broken-down time.
///
/// # Returns
/// * Pointer to `result` on success
/// * NULL on error (null pointer)
///
/// # Safety
/// Both pointers must be valid and properly aligned if not null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmtime_r(timep: *const i64, result: *mut tm) -> *mut tm {
    if timep.is_null() || result.is_null() {
        return core::ptr::null_mut();
    }

    let secs = unsafe { *timep };
    let (year, month, day, hour, minute, second) = timestamp_to_datetime(secs);

    unsafe {
        (*result).tm_sec = second as c_int;
        (*result).tm_min = minute as c_int;
        (*result).tm_hour = hour as c_int;
        (*result).tm_mday = day as c_int;
        (*result).tm_mon = (month - 1) as c_int; // 0-11
        (*result).tm_year = (year - 1900) as c_int;
        (*result).tm_wday = day_of_week_sunday(year, month, day) as c_int;
        (*result).tm_yday = (day_of_year(year, month, day) - 1) as c_int; // 0-365
        (*result).tm_isdst = 0; // UTC has no DST
    }

    result
}

/// Convert a timestamp to broken-down local time.
///
/// This is a POSIX-compatible implementation of `localtime_r(3)`.
/// Uses the timezone offset captured at sandbox creation.
///
/// # Arguments
/// * `timep` - Pointer to a time_t (seconds since Unix epoch in UTC).
/// * `result` - Pointer to a `tm` struct to fill with the broken-down time.
///
/// # Returns
/// * Pointer to `result` on success
/// * NULL on error (null pointer or clock not available)
///
/// # Safety
/// Both pointers must be valid and properly aligned if not null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn localtime_r(timep: *const i64, result: *mut tm) -> *mut tm {
    if timep.is_null() || result.is_null() {
        return core::ptr::null_mut();
    }

    // SAFETY: GUEST_HANDLE is initialized during entrypoint, we are single-threaded
    #[allow(static_mut_refs)]
    let handle = unsafe { &GUEST_HANDLE };

    let offset = utc_offset_seconds(handle).unwrap_or(0) as i64;
    let local_secs = unsafe { *timep } + offset;

    let (year, month, day, hour, minute, second) = timestamp_to_datetime(local_secs);

    unsafe {
        (*result).tm_sec = second as c_int;
        (*result).tm_min = minute as c_int;
        (*result).tm_hour = hour as c_int;
        (*result).tm_mday = day as c_int;
        (*result).tm_mon = (month - 1) as c_int; // 0-11
        (*result).tm_year = (year - 1900) as c_int;
        (*result).tm_wday = day_of_week_sunday(year, month, day) as c_int;
        (*result).tm_yday = (day_of_year(year, month, day) - 1) as c_int; // 0-365
        (*result).tm_isdst = -1; // DST unknown
    }

    result
}

/// Convert broken-down time to timestamp.
///
/// This is a POSIX-compatible implementation of `mktime(3)`.
/// Interprets the tm struct as local time.
///
/// # Arguments
/// * `timeptr` - Pointer to a `tm` struct with the broken-down time.
///
/// # Returns
/// * Seconds since Unix epoch on success
/// * `-1` on error (null pointer or invalid date)
///
/// # Safety
/// The pointer must be valid and properly aligned if not null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mktime(timeptr: *mut tm) -> i64 {
    if timeptr.is_null() {
        return -1;
    }

    let t = unsafe { &mut *timeptr };

    let year = t.tm_year + 1900;
    let month = (t.tm_mon + 1) as u8;
    let day = t.tm_mday as u8;
    let hour = t.tm_hour as u8;
    let minute = t.tm_min as u8;
    let second = t.tm_sec as u8;

    // Calculate timestamp (as local time)
    let local_secs = match datetime_to_timestamp(year, month, day, hour, minute, second) {
        Some(s) => s,
        None => return -1,
    };

    // Adjust for timezone to get UTC
    // SAFETY: GUEST_HANDLE is initialized during entrypoint, we are single-threaded
    #[allow(static_mut_refs)]
    let handle = unsafe { &GUEST_HANDLE };

    let offset = utc_offset_seconds(handle).unwrap_or(0) as i64;
    let utc_secs = local_secs - offset;

    // Update the tm struct with normalized values
    let (year, month, day, hour, minute, second) = timestamp_to_datetime(local_secs);
    t.tm_sec = second as c_int;
    t.tm_min = minute as c_int;
    t.tm_hour = hour as c_int;
    t.tm_mday = day as c_int;
    t.tm_mon = (month - 1) as c_int;
    t.tm_year = (year - 1900) as c_int;
    t.tm_wday = day_of_week_sunday(year, month, day) as c_int;
    t.tm_yday = (day_of_year(year, month, day) - 1) as c_int;

    utc_secs
}

/// Convert broken-down UTC time to timestamp.
///
/// This is a POSIX-compatible implementation of `timegm(3)`.
/// Interprets the tm struct as UTC time.
///
/// # Arguments
/// * `timeptr` - Pointer to a `tm` struct with the broken-down time.
///
/// # Returns
/// * Seconds since Unix epoch on success
/// * `-1` on error (null pointer or invalid date)
///
/// # Safety
/// The pointer must be valid and properly aligned if not null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn timegm(timeptr: *mut tm) -> i64 {
    if timeptr.is_null() {
        return -1;
    }

    let t = unsafe { &mut *timeptr };

    let year = t.tm_year + 1900;
    let month = (t.tm_mon + 1) as u8;
    let day = t.tm_mday as u8;
    let hour = t.tm_hour as u8;
    let minute = t.tm_min as u8;
    let second = t.tm_sec as u8;

    match datetime_to_timestamp(year, month, day, hour, minute, second) {
        Some(secs) => {
            // Update the tm struct with normalized values and weekday/yearday
            t.tm_wday = day_of_week_sunday(year, month, day) as c_int;
            t.tm_yday = (day_of_year(year, month, day) - 1) as c_int;
            secs
        }
        None => -1,
    }
}

/// Format time according to a format string.
///
/// This is a POSIX-compatible implementation of `strftime(3)`.
///
/// # Supported Format Specifiers
/// * `%a` - Abbreviated weekday name (Sun-Sat)
/// * `%A` - Full weekday name (Sunday-Saturday)
/// * `%b` - Abbreviated month name (Jan-Dec)
/// * `%B` - Full month name (January-December)
/// * `%d` - Day of month (01-31)
/// * `%e` - Day of month, space-padded ( 1-31)
/// * `%H` - Hour in 24h format (00-23)
/// * `%I` - Hour in 12h format (01-12)
/// * `%j` - Day of year (001-366)
/// * `%m` - Month as decimal (01-12)
/// * `%M` - Minute (00-59)
/// * `%p` - AM or PM
/// * `%P` - am or pm
/// * `%S` - Second (00-59)
/// * `%u` - Day of week (1-7, Monday = 1)
/// * `%w` - Day of week (0-6, Sunday = 0)
/// * `%y` - Year without century (00-99)
/// * `%Y` - Year with century
/// * `%z` - Timezone offset (+0000)
/// * `%Z` - Timezone name (always "UTC" or "LOCAL")
/// * `%%` - Literal %
/// * `%n` - Newline
/// * `%t` - Tab
///
/// # Arguments
/// * `s` - Output buffer.
/// * `maxsize` - Maximum bytes to write (including null terminator).
/// * `format` - Format string.
/// * `timeptr` - Pointer to a `tm` struct.
///
/// # Returns
/// * Number of bytes written (excluding null terminator) on success
/// * `0` if the buffer is too small or on error
///
/// # Safety
/// All pointers must be valid. `s` must have at least `maxsize` bytes available.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strftime(
    s: *mut u8,
    maxsize: usize,
    format: *const u8,
    timeptr: *const tm,
) -> usize {
    if s.is_null() || format.is_null() || timeptr.is_null() || maxsize == 0 {
        return 0;
    }

    let t = unsafe { &*timeptr };
    let mut writer = StrftimeWriter::new(s, maxsize);

    // Get format string length
    let mut fmt_len = 0;
    while unsafe { *format.add(fmt_len) } != 0 {
        fmt_len += 1;
    }

    let mut fmt_pos = 0;
    while fmt_pos < fmt_len {
        let c = unsafe { *format.add(fmt_pos) };
        fmt_pos += 1;

        if c != b'%' {
            if !writer.write_byte(c) {
                return 0;
            }
            continue;
        }

        // Handle format specifier
        if fmt_pos >= fmt_len {
            break;
        }

        let spec = unsafe { *format.add(fmt_pos) };
        fmt_pos += 1;

        let success = match spec {
            b'%' => writer.write_byte(b'%'),
            b'n' => writer.write_byte(b'\n'),
            b't' => writer.write_byte(b'\t'),
            b'a' => writer.write_bytes(short_weekday_name(t.tm_wday)),
            b'A' => writer.write_bytes(full_weekday_name(t.tm_wday)),
            b'b' | b'h' => writer.write_bytes(short_month_name(t.tm_mon)),
            b'B' => writer.write_bytes(full_month_name(t.tm_mon)),
            b'd' => writer.write_num_padded(t.tm_mday, 2, b'0'),
            b'e' => writer.write_num_padded(t.tm_mday, 2, b' '),
            b'H' => writer.write_num_padded(t.tm_hour, 2, b'0'),
            b'I' => {
                let h = match t.tm_hour {
                    0 => 12,
                    1..=12 => t.tm_hour,
                    _ => t.tm_hour - 12,
                };
                writer.write_num_padded(h, 2, b'0')
            }
            b'j' => writer.write_num_padded(t.tm_yday + 1, 3, b'0'),
            b'm' => writer.write_num_padded(t.tm_mon + 1, 2, b'0'),
            b'M' => writer.write_num_padded(t.tm_min, 2, b'0'),
            b'p' => writer.write_bytes(if t.tm_hour >= 12 { b"PM" } else { b"AM" }),
            b'P' => writer.write_bytes(if t.tm_hour >= 12 { b"pm" } else { b"am" }),
            b'S' => writer.write_num_padded(t.tm_sec, 2, b'0'),
            b'u' => {
                // Monday = 1, Sunday = 7
                let day = if t.tm_wday == 0 { 7 } else { t.tm_wday };
                writer.write_num_padded(day, 1, b'0')
            }
            b'w' => writer.write_num_padded(t.tm_wday, 1, b'0'),
            b'y' => writer.write_num_padded((t.tm_year + 1900) % 100, 2, b'0'),
            b'Y' => writer.write_num_padded(t.tm_year + 1900, 4, b'0'),
            b'z' => {
                // Timezone offset
                // SAFETY: GUEST_HANDLE is initialized during entrypoint
                #[allow(static_mut_refs)]
                let handle = unsafe { &GUEST_HANDLE };
                let offset = utc_offset_seconds(handle).unwrap_or(0);
                let (sign, abs_offset) = if offset >= 0 {
                    (b'+', offset as u32)
                } else {
                    (b'-', (-offset) as u32)
                };
                let hours = (abs_offset / 3600) as i32;
                let mins = ((abs_offset % 3600) / 60) as i32;
                writer.write_byte(sign)
                    && writer.write_num_padded(hours, 2, b'0')
                    && writer.write_num_padded(mins, 2, b'0')
            }
            b'Z' => {
                // Timezone name (simplified)
                if t.tm_isdst == 0 {
                    writer.write_bytes(b"UTC")
                } else {
                    writer.write_bytes(b"LOCAL")
                }
            }
            _ => writer.write_byte(b'%') && writer.write_byte(spec), // Unknown specifier, output as-is
        };

        if !success {
            return 0;
        }
    }

    // Null terminate
    writer.null_terminate();
    writer.len()
}

/// Helper struct for strftime output.
struct StrftimeWriter {
    buf: *mut u8,
    maxsize: usize,
    pos: usize,
}

impl StrftimeWriter {
    fn new(buf: *mut u8, maxsize: usize) -> Self {
        Self {
            buf,
            maxsize,
            pos: 0,
        }
    }

    fn len(&self) -> usize {
        self.pos
    }

    fn write_byte(&mut self, b: u8) -> bool {
        if self.pos + 1 >= self.maxsize {
            return false;
        }
        unsafe { *self.buf.add(self.pos) = b };
        self.pos += 1;
        true
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> bool {
        if self.pos + bytes.len() >= self.maxsize {
            return false;
        }
        for &b in bytes {
            unsafe { *self.buf.add(self.pos) = b };
            self.pos += 1;
        }
        true
    }

    fn write_num_padded(&mut self, n: c_int, width: usize, pad: u8) -> bool {
        let mut buf = [0u8; 16];
        let mut num = n.unsigned_abs();
        let mut pos = buf.len();

        loop {
            pos -= 1;
            buf[pos] = b'0' + (num % 10) as u8;
            num /= 10;
            if num == 0 {
                break;
            }
        }

        let digits = buf.len() - pos;
        let padding = if width > digits { width - digits } else { 0 };

        // Handle negative numbers
        if n < 0 && !self.write_byte(b'-') {
            return false;
        }

        // Add padding
        for _ in 0..padding {
            if !self.write_byte(pad) {
                return false;
            }
        }

        self.write_bytes(&buf[pos..])
    }

    fn null_terminate(&mut self) {
        if self.pos < self.maxsize {
            unsafe { *self.buf.add(self.pos) = 0 };
        }
    }
}

// ============================================================================
// Date/time calculation helpers - use shared implementations from hyperlight_guest
// ============================================================================

// Re-export shared date/time utilities
use hyperlight_guest::time::{
    datetime_to_timestamp, day_of_week_sunday, day_of_year, timestamp_to_datetime,
};

/// Short weekday name from tm_wday (0=Sunday).
const fn short_weekday_name(wday: c_int) -> &'static [u8] {
    match wday {
        0 => b"Sun",
        1 => b"Mon",
        2 => b"Tue",
        3 => b"Wed",
        4 => b"Thu",
        5 => b"Fri",
        6 => b"Sat",
        _ => b"???",
    }
}

/// Full weekday name from tm_wday (0=Sunday).
const fn full_weekday_name(wday: c_int) -> &'static [u8] {
    match wday {
        0 => b"Sunday",
        1 => b"Monday",
        2 => b"Tuesday",
        3 => b"Wednesday",
        4 => b"Thursday",
        5 => b"Friday",
        6 => b"Saturday",
        _ => b"???",
    }
}

/// Short month name from tm_mon (0=January).
const fn short_month_name(mon: c_int) -> &'static [u8] {
    match mon {
        0 => b"Jan",
        1 => b"Feb",
        2 => b"Mar",
        3 => b"Apr",
        4 => b"May",
        5 => b"Jun",
        6 => b"Jul",
        7 => b"Aug",
        8 => b"Sep",
        9 => b"Oct",
        10 => b"Nov",
        11 => b"Dec",
        _ => b"???",
    }
}

/// Full month name from tm_mon (0=January).
const fn full_month_name(mon: c_int) -> &'static [u8] {
    match mon {
        0 => b"January",
        1 => b"February",
        2 => b"March",
        3 => b"April",
        4 => b"May",
        5 => b"June",
        6 => b"July",
        7 => b"August",
        8 => b"September",
        9 => b"October",
        10 => b"November",
        11 => b"December",
        _ => b"???",
    }
}
