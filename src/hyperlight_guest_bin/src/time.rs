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

//! Time types that mirror `std::time` for guest code.
//!
//! This module provides `SystemTime` and `Instant` types that have the same API
//! as `std::time::SystemTime` and `std::time::Instant`, using the paravirtualized
//! clock configured by the hypervisor.
//!
//! # Example
//!
//! ```ignore
//! use hyperlight_guest_bin::time::{SystemTime, Instant, UNIX_EPOCH};
//! use core::time::Duration;
//!
//! // Wall-clock time (like std::time::SystemTime)
//! let now = SystemTime::now();
//! let duration = now.duration_since(UNIX_EPOCH).unwrap();
//! let unix_timestamp = duration.as_secs();
//!
//! // Monotonic time for measuring elapsed time (like std::time::Instant)
//! let start = Instant::now();
//! // ... do work ...
//! let elapsed = start.elapsed();
//! ```

use core::time::Duration;

use hyperlight_guest::time as guest_time;

use crate::GUEST_HANDLE;

/// A measurement of the system clock, similar to `std::time::SystemTime`.
///
/// This represents wall-clock time (UTC) and can be compared to `UNIX_EPOCH`
/// to get a Unix timestamp.
///
/// Unlike monotonic time, this clock may jump forwards or backwards if the
/// host system's clock is adjusted.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SystemTime(u64);

/// An anchor in time representing the Unix epoch (1970-01-01 00:00:00 UTC).
pub const UNIX_EPOCH: SystemTime = SystemTime(0);

/// An error returned when the system time is before the Unix epoch.
#[derive(Clone, Debug)]
pub struct SystemTimeError(Duration);

impl SystemTimeError {
    /// Returns the positive duration representing how far the time is
    /// before the reference point.
    pub fn duration(&self) -> Duration {
        self.0
    }
}

impl SystemTime {
    /// Returns the current system time (UTC wall-clock time).
    ///
    /// Returns the Unix epoch if the clock is not available.
    pub fn now() -> Self {
        // SAFETY: GUEST_HANDLE is initialized during entrypoint, we are single-threaded
        #[allow(static_mut_refs)]
        let handle = unsafe { &GUEST_HANDLE };

        let ns = guest_time::wall_clock_time_ns(handle).unwrap_or(0);
        SystemTime(ns)
    }

    /// Returns the amount of time elapsed from an earlier point in time.
    ///
    /// # Errors
    ///
    /// Returns `SystemTimeError` if `earlier` is later than `self`.
    pub fn duration_since(&self, earlier: SystemTime) -> Result<Duration, SystemTimeError> {
        if self.0 >= earlier.0 {
            Ok(Duration::from_nanos(self.0 - earlier.0))
        } else {
            Err(SystemTimeError(Duration::from_nanos(earlier.0 - self.0)))
        }
    }

    /// Returns the amount of time elapsed since this system time was created.
    ///
    /// # Errors
    ///
    /// Returns `SystemTimeError` if the current time is before `self`.
    pub fn elapsed(&self) -> Result<Duration, SystemTimeError> {
        Self::now().duration_since(*self)
    }

    /// Returns `Some(t)` where `t` is the time `self + duration` if `t` can
    /// be represented, or `None` if the result would overflow.
    pub fn checked_add(&self, duration: Duration) -> Option<SystemTime> {
        self.0
            .checked_add(duration.as_nanos() as u64)
            .map(SystemTime)
    }

    /// Returns `Some(t)` where `t` is the time `self - duration` if `t` can
    /// be represented, or `None` if the result would underflow.
    pub fn checked_sub(&self, duration: Duration) -> Option<SystemTime> {
        self.0
            .checked_sub(duration.as_nanos() as u64)
            .map(SystemTime)
    }
}

impl core::ops::Add<Duration> for SystemTime {
    type Output = SystemTime;

    fn add(self, dur: Duration) -> SystemTime {
        self.checked_add(dur).unwrap_or(SystemTime(u64::MAX))
    }
}

impl core::ops::Sub<Duration> for SystemTime {
    type Output = SystemTime;

    fn sub(self, dur: Duration) -> SystemTime {
        self.checked_sub(dur).unwrap_or(SystemTime(0))
    }
}

/// A measurement of a monotonically increasing clock, similar to `std::time::Instant`.
///
/// This is suitable for measuring elapsed time. Unlike `SystemTime`, this clock
/// is guaranteed to never go backwards.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(u64);

impl Instant {
    /// Returns the current monotonic time.
    ///
    /// Returns a zero instant if the clock is not available.
    pub fn now() -> Self {
        // SAFETY: GUEST_HANDLE is initialized during entrypoint, we are single-threaded
        #[allow(static_mut_refs)]
        let handle = unsafe { &GUEST_HANDLE };

        let ns = guest_time::monotonic_time_ns(handle).unwrap_or(0);
        Instant(ns)
    }

    /// Returns the amount of time elapsed from another instant to this one.
    ///
    /// # Panics
    ///
    /// Panics if `earlier` is later than `self` (monotonic time should not go backwards).
    pub fn duration_since(&self, earlier: Instant) -> Duration {
        self.checked_duration_since(earlier)
            .expect("supplied instant is later than self")
    }

    /// Returns the amount of time elapsed from another instant to this one,
    /// or `None` if that instant is later than this one.
    pub fn checked_duration_since(&self, earlier: Instant) -> Option<Duration> {
        if self.0 >= earlier.0 {
            Some(Duration::from_nanos(self.0 - earlier.0))
        } else {
            None
        }
    }

    /// Returns the amount of time elapsed from another instant to this one,
    /// or zero if that instant is later than this one.
    pub fn saturating_duration_since(&self, earlier: Instant) -> Duration {
        self.checked_duration_since(earlier).unwrap_or_default()
    }

    /// Returns the amount of time elapsed since this instant was created.
    pub fn elapsed(&self) -> Duration {
        Self::now().duration_since(*self)
    }

    /// Returns `Some(t)` where `t` is the time `self + duration` if `t` can
    /// be represented, or `None` if the result would overflow.
    pub fn checked_add(&self, duration: Duration) -> Option<Instant> {
        self.0.checked_add(duration.as_nanos() as u64).map(Instant)
    }

    /// Returns `Some(t)` where `t` is the time `self - duration` if `t` can
    /// be represented, or `None` if the result would underflow.
    pub fn checked_sub(&self, duration: Duration) -> Option<Instant> {
        self.0.checked_sub(duration.as_nanos() as u64).map(Instant)
    }
}

impl core::ops::Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, dur: Duration) -> Instant {
        self.checked_add(dur).unwrap_or(Instant(u64::MAX))
    }
}

impl core::ops::Sub<Duration> for Instant {
    type Output = Instant;

    fn sub(self, dur: Duration) -> Instant {
        self.checked_sub(dur).unwrap_or(Instant(0))
    }
}

impl core::ops::Sub<Instant> for Instant {
    type Output = Duration;

    fn sub(self, other: Instant) -> Duration {
        self.duration_since(other)
    }
}

/// Get the UTC offset in seconds that was captured when the sandbox was created.
///
/// This represents the host's local timezone offset from UTC. Positive values
/// are east of UTC (e.g., +3600 for UTC+1), negative values are west (e.g.,
/// -18000 for UTC-5/EST).
///
/// Returns `None` if the clock is not available.
pub fn utc_offset_seconds() -> Option<i32> {
    // SAFETY: GUEST_HANDLE is initialized during entrypoint, we are single-threaded
    #[allow(static_mut_refs)]
    let handle = unsafe { &GUEST_HANDLE };

    guest_time::utc_offset_seconds(handle)
}

/// Get the current local time as nanoseconds since the Unix epoch.
///
/// This returns the wall-clock time adjusted for the host's timezone offset
/// that was captured at sandbox creation time.
///
/// Note: This uses a static timezone offset and does not account for DST
/// changes that might occur during the sandbox lifetime.
///
/// Returns `None` if the clock is not available.
pub fn local_time_ns() -> Option<u64> {
    // SAFETY: GUEST_HANDLE is initialized during entrypoint, we are single-threaded
    #[allow(static_mut_refs)]
    let handle = unsafe { &GUEST_HANDLE };

    guest_time::local_time_ns(handle)
}

/// Days of the week.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Weekday {
    /// Monday (0)
    Monday = 0,
    /// Tuesday (1)
    Tuesday = 1,
    /// Wednesday (2)
    Wednesday = 2,
    /// Thursday (3)
    Thursday = 3,
    /// Friday (4)
    Friday = 4,
    /// Saturday (5)
    Saturday = 5,
    /// Sunday (6)
    Sunday = 6,
}

impl Weekday {
    /// Returns the full name of the weekday (e.g., "Thursday").
    pub const fn name(self) -> &'static str {
        match self {
            Weekday::Monday => "Monday",
            Weekday::Tuesday => "Tuesday",
            Weekday::Wednesday => "Wednesday",
            Weekday::Thursday => "Thursday",
            Weekday::Friday => "Friday",
            Weekday::Saturday => "Saturday",
            Weekday::Sunday => "Sunday",
        }
    }

    /// Returns the short name of the weekday (e.g., "Thu").
    pub const fn short_name(self) -> &'static str {
        match self {
            Weekday::Monday => "Mon",
            Weekday::Tuesday => "Tue",
            Weekday::Wednesday => "Wed",
            Weekday::Thursday => "Thu",
            Weekday::Friday => "Fri",
            Weekday::Saturday => "Sat",
            Weekday::Sunday => "Sun",
        }
    }

    /// Returns the weekday from a number (0 = Monday, 6 = Sunday).
    pub const fn from_number(n: u8) -> Option<Self> {
        match n {
            0 => Some(Weekday::Monday),
            1 => Some(Weekday::Tuesday),
            2 => Some(Weekday::Wednesday),
            3 => Some(Weekday::Thursday),
            4 => Some(Weekday::Friday),
            5 => Some(Weekday::Saturday),
            6 => Some(Weekday::Sunday),
            _ => None,
        }
    }
}

/// Months of the year.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Month {
    /// January (1)
    January = 1,
    /// February (2)
    February = 2,
    /// March (3)
    March = 3,
    /// April (4)
    April = 4,
    /// May (5)
    May = 5,
    /// June (6)
    June = 6,
    /// July (7)
    July = 7,
    /// August (8)
    August = 8,
    /// September (9)
    September = 9,
    /// October (10)
    October = 10,
    /// November (11)
    November = 11,
    /// December (12)
    December = 12,
}

impl Month {
    /// Returns the full name of the month (e.g., "January").
    pub const fn name(self) -> &'static str {
        match self {
            Month::January => "January",
            Month::February => "February",
            Month::March => "March",
            Month::April => "April",
            Month::May => "May",
            Month::June => "June",
            Month::July => "July",
            Month::August => "August",
            Month::September => "September",
            Month::October => "October",
            Month::November => "November",
            Month::December => "December",
        }
    }

    /// Returns the short name of the month (e.g., "Jan").
    pub const fn short_name(self) -> &'static str {
        match self {
            Month::January => "Jan",
            Month::February => "Feb",
            Month::March => "Mar",
            Month::April => "Apr",
            Month::May => "May",
            Month::June => "Jun",
            Month::July => "Jul",
            Month::August => "Aug",
            Month::September => "Sep",
            Month::October => "Oct",
            Month::November => "Nov",
            Month::December => "Dec",
        }
    }

    /// Returns the month from a number (1 = January, 12 = December).
    pub const fn from_number(n: u8) -> Option<Self> {
        match n {
            1 => Some(Month::January),
            2 => Some(Month::February),
            3 => Some(Month::March),
            4 => Some(Month::April),
            5 => Some(Month::May),
            6 => Some(Month::June),
            7 => Some(Month::July),
            8 => Some(Month::August),
            9 => Some(Month::September),
            10 => Some(Month::October),
            11 => Some(Month::November),
            12 => Some(Month::December),
            _ => None,
        }
    }
}

/// A broken-down date and time.
///
/// This provides a human-readable representation of a point in time,
/// with year, month, day, hour, minute, second, and nanosecond components.
///
/// # Example
///
/// ```ignore
/// use hyperlight_guest_bin::time::DateTime;
///
/// let dt = DateTime::now();
/// // "Thursday 15th January 2026 15:34"
/// hl_print!("{} {} {} {} {:02}:{:02}",
///     dt.weekday().name(),
///     dt.day_ordinal(),
///     dt.month().name(),
///     dt.year(),
///     dt.hour(),
///     dt.minute());
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DateTime {
    year: i32,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    nanosecond: u32,
    weekday: u8,
}

impl DateTime {
    /// Creates a new DateTime from components.
    ///
    /// # Arguments
    /// * `year` - Year (can be negative for BCE)
    /// * `month` - Month (1-12)
    /// * `day` - Day of month (1-31)
    /// * `hour` - Hour (0-23)
    /// * `minute` - Minute (0-59)
    /// * `second` - Second (0-59)
    /// * `nanosecond` - Nanosecond (0-999_999_999)
    ///
    /// Returns `None` if any component is out of range.
    pub fn new(
        year: i32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        nanosecond: u32,
    ) -> Option<Self> {
        if !(1..=12).contains(&month)
            || !(1..=31).contains(&day)
            || hour > 23
            || minute > 59
            || second > 59
            || nanosecond > 999_999_999
        {
            return None;
        }

        // Validate day for the given month
        let max_day = days_in_month(year, month);
        if day > max_day {
            return None;
        }

        let weekday = day_of_week(year, month, day);

        Some(Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanosecond,
            weekday,
        })
    }

    /// Creates a DateTime from nanoseconds since Unix epoch (UTC).
    pub fn from_timestamp_nanos(nanos: u64) -> Self {
        let total_secs = (nanos / NANOS_PER_SEC) as i64;
        let ns = (nanos % NANOS_PER_SEC) as u32;

        let (year, month, day, hour, minute, second) = timestamp_to_datetime(total_secs);
        let weekday = day_of_week(year, month, day);

        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanosecond: ns,
            weekday,
        }
    }

    /// Creates a DateTime from a SystemTime.
    pub fn from_system_time(time: SystemTime) -> Self {
        Self::from_timestamp_nanos(time.0)
    }

    /// Returns the current UTC time as a DateTime.
    pub fn now() -> Self {
        Self::from_system_time(SystemTime::now())
    }

    /// Returns the current local time as a DateTime.
    ///
    /// This uses the timezone offset captured at sandbox creation.
    pub fn now_local() -> Self {
        match local_time_ns() {
            Some(ns) => Self::from_timestamp_nanos(ns),
            None => Self::now(), // Fall back to UTC
        }
    }

    /// Returns the year.
    pub const fn year(&self) -> i32 {
        self.year
    }

    /// Returns the month (1-12).
    pub const fn month_number(&self) -> u8 {
        self.month
    }

    /// Returns the month as a Month enum.
    pub fn month(&self) -> Month {
        Month::from_number(self.month).unwrap_or(Month::January)
    }

    /// Returns the day of month (1-31).
    pub const fn day(&self) -> u8 {
        self.day
    }

    /// Returns the hour (0-23).
    pub const fn hour(&self) -> u8 {
        self.hour
    }

    /// Returns the minute (0-59).
    pub const fn minute(&self) -> u8 {
        self.minute
    }

    /// Returns the second (0-59).
    pub const fn second(&self) -> u8 {
        self.second
    }

    /// Returns the nanosecond (0-999_999_999).
    pub const fn nanosecond(&self) -> u32 {
        self.nanosecond
    }

    /// Returns the weekday as a Weekday enum.
    pub fn weekday(&self) -> Weekday {
        Weekday::from_number(self.weekday).unwrap_or(Weekday::Monday)
    }

    /// Returns the day of year (1-366).
    pub fn day_of_year(&self) -> u16 {
        calc_day_of_year(self.year, self.month, self.day)
    }

    /// Returns the day with an ordinal suffix (e.g., "1st", "2nd", "15th").
    pub fn day_ordinal(&self) -> &'static str {
        ordinal_suffix(self.day)
    }

    /// Returns hours in 12-hour format (1-12).
    pub fn hour12(&self) -> u8 {
        match self.hour {
            0 => 12,
            1..=12 => self.hour,
            _ => self.hour - 12,
        }
    }

    /// Returns true if the time is PM (12:00-23:59).
    pub fn is_pm(&self) -> bool {
        self.hour >= 12
    }

    /// Returns "AM" or "PM".
    pub fn am_pm(&self) -> &'static str {
        if self.is_pm() { "PM" } else { "AM" }
    }

    /// Returns "am" or "pm" (lowercase).
    pub fn am_pm_lower(&self) -> &'static str {
        if self.is_pm() { "pm" } else { "am" }
    }

    /// Converts this DateTime to nanoseconds since Unix epoch.
    ///
    /// Returns `None` if the datetime is before the Unix epoch.
    pub fn to_timestamp_nanos(&self) -> Option<u64> {
        let secs = datetime_to_timestamp(
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
        )?;
        if secs < 0 {
            return None;
        }
        Some(secs as u64 * NANOS_PER_SEC + self.nanosecond as u64)
    }
}

// ============================================================================
// Date/time calculation helpers - use shared implementations from hyperlight_guest
// ============================================================================

// Re-export shared date/time utilities
use guest_time::{
    NANOS_PER_SEC, datetime_to_timestamp, day_of_year as calc_day_of_year, days_in_month,
    timestamp_to_datetime,
};

/// Returns the day of week (0 = Monday, 6 = Sunday) for a date.
#[inline]
fn day_of_week(year: i32, month: u8, day: u8) -> u8 {
    guest_time::day_of_week_monday(year, month, day)
}

/// Returns ordinal suffix for a day number (e.g., "1st", "2nd", "15th").
const fn ordinal_suffix(day: u8) -> &'static str {
    match day {
        1 => "1st",
        2 => "2nd",
        3 => "3rd",
        4 => "4th",
        5 => "5th",
        6 => "6th",
        7 => "7th",
        8 => "8th",
        9 => "9th",
        10 => "10th",
        11 => "11th",
        12 => "12th",
        13 => "13th",
        14 => "14th",
        15 => "15th",
        16 => "16th",
        17 => "17th",
        18 => "18th",
        19 => "19th",
        20 => "20th",
        21 => "21st",
        22 => "22nd",
        23 => "23rd",
        24 => "24th",
        25 => "25th",
        26 => "26th",
        27 => "27th",
        28 => "28th",
        29 => "29th",
        30 => "30th",
        31 => "31st",
        _ => "th",
    }
}
