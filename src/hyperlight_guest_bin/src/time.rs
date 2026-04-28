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

//! A `std::time`-compatible API built on the paravirtualized guest clock.
//!
//! This module provides [`Instant`] and [`SystemTime`] types that mirror the
//! shape of `std::time::Instant` and `std::time::SystemTime`, so guest code
//! that ordinarily uses the standard library's time APIs can be ported with
//! minimal changes.
//!
//! # Clock source
//!
//! Both types read from the shared paravirtualized clock page armed by the
//! host. See [`hyperlight_guest::time`] for the low-level details.
//!
//! # Availability
//!
//! If the host was built without the `enable_guest_clock` feature, every
//! constructor in this module returns [`TimeError::Unavailable`]. A guest
//! that wants to gracefully degrade should probe [`is_available`] once at
//! start-up rather than relying on `Instant::now()` to fail later.
//!
//! # Example
//!
//! ```no_run
//! use hyperlight_guest_bin::time::{Instant, SystemTime, UNIX_EPOCH};
//!
//! if let Ok(start) = Instant::now() {
//!     do_some_work();
//!     if let Ok(elapsed) = start.elapsed() {
//!         log::info!("work took {} us", elapsed.as_micros());
//!     }
//! }
//!
//! if let Ok(now) = SystemTime::now()
//!     && let Ok(since_epoch) = now.duration_since(UNIX_EPOCH)
//! {
//!     log::info!("wall-clock seconds since epoch: {}", since_epoch.as_secs());
//! }
//! # fn do_some_work() {}
//! ```

use core::time::Duration;

use hyperlight_guest::time;

/// Errors returned by the time API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeError {
    /// The host did not arm a paravirtualized clock for this sandbox (the
    /// host was built without the `enable_guest_clock` feature, or clock
    /// setup failed).
    Unavailable,
    /// The seqlock retry cap was exhausted. The caller may simply retry.
    Retry,
    /// `SystemTime::duration_since` was called with an argument that lies
    /// in the future relative to `self`.
    NegativeDuration(Duration),
}

impl core::fmt::Display for TimeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unavailable => f.write_str("guest clock is not available"),
            Self::Retry => f.write_str("guest clock read retry cap exhausted"),
            Self::NegativeDuration(_) => f.write_str("second time is later than self"),
        }
    }
}

/// Returns `true` if the host has armed a paravirtualized clock.
#[inline]
pub fn is_available() -> bool {
    time::is_available()
}

/// Read raw monotonic nanoseconds, or convert a [`time`] read failure into a
/// [`TimeError`]. Factored out so `Instant::now` and `SystemTime::now` share
/// the same failure classification.
#[inline]
fn read_monotonic_ns() -> Result<u64, TimeError> {
    if !time::is_available() {
        return Err(TimeError::Unavailable);
    }
    time::monotonic_time_ns().ok_or(TimeError::Retry)
}

/// A measurement of a monotonically non-decreasing clock, analogous to
/// [`std::time::Instant`].
///
/// Unlike `std::time::Instant`, construction is fallible: it returns
/// `TimeError::Unavailable` when the host has no guest-clock feature
/// enabled, and `TimeError::Retry` on a (vanishingly rare) seqlock retry
/// storm.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant {
    /// Nanoseconds since sandbox creation, as reported by the paravirt
    /// clock.
    ns: u64,
}

impl Instant {
    /// Returns an instant corresponding to "now".
    pub fn now() -> Result<Self, TimeError> {
        Ok(Self {
            ns: read_monotonic_ns()?,
        })
    }

    /// Returns the amount of time elapsed from another instant to this one,
    /// or `None` if that instant is later than this one.
    pub fn checked_duration_since(&self, earlier: Instant) -> Option<Duration> {
        self.ns.checked_sub(earlier.ns).map(Duration::from_nanos)
    }

    /// Returns the amount of time elapsed from another instant to this one,
    /// saturating at zero when the other instant is later.
    pub fn saturating_duration_since(&self, earlier: Instant) -> Duration {
        self.checked_duration_since(earlier)
            .unwrap_or(Duration::ZERO)
    }

    /// Returns the amount of time elapsed since this instant.
    pub fn elapsed(&self) -> Result<Duration, TimeError> {
        let now = Self::now()?;
        Ok(now.saturating_duration_since(*self))
    }
}

impl core::ops::Sub<Instant> for Instant {
    type Output = Duration;

    /// Panics if `rhs` is later than `self`. Mirrors the behaviour of
    /// `std::time::Instant::sub`.
    fn sub(self, rhs: Instant) -> Duration {
        self.checked_duration_since(rhs)
            .expect("supplied instant is later than self")
    }
}

/// A measurement of the system clock, analogous to
/// [`std::time::SystemTime`].
///
/// Represents wall-clock time, using the host's boot-time stamp combined
/// with the paravirtualized monotonic clock. Snapshot-restore preserves
/// the freshly re-stamped boot time, so `SystemTime::now()` will jump
/// forward by real elapsed wall-clock time across a restore — exactly the
/// behaviour a guest using `std::time::SystemTime` would expect.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SystemTime {
    /// Nanoseconds since the Unix epoch.
    ns: u64,
}

/// An anchor point corresponding to 1970-01-01 00:00:00 UTC. Subtract from
/// a `SystemTime` to get the wall-clock duration since the epoch.
pub const UNIX_EPOCH: SystemTime = SystemTime { ns: 0 };

impl SystemTime {
    /// Returns the current wall-clock time.
    pub fn now() -> Result<Self, TimeError> {
        if !time::is_available() {
            return Err(TimeError::Unavailable);
        }
        let ns = time::wall_clock_time_ns().ok_or(TimeError::Retry)?;
        Ok(Self { ns })
    }

    /// Returns the duration from `earlier` to `self`, or
    /// `TimeError::NegativeDuration(d)` — where `d` is the magnitude of the
    /// difference — if `earlier` is later than `self`. Mirrors
    /// `std::time::SystemTime::duration_since`.
    pub fn duration_since(&self, earlier: SystemTime) -> Result<Duration, TimeError> {
        if self.ns >= earlier.ns {
            Ok(Duration::from_nanos(self.ns - earlier.ns))
        } else {
            Err(TimeError::NegativeDuration(Duration::from_nanos(
                earlier.ns - self.ns,
            )))
        }
    }

    /// Returns the amount of time elapsed since `self`.
    pub fn elapsed(&self) -> Result<Duration, TimeError> {
        let now = Self::now()?;
        now.duration_since(*self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The error type is both `Debug` and `Display` so it plays nicely with
    // `?` in guest code and with `log::error!("{err}")` style logging.
    #[test]
    fn time_error_display() {
        extern crate std;
        use std::format;
        assert_eq!(
            format!("{}", TimeError::Unavailable),
            "guest clock is not available"
        );
        assert_eq!(
            format!("{}", TimeError::NegativeDuration(Duration::from_secs(1))),
            "second time is later than self"
        );
    }
}
