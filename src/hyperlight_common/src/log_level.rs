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

/// This type is a unified definition of log level filters between the guest and host.
///
/// This is needed because currently the guest uses both the `log` and `tracing` crates,
/// and needs each type of `LevelFilter` from both crates.
///
/// To avoid as much as possible the amount of conversions between the two types, we define a
/// single type that can be converted to both `log::LevelFilter` and `tracing_core::LevelFilter`.
/// NOTE: This also takes care of the fact that the `tracing` and `log` enum types for the log
/// levels are not guaranteed to have the same discriminants, so we can't just cast between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestLogFilter {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<GuestLogFilter> for tracing_core::LevelFilter {
    fn from(filter: GuestLogFilter) -> Self {
        match filter {
            GuestLogFilter::Off => tracing_core::LevelFilter::OFF,
            GuestLogFilter::Error => tracing_core::LevelFilter::ERROR,
            GuestLogFilter::Warn => tracing_core::LevelFilter::WARN,
            GuestLogFilter::Info => tracing_core::LevelFilter::INFO,
            GuestLogFilter::Debug => tracing_core::LevelFilter::DEBUG,
            GuestLogFilter::Trace => tracing_core::LevelFilter::TRACE,
        }
    }
}

impl From<GuestLogFilter> for log::LevelFilter {
    fn from(filter: GuestLogFilter) -> Self {
        match filter {
            GuestLogFilter::Off => log::LevelFilter::Off,
            GuestLogFilter::Error => log::LevelFilter::Error,
            GuestLogFilter::Warn => log::LevelFilter::Warn,
            GuestLogFilter::Info => log::LevelFilter::Info,
            GuestLogFilter::Debug => log::LevelFilter::Debug,
            GuestLogFilter::Trace => log::LevelFilter::Trace,
        }
    }
}

/// Used by the host to convert a [`tracing_core::LevelFilter`] to the intermediary [`GuestLogFilter`]
/// filter that is later converted to `u64` and passed to the guest via the C API.
impl From<tracing_core::LevelFilter> for GuestLogFilter {
    fn from(value: tracing_core::LevelFilter) -> Self {
        match value {
            tracing_core::LevelFilter::OFF => Self::Off,
            tracing_core::LevelFilter::ERROR => Self::Error,
            tracing_core::LevelFilter::WARN => Self::Warn,
            tracing_core::LevelFilter::INFO => Self::Info,
            tracing_core::LevelFilter::DEBUG => Self::Debug,
            tracing_core::LevelFilter::TRACE => Self::Trace,
        }
    }
}

/// Used by the guest to convert a `u64` value passed from the host via the C API to the
/// intermediary [`GuestLogFilter`] filter that is later converted to both
/// `tracing_core::LevelFilter` and `log::LevelFilter`.
impl TryFrom<u64> for GuestLogFilter {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, <GuestLogFilter as TryFrom<u64>>::Error> {
        match value {
            0 => Ok(Self::Off),
            1 => Ok(Self::Error),
            2 => Ok(Self::Warn),
            3 => Ok(Self::Info),
            4 => Ok(Self::Debug),
            5 => Ok(Self::Trace),
            _ => Err(()),
        }
    }
}

/// Used by the host to convert the [`GuestLogFilter`] to a `u64` that is passed to the guest via
/// the C API.
impl From<GuestLogFilter> for u64 {
    fn from(value: GuestLogFilter) -> Self {
        match value {
            GuestLogFilter::Off => 0,
            GuestLogFilter::Error => 1,
            GuestLogFilter::Warn => 2,
            GuestLogFilter::Info => 3,
            GuestLogFilter::Debug => 4,
            GuestLogFilter::Trace => 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::GuestLogFilter;

    #[test]
    fn guest_log_filter_u64_roundtrip() {
        let variants = [
            GuestLogFilter::Off,
            GuestLogFilter::Error,
            GuestLogFilter::Warn,
            GuestLogFilter::Info,
            GuestLogFilter::Debug,
            GuestLogFilter::Trace,
        ];

        for variant in variants {
            let as_u64: u64 = variant.into();
            let back =
                GuestLogFilter::try_from(as_u64).expect("conversion from u64 should succeed");
            assert_eq!(variant, back);
        }
    }

    #[test]
    fn guest_log_filter_tracing_roundtrip() {
        let variants = [
            GuestLogFilter::Off,
            GuestLogFilter::Error,
            GuestLogFilter::Warn,
            GuestLogFilter::Info,
            GuestLogFilter::Debug,
            GuestLogFilter::Trace,
        ];

        for variant in variants {
            let tracing_filter: tracing_core::LevelFilter = variant.into();
            let back: GuestLogFilter = tracing_filter.into();
            assert_eq!(variant, back);
        }
    }

    #[test]
    fn guest_log_filter_log_conversion() {
        let variants = [
            GuestLogFilter::Off,
            GuestLogFilter::Error,
            GuestLogFilter::Warn,
            GuestLogFilter::Info,
            GuestLogFilter::Debug,
            GuestLogFilter::Trace,
        ];

        let log_variants = [
            log::LevelFilter::Off,
            log::LevelFilter::Error,
            log::LevelFilter::Warn,
            log::LevelFilter::Info,
            log::LevelFilter::Debug,
            log::LevelFilter::Trace,
        ];

        for (variant, log_variant) in variants.into_iter().zip(log_variants) {
            let log_filter = log::LevelFilter::from(variant);
            assert_eq!(log_filter, log_variant);
        }
    }

    #[test]
    fn guest_log_filter_try_from_u64_rejects_invalid() {
        // Any value outside the defined range [0, 5] should be rejected.
        assert!(GuestLogFilter::try_from(u64::MAX).is_err());
        assert!(GuestLogFilter::try_from(6).is_err());
    }
}
