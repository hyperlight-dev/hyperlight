// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use log::Level;
use serde::{Deserialize, Serialize};
#[cfg(feature = "tracing")]
use tracing::{Span, instrument};

/// Variant order is the wire tag.
#[repr(u8)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum LogLevel {
    Trace = 0,
    Debug = 1,
    Information = 2,
    Warning = 3,
    Error = 4,
    Critical = 5,
    None = 6,
}

impl From<u8> for LogLevel {
    #[cfg_attr(feature = "tracing", instrument(skip_all, parent = Span::current(), level= "Trace"))]
    fn from(val: u8) -> LogLevel {
        match val {
            0 => LogLevel::Trace,
            1 => LogLevel::Debug,
            2 => LogLevel::Information,
            3 => LogLevel::Warning,
            4 => LogLevel::Error,
            5 => LogLevel::Critical,
            _ => LogLevel::None,
        }
    }
}

impl From<&LogLevel> for Level {
    // There is a test (sandbox::outb::tests::test_log_emit_guest_log) which emits trace record as logs
    // which causes a panic when this function is instrumented as the logger is contained in refcell and
    // instrumentation ends up causing a double mutborrow. So this is not instrumented.
    //TODO: instrument this once we fix the test
    fn from(val: &LogLevel) -> Level {
        match val {
            LogLevel::Trace => Level::Trace,
            LogLevel::Debug => Level::Debug,
            LogLevel::Information => Level::Info,
            LogLevel::Warning => Level::Warn,
            LogLevel::Error => Level::Error,
            LogLevel::Critical => Level::Error,
            // If the log level is None then we will log as trace
            LogLevel::None => Level::Trace,
        }
    }
}

impl From<Level> for LogLevel {
    fn from(val: Level) -> LogLevel {
        match val {
            Level::Trace => LogLevel::Trace,
            Level::Debug => LogLevel::Debug,
            Level::Info => LogLevel::Information,
            Level::Warn => LogLevel::Warning,
            Level::Error => LogLevel::Error,
        }
    }
}
