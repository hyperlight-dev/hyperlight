/*
Copyright 2024 The Hyperlight Authors.

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

use anyhow::{bail, Error, Result};
use log::Level;
use strum::EnumIter;
#[cfg(feature = "tracing")]
use tracing::{instrument, Span};

use crate::flatbuffers::hyperlight::generated::LogLevel as FbLogLevel;

#[repr(u8)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, EnumIter)]
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

impl TryFrom<&FbLogLevel> for LogLevel {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(val: &FbLogLevel) -> Result<LogLevel> {
        match *val {
            FbLogLevel::Trace => Ok(LogLevel::Trace),
            FbLogLevel::Debug => Ok(LogLevel::Debug),
            FbLogLevel::Information => Ok(LogLevel::Information),
            FbLogLevel::Warning => Ok(LogLevel::Warning),
            FbLogLevel::Error => Ok(LogLevel::Error),
            FbLogLevel::Critical => Ok(LogLevel::Critical),
            FbLogLevel::None => Ok(LogLevel::None),
            _ => {
                bail!("Unsupported Flatbuffers log level: {:?}", val);
            }
        }
    }
}

impl From<&LogLevel> for FbLogLevel {
    #[cfg_attr(feature = "tracing", instrument(skip_all, parent = Span::current(), level= "Trace"))]
    fn from(val: &LogLevel) -> FbLogLevel {
        match val {
            LogLevel::Critical => FbLogLevel::Critical,
            LogLevel::Debug => FbLogLevel::Debug,
            LogLevel::Error => FbLogLevel::Error,
            LogLevel::Information => FbLogLevel::Information,
            LogLevel::None => FbLogLevel::None,
            LogLevel::Trace => FbLogLevel::Trace,
            LogLevel::Warning => FbLogLevel::Warning,
        }
    }
}

impl From<&LogLevel> for Level {
    // There is a test (sandbox::outb::tests::test_log_outb_log) which emits trace record as logs
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
