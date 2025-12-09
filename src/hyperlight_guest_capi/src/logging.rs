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

use core::ffi::c_char;

/// C-compatible log level enum
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Level {
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

impl From<Level> for tracing::log::Level {
    fn from(level: Level) -> Self {
        match level {
            Level::Error => tracing::log::Level::Error,
            Level::Warn => tracing::log::Level::Warn,
            Level::Info => tracing::log::Level::Info,
            Level::Debug => tracing::log::Level::Debug,
            Level::Trace => tracing::log::Level::Trace,
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_log(level: Level, message: *const c_char, line: i32, file: *const c_char) {
    let log_level: tracing::log::Level = level.into();

    if tracing::log::log_enabled!(log_level) {
        let message = unsafe { core::ffi::CStr::from_ptr(message).to_string_lossy() };
        let file = unsafe { core::ffi::CStr::from_ptr(file).to_string_lossy() };

        tracing::log::logger().log(
            &tracing::log::RecordBuilder::new()
                .args(format_args!("{}: {}", log_level, message))
                .level(log_level)
                .line(Some(line as u32))
                .file(Some(&file))
                .build(),
        );
    }
}
