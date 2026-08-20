// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use alloc::format;

use hyperlight_common::flatbuffer_wrappers::guest_log_level::LogLevel;
use log::{LevelFilter, Metadata, Record};

use crate::GUEST_HANDLE;

// this is private on purpose so that `log` can only be called though the `log!` macros.
struct GuestLogger {}

pub(crate) fn init_logger(filter: LevelFilter) {
    // if this `expect` fails we have no way to recover anyway, so we actually prefer a panic here
    // below temporary guest logger is promoted to static by the compiler.
    log::set_logger(&GuestLogger {}).expect("unable to setup guest logger");
    log::set_max_level(filter);
}

impl log::Log for GuestLogger {
    // The various macros like `info!` and `error!` will call the global log::max_level()
    // before calling our `log`. This means that we should log every message we get, because
    // we won't even see the ones that are above the set max level.
    fn enabled(&self, _: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let handle = unsafe { GUEST_HANDLE };
        if self.enabled(record.metadata()) {
            handle.log_message(
                record.level().into(),
                format!("{}", record.args()).as_str(),
                record.module_path().unwrap_or("Unknown"),
                record.target(),
                record.file().unwrap_or("Unknown"),
                record.line().unwrap_or(0),
            );
        }
    }

    fn flush(&self) {}
}

pub fn log_message(
    level: LogLevel,
    message: &str,
    module_path: &str,
    target: &str,
    file: &str,
    line: u32,
) {
    let handle = unsafe { GUEST_HANDLE };
    handle.log_message(level, message, module_path, target, file, line);
}
