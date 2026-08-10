// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
use hyperlight_common::flatbuffer_wrappers::guest_log_level::LogLevel;
use hyperlight_guest::transport;
use log::{LevelFilter, Metadata, Record};

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
        if self.enabled(record.metadata()) {
            log_message(
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
    let _send_to_host = || {
        let log = GuestLogData::new(
            message.to_string(),
            module_path.to_string(),
            level,
            target.to_string(),
            file.to_string(),
            line,
        );
        let bytes: Vec<u8> = log
            .try_into()
            .expect("Failed to convert GuestLogData to bytes");

        transport::with_ctx(|ctx| {
            ctx.emit_log(&bytes)
                .expect("Unable to send log data via virtq");
        });
    };

    #[cfg(all(feature = "trace_guest", target_arch = "x86_64"))]
    if hyperlight_guest_tracing::is_trace_enabled() {
        tracing::trace!(
            event = message,
            level = ?level,
            code.filepath = module_path,
            caller = target,
            source_file = file,
            code.lineno = line,
        );
    } else {
        _send_to_host();
    }
    #[cfg(not(all(feature = "trace_guest", target_arch = "x86_64")))]
    {
        _send_to_host();
    }
}
