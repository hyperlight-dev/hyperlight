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

// this is a non threadsafe logger for testing purposes, to test the log messages emitted by the guest.
// it will only log messages from the hyperlight_guest target. It will not log messages from other targets.
// this target is only used when handling an outb log request from the guest, so this logger will only capture those messages.

use std::sync::Once;
use std::thread::current;

use log::{set_logger, set_max_level, Level, Log, Metadata, Record};

pub static LOGGER: SimpleLogger = SimpleLogger {};
static INITLOGGER: Once = Once::new();
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct LogCall {
    pub level: Level,
    pub args: String,
    pub target: String,
    pub line: Option<u32>,
    pub file: Option<String>,
    pub module_path: Option<String>,
}

static mut LOGCALLS: Vec<LogCall> = Vec::<LogCall>::new();
static mut NUMBER_OF_ENABLED_CALLS: usize = 0;

pub struct SimpleLogger {}

impl SimpleLogger {
    pub fn initialize_test_logger() {
        INITLOGGER.call_once(|| {
            set_logger(&LOGGER).unwrap();
            set_max_level(log::LevelFilter::Trace);
        });
    }

    pub fn num_enabled_calls(&self) -> usize {
        unsafe { NUMBER_OF_ENABLED_CALLS }
    }

    pub fn num_log_calls(&self) -> usize {
        unsafe { LOGCALLS.len() }
    }
    pub fn get_log_call(&self, idx: usize) -> Option<LogCall> {
        unsafe { LOGCALLS.get(idx).cloned() }
    }

    pub fn clear_log_calls(&self) {
        unsafe {
            LOGCALLS.clear();
            NUMBER_OF_ENABLED_CALLS = 0;
        }
    }

    pub fn test_log_records<F: Fn(&Vec<LogCall>)>(&self, f: F) {
        unsafe {
            // this logger is only used for testing so unsafe is fine here
            #[allow(static_mut_refs)]
            f(&LOGCALLS);
        };
        self.clear_log_calls();
    }
}

impl Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        // This allows us to count the actual number of messages that have been logged by the guest
        // because the guest derives its log level from the host log level then the number times that enabled is called for
        // the "hyperlight_guest" target will be the same as the number of messages logged by the guest.
        // In other words this function should always return true for the "hyperlight_guest" target.
        unsafe {
            if metadata.target() == "hyperlight_guest" {
                NUMBER_OF_ENABLED_CALLS += 1;
            }
            metadata.target() == "hyperlight_guest" && metadata.level() <= log::max_level()
        }
    }
    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        unsafe {
            LOGCALLS.push(LogCall {
                level: record.level(),
                args: format!("{}", record.args()),
                target: record.target().to_string(),
                line: record.line(),
                file: match record.file() {
                    None => record.file_static().map(|file| file.to_string()),
                    Some(file) => Some(file.to_string()),
                },
                module_path: match record.module_path() {
                    None => record
                        .module_path_static()
                        .map(|module_path| module_path.to_string()),
                    Some(module_path) => Some(module_path.to_string()),
                },
            });
        };

        println!("Thread {:?} {:?}", current().id(), record);
    }

    fn flush(&self) {}
}
