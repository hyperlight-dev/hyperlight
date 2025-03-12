use std::sync::{Mutex, Once};
use std::thread::current;

use log::{Level, Log, Metadata, Record, set_logger, set_max_level};

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

static LOGCALLS: Mutex<Vec<LogCall>> = Mutex::new(Vec::new());
static NUMBER_OF_ENABLED_CALLS: Mutex<usize> = Mutex::new(0);

pub struct SimpleLogger {}

impl SimpleLogger {
    pub fn initialize_test_logger() {
        INITLOGGER.call_once(|| {
            set_logger(&LOGGER).unwrap();
            set_max_level(log::LevelFilter::Trace);
        });
    }

    pub fn num_enabled_calls(&self) -> usize {
        *NUMBER_OF_ENABLED_CALLS.lock().unwrap()
    }

    pub fn num_log_calls(&self) -> usize {
        LOGCALLS.lock().unwrap().len()
    }

    pub fn get_log_call(&self, idx: usize) -> Option<LogCall> {
        LOGCALLS.lock().unwrap().get(idx).cloned()
    }

    pub fn clear_log_calls(&self) {
        let mut logcalls = LOGCALLS.lock().unwrap();
        logcalls.clear();
        *NUMBER_OF_ENABLED_CALLS.lock().unwrap() = 0;
    }

    pub fn test_log_records<F: Fn(&Vec<LogCall>)>(&self, f: F) {
        let logcalls = LOGCALLS.lock().unwrap();
        f(&logcalls);
        self.clear_log_calls();
    }
}

impl Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        // This allows us to count the actual number of messages that have been logged by the guest
        // because the guest derives its log level from the host log level then the number times that enabled is called for
        // the "hyperlight-guest" target will be the same as the number of messages logged by the guest.
        // In other words this function should always return true for the "hyperlight-guest" target.
        let mut num_enabled = NUMBER_OF_ENABLED_CALLS.lock().unwrap();
        if metadata.target() == "hyperlight-guest" {
            *num_enabled += 1;
        }
        metadata.target() == "hyperlight-guest" && metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let mut logcalls = LOGCALLS.lock().unwrap();
        logcalls.push(LogCall {
            level: record.level(),
            args: format!("{}", record.args()),
            target: record.target().to_string(),
            line: record.line(),
            file: record.file().map(|file| file.to_string()),
            module_path: record
                .module_path()
                .map(|module_path| module_path.to_string()),
        });

        println!("Thread {:?} {:?}", current().id(), record);
    }

    fn flush(&self) {}
}
