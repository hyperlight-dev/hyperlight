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

use std::sync::{Arc, Mutex};

use hyperlight_common::flatbuffer_wrappers::function_types::{FunctionCallResult, ParameterValue};
use hyperlight_common::flatbuffer_wrappers::guest_error::{ErrorCode, GuestError};
use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
use hyperlight_common::flatbuffer_wrappers::guest_log_level::LogLevel;
use hyperlight_common::outb::{Exception, OutBAction};
use tracing::{Span, instrument};

use super::host_funcs::FunctionRegistry;
#[cfg(feature = "mem_profile")]
use crate::hypervisor::regs::CommonRegisters;
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::shared_mem::HostSharedMemory;
#[cfg(feature = "mem_profile")]
use crate::sandbox::trace::MemTraceInfo;

/// Errors that can occur when handling an outb operation from the guest.
#[derive(Debug, thiserror::Error)]
pub enum HandleOutbError {
    #[error("Guest aborted: error code {code}, message: {message}")]
    GuestAborted {
        /// The error code from the guest
        code: u8,
        /// The error message from the guest
        message: String,
    },
    #[error("Invalid outb port: {0}")]
    InvalidPort(String),
    #[error("Failed to read guest log data: {0}")]
    ReadLogData(String),
    #[error("Failed to read host function call: {0}")]
    ReadHostFunctionCall(String),
    #[error("Failed to acquire lock at {0}:{1} - {2}")]
    LockFailed(&'static str, u32, String),
    #[error("Failed to write host function response: {0}")]
    WriteHostFunctionResponse(String),
    #[error("Invalid character for debug print: {0}")]
    InvalidDebugPrintChar(u32),
    #[cfg(feature = "mem_profile")]
    #[error("Memory profiling error: {0}")]
    MemProfile(String),
}

#[instrument(err(Debug), skip_all, parent = Span::current(), level="Trace")]
pub(super) fn outb_log(
    mgr: &mut SandboxMemoryManager<HostSharedMemory>,
) -> Result<(), HandleOutbError> {
    let log_data: GuestLogData = mgr
        .read_guest_log_data()
        .map_err(|e| HandleOutbError::ReadLogData(e.to_string()))?;

    // Emit guest log data as a tracing event with structured fields.
    //
    // We match on the level at runtime because tracing macros determine their
    // level at compile time. Guest file/line/module are passed as structured
    // fields (rather than tracing metadata) because they originate from the
    // guest, not from this call site.
    //
    // Consumers using a `log` logger (without a tracing subscriber) still
    // receive these events thanks to the `tracing` crate's `log` feature,
    // which forwards tracing events to the `log` facade when no subscriber
    // is set.
    let source_file = log_data.source_file.as_str();
    let line = log_data.line;
    let source = log_data.source.as_str();
    let message = log_data.message.as_str();

    match &log_data.level {
        LogLevel::Error | LogLevel::Critical => {
            tracing::error!(
                target: "hyperlight_guest",
                guest_file = source_file,
                guest_line = line,
                guest_module = source,
                "{}",
                message
            );
        }
        LogLevel::Warning => {
            tracing::warn!(
                target: "hyperlight_guest",
                guest_file = source_file,
                guest_line = line,
                guest_module = source,
                "{}",
                message
            );
        }
        LogLevel::Information => {
            tracing::info!(
                target: "hyperlight_guest",
                guest_file = source_file,
                guest_line = line,
                guest_module = source,
                "{}",
                message
            );
        }
        LogLevel::Debug => {
            tracing::debug!(
                target: "hyperlight_guest",
                guest_file = source_file,
                guest_line = line,
                guest_module = source,
                "{}",
                message
            );
        }
        LogLevel::Trace | LogLevel::None => {
            tracing::trace!(
                target: "hyperlight_guest",
                guest_file = source_file,
                guest_line = line,
                guest_module = source,
                "{}",
                message
            );
        }
    }

    Ok(())
}

const ABORT_TERMINATOR: u8 = 0xFF;
const MAX_ABORT_BUFFER_LEN: usize = 1024;

fn outb_abort(
    mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
    data: u32,
) -> Result<(), HandleOutbError> {
    let buffer = mem_mgr.get_abort_buffer_mut();

    let bytes = data.to_le_bytes(); // [len, b1, b2, b3]
    let len = bytes[0].min(3);

    for &b in &bytes[1..=len as usize] {
        if b == ABORT_TERMINATOR {
            let guest_error_code = *buffer.first().unwrap_or(&0);

            let result = {
                let message = if let Some(&maybe_exception_code) = buffer.get(1) {
                    match Exception::try_from(maybe_exception_code) {
                        Ok(exception) => {
                            let extra_msg = String::from_utf8_lossy(&buffer[2..]);
                            format!("Exception: {:?} | {}", exception, extra_msg)
                        }
                        Err(_) => String::from_utf8_lossy(&buffer[1..]).into(),
                    }
                } else {
                    String::new()
                };

                Err(HandleOutbError::GuestAborted {
                    code: guest_error_code,
                    message,
                })
            };

            buffer.clear();
            return result;
        }

        if buffer.len() >= MAX_ABORT_BUFFER_LEN {
            buffer.clear();
            return Err(HandleOutbError::GuestAborted {
                code: 0,
                message: "Guest abort buffer overflowed".into(),
            });
        }

        buffer.push(b);
    }
    Ok(())
}

/// Handles OutB operations from the guest.
#[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
pub(crate) fn handle_outb(
    mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
    host_funcs: &Arc<Mutex<FunctionRegistry>>,
    port: u16,
    data: u32,
    #[cfg(feature = "mem_profile")] regs: &CommonRegisters,
    #[cfg(feature = "mem_profile")] trace_info: &mut MemTraceInfo,
) -> Result<(), HandleOutbError> {
    match port
        .try_into()
        .map_err(|e: anyhow::Error| HandleOutbError::InvalidPort(e.to_string()))?
    {
        OutBAction::Log => outb_log(mem_mgr),
        OutBAction::CallFunction => {
            let call = mem_mgr
                .get_host_function_call()
                .map_err(|e| HandleOutbError::ReadHostFunctionCall(e.to_string()))?;
            let name = call.function_name.clone();
            let args: Vec<ParameterValue> = call.parameters.unwrap_or(vec![]);
            let res = host_funcs
                .try_lock()
                .map_err(|e| HandleOutbError::LockFailed(file!(), line!(), e.to_string()))?
                .call_host_function(&name, args)
                .map_err(|e| GuestError::new(ErrorCode::HostFunctionError, e.to_string()));

            let func_result = FunctionCallResult::new(res);

            mem_mgr
                .write_response_from_host_function_call(&func_result)
                .map_err(|e| HandleOutbError::WriteHostFunctionResponse(e.to_string()))?;

            Ok(())
        }
        OutBAction::Abort => outb_abort(mem_mgr, data),
        OutBAction::DebugPrint => {
            let ch: char = match char::from_u32(data) {
                Some(c) => c,
                None => {
                    return Err(HandleOutbError::InvalidDebugPrintChar(data));
                }
            };

            eprint!("{}", ch);
            Ok(())
        }
        #[cfg(feature = "trace_guest")]
        OutBAction::TraceBatch => Ok(()),
        #[cfg(feature = "mem_profile")]
        OutBAction::TraceMemoryAlloc => trace_info.handle_trace_mem_alloc(regs, mem_mgr),
        #[cfg(feature = "mem_profile")]
        OutBAction::TraceMemoryFree => trace_info.handle_trace_mem_free(regs, mem_mgr),
    }
}
#[cfg(test)]
mod tests {
    use hyperlight_common::flatbuffer_wrappers::guest_log_level::LogLevel;
    use hyperlight_testing::logger::{LOGGER, Logger};
    use hyperlight_testing::simple_guest_as_string;
    use tracing_core::callsite::rebuild_interest_cache;

    use super::outb_log;
    use crate::GuestBinary;
    use crate::mem::mgr::SandboxMemoryManager;
    use crate::sandbox::SandboxConfiguration;
    use crate::sandbox::outb::GuestLogData;
    use crate::testing::log_values::test_value_as_str;

    fn new_guest_log_data(level: LogLevel) -> GuestLogData {
        GuestLogData::new(
            "test log".to_string(),
            "test source".to_string(),
            level,
            "test caller".to_string(),
            "test source file".to_string(),
            123,
        )
    }

    // Verifies that guest log events are forwarded to a `log` logger when no
    // tracing subscriber is set. This exercises the `tracing` crate's built-in
    // `log` compatibility feature, proving that consumers who only set up a
    // `log` logger (not a tracing subscriber) still receive guest output.
    #[test]
    #[ignore]
    fn test_log_outb_log() {
        Logger::initialize_test_logger();
        LOGGER.set_max_level(log::LevelFilter::Off);

        let sandbox_cfg = SandboxConfiguration::default();

        let new_mgr = || {
            let bin = GuestBinary::FilePath(simple_guest_as_string().unwrap());
            let snapshot = crate::sandbox::snapshot::Snapshot::from_env(bin, sandbox_cfg).unwrap();
            let mgr = SandboxMemoryManager::from_snapshot(&snapshot).unwrap();
            let (hmgr, _) = mgr.build().unwrap();
            hmgr
        };
        {
            // We set a logger but there is no guest log data
            // in memory, so expect a log operation to fail
            let mut mgr = new_mgr();
            assert!(outb_log(&mut mgr).is_err());
        }
        {
            // Write a log message so outb_log will succeed.
            // Since the logger level is set off, expect logs to be no-ops
            let mut mgr = new_mgr();
            let log_msg = new_guest_log_data(LogLevel::Information);

            let guest_log_data_buffer: Vec<u8> = log_msg.try_into().unwrap();
            let offset = mgr.layout.get_output_data_buffer_scratch_host_offset();
            mgr.scratch_mem
                .push_buffer(
                    offset,
                    sandbox_cfg.get_output_data_size(),
                    &guest_log_data_buffer,
                )
                .unwrap();

            let res = outb_log(&mut mgr);
            assert!(res.is_ok());
            assert_eq!(0, LOGGER.num_log_calls());
            LOGGER.clear_log_calls();
        }
        {
            // now, test logging
            LOGGER.set_max_level(log::LevelFilter::Trace);
            let mut mgr = new_mgr();
            LOGGER.clear_log_calls();

            // set up the logger and set the log level to the maximum
            // possible (Trace) to ensure we're able to test all
            // the possible branches of the match in outb_log

            let levels = vec![
                LogLevel::Trace,
                LogLevel::Debug,
                LogLevel::Information,
                LogLevel::Warning,
                LogLevel::Error,
                LogLevel::Critical,
                LogLevel::None,
            ];
            for level in levels {
                let layout = mgr.layout;
                let log_data = new_guest_log_data(level);

                let guest_log_data_buffer: Vec<u8> = log_data.clone().try_into().unwrap();
                mgr.scratch_mem
                    .push_buffer(
                        layout.get_output_data_buffer_scratch_host_offset(),
                        sandbox_cfg.get_output_data_size(),
                        guest_log_data_buffer.as_slice(),
                    )
                    .unwrap();

                outb_log(&mut mgr).unwrap();

                LOGGER.test_log_records(|log_calls| {
                    let expected_level: tracing::Level = match level {
                        LogLevel::Trace => tracing::Level::TRACE,
                        LogLevel::Debug => tracing::Level::DEBUG,
                        LogLevel::Information => tracing::Level::INFO,
                        LogLevel::Warning => tracing::Level::WARN,
                        LogLevel::Error => tracing::Level::ERROR,
                        LogLevel::Critical => tracing::Level::ERROR,
                        LogLevel::None => tracing::Level::TRACE,
                    };

                    assert!(
                        log_calls
                            .iter()
                            .filter(|log_call| {
                                log_call.level.as_str() == expected_level.as_str()
                                    && log_call.args.contains("test log")
                            })
                            .count()
                            == 1,
                        "log call did not occur for level {:?}",
                        level.clone()
                    );
                });
            }
        }
    }

    // Tests that outb_log emits traces when a trace subscriber is set
    // this test is ignored because it is incompatible with other tests , specifically those which require a logger for tracing
    // marking  this test as ignored means that running `cargo test` will not run this test but will allow a developer who runs that command
    // from their workstation to be successful without needed to know about test interdependencies
    // this test will be run explicitly as a part of the CI pipeline
    #[ignore]
    #[test]
    fn test_trace_outb_log() {
        Logger::initialize_log_tracer();
        rebuild_interest_cache();
        let subscriber =
            hyperlight_testing::tracing_subscriber::TracingSubscriber::new(tracing::Level::TRACE);
        let sandbox_cfg = SandboxConfiguration::default();
        tracing::subscriber::with_default(subscriber.clone(), || {
            let new_mgr = || {
                let bin = GuestBinary::FilePath(simple_guest_as_string().unwrap());
                let snapshot =
                    crate::sandbox::snapshot::Snapshot::from_env(bin, sandbox_cfg).unwrap();
                let mgr = SandboxMemoryManager::from_snapshot(&snapshot).unwrap();
                let (hmgr, _) = mgr.build().unwrap();
                hmgr
            };

            // as a span does not exist one will be automatically created
            // after that there will be an event for each log message
            // we are interested only in the events for the log messages that we created

            let levels = vec![
                LogLevel::Trace,
                LogLevel::Debug,
                LogLevel::Information,
                LogLevel::Warning,
                LogLevel::Error,
                LogLevel::Critical,
                LogLevel::None,
            ];
            for level in levels {
                let mut mgr = new_mgr();
                let layout = mgr.layout;
                let log_data: GuestLogData = new_guest_log_data(level);
                subscriber.clear();

                let guest_log_data_buffer: Vec<u8> = log_data.try_into().unwrap();
                mgr.scratch_mem
                    .push_buffer(
                        layout.get_output_data_buffer_scratch_host_offset(),
                        sandbox_cfg.get_output_data_size(),
                        guest_log_data_buffer.as_slice(),
                    )
                    .unwrap();
                subscriber.clear();
                outb_log(&mut mgr).unwrap();

                subscriber.test_trace_records(|spans, events| {
                    let expected_level = match level {
                        LogLevel::Trace => "TRACE",
                        LogLevel::Debug => "DEBUG",
                        LogLevel::Information => "INFO",
                        LogLevel::Warning => "WARN",
                        LogLevel::Error => "ERROR",
                        LogLevel::Critical => "ERROR",
                        LogLevel::None => "TRACE",
                    };

                    // We cannot get the parent span using the `current_span()` method as by the time we get to this point that span has been exited so there is no current span
                    // We need to make sure that the span that we created is in the spans map instead
                    // We are only interested in the first one that was created when calling outb_log.

                    assert!(!spans.is_empty(), "expected at least one span, found none");

                    let span_value = spans
                        .get(&1)
                        .unwrap()
                        .as_object()
                        .unwrap()
                        .get("span")
                        .unwrap()
                        .get("attributes")
                        .unwrap()
                        .as_object()
                        .unwrap()
                        .get("metadata")
                        .unwrap()
                        .as_object()
                        .unwrap();

                    //test_value_as_str(span_value, "level", "INFO");
                    test_value_as_str(span_value, "module_path", "hyperlight_host::sandbox::outb");
                    let expected_file = if cfg!(windows) {
                        "src\\hyperlight_host\\src\\sandbox\\outb.rs"
                    } else {
                        "src/hyperlight_host/src/sandbox/outb.rs"
                    };
                    test_value_as_str(span_value, "file", expected_file);
                    test_value_as_str(span_value, "target", "hyperlight_host::sandbox::outb");

                    let mut count_matching_events = 0;

                    for json_value in events {
                        let event_values = json_value.as_object().unwrap().get("event").unwrap();
                        let metadata_values_map =
                            event_values.get("metadata").unwrap().as_object().unwrap();
                        let event_values_map = event_values.as_object().unwrap();
                        test_value_as_str(metadata_values_map, "level", expected_level);
                        test_value_as_str(event_values_map, "guest_file", "test source file");
                        test_value_as_str(event_values_map, "guest_module", "test source");
                        test_value_as_str(metadata_values_map, "target", "hyperlight_guest");
                        count_matching_events += 1;
                    }
                    assert!(
                        count_matching_events == 1,
                        "trace log call did not occur for level {:?}",
                        level.clone()
                    );
                });
            }
        });
    }
}
