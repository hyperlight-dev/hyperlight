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

use hyperlight_common::flatbuffer_wrappers::function_types::ParameterValue;
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
use hyperlight_common::outb::{Exception, OutBAction};
use log::{Level, Record};
use tracing::{Span, instrument};
use tracing_log::format_trace;

use super::host_funcs::FunctionRegistry;
use super::mem_mgr::MemMgrWrapper;
use crate::hypervisor::handlers::{OutBHandler, OutBHandlerFunction, OutBHandlerWrapper};
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::shared_mem::HostSharedMemory;
use crate::{HyperlightError, Result, new_error};

#[instrument(err(Debug), skip_all, parent = Span::current(), level="Trace")]
pub(super) fn outb_log(mgr: &mut SandboxMemoryManager<HostSharedMemory>) -> Result<()> {
    // This code will create either a logging record or a tracing record for the GuestLogData depending on if the host has set up a tracing subscriber.
    // In theory as we have enabled the log feature in the Cargo.toml for tracing this should happen
    // automatically (based on if there is tracing subscriber present) but only works if the event created using macros. (see https://github.com/tokio-rs/tracing/blob/master/tracing/src/macros.rs#L2421 )
    // The reason that we don't want to use the tracing macros is that we want to be able to explicitly
    // set the file and line number for the log record which is not possible with macros.
    // This is because the file and line number come from the  guest not the call site.

    let log_data: GuestLogData = mgr.read_guest_log_data()?;

    let record_level: Level = (&log_data.level).into();

    // Work out if we need to log or trace
    // this API is marked as follows but it is the easiest way to work out if we should trace or log

    // Private API for internal use by tracing's macros.
    //
    // This function is *not* considered part of `tracing`'s public API, and has no
    // stability guarantees. If you use it, and it breaks or disappears entirely,
    // don't say we didn't warn you.

    let should_trace = tracing_core::dispatcher::has_been_set();
    let source_file = Some(log_data.source_file.as_str());
    let line = Some(log_data.line);
    let source = Some(log_data.source.as_str());

    // See https://github.com/rust-lang/rust/issues/42253 for the reason this has to be done this way

    if should_trace {
        // Create a tracing event for the GuestLogData
        // Ideally we would create tracing metadata based on the Guest Log Data
        // but tracing derives the metadata at compile time
        // see https://github.com/tokio-rs/tracing/issues/2419
        // so we leave it up to the subscriber to figure out that there are logging fields present with this data
        format_trace(
            &Record::builder()
                .args(format_args!("{}", log_data.message))
                .level(record_level)
                .target("hyperlight_guest")
                .file(source_file)
                .line(line)
                .module_path(source)
                .build(),
        )?;
    } else {
        // Create a log record for the GuestLogData
        log::logger().log(
            &Record::builder()
                .args(format_args!("{}", log_data.message))
                .level(record_level)
                .target("hyperlight_guest")
                .file(Some(&log_data.source_file))
                .line(Some(log_data.line))
                .module_path(Some(&log_data.source))
                .build(),
        );
    }

    Ok(())
}

const ABORT_TERMINATOR: u8 = 0xFF;
const MAX_ABORT_BUFFER_LEN: usize = 1024;

fn outb_abort(mem_mgr: &mut MemMgrWrapper<HostSharedMemory>, data: u32) -> Result<()> {
    let buffer = mem_mgr.get_abort_buffer_mut();

    let bytes = data.to_le_bytes(); // [len, b1, b2, b3]
    let len = bytes[0].min(3);

    for &b in &bytes[1..=len as usize] {
        if b == ABORT_TERMINATOR {
            let guest_error_code = *buffer.first().unwrap_or(&0);
            let guest_error = ErrorCode::from(guest_error_code as u64);

            let result = match guest_error {
                ErrorCode::StackOverflow => Err(HyperlightError::StackOverflow()),
                _ => {
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

                    Err(HyperlightError::GuestAborted(guest_error_code, message))
                }
            };

            buffer.clear();
            return result;
        }

        if buffer.len() >= MAX_ABORT_BUFFER_LEN {
            buffer.clear();
            return Err(HyperlightError::GuestAborted(
                0,
                "Guest abort buffer overflowed".into(),
            ));
        }

        buffer.push(b);
    }

    Ok(())
}

/// Handles OutB operations from the guest.
#[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
fn handle_outb_impl(
    mem_mgr: &mut MemMgrWrapper<HostSharedMemory>,
    host_funcs: Arc<Mutex<FunctionRegistry>>,
    port: u16,
    data: u32,
) -> Result<()> {
    match port.try_into()? {
        OutBAction::Log => outb_log(mem_mgr.as_mut()),
        OutBAction::CallFunction => {
            let call = mem_mgr.as_mut().get_host_function_call()?; // pop output buffer
            let name = call.function_name.clone();
            let args: Vec<ParameterValue> = call.parameters.unwrap_or(vec![]);
            let res = host_funcs
                .try_lock()
                .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
                .call_host_function(&name, args)?;
            mem_mgr
                .as_mut()
                .write_response_from_host_method_call(&res)?; // push input buffers

            Ok(())
        }
        OutBAction::Abort => outb_abort(mem_mgr, data),
        OutBAction::DebugPrint => {
            let ch: char = match char::from_u32(data) {
                Some(c) => c,
                None => {
                    return Err(new_error!("Invalid character for logging: {}", data));
                }
            };

            eprint!("{}", ch);
            Ok(())
        }
    }
}

/// Given a `MemMgrWrapper` and ` HostFuncsWrapper` -- both passed by _value_
///  -- return an `OutBHandlerWrapper` wrapping the core OUTB handler logic.
///
/// TODO: pass at least the `host_funcs_wrapper` param by reference.
#[instrument(skip_all, parent = Span::current(), level= "Trace")]
pub(crate) fn outb_handler_wrapper(
    mut mem_mgr_wrapper: MemMgrWrapper<HostSharedMemory>,
    host_funcs_wrapper: Arc<Mutex<FunctionRegistry>>,
) -> OutBHandlerWrapper {
    let outb_func: OutBHandlerFunction = Box::new(move |port, payload| {
        handle_outb_impl(
            &mut mem_mgr_wrapper,
            host_funcs_wrapper.clone(),
            port,
            payload,
        )
    });
    let outb_hdl = OutBHandler::from(outb_func);
    Arc::new(Mutex::new(outb_hdl))
}

#[cfg(test)]
mod tests {
    use hyperlight_common::flatbuffer_wrappers::guest_log_level::LogLevel;
    use hyperlight_testing::logger::{LOGGER, Logger};
    use log::Level;
    use tracing_core::callsite::rebuild_interest_cache;

    use super::outb_log;
    use crate::mem::layout::SandboxMemoryLayout;
    use crate::mem::mgr::SandboxMemoryManager;
    use crate::mem::shared_mem::SharedMemory;
    use crate::sandbox::SandboxConfiguration;
    use crate::sandbox::outb::GuestLogData;
    use crate::testing::log_values::test_value_as_str;
    use crate::testing::simple_guest_exe_info;

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

    #[test]
    #[ignore]
    fn test_log_outb_log() {
        Logger::initialize_test_logger();
        LOGGER.set_max_level(log::LevelFilter::Off);

        let sandbox_cfg = SandboxConfiguration::default();

        let new_mgr = || {
            let mut exe_info = simple_guest_exe_info().unwrap();
            let mut mgr = SandboxMemoryManager::load_guest_binary_into_memory(
                sandbox_cfg,
                &mut exe_info,
                None,
            )
            .unwrap();
            let mem_size = mgr.get_shared_mem_mut().mem_size();
            let layout = mgr.layout;
            let shared_mem = mgr.get_shared_mem_mut();
            layout
                .write(shared_mem, SandboxMemoryLayout::BASE_ADDRESS, mem_size)
                .unwrap();
            let (hmgr, _) = mgr.build();
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
            let offset = mgr.layout.get_output_data_offset();
            mgr.get_shared_mem_mut()
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
                mgr.get_shared_mem_mut()
                    .push_buffer(
                        layout.get_output_data_offset(),
                        sandbox_cfg.get_output_data_size(),
                        guest_log_data_buffer.as_slice(),
                    )
                    .unwrap();

                outb_log(&mut mgr).unwrap();

                LOGGER.test_log_records(|log_calls| {
                    let expected_level: Level = (&level).into();

                    assert!(
                        log_calls
                            .iter()
                            .filter(|log_call| {
                                log_call.level == expected_level
                                    && log_call.line == Some(log_data.line)
                                    && log_call.args == log_data.message
                                    && log_call.module_path == Some(log_data.source.clone())
                                    && log_call.file == Some(log_data.source_file.clone())
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
                let mut exe_info = simple_guest_exe_info().unwrap();
                let mut mgr = SandboxMemoryManager::load_guest_binary_into_memory(
                    sandbox_cfg,
                    &mut exe_info,
                    None,
                )
                .unwrap();
                let mem_size = mgr.get_shared_mem_mut().mem_size();
                let layout = mgr.layout;
                let shared_mem = mgr.get_shared_mem_mut();
                layout
                    .write(shared_mem, SandboxMemoryLayout::BASE_ADDRESS, mem_size)
                    .unwrap();
                let (hmgr, _) = mgr.build();
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
                mgr.get_shared_mem_mut()
                    .push_buffer(
                        layout.get_output_data_offset(),
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
                    // We expect to have created 21 spans at this point. We are only interested in the first one that was created when calling outb_log.

                    assert!(
                        spans.len() == 21,
                        "expected 21 spans, found {}",
                        spans.len()
                    );

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
                        test_value_as_str(event_values_map, "log.file", "test source file");
                        test_value_as_str(event_values_map, "log.module_path", "test source");
                        test_value_as_str(event_values_map, "log.target", "hyperlight_guest");
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
