// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use std::sync::{Arc, Mutex};

use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCallType;
use hyperlight_common::flatbuffer_wrappers::function_types::FunctionCallResult;
use hyperlight_common::flatbuffer_wrappers::guest_error::{ErrorCode, GuestError};
use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
use hyperlight_common::flatbuffer_wrappers::guest_log_level::LogLevel;
use hyperlight_common::outb::{Exception, OutBAction};
use hyperlight_common::transport::MsgKind;
use hyperlight_common::virtq::ReplyChain;
use tracing::{Span, instrument};

use super::host_funcs::FunctionRegistry;
#[cfg(feature = "mem_profile")]
use crate::hypervisor::regs::CommonRegisters;
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::shared_mem::HostSharedMemory;
use crate::mem::virtq;
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

pub(crate) fn emit_guest_log(log_data: &GuestLogData) {
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
        OutBAction::VirtqNotify => outb_virtq_call(mem_mgr, host_funcs),
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

/// Drain G2H messages published before this notification.
fn outb_virtq_call(
    mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
    host_funcs: &Arc<Mutex<FunctionRegistry>>,
) -> Result<(), HandleOutbError> {
    let max_recv_len = mem_mgr.layout.get_g2h_queue_dims().pool_len();

    let Some(consumer) = mem_mgr.g2h_consumer.as_mut() else {
        return Err(HandleOutbError::ReadHostFunctionCall(
            "G2H consumer is not attached".into(),
        ));
    };

    // Drain entries, processing logs, until we find one call.
    let (mut request, reply, header) = loop {
        let maybe_next = consumer.poll(max_recv_len).map_err(|error| {
            HandleOutbError::ReadHostFunctionCall(format!("G2H poll failed: {error}"))
        })?;

        let Some((mut request, reply)) = maybe_next else {
            // No entry can be a backpressure or prefill notification.
            return Ok(());
        };

        let header = virtq::read_message_header(&mut request)
            .map_err(|error| HandleOutbError::ReadHostFunctionCall(error.to_string()))?;

        match header.msg_kind() {
            Ok(MsgKind::Request) => break (request, reply, header),
            Ok(MsgKind::Log) => {
                if header.cid != 0 {
                    return Err(HandleOutbError::ReadHostFunctionCall(
                        "G2H log has a nonzero correlation ID".into(),
                    ));
                }

                if !matches!(reply, ReplyChain::Ack(_)) {
                    return Err(HandleOutbError::ReadHostFunctionCall(
                        "G2H log has writable response buffers".into(),
                    ));
                }

                let log = virtq::read_guest_log_data(&mut request)
                    .map_err(|error| HandleOutbError::ReadHostFunctionCall(error.to_string()))?;

                emit_guest_log(&log);

                consumer.complete(request, reply).map_err(|error| {
                    HandleOutbError::ReadHostFunctionCall(format!(
                        "G2H log completion failed: {error}"
                    ))
                })?;
            }
            Ok(kind) => {
                return Err(HandleOutbError::ReadHostFunctionCall(format!(
                    "Expected G2H request, got {kind:?}"
                )));
            }
            Err(kind) => {
                return Err(HandleOutbError::ReadHostFunctionCall(format!(
                    "Unknown G2H message kind {kind:#x}"
                )));
            }
        }
    };

    if header.cid == 0 {
        return Err(HandleOutbError::ReadHostFunctionCall(
            "G2H request has correlation ID zero".into(),
        ));
    }

    let mut resp = reply.into_writable().map_err(|_| {
        HandleOutbError::WriteHostFunctionResponse(
            "G2H request has no writable response buffers".into(),
        )
    })?;

    let call = virtq::get_host_function_call(&mut request)
        .map_err(|error| HandleOutbError::ReadHostFunctionCall(error.to_string()))?;

    if call.function_call_type() != FunctionCallType::Host {
        return Err(HandleOutbError::ReadHostFunctionCall(
            "G2H request does not target a host function".into(),
        ));
    }

    let name = call.function_name;
    let args = call.parameters.unwrap_or_default();

    let result = host_funcs
        .try_lock()
        .map_err(|err| HandleOutbError::LockFailed(file!(), line!(), err.to_string()))?
        .call_host_function(&name, args)
        .map_err(|err| GuestError::new(ErrorCode::HostFunctionError, err.to_string()));

    let result = FunctionCallResult::new(result);
    let resp_capacity = resp.capacity();

    // Capacity is checked before writing, so an oversized result leaves the
    // chain untouched and can be replaced with a bounded transport error.
    if !virtq::try_write_response(&mut resp, header.cid, &result)
        .map_err(|err| HandleOutbError::WriteHostFunctionResponse(err.to_string()))?
    {
        let fallback = FunctionCallResult::new(Err(GuestError::new(
            ErrorCode::HostFunctionError,
            "Host response exceeds virtqueue capacity".into(),
        )));

        // The guest must receive a response for this correlation id. Failure
        // to fit even this small error makes the transport unusable.
        if !virtq::try_write_response(&mut resp, header.cid, &fallback)
            .map_err(|err| HandleOutbError::WriteHostFunctionResponse(err.to_string()))?
        {
            return Err(HandleOutbError::WriteHostFunctionResponse(format!(
                "Writable response capacity {resp_capacity} cannot hold a transport error"
            )));
        }
    }

    consumer
        .complete(request, resp)
        .map_err(|err| HandleOutbError::WriteHostFunctionResponse(err.to_string()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use hyperlight_common::flatbuffer_wrappers::guest_log_level::LogLevel;
    use hyperlight_testing::logger::{LOGGER, Logger};
    use tracing_core::callsite::rebuild_interest_cache;

    use super::{GuestLogData, emit_guest_log};
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
    // tracing subscriber is set.
    #[test]
    #[ignore]
    fn test_log_emit_guest_log() {
        Logger::initialize_test_logger();
        LOGGER.set_max_level(log::LevelFilter::Off);

        emit_guest_log(&new_guest_log_data(LogLevel::Information));
        assert_eq!(0, LOGGER.num_log_calls());
        LOGGER.clear_log_calls();

        LOGGER.set_max_level(log::LevelFilter::Trace);
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
            LOGGER.clear_log_calls();
            emit_guest_log(&new_guest_log_data(level));

            LOGGER.test_log_records(|log_calls| {
                let expected_level: tracing::Level = match level {
                    LogLevel::Trace => tracing::Level::TRACE,
                    LogLevel::Debug => tracing::Level::DEBUG,
                    LogLevel::Information => tracing::Level::INFO,
                    LogLevel::Warning => tracing::Level::WARN,
                    LogLevel::Error | LogLevel::Critical => tracing::Level::ERROR,
                    LogLevel::None => tracing::Level::TRACE,
                };

                assert_eq!(
                    log_calls
                        .iter()
                        .filter(|log_call| {
                            log_call.level.as_str() == expected_level.as_str()
                                && log_call.args.contains("test log")
                        })
                        .count(),
                    1,
                    "log call did not occur for level {level:?}"
                );
            });
        }
    }

    // Tests that guest logs emit traces when a trace subscriber is set
    // this test is ignored because it is incompatible with other tests , specifically those which require a logger for tracing
    // marking  this test as ignored means that running `cargo test` will not run this test but will allow a developer who runs that command
    // from their workstation to be successful without needed to know about test interdependencies
    // this test will be run explicitly as a part of the CI pipeline
    #[ignore]
    #[test]
    fn test_trace_emit_guest_log() {
        Logger::initialize_log_tracer();
        rebuild_interest_cache();
        let subscriber =
            hyperlight_testing::tracing_subscriber::TracingSubscriber::new(tracing::Level::TRACE);
        tracing::subscriber::with_default(subscriber.clone(), || {
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
                let log_data: GuestLogData = new_guest_log_data(level);
                subscriber.clear();
                emit_guest_log(&log_data);

                subscriber.test_trace_records(|_, events| {
                    let expected_level = match level {
                        LogLevel::Trace => "TRACE",
                        LogLevel::Debug => "DEBUG",
                        LogLevel::Information => "INFO",
                        LogLevel::Warning => "WARN",
                        LogLevel::Error => "ERROR",
                        LogLevel::Critical => "ERROR",
                        LogLevel::None => "TRACE",
                    };

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
