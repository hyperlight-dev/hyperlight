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

use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::{FunctionCallResult, ParameterValue};
use hyperlight_common::flatbuffer_wrappers::guest_error::{ErrorCode, GuestError};
use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
use hyperlight_common::outb::{Exception, OutBAction};
use hyperlight_common::virtq::msg::{MsgKind, VirtqMsgHeader};
use hyperlight_common::virtq::{self};
use log::{Level, Record};
use tracing::{Span, instrument};
use tracing_log::format_trace;

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
    #[error("Trace formatting error: {0}")]
    TraceFormat(String),
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

/// Emit a guest log record from a virtqueue payload.
///
/// Deserializes [`GuestLogData`] from the raw bytes and emits either
/// a tracing event or a log record.
pub(crate) fn emit_guest_log(payload: &[u8]) {
    let Ok(log_data) = GuestLogData::try_from(payload) else {
        return;
    };

    // This code will create either a logging record or a tracing record
    // for the GuestLogData depending on if the host has set up a tracing
    // subscriber.
    // In theory as we have enabled the log feature in the Cargo.toml for
    // tracing this should happen automatically (based on if there is a
    // tracing subscriber present) but only works if the event is created
    // using macros.
    // (see https://github.com/tokio-rs/tracing/blob/master/tracing/src/macros.rs#L2421)
    // The reason that we don't want to use the tracing macros is that we
    // want to be able to explicitly set the file and line number for the
    // log record which is not possible with macros.
    // This is because the file and line number come from the guest not
    // the call site.

    let record_level: Level = (&log_data.level).into();

    // Work out if we need to log or trace.
    // This API is marked as internal but it is the easiest way to work
    // out if we should trace or log.
    let should_trace = tracing_core::dispatcher::has_been_set();
    let source_file = Some(log_data.source_file.as_str());
    let line = Some(log_data.line);
    let source = Some(log_data.source.as_str());

    // See https://github.com/rust-lang/rust/issues/42253 for the reason
    // this has to be done this way.

    if should_trace {
        // Create a tracing event for the GuestLogData.
        // Ideally we would create tracing metadata based on the Guest
        // Log Data but tracing derives the metadata at compile time.
        // see https://github.com/tokio-rs/tracing/issues/2419
        // So we leave it up to the subscriber to figure out that there
        // are logging fields present with this data.
        let _ = format_trace(
            &Record::builder()
                .args(format_args!("{}", log_data.message))
                .level(record_level)
                .target("hyperlight_guest")
                .file(source_file)
                .line(line)
                .module_path(source)
                .build(),
        );
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

/// Handle a guest-to-host function call received via the G2H virtqueue.
///
/// Log entries that arrive before the Request are processed inline.
fn outb_virtq_call(
    mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
    host_funcs: &Arc<Mutex<FunctionRegistry>>,
) -> Result<(), HandleOutbError> {
    let g2h_pool_size = mem_mgr.g2h_pool_size();

    let consumer = mem_mgr.g2h_consumer.as_mut().ok_or_else(|| {
        HandleOutbError::ReadHostFunctionCall("G2H consumer not initialized".into())
    })?;

    // Drain entries, processing Log messages, until we find a Request.
    let (entry, completion) = loop {
        let Ok(maybe_next) = consumer.poll(g2h_pool_size) else {
            return Err(HandleOutbError::ReadHostFunctionCall(
                "G2H poll failed".into(),
            ));
        };

        let Some((entry, completion)) = maybe_next else {
            // No G2H entry - backpressure-only notify or prefill notify.
            return Ok(());
        };

        let hdr_size = VirtqMsgHeader::SIZE;
        let entry_data = entry.data();

        if entry_data.len() < hdr_size {
            return Err(HandleOutbError::ReadHostFunctionCall(
                "G2H entry too short".into(),
            ));
        }

        let hdr: VirtqMsgHeader = *bytemuck::from_bytes(&entry_data[..hdr_size]);

        match hdr.msg_kind() {
            Ok(MsgKind::Log) => {
                let available = entry_data.len() - hdr_size;
                let log_len = (hdr.payload_len as usize).min(available);
                let payload = &entry_data[hdr_size..hdr_size + log_len];

                emit_guest_log(payload);

                consumer.complete(completion).map_err(|e| {
                    HandleOutbError::ReadHostFunctionCall(format!("G2H complete log: {e}"))
                })?;

                continue;
            }
            Ok(MsgKind::Request) => break (entry, completion),
            Ok(other) => {
                return Err(HandleOutbError::ReadHostFunctionCall(format!(
                    "G2H: expected Request via outb, got {:?}",
                    other
                )));
            }
            Err(unknown) => {
                return Err(HandleOutbError::ReadHostFunctionCall(format!(
                    "G2H: unknown message kind: 0x{unknown:02x}"
                )));
            }
        }
    };

    // Validate completion buffer before calling the host function
    let virtq::SendCompletion::Writable(mut wc) = completion else {
        return Err(HandleOutbError::WriteHostFunctionResponse(
            "G2H: expected writable completion, got ack (ring corruption)".into(),
        ));
    };

    let entry_data = entry.data();
    let hdr: VirtqMsgHeader = *bytemuck::from_bytes(&entry_data[..VirtqMsgHeader::SIZE]);
    let available = entry_data.len() - VirtqMsgHeader::SIZE;
    let payload_len = (hdr.payload_len as usize).min(available);
    let payload = &entry_data[VirtqMsgHeader::SIZE..VirtqMsgHeader::SIZE + payload_len];

    let call = FunctionCall::try_from(payload)
        .map_err(|e| HandleOutbError::ReadHostFunctionCall(e.to_string()))?;

    let name = call.function_name.clone();
    let args: Vec<ParameterValue> = call.parameters.unwrap_or(vec![]);

    let registry = host_funcs
        .try_lock()
        .map_err(|e| HandleOutbError::LockFailed(file!(), line!(), e.to_string()))?;

    let res = registry
        .call_host_function(&name, args)
        .map_err(|e| GuestError::new(ErrorCode::HostFunctionError, e.to_string()));

    let func_result = FunctionCallResult::new(res);
    let mut builder = flatbuffers::FlatBufferBuilder::new();
    let mut result_payload = func_result.encode(&mut builder).to_vec();

    let total = VirtqMsgHeader::SIZE + result_payload.len();
    if total > wc.capacity() {
        let too_large = GuestError::new(
            ErrorCode::HostFunctionError,
            "response too large for completion buffer".into(),
        );
        let fallback = FunctionCallResult::new(Err(too_large));
        let mut fb = flatbuffers::FlatBufferBuilder::new();
        result_payload = fallback.encode(&mut fb).to_vec();
    }

    let resp_header = VirtqMsgHeader::new(MsgKind::Response, 0, result_payload.len() as u32);
    let resp_header_bytes = bytemuck::bytes_of(&resp_header);

    wc.write_all(resp_header_bytes)
        .map_err(|e| HandleOutbError::WriteHostFunctionResponse(format!("{e}")))?;
    wc.write_all(&result_payload)
        .map_err(|e| HandleOutbError::WriteHostFunctionResponse(format!("{e}")))?;
    consumer
        .complete(wc.into())
        .map_err(|e| HandleOutbError::WriteHostFunctionResponse(format!("{e}")))?;

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
        OutBAction::Log | OutBAction::CallFunction => {
            // Legacy paths removed - these actions should no longer be
            // emitted by the guest. Ignore gracefully.
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
        OutBAction::VirtqNotify => outb_virtq_call(mem_mgr, host_funcs),
        #[cfg(feature = "trace_guest")]
        OutBAction::TraceBatch => Ok(()),
        #[cfg(feature = "mem_profile")]
        OutBAction::TraceMemoryAlloc => trace_info.handle_trace_mem_alloc(regs, mem_mgr),
        #[cfg(feature = "mem_profile")]
        OutBAction::TraceMemoryFree => trace_info.handle_trace_mem_free(regs, mem_mgr),
    }
}
