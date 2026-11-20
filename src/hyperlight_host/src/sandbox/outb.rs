// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use std::sync::{Arc, Mutex};

use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCallType;
use hyperlight_common::flatbuffer_wrappers::function_types::FunctionCallResult;
use hyperlight_common::flatbuffer_wrappers::guest_error::{ErrorCode, GuestError};
use hyperlight_common::outb::{Exception, OutBAction};
use hyperlight_common::transport::MsgKind;
use hyperlight_common::virtq::ReplyChain;
use tracing::{Span, instrument};

use super::host_funcs::FunctionRegistry;
#[cfg(feature = "mem_profile")]
use crate::hypervisor::regs::CommonRegisters;
use crate::mem::mgr::{ExecutionMode, SandboxMemoryManager};
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
    #[error("Guest called a host function during a snapshot checkpoint")]
    HostCallDuringCheckpoint,
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
