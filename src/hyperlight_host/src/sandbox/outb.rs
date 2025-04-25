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

use std::sync::{Arc, Mutex};

use hyperlight_common::flatbuffer_wrappers::function_types::ParameterValue;
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
use hyperlight_common::outb::OutBAction;
use log::{Level, Record};
use tracing::{instrument, Span};
use tracing_log::format_trace;

use super::host_funcs::HostFuncsWrapper;
use crate::hypervisor::handlers::{OutBHandler, OutBHandlerFunction, OutBHandlerWrapper};
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::shared_mem::HostSharedMemory;
use crate::{new_error, HyperlightError, Result};

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
    // this API is marked as follows, but it is the easiest way to work out if we should trace or log

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

/// Handles OutB operations from the guest.
#[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
fn handle_outb_impl(
    mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
    host_funcs: Arc<Mutex<HostFuncsWrapper>>,
    port: u16,
    byte: u64,
) -> Result<()> {
    match port.try_into()? {
        OutBAction::Log => outb_log(mem_mgr),
        OutBAction::CallFunction => {
            let call = mem_mgr.get_host_function_call()?; // pop output buffer
            let name = call.function_name.clone();
            let args: Vec<ParameterValue> = call.parameters.unwrap_or(vec![]);
            let res = host_funcs
                .try_lock()
                .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
                .call_host_function(&name, args)?;
            mem_mgr.write_response_from_host_method_call(&res)?; // push input buffers

            Ok(())
        }
        OutBAction::Abort => {
            let guest_error = ErrorCode::from(byte);
            let panic_context = mem_mgr.read_guest_panic_context_data()?;
            // trim off trailing \0 bytes if they exist
            let index_opt = panic_context.iter().position(|&x| x == 0x00);
            let trimmed = match index_opt {
                Some(n) => &panic_context[0..n],
                None => &panic_context,
            };
            let s = String::from_utf8_lossy(trimmed);
            match guest_error {
                ErrorCode::StackOverflow => Err(HyperlightError::StackOverflow()),
                _ => Err(HyperlightError::GuestAborted(
                    byte as u8,
                    s.trim().to_string(),
                )),
            }
        }
        OutBAction::DebugPrint => {
            let ch: char = match char::from_u32(byte as u32) {
                Some(c) => c,
                None => {
                    return Err(new_error!("Invalid character for logging: {}", byte));
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
    mut mem_mgr_wrapper: SandboxMemoryManager<HostSharedMemory>,
    host_funcs_wrapper: Arc<Mutex<HostFuncsWrapper>>,
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
