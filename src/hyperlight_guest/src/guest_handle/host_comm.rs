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

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
use hyperlight_common::flatbuffer_wrappers::guest_log_level::LogLevel;
use tracing::instrument;

use super::handle::GuestHandle;
use crate::error::{HyperlightGuestError, Result};

impl GuestHandle {
    /// Get user memory region as bytes.
    #[instrument(skip_all, level = "Trace")]
    pub fn read_n_bytes_from_user_memory(&self, num: u64) -> Result<Vec<u8>> {
        let peb_ptr = self.peb().unwrap();
        let user_memory_region_ptr = unsafe { (*peb_ptr).init_data.ptr as *mut u8 };
        let user_memory_region_size = unsafe { (*peb_ptr).init_data.size };

        if num > user_memory_region_size {
            Err(HyperlightGuestError::new(
                ErrorCode::GuestError,
                format!(
                    "Requested {} bytes from user memory, but only {} bytes are available",
                    num, user_memory_region_size
                ),
            ))
        } else {
            let user_memory_region_slice =
                unsafe { core::slice::from_raw_parts(user_memory_region_ptr, num as usize) };
            let user_memory_region_bytes = user_memory_region_slice.to_vec();

            Ok(user_memory_region_bytes)
        }
    }

    /// Log a message with the specified log level, source, caller, source file, and line number.
    pub fn log_message(
        &self,
        log_level: LogLevel,
        message: &str,
        source: &str,
        caller: &str,
        source_file: &str,
        line: u32,
    ) {
        // Closure to send log message to host via G2H virtqueue
        let _send_to_host = || {
            let guest_log_data = GuestLogData::new(
                message.to_string(),
                source.to_string(),
                log_level,
                caller.to_string(),
                source_file.to_string(),
                line,
            );

            let bytes: Vec<u8> = guest_log_data
                .try_into()
                .expect("Failed to convert GuestLogData to bytes");

            crate::virtq::with_context(|ctx| {
                ctx.emit_log(&bytes)
                    .expect("Unable to send log data via virtq");
            });
        };

        #[cfg(all(feature = "trace_guest", target_arch = "x86_64"))]
        if hyperlight_guest_tracing::is_trace_enabled() {
            // If the "trace_guest" feature is enabled and tracing is initialized, log using tracing
            tracing::trace!(
                event = message,
                level = ?log_level,
                code.filepath = source,
                caller = caller,
                source_file = source_file,
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
}
