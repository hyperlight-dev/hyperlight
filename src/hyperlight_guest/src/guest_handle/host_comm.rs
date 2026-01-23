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

use flatbuffers::FlatBufferBuilder;
use hyperlight_common::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
use hyperlight_common::flatbuffer_wrappers::function_types::{
    FunctionCallResult, ParameterValue, ReturnType, ReturnValue,
};
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
use hyperlight_common::flatbuffer_wrappers::guest_log_level::LogLevel;
use hyperlight_common::flatbuffer_wrappers::util::estimate_flatbuffer_capacity;
use hyperlight_common::outb::OutBAction;
use tracing::instrument;

use super::handle::GuestHandle;
use crate::error::{HyperlightGuestError, Result};
use crate::exit::out32;

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

    /// Get a return value from a host function call.
    /// This usually requires a host function to be called first using
    /// `call_host_function_internal`.
    ///
    /// When calling `call_host_function<T>`, this function is called
    /// internally to get the return value.
    #[instrument(skip_all, level = "Trace")]
    pub fn get_host_return_value<T: TryFrom<ReturnValue>>(&self) -> Result<T> {
        let inner = self
            .try_pop_shared_input_data_into::<FunctionCallResult>()
            .expect("Unable to deserialize a return value from host")
            .into_inner();

        match inner {
            Ok(ret) => T::try_from(ret).map_err(|_| {
                let expected = core::any::type_name::<T>();
                HyperlightGuestError::new(
                    ErrorCode::UnsupportedParameterType,
                    format!("Host return value could not be converted to expected {expected}",),
                )
            }),
            Err(e) => Err(HyperlightGuestError {
                kind: e.code,
                message: e.message,
            }),
        }
    }

    pub fn get_host_return_raw(&self) -> Result<ReturnValue> {
        let inner = self
            .try_pop_shared_input_data_into::<FunctionCallResult>()
            .expect("Unable to deserialize a return value from host")
            .into_inner();

        match inner {
            Ok(ret) => Ok(ret),
            Err(e) => Err(HyperlightGuestError {
                kind: e.code,
                message: e.message,
            }),
        }
    }

    /// Call a host function without reading its return value from shared mem.
    /// This is used by both the Rust and C APIs to reduce code duplication.
    ///
    /// Note: The function return value must be obtained by calling
    /// `get_host_return_value`.
    #[instrument(skip_all, level = "Trace")]
    pub fn call_host_function_without_returning_result(
        &self,
        function_name: &str,
        parameters: Option<Vec<ParameterValue>>,
        return_type: ReturnType,
    ) -> Result<()> {
        let estimated_capacity =
            estimate_flatbuffer_capacity(function_name, parameters.as_deref().unwrap_or(&[]));

        let host_function_call = FunctionCall::new(
            function_name.to_string(),
            parameters,
            FunctionCallType::Host,
            return_type,
        );

        let mut builder = FlatBufferBuilder::with_capacity(estimated_capacity);

        let host_function_call_buffer = host_function_call.encode(&mut builder);
        self.push_shared_output_data(host_function_call_buffer)?;

        unsafe {
            out32(OutBAction::CallFunction as u16, 0);
        }

        Ok(())
    }

    /// Call a host function with the given parameters and return type.
    /// This function serializes the function call and its parameters,
    /// sends it to the host, and then retrieves the return value.
    ///
    /// The return value is deserialized into the specified type `T`.
    #[instrument(skip_all, level = "Info")]
    pub fn call_host_function<T: TryFrom<ReturnValue>>(
        &self,
        function_name: &str,
        parameters: Option<Vec<ParameterValue>>,
        return_type: ReturnType,
    ) -> Result<T> {
        self.call_host_function_without_returning_result(function_name, parameters, return_type)?;
        self.get_host_return_value::<T>()
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
        // Closure to send log message to host
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

            self.push_shared_output_data(&bytes)
                .expect("Unable to push log data to shared output data");

            unsafe {
                out32(OutBAction::Log as u16, 0);
            }
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
