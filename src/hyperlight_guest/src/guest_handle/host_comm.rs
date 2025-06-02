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

use hyperlight_common::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterValue, ReturnType, ReturnValue,
};
use hyperlight_common::flatbuffer_wrappers::guest_error::{ErrorCode, GuestError};
use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
use hyperlight_common::flatbuffer_wrappers::guest_log_level::LogLevel;
use hyperlight_common::outb::OutBAction;

use super::handle::GuestHandle;
use crate::error::{HyperlightGuestError, Result};
use crate::exit::out32;

impl GuestHandle {
    /// Get a return value from a host function call.
    /// This usually requires a host function to be called first using
    /// `call_host_function_internal`.
    ///
    /// When calling `call_host_function<T>`, this function is called
    /// internally to get the return value.
    pub fn get_host_return_value<T: TryFrom<ReturnValue>>(&self) -> Result<T> {
        let return_value = self
            .try_pop_shared_input_data_into::<ReturnValue>()
            .expect("Unable to deserialize a return value from host");
        T::try_from(return_value).map_err(|_| {
            HyperlightGuestError::new(
                ErrorCode::GuestError,
                format!(
                    "Host return value was not a {} as expected",
                    core::any::type_name::<T>()
                ),
            )
        })
    }

    /// Call a host function without reading its return value from shared mem.
    /// This is used by both the Rust and C APIs to reduce code duplication.
    ///
    /// Note: The function return value must be obtained by calling
    /// `get_host_return_value`.
    pub fn call_host_function_without_returning_result(
        &self,
        function_name: &str,
        parameters: Option<Vec<ParameterValue>>,
        return_type: ReturnType,
    ) -> Result<()> {
        let host_function_call = FunctionCall::new(
            function_name.to_string(),
            parameters,
            FunctionCallType::Host,
            return_type,
        );

        let host_function_call_buffer: Vec<u8> = host_function_call
            .try_into()
            .expect("Unable to serialize host function call");

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
    pub fn call_host_function<T: TryFrom<ReturnValue>>(
        &self,
        function_name: &str,
        parameters: Option<Vec<ParameterValue>>,
        return_type: ReturnType,
    ) -> Result<T> {
        self.call_host_function_without_returning_result(function_name, parameters, return_type)?;
        self.get_host_return_value::<T>()
    }

    /// Write an error to the shared output data buffer.
    pub fn write_error(&self, error_code: ErrorCode, message: Option<&str>) {
        let guest_error: GuestError = GuestError::new(
            error_code.clone(),
            message.map_or("".to_string(), |m| m.to_string()),
        );
        let guest_error_buffer: Vec<u8> = (&guest_error)
            .try_into()
            .expect("Invalid guest_error_buffer, could not be converted to a Vec<u8>");

        if let Err(e) = self.push_shared_output_data(guest_error_buffer) {
            panic!("Unable to push guest error to shared output data: {:#?}", e);
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

        self.push_shared_output_data(bytes)
            .expect("Unable to push log data to shared output data");

        unsafe {
            out32(OutBAction::Log as u16, 0);
        }
    }
}
