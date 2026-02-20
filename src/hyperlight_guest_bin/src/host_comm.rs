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

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ffi::{CStr, c_char};
use core::mem;

use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterValue, ReturnType, ReturnValue,
};
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::flatbuffer_wrappers::util::get_flatbuffer_result;
use hyperlight_common::func::{ParameterTuple, SupportedReturnType};
use hyperlight_guest::error::{HyperlightGuestError, Result};

const BUFFER_SIZE: usize = 1000;
static mut MESSAGE_BUFFER: Vec<u8> = Vec::new();

use crate::GUEST_HANDLE;

pub fn call_host_function<T>(
    function_name: &str,
    parameters: Option<Vec<ParameterValue>>,
    return_type: ReturnType,
) -> Result<T>
where
    T: TryFrom<ReturnValue>,
{
    let handle = unsafe { GUEST_HANDLE };
    handle.call_host_function::<T>(function_name, parameters, return_type)
}

pub fn call_host<T>(function_name: impl AsRef<str>, args: impl ParameterTuple) -> Result<T>
where
    T: SupportedReturnType + TryFrom<ReturnValue>,
{
    call_host_function::<T>(function_name.as_ref(), Some(args.into_value()), T::TYPE)
}

pub fn call_host_function_without_returning_result(
    function_name: &str,
    parameters: Option<Vec<ParameterValue>>,
    return_type: ReturnType,
) -> Result<()> {
    let handle = unsafe { GUEST_HANDLE };
    handle.call_host_function_without_returning_result(function_name, parameters, return_type)
}

pub fn get_host_return_value_raw() -> Result<ReturnValue> {
    let handle = unsafe { GUEST_HANDLE };
    handle.get_host_return_raw()
}

pub fn get_host_return_value<T: TryFrom<ReturnValue>>() -> Result<T> {
    let handle = unsafe { GUEST_HANDLE };
    handle.get_host_return_value::<T>()
}

pub fn read_n_bytes_from_user_memory(num: u64) -> Result<Vec<u8>> {
    let handle = unsafe { GUEST_HANDLE };
    handle.read_n_bytes_from_user_memory(num)
}

/// Print a message using the host's print function.
///
/// This function requires memory to be setup to be used. In particular, the
/// existence of the input and output memory regions.
pub fn print_output_with_host_print(function_call: FunctionCall) -> Result<Vec<u8>> {
    let handle = unsafe { GUEST_HANDLE };
    if let ParameterValue::String(message) = function_call.parameters.unwrap().remove(0) {
        let res = handle.call_host_function::<i32>(
            "HostPrint",
            Some(Vec::from(&[ParameterValue::String(message.to_string())])),
            ReturnType::Int,
        )?;

        Ok(get_flatbuffer_result(res))
    } else {
        Err(HyperlightGuestError::new(
            ErrorCode::GuestError,
            "Wrong Parameters passed to print_output_with_host_print".to_string(),
        ))
    }
}

/// Exposes a C API to allow the guest to print a string
///
/// # Safety
/// This function is not thread safe
#[unsafe(no_mangle)]
#[allow(static_mut_refs)]
pub unsafe extern "C" fn _putchar(c: c_char) {
    let handle = unsafe { GUEST_HANDLE };
    let char = c as u8;
    let message_buffer = unsafe { &mut MESSAGE_BUFFER };

    // Extend buffer capacity if it's empty (like `with_capacity` in lazy_static).
    // TODO: replace above Vec::new() with Vec::with_capacity once it's stable in const contexts.
    if message_buffer.capacity() == 0 {
        message_buffer.reserve(BUFFER_SIZE);
    }

    message_buffer.push(char);

    if message_buffer.len() == BUFFER_SIZE || char == b'\0' {
        let str = if char == b'\0' {
            CStr::from_bytes_until_nul(message_buffer)
                .expect("No null byte in buffer")
                .to_string_lossy()
                .into_owned()
        } else {
            String::from_utf8(mem::take(message_buffer))
                .expect("Failed to convert buffer to string")
        };

        // HostPrint returns an i32, but we don't care about the return value
        let _ = handle
            .call_host_function::<i32>(
                "HostPrint",
                Some(Vec::from(&[ParameterValue::String(str)])),
                ReturnType::Int,
            )
            .expect("Failed to call HostPrint");

        // Clear the buffer after sending
        message_buffer.clear();
    }
}
