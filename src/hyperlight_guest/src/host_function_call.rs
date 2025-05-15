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

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::arch;

use hyperlight_common::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterValue, ReturnType, ReturnValue,
};
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::flatbuffer_wrappers::util::get_flatbuffer_result;
use hyperlight_common::outb::OutBAction;

use crate::error::{HyperlightGuestError, Result};
use crate::shared_input_data::try_pop_shared_input_data_into;
use crate::shared_output_data::push_shared_output_data;

/// Get a return value from a host function call.
/// This usually requires a host function to be called first using `call_host_function`.
pub fn get_host_return_value<T: TryFrom<ReturnValue>>() -> Result<T> {
    let return_value = try_pop_shared_input_data_into::<ReturnValue>()
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

// TODO: Make this generic, return a Result<T, ErrorCode> this should allow callers to call this function and get the result type they expect
// without having to do the conversion themselves

pub fn call_host_function(
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

    push_shared_output_data(host_function_call_buffer)?;

    outb(OutBAction::CallFunction as u16, &[0]);

    Ok(())
}

pub fn outb(port: u16, data: &[u8]) {
    unsafe {
        let mut i = 0;
        while i < data.len() {
            let remaining = data.len() - i;
            let chunk_len = remaining.min(3);
            let mut chunk = [0u8; 4];
            chunk[0] = chunk_len as u8;
            chunk[1..1 + chunk_len].copy_from_slice(&data[i..i + chunk_len]);
            let val = u32::from_le_bytes(chunk);
            out32(port, val);
            i += chunk_len;
        }
    }
}

pub(crate) unsafe fn out32(port: u16, val: u32) {
    arch::asm!("out dx, eax", in("dx") port, in("eax") val, options(preserves_flags, nomem, nostack));
}

/// Prints a message using `OutBAction::DebugPrint`. It transmits bytes of a message
/// through several VMExists and, with such, it is slower than
/// `print_output_with_host_print`.
///
/// This function should be used in debug mode only. This function does not
/// require memory to be setup to be used.
pub fn debug_print(msg: &str) {
    outb(OutBAction::DebugPrint as u16, msg.as_bytes());
}

/// Print a message using the host's print function.
///
/// This function requires memory to be setup to be used. In particular, the
/// existence of the input and output memory regions.
pub fn print_output_with_host_print(function_call: &FunctionCall) -> Result<Vec<u8>> {
    if let ParameterValue::String(message) = function_call.parameters.clone().unwrap()[0].clone() {
        call_host_function(
            "HostPrint",
            Some(Vec::from(&[ParameterValue::String(message.to_string())])),
            ReturnType::Int,
        )?;
        let res_i = get_host_return_value::<i32>()?;
        Ok(get_flatbuffer_result(res_i))
    } else {
        Err(HyperlightGuestError::new(
            ErrorCode::GuestError,
            "Wrong Parameters passed to print_output_with_host_print".to_string(),
        ))
    }
}
