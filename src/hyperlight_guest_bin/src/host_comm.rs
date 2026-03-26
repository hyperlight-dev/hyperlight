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

use alloc::string::ToString;
use alloc::vec::Vec;

use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterValue, ReturnType, ReturnValue,
};
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::flatbuffer_wrappers::util::get_flatbuffer_result;
use hyperlight_common::func::{ParameterTuple, SupportedReturnType};
use hyperlight_guest::error::{HyperlightGuestError, Result};

use crate::GUEST_HANDLE;

pub fn call_host_function<T>(
    function_name: &str,
    parameters: Option<Vec<ParameterValue>>,
    return_type: ReturnType,
) -> Result<T>
where
    T: TryFrom<ReturnValue>,
{
    #[cfg(feature = "virtq")]
    {
        hyperlight_guest::virtq::with_context(|ctx| {
            ctx.call_host_function(function_name, parameters, return_type)
        })
    }
    #[cfg(not(feature = "virtq"))]
    {
        let handle = unsafe { GUEST_HANDLE };
        handle.call_host_function::<T>(function_name, parameters, return_type)
    }
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
            Some(Vec::from(&[ParameterValue::String(message)])),
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
