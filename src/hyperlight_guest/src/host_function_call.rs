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
use core::arch::global_asm;

use hyperlight_common::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterValue, ReturnType, ReturnValue,
};
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::flatbuffer_wrappers::util::get_flatbuffer_result;
use hyperlight_common::mem::RunMode;

use crate::error::{HyperlightGuestError, Result};
use crate::host_error::check_for_host_error;
use crate::host_functions::validate_host_function_call;
use crate::shared_input_data::try_pop_shared_input_data_into;
use crate::shared_output_data::push_shared_output_data;
use crate::{OUTB_PTR, OUTB_PTR_WITH_CONTEXT, P_PEB, RUNNING_MODE};

pub enum OutBAction {
    Log = 99,
    CallFunction = 101,
    Abort = 102,
}

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

    validate_host_function_call(&host_function_call)?;

    let host_function_call_buffer: Vec<u8> = host_function_call
        .try_into()
        .expect("Unable to serialize host function call");

    push_shared_output_data(host_function_call_buffer)?;

    outb(OutBAction::CallFunction as u16, 0);

    Ok(())
}

pub fn outb(port: u16, value: u8) {
    unsafe {
        match RUNNING_MODE {
            RunMode::Hypervisor => {
                hloutb(port, value);
            }
            RunMode::InProcessLinux | RunMode::InProcessWindows => {
                if let Some(outb_func) = OUTB_PTR_WITH_CONTEXT {
                    if let Some(peb_ptr) = P_PEB {
                        outb_func((*peb_ptr).pOutbContext, port, value);
                    }
                } else if let Some(outb_func) = OUTB_PTR {
                    outb_func(port, value);
                } else {
                    panic!("Tried to call outb without hypervisor and without outb function ptrs");
                }
            }
            _ => {
                panic!("Tried to call outb in invalid runmode");
            }
        }

        check_for_host_error();
    }
}

extern "win64" {
    fn hloutb(port: u16, value: u8);
}

pub fn print_output_as_guest_function(function_call: &FunctionCall) -> Result<Vec<u8>> {
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
            "Wrong Parameters passed to print_output_as_guest_function".to_string(),
        ))
    }
}

// port: RCX(cx), value: RDX(dl)
global_asm!(
    ".global hloutb
        hloutb:
            xor rax, rax
            mov al, dl
            mov dx, cx
            out dx, al
            ret"
);
