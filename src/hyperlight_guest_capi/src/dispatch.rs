// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use alloc::boxed::Box;
use alloc::slice;
use alloc::vec::Vec;
use core::ffi::{CStr, c_char};
use core::ptr::NonNull;

use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterType, ReturnType, ReturnValue,
};
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_guest::error::{HyperlightGuestError, Result};
use hyperlight_guest_bin::guest_function::definition::GuestFunctionDefinition;
use hyperlight_guest_bin::guest_function::register::GuestFunctionRegister;
use hyperlight_guest_bin::host_comm::call_host_function;

use crate::error::take_guest_error;
use crate::types::{FfiFunctionCall, FfiReturnValue, OwnedFfiFunctionCall};

static mut REGISTERED_C_GUEST_FUNCTIONS: GuestFunctionRegister<CGuestFunc> =
    GuestFunctionRegister::new();
static mut LAST_HOST_RESULT: Option<Result<ReturnValue>> = None;

type CGuestFunc = extern "C" fn(&FfiFunctionCall) -> *mut FfiReturnValue;

unsafe extern "C" {
    // The C guest supplies this fallback. Non-null results come from hl_result_from_*.
    fn c_guest_dispatch_function(function_call: &FfiFunctionCall) -> *mut FfiReturnValue;
}

#[unsafe(no_mangle)]
pub fn guest_dispatch_function(function_call: FunctionCall) -> Result<ReturnValue> {
    // Discard an error left by guest code outside the current dispatch.
    let _ = take_guest_error();

    let registry = &raw const REGISTERED_C_GUEST_FUNCTIONS;
    // SAFETY: Guest execution is serialized. The registry borrow ends before C runs.
    let registered_func =
        if let Some(definition) = unsafe { (&*registry).get(&function_call.function_name) } {
            let function_call_parameter_types: Vec<ParameterType> = function_call
                .parameters
                .iter()
                .flatten()
                .map(|p| p.into())
                .collect();
            definition.verify_parameters(&function_call_parameter_types)?;
            Some(definition.function_pointer)
        } else {
            None
        };

    let ffi_func_call = OwnedFfiFunctionCall::from_function_call(function_call)?;
    let function_result = match registered_func {
        Some(callback) => callback(ffi_func_call.as_ffi()),
        // SAFETY: The call owner keeps all borrowed C arguments alive.
        None => unsafe { c_guest_dispatch_function(ffi_func_call.as_ffi()) },
    };
    let function_result = NonNull::new(function_result).map(|result| {
        // SAFETY: C callbacks transfer ownership of an hl_result_from_* allocation.
        unsafe { Box::from_raw(result.as_ptr()) }
    });

    if let Some(error) = take_guest_error() {
        return Err(error);
    }

    let Some(function_result) = function_result else {
        // SAFETY: The call owner keeps the NUL-terminated name alive.
        let function_name = unsafe { ffi_func_call.as_ffi().copy_function_name() };
        let error = match registered_func {
            Some(_) => HyperlightGuestError::new(
                ErrorCode::GuestError,
                alloc::format!("C guest function {function_name:?} returned null"),
            ),
            None => HyperlightGuestError::new(ErrorCode::GuestFunctionNotFound, function_name),
        };
        return Err(error);
    };

    // SAFETY: C callbacks return values created by hl_result_from_*.
    Ok(unsafe { (*function_result).into_return_value() })
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_register_function_definition(
    function_name: *const c_char,
    func_ptr: CGuestFunc,
    param_no: usize,
    params_type: *const ParameterType,
    return_type: ReturnType,
) {
    let func_name = unsafe { CStr::from_ptr(function_name).to_string_lossy().into_owned() };

    let func_params = unsafe { slice::from_raw_parts(params_type, param_no).to_vec() };

    let func_def = GuestFunctionDefinition::new(func_name, func_params, return_type, func_ptr);

    let registry = &raw mut REGISTERED_C_GUEST_FUNCTIONS;
    // SAFETY: Single vCPU guest execution serializes registry access.
    unsafe { (&mut *registry).register(func_def) };
}

/// Call a host function. The return value can be retrieved with
/// `hl_get_host_return_value_as_*` immediately after.
#[unsafe(no_mangle)]
pub extern "C" fn hl_call_host_function(function_call: &FfiFunctionCall) {
    let parameters = unsafe { function_call.copy_parameters() };
    let func_name = unsafe { function_call.copy_function_name() };
    let return_type = unsafe { function_call.copy_return_type() };

    let result = call_host_function::<ReturnValue>(&func_name, Some(parameters), return_type);
    // SAFETY: Single vCPU guest execution serializes access to this slot.
    let _ = unsafe { (&raw mut LAST_HOST_RESULT).replace(Some(result)) };
}

/// Retrieve the return value stashed by the last `hl_call_host_function`.
///
/// Panics if no value was stashed, the host returned an error, or the type differs.
pub(crate) fn take_last_host_return<T: TryFrom<ReturnValue>>() -> T {
    // SAFETY: Single vCPU guest execution serializes access to this slot.
    let value = unsafe { (&raw mut LAST_HOST_RESULT).replace(None) }
        .expect("No host return value available")
        .expect("Host function returned an error");

    match T::try_from(value) {
        Ok(value) => value,
        Err(_) => panic!("Host return value type mismatch"),
    }
}
