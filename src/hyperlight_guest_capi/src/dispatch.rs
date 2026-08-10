// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use alloc::boxed::Box;
use alloc::slice;
use alloc::vec::Vec;
use core::ffi::{CStr, c_char};

use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterType, ReturnType, ReturnValue,
};
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_guest::error::{HyperlightGuestError, Result};
use hyperlight_guest::transport;
use hyperlight_guest_bin::guest_function::definition::GuestFunctionDefinition;
use hyperlight_guest_bin::guest_function::register::GuestFunctionRegister;
use hyperlight_guest_bin::host_comm::call_host_function;

use crate::types::{FfiFunctionCall, FfiReturnValue, OwnedFfiFunctionCall};
static mut REGISTERED_C_GUEST_FUNCTIONS: GuestFunctionRegister<CGuestFunc> =
    GuestFunctionRegister::new();

type CGuestFunc = extern "C" fn(&FfiFunctionCall) -> *mut FfiReturnValue;

unsafe extern "C" {
    // The guest must return a value created by an hl_result_from_* function.
    fn c_guest_dispatch_function(function_call: &FfiFunctionCall) -> *mut FfiReturnValue;
}

#[unsafe(no_mangle)]
pub fn guest_dispatch_function(function_call: FunctionCall) -> Result<ReturnValue> {
    // Discard an error left by guest code outside the current dispatch.
    let _ = transport::with_ctx(|ctx| ctx.take_guest_error());

    // Use &raw const to get an immutable reference to the static HashMap
    // this is to avoid the clippy warning "shared reference to mutable static"
    if let Some(registered_func) =
        unsafe { (*(&raw const REGISTERED_C_GUEST_FUNCTIONS)).get(&function_call.function_name) }
    {
        let function_call_parameter_types: Vec<ParameterType> = function_call
            .parameters
            .iter()
            .flatten()
            .map(|p| p.into())
            .collect();
        registered_func.verify_parameters(&function_call_parameter_types)?;

        let function_name = function_call.function_name.clone();
        let ffi_func_call = OwnedFfiFunctionCall::from_function_call(function_call)?;
        let function_result = (registered_func.function_pointer)(ffi_func_call.as_ffi());
        if function_result.is_null() {
            if let Some(error) = transport::with_ctx(|ctx| ctx.take_guest_error()) {
                return Err(HyperlightGuestError::new(error.code, error.message));
            }
            return Err(HyperlightGuestError::new(
                ErrorCode::GuestError,
                alloc::format!("C guest function {function_name:?} returned null"),
            ));
        }

        // SAFETY: the pointer is non-null and C functions return ownership.
        let function_result = unsafe { Box::from_raw(function_result) };
        // SAFETY: registered C functions return values created by hl_result_from_*.
        let function_result = unsafe { (*function_result).into_return_value() };

        if let Some(error) = transport::with_ctx(|ctx| ctx.take_guest_error()) {
            return Err(HyperlightGuestError::new(error.code, error.message));
        }

        Ok(function_result)
    } else {
        // The given function is not registered. The guest should implement a function called c_guest_dispatch_function to handle this.

        // TODO: ideally we would define a default implementation of this with weak linkage so the guest is not required
        // to implement the function but its seems that weak linkage is an unstable feature so for now its probably better
        // to not do that.
        let function_name = function_call.function_name.clone();
        let ffi_func_call = OwnedFfiFunctionCall::from_function_call(function_call)?;
        let function_result = unsafe { c_guest_dispatch_function(ffi_func_call.as_ffi()) };
        if function_result.is_null() {
            if let Some(error) = transport::with_ctx(|ctx| ctx.take_guest_error()) {
                return Err(HyperlightGuestError::new(error.code, error.message));
            }
            Err(HyperlightGuestError::new(
                ErrorCode::GuestFunctionNotFound,
                function_name,
            ))
        } else {
            let result = unsafe { Box::from_raw(function_result) };
            // SAFETY: non-null fallback results are created by hl_result_from_*.
            let result = unsafe { (*result).into_return_value() };

            if let Some(error) = transport::with_ctx(|ctx| ctx.take_guest_error()) {
                return Err(HyperlightGuestError::new(error.code, error.message));
            }

            Ok(result)
        }
    }
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

    // Use &raw mut to get a mutable raw pointer, then dereference it
    // this is to avoid the clippy warning "shared reference to mutable static"
    unsafe { (&mut *(&raw mut REGISTERED_C_GUEST_FUNCTIONS)).register(func_def) };
}

/// Call a host function. The return value can be retrieved with
/// `hl_get_host_return_value_as_*` immediately after.
#[unsafe(no_mangle)]
pub extern "C" fn hl_call_host_function(function_call: &FfiFunctionCall) {
    let parameters = unsafe { function_call.copy_parameters() };
    let func_name = unsafe { function_call.copy_function_name() };
    let return_type = unsafe { function_call.copy_return_type() };

    let result = call_host_function::<ReturnValue>(&func_name, Some(parameters), return_type);
    transport::with_ctx(|ctx| ctx.stash_host_result(result));
}

/// Retrieve the return value stashed by the last `hl_call_host_function`.
pub(crate) fn take_last_host_return<T: TryFrom<ReturnValue>>() -> T {
    transport::with_ctx(|ctx| ctx.take_host_return::<T>())
}
