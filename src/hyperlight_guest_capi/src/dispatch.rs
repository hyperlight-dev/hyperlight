use alloc::boxed::Box;
use alloc::slice;
use alloc::vec::Vec;
use core::ffi::{c_char, CStr};
use core::mem;

use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterType, ReturnType};
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_guest::error::{HyperlightGuestError, Result};
use hyperlight_guest::guest_function_definition::GuestFunctionDefinition;
use hyperlight_guest::guest_function_register::GuestFunctionRegister;
use hyperlight_guest::host_function_call::call_host_function_internal;

use crate::types::{FfiFunctionCall, FfiVec};
static mut REGISTERED_C_GUEST_FUNCTIONS: GuestFunctionRegister = GuestFunctionRegister::new();

type CGuestFunc = extern "C" fn(&FfiFunctionCall) -> Box<FfiVec>;

extern "C" {
    // NOTE *mut FfiVec must be a Box<FfiVec>. This will be the case as long as the guest
    // returns a FfiVec that they created using the c-api hl_flatbuffer_result_from_* functions.
    fn c_guest_dispatch_function(function_call: &FfiFunctionCall) -> *mut FfiVec;
}

#[no_mangle]
pub fn guest_dispatch_function(function_call: FunctionCall) -> Result<Vec<u8>> {
    if let Some(registered_func) =
        unsafe { REGISTERED_C_GUEST_FUNCTIONS.get(&function_call.function_name) }
    {
        let function_call_parameter_types: Vec<ParameterType> = function_call
            .parameters
            .iter()
            .flatten()
            .map(|p| p.into())
            .collect();
        registered_func.verify_parameters(&function_call_parameter_types)?;

        let ffi_func_call = FfiFunctionCall::from_function_call(function_call)?;

        let guest_func =
            unsafe { mem::transmute::<usize, CGuestFunc>(registered_func.function_pointer) };
        let function_result = guest_func(&ffi_func_call);

        unsafe { Ok(FfiVec::into_vec(*function_result)) }
    } else {
        // The given function is not registered. The guest should implement a function called c_guest_dispatch_function to handle this.

        // TODO: ideally we would define a default implementation of this with weak linkage so the guest is not required
        // to implement the function but its seems that weak linkage is an unstable feature so for now its probably better
        // to not do that.
        let function_name = function_call.function_name.clone();
        let ffi_func_call = FfiFunctionCall::from_function_call(function_call)?;
        let function_result = unsafe { c_guest_dispatch_function(&ffi_func_call) };
        if function_result.is_null() {
            Err(HyperlightGuestError::new(
                ErrorCode::GuestFunctionNotFound,
                function_name,
            ))
        } else {
            let result = unsafe { Box::from_raw(function_result) };
            Ok(unsafe { FfiVec::into_vec(*result) })
        }
    }
}

#[no_mangle]
pub extern "C" fn hl_register_function_definition(
    function_name: *const c_char,
    func_ptr: CGuestFunc,
    param_no: usize,
    params_type: *const ParameterType,
    return_type: ReturnType,
) {
    let func_name = unsafe { CStr::from_ptr(function_name).to_string_lossy().into_owned() };

    let func_params = unsafe { slice::from_raw_parts(params_type, param_no).to_vec() };

    let func_def =
        GuestFunctionDefinition::new(func_name, func_params, return_type, func_ptr as usize);

    #[allow(static_mut_refs)]
    unsafe { &mut REGISTERED_C_GUEST_FUNCTIONS }.register(func_def);
}

/// The caller is responsible for freeing the memory associated with given `FfiFunctionCall`.
#[no_mangle]
pub extern "C" fn hl_call_host_function(function_call: &FfiFunctionCall) {
    let parameters = unsafe { function_call.copy_parameters() };
    let func_name = unsafe { function_call.copy_function_name() };
    let return_type = unsafe { function_call.copy_return_type() };

    // Use the non-generic internal implementation
    // The C API will then call specific getter functions to fetch the properly typed return value
    let _ = call_host_function_internal(&func_name, Some(parameters), return_type)
        .expect("Failed to call host function");
}
