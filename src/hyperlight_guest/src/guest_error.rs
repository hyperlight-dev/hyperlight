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

use alloc::string::ToString;
use alloc::vec::Vec;
use core::ffi::{c_char, CStr};

use hyperlight_common::flatbuffer_wrappers::guest_error::{ErrorCode, GuestError};
use hyperlight_common::outb::OutBAction;

use crate::entrypoint::halt;
use crate::host_function_call::outb;
use crate::shared_output_data::push_shared_output_data;

pub(crate) fn write_error(error_code: ErrorCode, message: Option<&str>) {
    let guest_error = GuestError::new(
        error_code.clone(),
        message.map_or("".to_string(), |m| m.to_string()),
    );
    let guest_error_buffer: Vec<u8> = (&guest_error)
        .try_into()
        .expect("Invalid guest_error_buffer, could not be converted to a Vec<u8>");

    push_shared_output_data(guest_error_buffer)
        .expect("Unable to push guest error to shared output data");
}

pub(crate) fn set_error(error_code: ErrorCode, message: &str) {
    write_error(error_code, Some(message));
}

pub(crate) fn set_error_and_halt(error_code: ErrorCode, message: &str) {
    set_error(error_code, message);
    halt();
}

#[no_mangle]
pub(crate) extern "win64" fn set_stack_allocate_error() {
    outb(OutBAction::Abort as u16, &[ErrorCode::StackOverflow as u8]);
}

/// Exposes a C API to allow the guest to set an error
///
/// # Safety
/// TODO
/// cbindgen:ignore
#[no_mangle]
#[allow(non_camel_case_types)]
pub unsafe extern "C" fn setError(code: u64, message: *const c_char) {
    let error_code = ErrorCode::from(code);
    match message.is_null() {
        true => write_error(error_code, None),
        false => {
            let message = unsafe { CStr::from_ptr(message).to_str().ok() }
                .expect("Invalid error message, could not be converted to a string");
            write_error(error_code, Some(message));
        }
    }
    halt();
}
