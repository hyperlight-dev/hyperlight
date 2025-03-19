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

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ffi::{c_char, CStr};

use hyperlight_common::flatbuffer_wrappers::guest_error::{ErrorCode, GuestError};
use log::error;

use crate::entrypoint::halt;
use crate::host_function_call::{outb, OutBAction};
use crate::PEB;

pub(crate) fn write_error(error_code: ErrorCode, message: Option<&str>) {
    let peb = unsafe { (*PEB).clone() };
    let guest_error = GuestError::new(
        error_code.clone(),
        message.map_or("".to_string(), |m| m.to_string()),
    );
    let mut guest_error_buffer: Vec<u8> = (&guest_error)
        .try_into()
        .expect("Invalid guest_error_buffer, could not be converted to a Vec<u8>");

    unsafe {
        assert_ne!(!peb.guest_error_data_ptr, 0);
        let len = guest_error_buffer.len();
        if guest_error_buffer.len() > peb.guest_error_data_size as usize {
            error!(
                "Guest error buffer is too small to hold the error message: size {} buffer size {} message may be truncated",
                guest_error_buffer.len(),
                peb.guest_error_data_size as usize
            );
            // get the length of the message
            let message_len = message.map_or("".to_string(), |m| m.to_string()).len();
            // message is too long, truncate it
            let truncate_len =
                message_len - (guest_error_buffer.len() - peb.guest_error_data_size as usize);
            let truncated_message = message
                .map_or("".to_string(), |m| m.to_string())
                .chars()
                .take(truncate_len)
                .collect::<String>();
            let guest_error = GuestError::new(error_code, truncated_message);
            guest_error_buffer = (&guest_error)
                .try_into()
                .expect("Invalid guest_error_buffer, could not be converted to a Vec<u8>");
        }

        // Optimally, we'd use copy_from_slice here, but, because
        // p_guest_error_buffer is a *mut c_void, we can't do that.
        // Instead, we do the copying manually using pointer arithmetic.
        // Plus; before, we'd do an assert w/ the result from copy_from_slice,
        // but, because copy_nonoverlapping doesn't return anything, we can't do that.
        // Instead, we do the prior asserts/checks to check the destination pointer isn't null
        // and that there is enough space in the destination buffer for the copy.
        let dest_ptr = peb.guest_error_data_ptr as *mut u8;
        core::ptr::copy_nonoverlapping(guest_error_buffer.as_ptr(), dest_ptr, len);
    }
}

pub(crate) fn reset_error() {
    unsafe {
        core::ptr::write_bytes(
            (*PEB).guest_error_data_ptr as *mut u8,
            0,
            (*PEB).guest_error_data_size as usize,
        );
    }
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
    outb(OutBAction::Abort as u16, ErrorCode::StackOverflow as u8);
}

#[no_mangle]
pub(crate) extern "win64" fn set_invalid_runmode_error() {
    panic!("Invalid run mode in __chkstk");
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
