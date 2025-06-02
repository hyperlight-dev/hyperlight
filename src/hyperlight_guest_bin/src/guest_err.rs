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

use core::ffi::{c_char, CStr};

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_guest::exit::halt;

use crate::GUEST_HANDLE;

/// Exposes a C API to allow the guest to set an error
///
/// # Safety
/// TODO
/// cbindgen:ignore
#[unsafe(no_mangle)]
#[allow(non_camel_case_types)]
pub unsafe extern "C" fn setError(code: u64, message: *const c_char) {
    let handle = unsafe { GUEST_HANDLE };

    let error_code = ErrorCode::from(code);
    match message.is_null() {
        true => handle.write_error(error_code, None),
        false => {
            let message = unsafe { CStr::from_ptr(message).to_str().ok() }
                .expect("Invalid error message, could not be converted to a string");
            handle.write_error(error_code, Some(message));
        }
    }

    halt();
}
