/*
Copyright 2025 The Hyperlight Authors.

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

use core::ffi::c_char;

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_guest_bin::guest_err::setError;

#[unsafe(no_mangle)]
pub extern "C" fn hl_set_error(err: ErrorCode, message: *const c_char) {
    unsafe {
        setError(err.into(), message);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_abort_with_code(err: i32) {
    hyperlight_guest::exit::abort_with_code(&[err as u8]);
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_abort_with_code_and_message(err: i32, message: *const c_char) {
    unsafe { hyperlight_guest::exit::abort_with_code_and_message(&[err as u8], message) };
}
