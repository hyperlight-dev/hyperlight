// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use core::ffi::{CStr, c_char};

use hyperlight_common::flatbuffer_wrappers::guest_error::{ErrorCode, GuestError};
use hyperlight_guest::transport;

use crate::alloc::borrow::ToOwned;

#[unsafe(no_mangle)]
pub extern "C" fn hl_set_error(err: ErrorCode, message: *const c_char) {
    let cstr = unsafe { CStr::from_ptr(message) };
    let guest_error = GuestError::new(
        err.into(),
        cstr.to_str()
            .expect("Failed to convert CStr to &str")
            .to_owned(),
    );
    transport::with_ctx(|ctx| ctx.set_guest_error(guest_error));
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_abort_with_code(err: i32) {
    hyperlight_guest::exit::abort_with_code(&[err as u8]);
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_abort_with_code_and_message(err: i32, message: *const c_char) {
    unsafe { hyperlight_guest::exit::abort_with_code_and_message(&[err as u8], message) };
}
