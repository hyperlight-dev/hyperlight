// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use core::ffi::{CStr, c_char};

use flatbuffers::FlatBufferBuilder;
use hyperlight_common::flatbuffer_wrappers::function_types::FunctionCallResult;
use hyperlight_common::flatbuffer_wrappers::guest_error::{ErrorCode, GuestError};
use hyperlight_guest_bin::GUEST_HANDLE;

use crate::alloc::borrow::ToOwned;

#[unsafe(no_mangle)]
pub extern "C" fn hl_set_error(err: ErrorCode, message: *const c_char) {
    let cstr = unsafe { CStr::from_ptr(message) };
    let guest_error = Err(GuestError::new(
        err.into(),
        cstr.to_str()
            .expect("Failed to convert CStr to &str")
            .to_owned(),
    ));
    let fcr = FunctionCallResult::new(guest_error);
    let mut builder = FlatBufferBuilder::new();
    let data = fcr.encode(&mut builder);
    unsafe {
        #[allow(static_mut_refs)] // we are single threaded
        GUEST_HANDLE
            .push_shared_output_data(data)
            .expect("Failed to set error")
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
