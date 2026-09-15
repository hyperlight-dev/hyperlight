// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use core::ffi::{CStr, c_char};

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_guest::error::HyperlightGuestError;

use crate::alloc::borrow::ToOwned;

static mut LAST_GUEST_ERROR: Option<HyperlightGuestError> = None;

/// Set the error returned by the current C guest dispatch.
///
/// # Safety
///
/// `message` must point to a live NUL-terminated string.
/// Calls must be serialized within a single-vCPU guest.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hl_set_error(err: ErrorCode, message: *const c_char) {
    // SAFETY: The caller supplies a live NUL-terminated string.
    let cstr = unsafe { CStr::from_ptr(message) };
    let guest_error = HyperlightGuestError::new(
        err,
        cstr.to_str()
            .expect("Failed to convert CStr to &str")
            .to_owned(),
    );
    // SAFETY: Single vCPU guest execution serializes access to this slot.
    let _ = unsafe { (&raw mut LAST_GUEST_ERROR).replace(Some(guest_error)) };
}

pub(crate) fn take_guest_error() -> Option<HyperlightGuestError> {
    // SAFETY: Single vCPU guest execution serializes access to this slot.
    unsafe { (&raw mut LAST_GUEST_ERROR).replace(None) }
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_abort_with_code(err: i32) {
    hyperlight_guest::exit::abort_with_code(&[err as u8]);
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_abort_with_code_and_message(err: i32, message: *const c_char) {
    unsafe { hyperlight_guest::exit::abort_with_code_and_message(&[err as u8], message) };
}
