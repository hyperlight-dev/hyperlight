use core::ffi::c_char;

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_guest::guest_error::setError;

/// # Safety
///
/// Dereferences the given raw pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hl_set_error(err: ErrorCode, message: *const c_char) {
    unsafe {
        setError(err.into(), message);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_abort_with_code(err: i32) {
    hyperlight_guest::entrypoint::abort_with_code(err);
}

/// # Safety
///
/// Dereferences the given raw pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hl_abort_with_code_and_message(err: i32, message: *const c_char) {
    unsafe { hyperlight_guest::entrypoint::abort_with_code_and_message(err, message) };
}
