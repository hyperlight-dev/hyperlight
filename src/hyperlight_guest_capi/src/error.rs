use core::ffi::c_char;

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_guest::guest_error::setError;

#[no_mangle]
pub extern "C" fn hl_set_error(err: ErrorCode, message: *const c_char) {
    unsafe {
        setError(err.into(), message);
    }
}

#[no_mangle]
pub extern "C" fn hl_abort_with_code(err: i32) {
    hyperlight_guest::entrypoint::abort_with_code(&[err as u8]);
}

#[no_mangle]
pub extern "C" fn hl_abort_with_code_and_message(err: i32, message: *const c_char) {
    unsafe { hyperlight_guest::entrypoint::abort_with_code_and_message(&[err as u8], message) };
}
