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

use alloc::format;
use core::ffi::c_char;

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::outb::Exception;
use hyperlight_guest::exit::abort_with_code_and_message;

/// Exception handler
#[unsafe(no_mangle)]
pub extern "C" fn hl_exception_handler(
    stack_pointer: u64,
    exception_number: u64,
    page_fault_address: u64,
) {
    let exception = Exception::try_from(exception_number as u8).expect("Invalid exception number");
    let msg = format!(
        "Page Fault Address: {:#x}\n\
            Stack Pointer: {:#x}",
        page_fault_address, stack_pointer
    );

    unsafe {
        abort_with_code_and_message(
            &[ErrorCode::GuestError as u8, exception as u8],
            msg.as_ptr() as *const c_char,
        );
    }
}
