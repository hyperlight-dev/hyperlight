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

use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::{c_char, CStr};
use core::mem;

use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};

use crate::host_function_call::call_host_function;

const BUFFER_SIZE: usize = 1000;

static mut MESSAGE_BUFFER: Vec<u8> = Vec::new();

/// Exposes a C API to allow the guest to print a string
///
/// # Safety
/// This function is not thread safe
#[no_mangle]
#[allow(static_mut_refs)]
pub unsafe extern "C" fn _putchar(c: c_char) {
    let char = c as u8;

    // Extend buffer capacity if it's empty (like `with_capacity` in lazy_static).
    // TODO: replace above Vec::new() with Vec::with_capacity once it's stable in const contexts.
    if MESSAGE_BUFFER.capacity() == 0 {
        MESSAGE_BUFFER.reserve(BUFFER_SIZE);
    }

    MESSAGE_BUFFER.push(char);

    if MESSAGE_BUFFER.len() == BUFFER_SIZE || char == b'\0' {
        let str = if char == b'\0' {
            CStr::from_bytes_until_nul(&MESSAGE_BUFFER)
                .expect("No null byte in buffer")
                .to_string_lossy()
                .into_owned()
        } else {
            String::from_utf8(mem::take(&mut MESSAGE_BUFFER))
                .expect("Failed to convert buffer to string")
        };

        // HostPrint returns an i32, but we don't care about the return value
        let _ = call_host_function::<i32>(
            "HostPrint",
            Some(Vec::from(&[ParameterValue::String(str)])),
            ReturnType::Int,
        )
        .expect("Failed to call HostPrint");

        // Clear the buffer after sending
        MESSAGE_BUFFER.clear();
    }
}
