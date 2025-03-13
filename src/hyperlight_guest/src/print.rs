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
use spin::Mutex;

use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};

use crate::host_function_call::call_host_function;

const BUFFER_SIZE: usize = 1000;

static MESSAGE_BUFFER: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// Exposes a C API to allow the guest to print a string
#[unsafe(no_mangle)]
pub extern "C" fn _putchar(c: c_char) {
    let char = c as u8;

    let mut locked_buffer = MESSAGE_BUFFER.lock();
    // Extend buffer capacity if it's empty (like `with_capacity` in lazy_static).
    // TODO: replace above Vec::new() with Vec::with_capacity once it's stable in const contexts.
    if locked_buffer.capacity() == 0 {
        locked_buffer.reserve(BUFFER_SIZE);
    }

    locked_buffer.push(char);

    if locked_buffer.len() == BUFFER_SIZE || char == b'\0' {
        let str = if char == b'\0' {
            CStr::from_bytes_until_nul(&locked_buffer)
                .expect("No null byte in buffer") // This expect is safe since we know there is a null byte
                .to_string_lossy()
                .into_owned()
        } else {
            String::from_utf8(mem::take(&mut locked_buffer))
                .expect("Failed to convert buffer to string")
        };

        locked_buffer.clear();

        call_host_function(
            "HostPrint",
            Some(Vec::from(&[ParameterValue::String(str)])),
            ReturnType::Void,
        )
        .expect("Failed to call HostPrint");
    }
}
