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

use core::slice::from_raw_parts;

use hyperlight_common::flatbuffer_wrappers::guest_error::{ErrorCode, GuestError};

use crate::PEB;

pub(crate) fn check_for_host_error() {
    unsafe {
        // TODO(danbugs:297): shouldn't this be `host_error_data_*`?
        let guest_error_buffer_ptr = (*PEB).guest_error_data_ptr as *mut u8;
        let guest_error_buffer_size = (*PEB).guest_error_data_size as usize;

        let guest_error_buffer = from_raw_parts(guest_error_buffer_ptr, guest_error_buffer_size);

        if !guest_error_buffer.is_empty() {
            let guest_error = GuestError::try_from(guest_error_buffer).expect("Invalid GuestError");
            if guest_error.code != ErrorCode::NoError {
                (*PEB).output_data_ptr = u64::MAX;
                panic!(
                    "Guest Error: {:?} - {}",
                    guest_error.code, guest_error.message
                );
            }
        }
    }
}
