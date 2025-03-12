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

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::slice::from_raw_parts_mut;

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;

use crate::error::{HyperlightGuestError, Result};
use crate::P_PEB;

pub fn push_shared_output_data(data: Vec<u8>) -> Result<()> {
    let peb_ptr = unsafe { P_PEB.unwrap() };
    let shared_buffer_size = unsafe { (*peb_ptr).outputdata.outputDataSize as usize };
    let odb = unsafe {
        from_raw_parts_mut(
            (*peb_ptr).outputdata.outputDataBuffer as *mut u8,
            shared_buffer_size,
        )
    };

    if odb.is_empty() {
        return Err(HyperlightGuestError::new(
            ErrorCode::GuestError,
            "Got a 0-size buffer in push_shared_output_data".to_string(),
        ));
    }

    // get offset to next free address on the stack
    let stack_ptr_rel: usize =
        usize::from_le_bytes(odb[..8].try_into().expect("Shared output buffer too small"));

    // check if the stack pointer is within the bounds of the buffer.
    // It can be equal to the size, but never greater
    // It can never be less than 8. An empty buffer's stack pointer is 8
    if stack_ptr_rel > shared_buffer_size || stack_ptr_rel < 8 {
        return Err(HyperlightGuestError::new(
            ErrorCode::GuestError,
            format!(
                "Invalid stack pointer: {} in push_shared_output_data",
                stack_ptr_rel
            ),
        ));
    }

    // check if there is enough space in the buffer
    let size_required = data.len() + 8; // the data plus the pointer pointing to the data
    let size_available = shared_buffer_size - stack_ptr_rel;
    if size_required > size_available {
        return Err(HyperlightGuestError::new(
            ErrorCode::GuestError,
            format!(
                "Not enough space in shared output buffer. Required: {}, Available: {}",
                size_required, size_available
            ),
        ));
    }

    // write the actual data
    odb[stack_ptr_rel..stack_ptr_rel + data.len()].copy_from_slice(&data);

    // write the offset to the newly written data, to the top of the stack
    let bytes = stack_ptr_rel.to_le_bytes();
    odb[stack_ptr_rel + data.len()..stack_ptr_rel + data.len() + 8].copy_from_slice(&bytes);

    // update stack pointer to point to next free address
    let new_stack_ptr_rel = stack_ptr_rel + data.len() + 8;
    odb[0..8].copy_from_slice(&(new_stack_ptr_rel).to_le_bytes());

    Ok(())
}
