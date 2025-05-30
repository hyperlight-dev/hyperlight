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
use core::any::type_name;
use core::slice::from_raw_parts_mut;

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;

use crate::error::{HyperlightGuestError, Result};
use crate::P_PEB;

// Pops the top element from the shared input data buffer and returns it as a T
pub fn try_pop_shared_input_data_into<T>() -> Result<T>
where
    T: for<'a> TryFrom<&'a [u8]>,
{
    let peb_ptr = unsafe { P_PEB.unwrap() };
    let shared_buffer_size = unsafe { (*peb_ptr).input_stack.size as usize };

    let idb =
        unsafe { from_raw_parts_mut((*peb_ptr).input_stack.ptr as *mut u8, shared_buffer_size) };

    if idb.is_empty() {
        return Err(HyperlightGuestError::new(
            ErrorCode::GuestError,
            "Got a 0-size buffer in pop_shared_input_data_into".to_string(),
        ));
    }

    // get relative offset to next free address
    let stack_ptr_rel: u64 =
        u64::from_le_bytes(idb[..8].try_into().expect("Shared input buffer too small"));

    if stack_ptr_rel as usize > shared_buffer_size || stack_ptr_rel < 16 {
        return Err(HyperlightGuestError::new(
            ErrorCode::GuestError,
            format!(
                "Invalid stack pointer: {} in pop_shared_input_data_into",
                stack_ptr_rel
            ),
        ));
    }

    // go back 8 bytes and read. This is the offset to the element on top of stack
    let last_element_offset_rel = u64::from_le_bytes(
        idb[stack_ptr_rel as usize - 8..stack_ptr_rel as usize]
            .try_into()
            .expect("Invalid stack pointer in pop_shared_input_data_into"),
    );

    let buffer = &idb[last_element_offset_rel as usize..];

    // convert the buffer to T
    let type_t = match T::try_from(buffer) {
        Ok(t) => Ok(t),
        Err(_e) => {
            return Err(HyperlightGuestError::new(
                ErrorCode::GuestError,
                format!("Unable to convert buffer to {}", type_name::<T>()),
            ));
        }
    };

    // update the stack pointer to point to the element we just popped of since that is now free
    idb[..8].copy_from_slice(&last_element_offset_rel.to_le_bytes());

    // zero out popped off buffer
    idb[last_element_offset_rel as usize..stack_ptr_rel as usize].fill(0);

    type_t
}
