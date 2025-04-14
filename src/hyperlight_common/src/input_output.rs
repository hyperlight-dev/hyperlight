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
use anyhow::{bail, Result};
use alloc::vec::Vec;
use core::any::type_name;
use core::slice::from_raw_parts_mut;

pub struct InputDataSection {
    ptr: *mut u8,
    len: usize,
}

impl InputDataSection {
    pub fn new(ptr: *mut u8, len: usize) -> Self {
        InputDataSection { ptr, len }
    }

    pub fn try_pop_shared_input_data_into<T>(&self) -> Result<T>
    where
        T: for<'a> TryFrom<&'a [u8]>,
    {
        let input_data_buffer = unsafe { from_raw_parts_mut(self.ptr, self.len) };

        if input_data_buffer.is_empty() {
            bail!("Got a 0-size buffer in pop_shared_input_data_into");
        }

        // get relative offset to next free address
        let stack_ptr_rel: usize = usize::from_le_bytes(
            input_data_buffer[..8]
                .try_into()
                .expect("Shared input buffer too small"),
        );

        if stack_ptr_rel > self.len || stack_ptr_rel < 16 {
            bail!("Invalid stack pointer: {} in pop_shared_input_data_into", stack_ptr_rel);
        }

        // go back 8 bytes and read. This is the offset to the element on top of stack
        let last_element_offset_rel = usize::from_le_bytes(
            input_data_buffer[stack_ptr_rel - 8..stack_ptr_rel]
                .try_into()
                .expect("Invalid stack pointer in pop_shared_input_data_into"),
        );

        let buffer = &input_data_buffer[last_element_offset_rel..];

        // convert the buffer to T
        let type_t = match T::try_from(buffer) {
            Ok(t) => Ok(t),
            Err(_e) => {
                bail!("Unable to convert buffer to {}", type_name::<T>());
            }
        };

        // update the stack pointer to point to the element we just popped of since that is now free
        input_data_buffer[..8].copy_from_slice(&last_element_offset_rel.to_le_bytes());

        // zero out popped off buffer
        input_data_buffer[last_element_offset_rel..stack_ptr_rel].fill(0);

        type_t
    }
}

pub struct OutputDataSection {
    pub ptr: *mut u8,
    pub len: usize,
}

impl OutputDataSection {
    pub fn new(ptr: *mut u8, len: usize) -> Self {
        OutputDataSection { ptr, len }
    }

    pub fn push_shared_output_data(&self, data: Vec<u8>) -> Result<()> {
        let output_data_buffer = unsafe { from_raw_parts_mut(self.ptr, self.len) };

        if output_data_buffer.is_empty() {
            bail!("Got a 0-size buffer in push_shared_output_data");
        }

        // get offset to next free address on the stack
        let mut stack_ptr_rel: usize = usize::from_le_bytes(
            output_data_buffer[..8]
                .try_into()
                .expect("Shared output buffer too small"),
        );

        if stack_ptr_rel == 0 {
            stack_ptr_rel = 8;
        }

        // check if the stack pointer is within the bounds of the buffer.
        // It can be equal to the size, but never greater
        // It can never be less than 8. An empty buffer's stack pointer is 8
        if stack_ptr_rel > self.len || stack_ptr_rel < 8 {
            bail!("Invalid stack pointer: {} in push_shared_output_data", stack_ptr_rel);
        }

        // check if there is enough space in the buffer
        let size_required = data.len() + 8; // the data plus the pointer pointing to the data
        let size_available = self.len - stack_ptr_rel;
        if size_required > size_available {
            bail!("Not enough space in shared output buffer. Required: {}, Available: {}", size_required, size_available);
        }

        // write the actual data
        output_data_buffer[stack_ptr_rel..stack_ptr_rel + data.len()].copy_from_slice(&data);

        // write the offset to the newly written data, to the top of the stack
        let bytes = stack_ptr_rel.to_le_bytes();
        output_data_buffer[stack_ptr_rel + data.len()..stack_ptr_rel + data.len() + 8]
            .copy_from_slice(&bytes);

        // update stack pointer to point to next free address
        let new_stack_ptr_rel = stack_ptr_rel + data.len() + 8;
        output_data_buffer[0..8].copy_from_slice(&new_stack_ptr_rel.to_le_bytes());

        Ok(())
    }
}

impl From<(u64, u64)> for InputDataSection {
    fn from((ptr, len): (u64, u64)) -> Self {
        InputDataSection::new(ptr as *mut u8, len as usize)
    }
}

impl From<(u64, u64)> for OutputDataSection {
    fn from((ptr, len): (u64, u64)) -> Self {
        OutputDataSection::new(ptr as *mut u8, len as usize)
    }
}
