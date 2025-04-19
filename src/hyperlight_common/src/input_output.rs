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
use alloc::vec::Vec;
use core::slice::from_raw_parts_mut;

use anyhow::{bail, Result};

/// The host will use the `InputDataSection` to pass data to the guest. This can be, for example,
/// the issuing of a function call or the result of calling a host function.
pub struct InputDataSection {
    ptr: *mut u8,
    len: u64,
}

impl InputDataSection {
    /// Creates a new `InputDataSection` with the given pointer and length.
    pub fn new(ptr: *mut u8, len: u64) -> Self {
        InputDataSection { ptr, len }
    }

    /// Tries to pop shared input data into a type `T`. The type `T` must implement the `TryFrom` trait
    pub fn try_pop_shared_input_data_into<T>(&self) -> Result<T>
    where
        T: for<'a> TryFrom<&'a [u8]>,
    {
        let shared_buffer_size = self.len as usize;

        let idb = unsafe { from_raw_parts_mut(self.ptr, shared_buffer_size) };

        if idb.is_empty() {
            bail!("Got a 0-size buffer in try_pop_shared_input_data_into");
        }

        // get relative offset to next free address
        let stack_ptr_rel: u64 = u64::from_le_bytes(match idb[..8].try_into() {
            Ok(bytes) => bytes,
            Err(_) => bail!("shared input buffer too small"),
        });

        if stack_ptr_rel as usize > shared_buffer_size || stack_ptr_rel < 16 {
            bail!(
                "Invalid stack pointer: {} in try_pop_shared_input_data_into",
                stack_ptr_rel
            );
        }

        // go back 8 bytes and read. This is the offset to the element on top of stack
        let last_element_offset_rel = u64::from_le_bytes(
            match idb[stack_ptr_rel as usize - 8..stack_ptr_rel as usize].try_into() {
                Ok(bytes) => bytes,
                Err(_) => bail!("Invalid stack pointer in pop_shared_input_data_into"),
            },
        );

        let buffer = &idb[last_element_offset_rel as usize..];

        // convert the buffer to T
        let type_t = match T::try_from(buffer) {
            Ok(t) => Ok(t),
            Err(_e) => bail!("failed to convert buffer to type T in pop_shared_input_data_into"),
        };

        // update the stack pointer to point to the element we just popped of since that is now free
        idb[..8].copy_from_slice(&last_element_offset_rel.to_le_bytes());

        // zero out popped off buffer
        idb[last_element_offset_rel as usize..stack_ptr_rel as usize].fill(0);

        type_t
    }
}

/// The guest will use the `OutputDataSection` to pass data back to the host. This can be, for example,
/// issuing a host function call or the result of a guest function call.
pub struct OutputDataSection {
    pub ptr: *mut u8,
    pub len: u64,
}

impl OutputDataSection {
    const STACK_PTR_SIZE: usize = size_of::<u64>();

    /// Creates a new `OutputDataSection` with the given pointer and length.
    pub fn new(ptr: *mut u8, len: u64) -> Self {
        OutputDataSection { ptr, len }
    }

    /// Pushes shared output data to the output buffer.
    pub fn push_shared_output_data(&self, data: Vec<u8>) -> Result<()> {
        let shared_buffer_size = self.len as usize;
        let odb: &mut [u8] = unsafe { from_raw_parts_mut(self.ptr, shared_buffer_size) };

        if odb.len() < Self::STACK_PTR_SIZE {
            bail!("shared output buffer is too small");
        }

        // get offset to next free address on the stack
        let mut stack_ptr_rel: u64 =
            u64::from_le_bytes(match odb[..Self::STACK_PTR_SIZE].try_into() {
                Ok(bytes) => bytes,
                Err(_) => bail!("failed to get stack pointer in shared output buffer"),
            });

        // if stack_ptr_rel is 0, it means this is the first time we're using the output buffer, so
        // we want to offset it by 8 as to not overwrite the stack_ptr location.
        if stack_ptr_rel == 0 {
            stack_ptr_rel = 8;
        }

        // check if the stack pointer is within the bounds of the buffer.
        // It can be equal to the size, but never greater
        // It can never be less than 8. An empty buffer's stack pointer is 8
        if stack_ptr_rel as usize > shared_buffer_size {
            bail!("invalid stack pointer in shared output buffer");
        }

        // check if there is enough space in the buffer
        let size_required: usize = data.len() + 8; // the data plus the pointer pointing to the data
        let size_available: usize = shared_buffer_size - stack_ptr_rel as usize;
        if size_required > size_available {
            bail!("not enough space in shared output buffer");
        }

        // write the actual data
        odb[stack_ptr_rel as usize..stack_ptr_rel as usize + data.len()].copy_from_slice(&data);

        // write the offset to the newly written data, to the top of the stack
        let bytes: [u8; Self::STACK_PTR_SIZE] = stack_ptr_rel.to_le_bytes();
        odb[stack_ptr_rel as usize + data.len()
            ..stack_ptr_rel as usize + data.len() + Self::STACK_PTR_SIZE]
            .copy_from_slice(&bytes);

        // update stack pointer to point to next free address
        let new_stack_ptr_rel: u64 =
            (stack_ptr_rel as usize + data.len() + Self::STACK_PTR_SIZE) as u64;
        odb[0..Self::STACK_PTR_SIZE].copy_from_slice(&new_stack_ptr_rel.to_le_bytes());

        Ok(())
    }
}

impl From<(u64, u64)> for InputDataSection {
    fn from((ptr, len): (u64, u64)) -> Self {
        InputDataSection::new(ptr as *mut u8, len)
    }
}

impl From<(u64, u64)> for OutputDataSection {
    fn from((ptr, len): (u64, u64)) -> Self {
        OutputDataSection::new(ptr as *mut u8, len)
    }
}
