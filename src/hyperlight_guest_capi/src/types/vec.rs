/*
Copyright 2025 The Hyperlight Authors.

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

use alloc::boxed::Box;
use alloc::slice;
use alloc::vec::Vec;
use core::ptr;

/// A ffi compatible struct to represent a vector of u8s.
/// Copying/cloning this struct does not copy the underlying bytes.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FfiVec {
    data: *mut u8,
    len: usize,
}

impl FfiVec {
    /// Creates a new `FfiVec` from the given Vec<u8> without copying memory.
    /// # Safety
    /// The caller must later reclaim memory by calling `into_vec`, otherwise memory will be leaked.
    /// The caller must not modify the returned `FfiVec`.
    pub unsafe fn from_vec(v: Vec<u8>) -> Self {
        let boxed = v.into_boxed_slice();
        let leaked = Box::into_raw(boxed);
        FfiVec {
            data: leaked as *mut u8,
            len: leaked.len(),
        }
    }

    /// Consumes `self` and returns the original Vec<u8> without copying memory.
    /// # Safety
    /// Self must have been obtained using `from_vec`, and must be in its original state (i.e. not modified).
    pub unsafe fn into_vec(mut self) -> Vec<u8> {
        let slice = unsafe { slice::from_raw_parts_mut(self.data, self.len) };
        let boxed: Box<[u8]> = unsafe { Box::from_raw(slice) };

        let res = boxed.into_vec();
        self.data = ptr::null_mut();
        self.len = 0;
        res
    }

    /// Copies the contents of `self` to a new independent Vec<u8>.
    /// # Safety
    /// Self must have been obtained using `from_vec`, and must be in its original state (i.e. not modified).
    pub unsafe fn copy_to_vec(&self) -> Vec<u8> {
        // deconstruct
        let slice = unsafe { slice::from_raw_parts_mut(self.data, self.len) };
        let boxed: Box<[u8]> = unsafe { Box::from_raw(slice) };
        let original = boxed.into_vec();
        // clone
        let clone = original.clone();
        // reverse deconstruct
        let boxed = original.into_boxed_slice();
        let leaked = Box::into_raw(boxed);
        assert_eq!(self.data, leaked as *mut u8);
        assert_eq!(self.len, leaked.len());
        clone
    }
}
