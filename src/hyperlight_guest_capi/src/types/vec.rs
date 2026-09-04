// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

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
    /// Creates a non-owning FFI view over `value` without copying.
    ///
    /// The caller must keep `value` alive and at a stable address while the
    /// view is used. The view must not be passed to [`Self::into_vec`].
    pub(crate) fn from_mut_slice(value: &mut [u8]) -> Self {
        Self {
            data: value.as_mut_ptr(),
            len: value.len(),
        }
    }

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

    /// Copies the contents of `self` to a new independent `Vec<u8>`.
    /// # Safety
    /// `data` must reference `len` readable bytes when `len` is nonzero.
    pub unsafe fn copy_to_vec(&self) -> Vec<u8> {
        if self.len == 0 {
            Vec::new()
        } else {
            // SAFETY: required by the caller.
            unsafe { slice::from_raw_parts(self.data, self.len) }.to_vec()
        }
    }
}
