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

use core::alloc::Layout;
use core::ffi::c_void;
use core::mem::{align_of, size_of};
use core::ptr;

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;

use crate::entrypoint::abort_with_code;

extern crate alloc;

/*
    C-wrappers for Rust's registered global allocator.

    Each memory allocation via `malloc/calloc/realloc` is stored together with a `alloc::Layout` describing
    the size and alignment of the allocation. This layout is stored just before the actual raw memory returned to the caller.

    Example: A call to malloc(64) will allocate space for both an `alloc::Layout` and 64 bytes of memory:

    ----------------------------------------------------------------------------------------
    | Layout { size: 64 + size_of::<Layout>(), ... }    |      64 bytes of memory         | ...
    ----------------------------------------------------------------------------------------
                                                        ^
                                                        |
                                                        |
                                                    ptr returned to caller
*/

// We assume the maximum alignment for any value is the alignment of u128.
const MAX_ALIGN: usize = align_of::<u128>();

/// Allocates a block of memory with the given size. The memory is only guaranteed to be initialized to 0s if `zero` is true, otherwise
/// it may or may not be initialized.
///
/// # Safety
/// The returned pointer must be freed with `memory::free` when it is no longer needed, otherwise memory will leak.
unsafe fn alloc_helper(size: usize, zero: bool) -> *mut c_void {
    if size == 0 {
        return ptr::null_mut();
    }

    // Allocate a block that includes space for both layout information and data
    let total_size = size
        .checked_add(size_of::<Layout>())
        .expect("data and layout size should not overflow in alloc");
    let layout = Layout::from_size_align(total_size, MAX_ALIGN).expect("Invalid layout");

    unsafe {
        let raw_ptr = match zero {
            true => alloc::alloc::alloc_zeroed(layout),
            false => alloc::alloc::alloc(layout),
        };
        if raw_ptr.is_null() {
            abort_with_code(&[ErrorCode::MallocFailed as u8]);
        } else {
            let layout_ptr = raw_ptr as *mut Layout;
            layout_ptr.write(layout);
            layout_ptr.add(1) as *mut c_void
        }
    }
}

/// Allocates a block of memory with the given size.
/// The memory is not guaranteed to be initialized to 0s.
///
/// # Safety
/// The returned pointer must be freed with `memory::free` when it is no longer needed, otherwise memory will leak.
#[no_mangle]
pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    alloc_helper(size, false)
}

/// Allocates a block of memory for an array of `nmemb` elements, each of `size` bytes.
/// The memory is initialized to 0s.
///
/// # Safety
/// The returned pointer must be freed with `memory::free` when it is no longer needed, otherwise memory will leak.
#[no_mangle]
pub unsafe extern "C" fn calloc(nmemb: usize, size: usize) -> *mut c_void {
    let total_size = nmemb
        .checked_mul(size)
        .expect("nmemb * size should not overflow in calloc");

    alloc_helper(total_size, true)
}

/// Frees the memory block pointed to by `ptr`.
///
/// # Safety
/// `ptr` must be a pointer to a memory block previously allocated by `memory::malloc`, `memory::calloc`, or `memory::realloc`.
#[no_mangle]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    if !ptr.is_null() {
        unsafe {
            let block_start = (ptr as *const Layout).sub(1);
            let layout = block_start.read();
            alloc::alloc::dealloc(block_start as *mut u8, layout)
        }
    }
}

/// Changes the size of the memory block pointed to by `ptr` to `size` bytes. If the returned ptr is non-null,
/// any usage of the old memory block is immediately undefined behavior.
///
/// # Safety
/// `ptr` must be a pointer to a memory block previously allocated by `memory::malloc`, `memory::calloc`, or `memory::realloc`.
#[no_mangle]
pub unsafe extern "C" fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    if ptr.is_null() {
        // If the pointer is null, treat as a malloc
        return malloc(size);
    }

    if size == 0 {
        // If the size is 0, treat as a free and return null
        free(ptr);
        return ptr::null_mut();
    }

    unsafe {
        let total_new_size = size
            .checked_add(size_of::<Layout>())
            .expect("data and layout size should not overflow in realloc");

        let block_start = (ptr as *const Layout).sub(1);
        let old_layout = block_start.read();
        let new_layout = Layout::from_size_align(total_new_size, MAX_ALIGN).unwrap();

        let new_block_start =
            alloc::alloc::realloc(block_start as *mut u8, old_layout, total_new_size)
                as *mut Layout;

        if new_block_start.is_null() {
            // Realloc failed
            abort_with_code(&[ErrorCode::MallocFailed as u8]);
        } else {
            // Update the stored Layout, then return ptr to memory right after the Layout.
            new_block_start.write(new_layout);
            new_block_start.add(1) as *mut c_void
        }
    }
}
