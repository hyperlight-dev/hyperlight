/*
Copyright 2025  The Hyperlight Authors.

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

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::{layout, vmem};

// There are no notable architecture-specific safety considerations
// here, and the general conditions are documented in the
// architecture-independent re-export in prim_alloc.rs
#[allow(clippy::missing_safety_doc)]
pub unsafe fn alloc_phys_pages(n: u64) -> u64 {
    let addr = crate::layout::allocator_gva();
    let nbytes = n * vmem::PAGE_SIZE as u64;
    let mut x = nbytes;
    unsafe {
        core::arch::asm!(
            "lock xadd qword ptr [{addr}], {x}",
            addr = in(reg) addr,
            x = inout(reg) x
        );
    }
    let limit = layout::scratch_allocator_limit_gpa();
    if super::allocation_exceeds_limit(x, nbytes, limit) {
        unsafe {
            crate::exit::abort_with_code_and_message(
                &[ErrorCode::MallocFailed as u8],
                c"Out of physical memory".as_ptr(),
            )
        }
    }
    x
}
