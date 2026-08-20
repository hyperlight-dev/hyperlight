// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;

// There are no notable architecture-specific safety considerations
// here, and the general conditions are documented in the
// architecture-independent re-export in prim_alloc.rs
#[allow(clippy::missing_safety_doc)]
pub unsafe fn alloc_phys_pages(n: u64) -> u64 {
    let addr = crate::layout::allocator_gva();
    let nbytes = n * hyperlight_common::vmem::PAGE_SIZE as u64;
    let mut x = nbytes;
    unsafe {
        core::arch::asm!(
            "lock xadd qword ptr [{addr}], {x}",
            addr = in(reg) addr,
            x = inout(reg) x
        );
    }
    // Set aside two pages at the top of the scratch region for the
    // exception stack, shared state, etc
    let max_avail =
        hyperlight_common::layout::SCRATCH_TOP_GPA - hyperlight_common::vmem::PAGE_SIZE * 2;
    if x.checked_add(nbytes)
        .is_none_or(|xx| xx >= max_avail as u64)
    {
        unsafe {
            crate::exit::abort_with_code_and_message(
                &[ErrorCode::MallocFailed as u8],
                c"Out of physical memory".as_ptr(),
            )
        }
    }
    x
}
