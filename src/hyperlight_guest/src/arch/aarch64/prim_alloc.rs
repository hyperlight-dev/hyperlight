// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::{layout, vmem};

// There are no notable architecture-specific safety considerations
// here, and the general conditions are documented in the
// architecture-independent re-export in prim_alloc.rs
#[allow(clippy::missing_safety_doc)]
pub unsafe fn alloc_phys_pages(n: u64) -> u64 {
    let addr = crate::layout::allocator_gva();
    let nbytes = n * vmem::PAGE_SIZE as u64;
    let mut prev_base: u64 = 0;
    unsafe {
        // todo: actually check for FEAT_LSE presence.
        core::arch::asm!("
            ldadd {nbytes}, {prev_base}, [{addr}]
        ",
            addr = in(reg) addr,
            nbytes = in(reg) nbytes,
            prev_base = out(reg) prev_base,
        );
    }
    let limit = layout::scratch_allocator_limit_gpa();
    if super::allocation_exceeds_limit(prev_base, nbytes, limit) {
        unsafe {
            crate::exit::abort_with_code_and_message(
                &[ErrorCode::MallocFailed as u8],
                c"Out of physical memory".as_ptr(),
            )
        }
    }
    prev_base
}
