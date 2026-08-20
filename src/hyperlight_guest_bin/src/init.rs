// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

/// To initialise the main stack, we just pre-emptively map the first
/// page of it. We assume the architecture-specific exception handler
/// will allocate pages on fault as necessary
pub(crate) unsafe fn init_stack() -> u64 {
    use hyperlight_common::vmem::{BasicMapping, MappingKind, PAGE_SIZE};
    use hyperlight_guest::layout::MAIN_STACK_TOP_GVA;
    let stack_top_page_base = (MAIN_STACK_TOP_GVA - 1) & !(PAGE_SIZE as u64 - 1);
    unsafe {
        crate::paging::map_region(
            hyperlight_guest::prim_alloc::alloc_phys_pages(1),
            stack_top_page_base as *mut u8,
            PAGE_SIZE as u64,
            MappingKind::Basic(BasicMapping {
                readable: true,
                writable: true,
                executable: false,
            }),
        );
        crate::paging::barrier::first_valid_same_ctx();
    }
    MAIN_STACK_TOP_GVA
}
