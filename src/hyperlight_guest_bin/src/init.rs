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
