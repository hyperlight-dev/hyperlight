/*
Copyright 2026  The Hyperlight Authors.

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

//! Guest-side virtqueue initialization.

use hyperlight_common::layout::{
    SCRATCH_TOP_G2H_QUEUE_DEPTH_OFFSET, SCRATCH_TOP_G2H_RING_GVA_OFFSET,
    SCRATCH_TOP_H2G_QUEUE_DEPTH_OFFSET, SCRATCH_TOP_H2G_RING_GVA_OFFSET,
    SCRATCH_TOP_VIRTQ_GENERATION_OFFSET, SCRATCH_TOP_VIRTQ_POOL_PAGES_OFFSET, scratch_top_ptr,
};
use hyperlight_common::mem::PAGE_SIZE_USIZE;
use hyperlight_common::virtq::Layout as VirtqLayout;
use hyperlight_guest::prim_alloc::alloc_phys_pages;
use hyperlight_guest::virtq::context::GuestContext;

use crate::paging::phys_to_virt;

/// Initialize virtqueue context.
pub(crate) fn init_virtqueues() {
    let g2h_gva = unsafe { *scratch_top_ptr::<u64>(SCRATCH_TOP_G2H_RING_GVA_OFFSET) };
    let g2h_depth = unsafe { *scratch_top_ptr::<u16>(SCRATCH_TOP_G2H_QUEUE_DEPTH_OFFSET) };
    let h2g_gva = unsafe { *scratch_top_ptr::<u64>(SCRATCH_TOP_H2G_RING_GVA_OFFSET) };
    let h2g_depth = unsafe { *scratch_top_ptr::<u16>(SCRATCH_TOP_H2G_QUEUE_DEPTH_OFFSET) };
    let pool_pages = unsafe { *scratch_top_ptr::<u16>(SCRATCH_TOP_VIRTQ_POOL_PAGES_OFFSET) } as u64;
    let generation = unsafe { *scratch_top_ptr::<u16>(SCRATCH_TOP_VIRTQ_GENERATION_OFFSET) };

    assert!(g2h_depth > 0 && h2g_depth > 0);
    assert!(g2h_gva != 0 && h2g_gva != 0);
    assert!(pool_pages > 0);

    // Zero ring memory
    let g2h_ring_size = VirtqLayout::query_size(g2h_depth as usize);
    unsafe { core::ptr::write_bytes(g2h_gva as *mut u8, 0, g2h_ring_size) };

    let h2g_ring_size = VirtqLayout::query_size(h2g_depth as usize);
    unsafe { core::ptr::write_bytes(h2g_gva as *mut u8, 0, h2g_ring_size) };

    // Allocate buffer pool from physical pages
    let pool_gpa = unsafe { alloc_phys_pages(pool_pages) };
    let pool_ptr = phys_to_virt(pool_gpa).expect("failed to map pool pages");
    let pool_gva = pool_ptr as u64;
    let pool_size = pool_pages as usize * PAGE_SIZE_USIZE;
    unsafe { core::ptr::write_bytes(pool_ptr, 0, pool_size) };

    // Create and install global context
    let ctx = unsafe { GuestContext::new(g2h_gva, g2h_depth, pool_gva, pool_size, generation) };
    hyperlight_guest::virtq::set_global_context(ctx);

    let _ = (h2g_gva, h2g_depth);
}
