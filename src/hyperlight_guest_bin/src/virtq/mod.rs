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

use core::num::NonZeroU16;

use hyperlight_common::layout::{
    SCRATCH_TOP_G2H_POOL_PAGES_OFFSET, SCRATCH_TOP_G2H_QUEUE_DEPTH_OFFSET,
    SCRATCH_TOP_G2H_RING_GVA_OFFSET, SCRATCH_TOP_H2G_POOL_GVA_OFFSET,
    SCRATCH_TOP_H2G_POOL_PAGES_OFFSET, SCRATCH_TOP_H2G_QUEUE_DEPTH_OFFSET,
    SCRATCH_TOP_H2G_RING_GVA_OFFSET, SCRATCH_TOP_SNAPSHOT_GENERATION_OFFSET, scratch_top_ptr,
};
use hyperlight_common::mem::PAGE_SIZE_USIZE;
use hyperlight_common::virtq::Layout as VirtqLayout;
use hyperlight_guest::prim_alloc::alloc_phys_pages;
use hyperlight_guest::virtq::context::{GuestContext, QueueConfig};

use crate::paging::phys_to_virt;

/// Initialize virtqueue context.
pub(crate) fn init_virtqueues() {
    let g2h_gva = unsafe { *scratch_top_ptr::<u64>(SCRATCH_TOP_G2H_RING_GVA_OFFSET) };
    let g2h_depth = unsafe { *scratch_top_ptr::<u16>(SCRATCH_TOP_G2H_QUEUE_DEPTH_OFFSET) };
    let h2g_gva = unsafe { *scratch_top_ptr::<u64>(SCRATCH_TOP_H2G_RING_GVA_OFFSET) };
    let h2g_depth = unsafe { *scratch_top_ptr::<u16>(SCRATCH_TOP_H2G_QUEUE_DEPTH_OFFSET) };
    let g2h_pages = unsafe { *scratch_top_ptr::<u16>(SCRATCH_TOP_G2H_POOL_PAGES_OFFSET) } as usize;
    let h2g_pages = unsafe { *scratch_top_ptr::<u16>(SCRATCH_TOP_H2G_POOL_PAGES_OFFSET) } as usize;
    let generation = unsafe { *scratch_top_ptr::<u16>(SCRATCH_TOP_SNAPSHOT_GENERATION_OFFSET) };

    assert!(g2h_depth > 0 && h2g_depth > 0 && g2h_pages > 0 && h2g_pages > 0);
    assert!(g2h_gva != 0 && h2g_gva != 0);

    // Zero ring memory
    let g2h_ring_size = VirtqLayout::query_size(g2h_depth as usize);
    unsafe { core::ptr::write_bytes(g2h_gva as *mut u8, 0, g2h_ring_size) };

    let h2g_ring_size = VirtqLayout::query_size(h2g_depth as usize);
    unsafe { core::ptr::write_bytes(h2g_gva as *mut u8, 0, h2g_ring_size) };

    // Build ring layouts
    let nz = NonZeroU16::new(g2h_depth).expect("G2H depth zero");
    let g2h_layout = unsafe { VirtqLayout::from_base(g2h_gva, nz) }.expect("invalid layout");

    let nz = NonZeroU16::new(h2g_depth).expect("H2G depth zero");
    let h2g_layout = unsafe { VirtqLayout::from_base(h2g_gva, nz) }.expect("invalid layout");

    // Allocate buffer pools
    let g2h_pool_gva = alloc_pool(g2h_pages);
    let h2g_pool_gva = alloc_pool(h2g_pages);

    // Publish H2G pool GVA so the host can prefill after restore
    unsafe { *scratch_top_ptr::<u64>(SCRATCH_TOP_H2G_POOL_GVA_OFFSET) = h2g_pool_gva };

    let ctx = GuestContext::new(
        QueueConfig {
            layout: g2h_layout,
            pool_gva: g2h_pool_gva,
            pool_pages: g2h_pages,
        },
        QueueConfig {
            layout: h2g_layout,
            pool_gva: h2g_pool_gva,
            pool_pages: h2g_pages,
        },
        generation,
    );
    hyperlight_guest::virtq::set_global_context(ctx);
}

/// Allocate and zero `n` physical pages, returning the GVA.
fn alloc_pool(n: usize) -> u64 {
    let gpa = unsafe { alloc_phys_pages(n as u64) };
    let ptr = phys_to_virt(gpa).expect("failed to map pool pages");
    let size = n as usize * PAGE_SIZE_USIZE;
    unsafe { core::ptr::write_bytes(ptr, 0, size) };
    ptr as u64
}
