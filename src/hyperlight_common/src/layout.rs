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

use core::mem::{offset_of, size_of};

#[cfg_attr(target_arch = "x86_64", path = "arch/amd64/layout.rs")]
#[cfg_attr(target_arch = "aarch64", path = "arch/aarch64/layout.rs")]
mod arch;

pub use arch::{
    SCRATCH_TOP_GPA, SCRATCH_TOP_GVA, SNAPSHOT_PT_GVA_MAX, SNAPSHOT_PT_GVA_MIN, io_page,
};

use crate::virtq;

const EXN_STACK_ALIGNMENT: usize = 16;
/// Pages reserved for the exception stack and scratch-top metadata.
pub const SCRATCH_TOP_RESERVED_PAGES: usize = 2;

// Fields are listed in ascending-address order. Public offsets are measured
// down from the top of scratch memory.
#[repr(C)]
struct ScratchTopMetadata {
    /// Host-published capacity of each H2G buffer.
    h2g_buffer_size: u64,
    /// Number of pages reserved for the H2G pool.
    h2g_pool_pages: u64,
    /// Guest-published GPA of the H2G pool.
    h2g_pool_gpa: u64,
    /// Guest-published GPA of the H2G ring.
    h2g_ring_gpa: u64,
    /// Host-published H2G descriptor count.
    h2g_queue_depth: u64,
    /// Host-published capacity of each G2H upper-tier buffer.
    g2h_buffer_size: u64,
    /// Number of pages reserved for the G2H pool.
    g2h_pool_pages: u64,
    /// Guest-published GPA of the G2H pool.
    g2h_pool_gpa: u64,
    /// Guest-published GPA of the G2H ring.
    g2h_ring_gpa: u64,
    /// Host-published G2H descriptor count.
    g2h_queue_depth: u64,
    /// Generation of the snapshot backing the sandbox.
    snapshot_generation: u64,
    /// GPA of the snapshot page-table copy in scratch memory.
    snapshot_pt_gpa_base: u64,
    /// Next GPA available to the dynamic scratch allocator.
    allocator: u64,
    /// Size of the scratch region in bytes.
    scratch_size: u64,
}

const fn scratch_top_offset(field_offset: usize) -> u64 {
    (size_of::<ScratchTopMetadata>() - field_offset) as u64
}

pub const SCRATCH_TOP_G2H_QUEUE_DEPTH_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, g2h_queue_depth));
pub const SCRATCH_TOP_G2H_RING_GPA_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, g2h_ring_gpa));
pub const SCRATCH_TOP_G2H_POOL_GPA_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, g2h_pool_gpa));
pub const SCRATCH_TOP_G2H_POOL_PAGES_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, g2h_pool_pages));
pub const SCRATCH_TOP_G2H_BUFFER_SIZE_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, g2h_buffer_size));
pub const SCRATCH_TOP_H2G_QUEUE_DEPTH_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, h2g_queue_depth));
pub const SCRATCH_TOP_H2G_RING_GPA_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, h2g_ring_gpa));
pub const SCRATCH_TOP_H2G_POOL_GPA_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, h2g_pool_gpa));
pub const SCRATCH_TOP_H2G_POOL_PAGES_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, h2g_pool_pages));
pub const SCRATCH_TOP_H2G_BUFFER_SIZE_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, h2g_buffer_size));
pub const SCRATCH_TOP_SIZE_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, scratch_size));
pub const SCRATCH_TOP_ALLOCATOR_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, allocator));
pub const SCRATCH_TOP_SNAPSHOT_PT_GPA_BASE_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, snapshot_pt_gpa_base));
pub const SCRATCH_TOP_SNAPSHOT_GENERATION_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, snapshot_generation));
pub const SCRATCH_TOP_EXN_STACK_OFFSET: u64 = size_of::<ScratchTopMetadata>() as u64;

const _: () = {
    assert!(size_of::<ScratchTopMetadata>().is_multiple_of(EXN_STACK_ALIGNMENT));
    assert!(SCRATCH_TOP_SIZE_OFFSET == 0x08);
    assert!(SCRATCH_TOP_ALLOCATOR_OFFSET == 0x10);
    assert!(SCRATCH_TOP_SNAPSHOT_PT_GPA_BASE_OFFSET == 0x18);
    assert!(SCRATCH_TOP_SNAPSHOT_GENERATION_OFFSET == 0x20);
    assert!(SCRATCH_TOP_G2H_QUEUE_DEPTH_OFFSET == 0x28);
    assert!(SCRATCH_TOP_G2H_RING_GPA_OFFSET == 0x30);
    assert!(SCRATCH_TOP_G2H_POOL_GPA_OFFSET == 0x38);
    assert!(SCRATCH_TOP_G2H_POOL_PAGES_OFFSET == 0x40);
    assert!(SCRATCH_TOP_G2H_BUFFER_SIZE_OFFSET == 0x48);
    assert!(SCRATCH_TOP_H2G_QUEUE_DEPTH_OFFSET == 0x50);
    assert!(SCRATCH_TOP_H2G_RING_GPA_OFFSET == 0x58);
    assert!(SCRATCH_TOP_H2G_POOL_GPA_OFFSET == 0x60);
    assert!(SCRATCH_TOP_H2G_POOL_PAGES_OFFSET == 0x68);
    assert!(SCRATCH_TOP_H2G_BUFFER_SIZE_OFFSET == 0x70);
    assert!(SCRATCH_TOP_EXN_STACK_OFFSET == 0x70);
};

/// Exclusive upper GPA boundary for dynamic scratch allocations.
pub const fn scratch_allocator_limit_gpa() -> u64 {
    (SCRATCH_TOP_GPA + 1 - SCRATCH_TOP_RESERVED_PAGES * crate::vmem::PAGE_SIZE) as u64
}

pub fn scratch_base_gpa(size: usize) -> u64 {
    (SCRATCH_TOP_GPA - size + 1) as u64
}
pub fn scratch_base_gva(size: usize) -> u64 {
    (SCRATCH_TOP_GVA - size + 1) as u64
}

/// Compute the minimum scratch region size needed for a sandbox.
///
/// The transport allowance contains one page-backed ring arena and both
/// page-backed buffer pools. The result saturates at [`usize::MAX`].
pub fn min_scratch_size(
    input_data_size: usize,
    output_data_size: usize,
    g2h_queue_depth: usize,
    h2g_queue_depth: usize,
    g2h_pool_pages: usize,
    h2g_pool_pages: usize,
) -> usize {
    let size = arch::min_scratch_size(input_data_size, output_data_size).and_then(|fixed| {
        let h2g_ring_offset = virtq::Layout::query_size(g2h_queue_depth)
            .checked_next_multiple_of(virtq::Descriptor::ALIGN)?;

        let ring_pages = h2g_ring_offset
            .checked_add(virtq::Layout::query_size(h2g_queue_depth))?
            .checked_next_multiple_of(crate::vmem::PAGE_SIZE)?;

        let pool_size = g2h_pool_pages
            .checked_add(h2g_pool_pages)?
            .checked_mul(crate::vmem::PAGE_SIZE)?;

        fixed.checked_add(ring_pages)?.checked_add(pool_size)
    });

    size.unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimum_scratch_includes_ring_arena_and_pools() {
        let fixed = arch::min_scratch_size(0, 0).unwrap();
        let transport_pages = 1 + 8 + 4;

        assert_eq!(
            fixed + transport_pages * crate::vmem::PAGE_SIZE,
            min_scratch_size(0, 0, 64, 32, 8, 4)
        );
    }

    #[test]
    fn minimum_scratch_saturates_on_overflow() {
        assert_eq!(usize::MAX, min_scratch_size(0, 0, 64, 32, usize::MAX, 4));
    }
}
