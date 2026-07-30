// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use core::mem::{offset_of, size_of};
use core::num::{NonZeroU16, NonZeroUsize};

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
    /// Padding that keeps the exception stack 16-byte aligned.
    _alignment_padding: [u8; 16],
    /// Host-published capacity of each H2G buffer.
    h2g_buffer_size: u64,
    /// Number of pages reserved for the H2G pool.
    h2g_pool_pages: u64,
    /// Host-published H2G descriptor count.
    h2g_queue_depth: u64,
    /// Host-published capacity of each G2H upper-tier buffer.
    g2h_buffer_size: u64,
    /// Number of pages reserved for the G2H pool.
    g2h_pool_pages: u64,
    /// Host-published G2H descriptor count.
    g2h_queue_depth: u64,
    /// Host-published GPA of the fixed transport arena.
    transport_arena_gpa: u64,
    /// Seed request for libc's pseudorandom number generator.
    libc_rng_seed: u64,
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
pub const SCRATCH_TOP_G2H_POOL_PAGES_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, g2h_pool_pages));
pub const SCRATCH_TOP_G2H_BUFFER_SIZE_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, g2h_buffer_size));
pub const SCRATCH_TOP_H2G_QUEUE_DEPTH_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, h2g_queue_depth));
pub const SCRATCH_TOP_H2G_POOL_PAGES_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, h2g_pool_pages));
pub const SCRATCH_TOP_H2G_BUFFER_SIZE_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, h2g_buffer_size));
pub const SCRATCH_TOP_TRANSPORT_ARENA_GPA_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, transport_arena_gpa));
pub const SCRATCH_TOP_SIZE_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, scratch_size));
pub const SCRATCH_TOP_ALLOCATOR_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, allocator));
pub const SCRATCH_TOP_SNAPSHOT_PT_GPA_BASE_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, snapshot_pt_gpa_base));
pub const SCRATCH_TOP_SNAPSHOT_GENERATION_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, snapshot_generation));
pub const SCRATCH_TOP_LIBC_RNG_SEED_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, libc_rng_seed));
pub const SCRATCH_TOP_EXN_STACK_OFFSET: u64 = size_of::<ScratchTopMetadata>() as u64;

const _: () = {
    assert!(size_of::<ScratchTopMetadata>().is_multiple_of(EXN_STACK_ALIGNMENT));
    assert!(SCRATCH_TOP_SIZE_OFFSET == 0x08);
    assert!(SCRATCH_TOP_ALLOCATOR_OFFSET == 0x10);
    assert!(SCRATCH_TOP_SNAPSHOT_PT_GPA_BASE_OFFSET == 0x18);
    assert!(SCRATCH_TOP_SNAPSHOT_GENERATION_OFFSET == 0x20);
    assert!(SCRATCH_TOP_LIBC_RNG_SEED_OFFSET == 0x28);
    assert!(SCRATCH_TOP_TRANSPORT_ARENA_GPA_OFFSET == 0x30);
    assert!(SCRATCH_TOP_G2H_QUEUE_DEPTH_OFFSET == 0x38);
    assert!(SCRATCH_TOP_G2H_POOL_PAGES_OFFSET == 0x40);
    assert!(SCRATCH_TOP_G2H_BUFFER_SIZE_OFFSET == 0x48);
    assert!(SCRATCH_TOP_H2G_QUEUE_DEPTH_OFFSET == 0x50);
    assert!(SCRATCH_TOP_H2G_POOL_PAGES_OFFSET == 0x58);
    assert!(SCRATCH_TOP_H2G_BUFFER_SIZE_OFFSET == 0x60);
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
/// The fixed transport prefix contains one page-backed ring arena and both
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
        let g2h = QueueDims::new(g2h_queue_depth, g2h_pool_pages)?;
        let h2g = QueueDims::new(h2g_queue_depth, h2g_pool_pages)?;

        let transport_len = TransportArena::checked_query_size(g2h, h2g)?;
        fixed.checked_add(transport_len)
    });

    size.unwrap_or(usize::MAX)
}

/// Validated address independent dimensions for one transport queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueDims {
    depth: NonZeroU16,
    pool_pages: NonZeroUsize,
}

impl QueueDims {
    /// Validate one queue descriptor count and pool page count.
    pub fn new(depth: usize, pool_pages: usize) -> Option<Self> {
        let depth = u16::try_from(depth).ok()?;
        let depth = NonZeroU16::new(depth)?;

        if !depth.get().is_power_of_two() {
            return None;
        }

        let pool_pages = NonZeroUsize::new(pool_pages)?;
        Some(Self { depth, pool_pages })
    }

    /// Number of descriptors in the queue.
    pub const fn depth(&self) -> NonZeroU16 {
        self.depth
    }

    /// Number of pages in the queue's buffer pool.
    pub const fn pool_pages(&self) -> NonZeroUsize {
        self.pool_pages
    }

    /// Compute the ring length, returning `None` on arithmetic overflow.
    pub fn checked_ring_len(&self) -> Option<usize> {
        virtq::Layout::checked_query_size(usize::from(self.depth.get()))
    }

    /// Compute the pool length, returning `None` on arithmetic overflow.
    pub fn checked_pool_len(&self) -> Option<usize> {
        self.pool_pages.get().checked_mul(crate::vmem::PAGE_SIZE)
    }
}

/// Addresses of both rings and pools in one fixed transport arena.
///
/// The G2H ring begins at the arena base. The H2G ring is descriptor aligned.
/// Both pools are page aligned.
///
/// ```text
/// +----------+------------+----------+-----+----------+----------+
/// | G2H ring | align pad  | H2G ring | pad | G2H pool | H2G pool |
/// +----------+------------+----------+-----+----------+----------+
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportArena {
    /// Address of the G2H ring and base of the arena.
    g2h_ring_addr: u64,
    /// Address of the H2G ring.
    h2g_ring_addr: u64,
    /// Address of the G2H pool.
    g2h_pool_addr: u64,
    /// Address of the H2G pool.
    h2g_pool_addr: u64,
    /// Page-aligned length occupied by both rings.
    ring_span_len: usize,
    /// Total page-aligned arena length.
    len: usize,
}

impl TransportArena {
    /// Derive one transport arena from its base address and queue dimensions.
    pub fn new(base_addr: u64, g2h: QueueDims, h2g: QueueDims) -> Option<Self> {
        if !base_addr.is_multiple_of(crate::vmem::PAGE_SIZE as u64) {
            return None;
        }

        let h2g_ring_offset = g2h
            .checked_ring_len()?
            .checked_next_multiple_of(virtq::Descriptor::ALIGN)?;

        let g2h_pool_offset = h2g_ring_offset
            .checked_add(h2g.checked_ring_len()?)?
            .checked_next_multiple_of(crate::vmem::PAGE_SIZE)?;

        let g2h_pool_len = g2h.checked_pool_len()?;
        let h2g_pool_offset = g2h_pool_offset.checked_add(g2h_pool_len)?;

        let h2g_pool_len = h2g.checked_pool_len()?;
        let len = h2g_pool_offset.checked_add(h2g_pool_len)?;

        let addr = |offset: usize| base_addr.checked_add(u64::try_from(offset).ok()?);
        let _end_addr = addr(len)?;

        Some(Self {
            g2h_ring_addr: base_addr,
            h2g_ring_addr: addr(h2g_ring_offset)?,
            g2h_pool_addr: addr(g2h_pool_offset)?,
            h2g_pool_addr: addr(h2g_pool_offset)?,
            ring_span_len: g2h_pool_offset,
            len,
        })
    }

    /// Compute the total arena size without assigning an address.
    pub fn checked_query_size(g2h: QueueDims, h2g: QueueDims) -> Option<usize> {
        Some(Self::new(0, g2h, h2g)?.len)
    }

    /// Base address of the arena.
    pub const fn base_addr(&self) -> u64 {
        self.g2h_ring_addr
    }

    /// Address of the G2H ring.
    pub const fn g2h_ring_addr(&self) -> u64 {
        self.g2h_ring_addr
    }

    /// Address of the H2G ring.
    pub const fn h2g_ring_addr(&self) -> u64 {
        self.h2g_ring_addr
    }

    /// Address of the G2H pool.
    pub const fn g2h_pool_addr(&self) -> u64 {
        self.g2h_pool_addr
    }

    /// Address of the H2G pool.
    pub const fn h2g_pool_addr(&self) -> u64 {
        self.h2g_pool_addr
    }

    /// Page-aligned length occupied by both rings.
    pub const fn ring_span_len(&self) -> usize {
        self.ring_span_len
    }

    /// Total page-aligned arena length.
    pub const fn size(&self) -> usize {
        self.len
    }

    /// Exclusive end address of the arena.
    pub const fn end_addr(&self) -> u64 {
        self.g2h_ring_addr + self.len as u64
    }

    /// Convert the arena's absolute addresses into offsets from the arena base.
    pub fn to_offsets(&self) -> (usize, usize, usize, usize) {
        // Already validated by `TransportArena::new`.
        let to_offset = |addr| usize::try_from(addr - self.g2h_ring_addr).unwrap();

        (
            to_offset(self.h2g_ring_addr),
            to_offset(self.g2h_pool_addr),
            to_offset(self.h2g_pool_addr),
            self.len,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_arena_derives_aligned_regions() {
        let base = 0x1_0000;
        let g2h = QueueDims::new(64, 8).unwrap();
        let h2g = QueueDims::new(32, 4).unwrap();
        let arena = TransportArena::new(base, g2h, h2g).unwrap();

        assert_eq!(arena.g2h_ring_addr(), base);
        assert!(
            arena
                .h2g_ring_addr()
                .is_multiple_of(virtq::Descriptor::ALIGN as u64)
        );
        assert!(
            arena
                .g2h_pool_addr()
                .is_multiple_of(crate::vmem::PAGE_SIZE as u64)
        );
        assert_eq!(
            arena.h2g_pool_addr(),
            base + 9 * crate::vmem::PAGE_SIZE as u64
        );
        assert_eq!(arena.end_addr(), base + 13 * crate::vmem::PAGE_SIZE as u64);
        assert_eq!(
            arena.to_offsets(),
            (
                0x410,
                crate::vmem::PAGE_SIZE,
                9 * crate::vmem::PAGE_SIZE,
                13 * crate::vmem::PAGE_SIZE,
            )
        );
        assert_eq!(arena.ring_span_len(), crate::vmem::PAGE_SIZE);
        assert_eq!(arena.size(), 13 * crate::vmem::PAGE_SIZE);
        assert_eq!(
            TransportArena::checked_query_size(g2h, h2g),
            Some(arena.size())
        );
        assert_eq!(TransportArena::new(base + 1, g2h, h2g), None);
        assert_eq!(QueueDims::new(3, 8), None);
        assert_eq!(QueueDims::new(64, 0), None);
        assert_eq!(QueueDims::new(usize::MAX, 8), None);
        let oversized = QueueDims::new(64, usize::MAX).unwrap();
        assert_eq!(TransportArena::new(base, oversized, h2g), None);
        assert_eq!(
            TransportArena::new(u64::MAX - crate::vmem::PAGE_SIZE as u64 + 1, g2h, h2g,),
            None
        );
    }

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
        assert_eq!(usize::MAX, min_scratch_size(0, 0, usize::MAX, 32, 8, 4));
    }
}
