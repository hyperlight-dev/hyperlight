// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Fixed scratch aliases and page-table operations.

use alloc::vec::Vec;
use core::ops::Range;

use fixedbitset::FixedBitSet;
use hyperlight_common::layout::{SCRATCH_TOP_GPA, SCRATCH_TOP_GVA, VIRTQ_BUFFER_GVA_END};
use hyperlight_common::virtq::SlotPool;
use hyperlight_common::vmem::{BasicMapping, MappingKind, PAGE_SIZE};

use crate::paging;

// Upper bounds stay fixed across scratch sizes.
pub(crate) const ALIAS_OFFSET: u64 = SCRATCH_TOP_GVA as u64 + 1 - VIRTQ_BUFFER_GVA_END;
// Permissions for transport alias mappings.
const PERMISSIONS: BasicMapping = BasicMapping {
    readable: true,
    writable: true,
    executable: false,
};

/// Translate a scratch address into its fixed alias.
pub(crate) const fn alias(addr: u64) -> u64 {
    addr - ALIAS_OFFSET
}

/// Translate a scratch address into its guest physical address.
const fn scratch_gpa(addr: u64) -> u64 {
    addr - (SCRATCH_TOP_GVA - SCRATCH_TOP_GPA) as u64
}

/// Indices of the pool pages that `slot` touches.
fn slot_pages(base: u64, slot: &Range<u64>) -> Range<usize> {
    let start = (slot.start - base) as usize;
    let end = (slot.end - base) as usize;

    start / PAGE_SIZE..end.div_ceil(PAGE_SIZE)
}

/// Map the alias of one scratch page.
///
/// # Safety
///
/// The scratch page must be aligned and owned by the caller. No view may
/// access its alias until any replaced translation is invalidated.
unsafe fn map_alias(page: u64) {
    // SAFETY: The caller owns this scratch page and keeps its alias unused.
    unsafe {
        paging::map_region(
            scratch_gpa(page),
            alias(page) as *mut u8,
            PAGE_SIZE as u64,
            MappingKind::Basic(PERMISSIONS),
        );
    }
}

/// Map pool aliases to scratch and recover retained slots after restore.
///
/// Restore zeroes scratch and leaves aliases of retained slots on captured
/// memory. The host may already have written a request into neighboring
/// slots, so only retained bytes are copied.
///
/// 1. Map missing aliases and record aliases of other memory as captured.
/// 2. Copy retained bytes on captured pages from their aliases into scratch.
/// 3. Remap captured pages to scratch and invalidate their old translations.
///
/// # Safety
///
/// The pool must own live scratch and its fixed alias pages. `retained` must
/// hold the pool's slots that were live at the last checkpoint. Their views
/// must stay unused during this call. Serialize paging and share alias leaves
/// across accessing roots.
pub(crate) unsafe fn map_pool(pool: &SlotPool, retained: &[Range<u64>]) {
    let base = pool.base_addr();
    let pages = pool.byte_len().div_ceil(PAGE_SIZE);
    let mut captured = FixedBitSet::with_capacity(pages);

    for index in 0..pages {
        let page = base + (index * PAGE_SIZE) as u64;

        match paging::virt_to_phys(alias(page)).next() {
            // SAFETY: The caller owns this scratch page and its unmapped alias.
            None => unsafe { map_alias(page) },
            Some(mapping) if mapping.phys_base == scratch_gpa(page) => {}
            Some(_) => captured.insert(index),
        }
    }

    if !captured.is_clear() {
        for slot in retained {
            for index in slot_pages(base, slot) {
                if !captured.contains(index) {
                    continue;
                }

                let page = base + (index * PAGE_SIZE) as u64;
                let start = slot.start.max(page);
                let end = slot.end.min(page + PAGE_SIZE as u64);
                let src = alias(start) as *const u8;

                // SAFETY: The alias maps captured memory, disjoint from this
                // pool's scratch. No view accesses the slot meanwhile.
                unsafe { src.copy_to_nonoverlapping(start as *mut u8, (end - start) as usize) };
            }
        }

        for index in captured.ones() {
            let page = base + (index * PAGE_SIZE) as u64;
            let aliased = alias(page);

            // SAFETY: No view accesses this page meanwhile.
            unsafe { map_alias(page) };

            // The alias changed output address, so drop its captured translation.
            paging::barrier::downgrade_in_place(aliased..aliased + PAGE_SIZE as u64);
        }
    }

    paging::barrier::first_valid_same_ctx();
}

/// Unmap pool aliases outside live slots and return the live slot ranges.
///
/// Live slots keep their aliases, so capture copies their pages. Pass the
/// returned ranges to [`map_pool`] so a restored guest can recover them.
///
/// # Safety
///
/// The pool must own its scratch and alias pages. Stop the peer and release
/// queue-owned allocations before this sweep. Serialize guest paging.
pub(crate) unsafe fn prune_pool(pool: &SlotPool) -> Vec<Range<u64>> {
    let base = pool.base_addr();

    let live: Vec<Range<u64>> = pool
        .live_addrs()
        .into_iter()
        .map(|addr| {
            let len = pool.allocation_len(addr).expect("live slot length");
            addr..addr + len as u64
        })
        .collect();

    let pages = pool.byte_len().div_ceil(PAGE_SIZE);
    let mut keep = FixedBitSet::with_capacity(pages);

    for slot in &live {
        keep.insert_range(slot_pages(base, slot));
    }

    // Unmap unused alias pages so snapshots omit transient pool contents.
    for index in keep.zeroes() {
        let page = alias(base + (index * PAGE_SIZE) as u64);

        // SAFETY: Views own live slots, so none reaches this page. The caller
        // serializes paging and preserves the alias leaves across accessing roots.
        unsafe {
            paging::map_region(0, page as *mut u8, PAGE_SIZE as u64, MappingKind::Unmapped);
        }
    }

    let aliases = alias(base)..alias(base) + (pages * PAGE_SIZE) as u64;
    paging::barrier::downgrade_in_place(aliases);

    live
}

#[cfg(test)]
mod tests {
    use hyperlight_common::layout::{VIRTQ_BUFFER_GVA_START, scratch_base_gva};

    use crate::transport::backing::{
        PAGE_SIZE, SCRATCH_TOP_GPA, SCRATCH_TOP_GVA, VIRTQ_BUFFER_GVA_END, alias, slot_pages,
    };

    #[test]
    fn slot_pages_cover_every_touched_page() {
        let base = 0x10_0000;
        let page = PAGE_SIZE as u64;

        assert_eq!(slot_pages(base, &(base..base + 256)), 0..1);
        assert_eq!(slot_pages(base, &(base + 256..base + page)), 0..1);
        assert_eq!(slot_pages(base, &(base + page - 1..base + page + 1)), 0..2);
        assert_eq!(slot_pages(base, &(base + page..base + 3 * page)), 1..3);
    }

    #[test]
    fn aliases_cover_the_full_scratch_address_space() {
        let lowest = (SCRATCH_TOP_GVA - SCRATCH_TOP_GPA) as u64;
        assert!(alias(lowest) >= VIRTQ_BUFFER_GVA_START);
        assert!(alias(lowest).is_multiple_of(PAGE_SIZE as u64));
        assert_eq!(alias(SCRATCH_TOP_GVA as u64), VIRTQ_BUFFER_GVA_END - 1);
    }

    #[test]
    fn aliases_preserve_byte_offsets_and_gaps() {
        for size in [16 * PAGE_SIZE, 0x58000, 16 * 1024 * 1024 * 1024] {
            let base = scratch_base_gva(size);
            let alias_base = VIRTQ_BUFFER_GVA_END - size as u64;
            assert_eq!(alias(base), alias_base);

            for offset in [0, 1, PAGE_SIZE - 1, PAGE_SIZE, 7 * PAGE_SIZE + 3, size - 1] {
                assert_eq!(alias(base + offset as u64), alias_base + offset as u64);
            }
        }
    }
}
