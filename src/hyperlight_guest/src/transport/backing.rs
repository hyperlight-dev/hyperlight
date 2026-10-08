// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Reusable virtual ranges for owner-backed transport aliases.

use alloc::vec::Vec;
use core::cell::RefCell;
use core::ops::Range;

use hyperlight_common::layout::{VIRTQ_BUFFER_GVA_END, VIRTQ_BUFFER_GVA_START};
use hyperlight_common::virtq::AllocError;
use hyperlight_common::vmem::{BasicMapping, Mapping, MappingKind, PAGE_SIZE};
use itertools::Itertools;

use super::SyncWrap;
use crate::paging;

/// Reservations are captured with their aliases and survive pool generations.
static ALLOCATOR: SyncWrap<RefCell<AliasAllocator>> = SyncWrap(RefCell::new(AliasAllocator::new()));
// Permissions for transport alias mappings.
const PERMISSIONS: BasicMapping = BasicMapping {
    readable: true,
    writable: true,
    executable: false,
};

/// First-fit free ranges followed by a page-aligned bump frontier.
struct AliasAllocator {
    /// Sorted, disjoint free ranges with adjacent ranges coalesced.
    free: Vec<Range<u64>>,
    next: u64,
}

impl AliasAllocator {
    /// Reserve addresses in the dedicated transport alias arena.
    const fn new() -> Self {
        Self {
            free: Vec::new(),
            next: VIRTQ_BUFFER_GVA_START,
        }
    }

    /// Reuse freed addresses before extending the page-table footprint.
    fn alloc(&mut self, len: u64) -> Result<Range<u64>, AllocError> {
        if len == 0 || !len.is_multiple_of(PAGE_SIZE as u64) {
            return Err(AllocError::InvalidArg);
        }

        if let Some(index) = self
            .free
            .iter()
            .position(|range| range.end - range.start >= len)
        {
            let start = self.free[index].start;
            let end = start + len;
            self.free[index].start = end;

            if end == self.free[index].end {
                self.free.remove(index);
            }

            return Ok(start..end);
        }

        let end = self.next.checked_add(len).ok_or(AllocError::Overflow)?;

        if end > VIRTQ_BUFFER_GVA_END {
            return Err(AllocError::NoSpace);
        }

        let range = self.next..end;
        self.next = end;
        Ok(range)
    }

    /// Validate an owned, unmapped range and merge it with adjacent free ranges.
    fn dealloc(&mut self, range: Range<u64>) {
        assert!(range.start >= VIRTQ_BUFFER_GVA_START && range.end <= self.next);
        assert!(range.start < range.end);
        assert!(range.start.is_multiple_of(PAGE_SIZE as u64));
        assert!(range.end.is_multiple_of(PAGE_SIZE as u64));

        // Only the insertion point's neighbors can overlap the returned range.
        let index = self.free.partition_point(|free| free.start < range.start);
        assert!(index == 0 || self.free[index - 1].end <= range.start);
        assert!(index == self.free.len() || range.end <= self.free[index].start);

        let join_prev = index > 0 && self.free[index - 1].end == range.start;
        let join_next = index < self.free.len() && range.end == self.free[index].start;

        match (join_prev, join_next) {
            (true, true) => self.free[index - 1].end = self.free.remove(index).end,
            (true, false) => self.free[index - 1].end = range.end,
            (false, true) => self.free[index].start = range.start,
            (false, false) => self.free.insert(index, range),
        }
    }
}

/// Require complete source coverage by readable, writable basic pages.
fn validate_source_pages(
    source: Range<u64>,
    pages: impl Iterator<Item = Mapping>,
) -> Result<(), AllocError> {
    let mut next_source = source.start;

    for page in pages {
        let writable = matches!(
            page.kind,
            MappingKind::Basic(perm) if perm.readable && perm.writable
        );

        if !writable
            || page.virt_base != next_source
            || page.len != PAGE_SIZE as u64
            || page.len > source.end.saturating_sub(next_source)
        {
            return Err(AllocError::InvalidArg);
        }

        next_source += page.len;
    }

    if next_source != source.end {
        return Err(AllocError::InvalidArg);
    }

    Ok(())
}

/// Yield coalesced aliases for the same pages checked by [`validate_source_pages`].
fn coalesce_mappings(
    source: u64,
    start: u64,
    pages: impl Iterator<Item = Mapping>,
) -> impl Iterator<Item = Mapping> {
    let runs = pages.coalesce(|mut run, page| {
        if run.phys_base.checked_add(run.len) != Some(page.phys_base) {
            return Err((run, page));
        }

        run.len += page.len;
        Ok(run)
    });

    runs.map(move |run| Mapping {
        virt_base: start + (run.virt_base - source),
        kind: MappingKind::Basic(PERMISSIONS),
        ..run
    })
}

/// Update owned alias entries and invalidate cleared translations.
///
/// # Safety
///
/// The caller must own the alias range and exclude all views during updates.
/// Mapped backing must remain live for later views.
/// Serialize paging and share alias leaves across accessing roots.
unsafe fn update_alias(mapping: Mapping) {
    // SAFETY: The caller owns these entries and provides valid backing.
    unsafe {
        paging::map_region(
            mapping.phys_base,
            mapping.virt_base as *mut u8,
            mapping.len,
            mapping.kind,
        );
    }

    if mapping.kind == MappingKind::Unmapped {
        paging::barrier::downgrade_in_place(mapping.virt_base..mapping.virt_base + mapping.len);
    }
}

/// Reserve an alias and map it to initialized scratch pages.
///
/// # Safety
///
/// The scratch range must be page-aligned, live, and initialized.
pub(crate) unsafe fn map(scratch: u64, len: u64) -> Result<Range<u64>, AllocError> {
    if !scratch.is_multiple_of(PAGE_SIZE as u64) {
        return Err(AllocError::InvalidArg);
    }

    let mut allocator = ALLOCATOR.0.borrow_mut();
    let alias = allocator.alloc(len)?;
    let end = scratch.checked_add(len).ok_or(AllocError::Overflow)?;

    let pages = paging::virt_to_phys_range(scratch, len);
    let res = validate_source_pages(scratch..end, pages);

    if let Err(error) = res {
        allocator.dealloc(alias);
        return Err(error);
    }

    let pages = paging::virt_to_phys_range(scratch, len);
    let start = alias.start;

    for mapping in coalesce_mappings(scratch, start, pages) {
        // SAFETY: The reservation is unused and source pages have valid backing.
        unsafe { update_alias(mapping) };
    }

    paging::barrier::first_valid_same_ctx();
    Ok(alias)
}

/// Unmap an owned alias and return its virtual range for reuse.
///
/// # Safety
///
/// The caller must own a range returned by [`map`] and exclude all remaining
/// views. Run on the serialized guest vCPU.
/// Serialize paging and share alias leaves across accessing roots.
pub(crate) unsafe fn unmap(alias: &Range<u64>) {
    // SAFETY: The caller exclusively owns these leaves and has released views.
    unsafe {
        update_alias(Mapping {
            phys_base: 0,
            virt_base: alias.start,
            len: alias.end - alias.start,
            kind: MappingKind::Unmapped,
        });
    }

    ALLOCATOR.0.borrow_mut().dealloc(alias.clone());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_walk_coalesces_contiguous_physical_pages() {
        let page = PAGE_SIZE as u64;
        let source = 0x10_0000;
        let alias = VIRTQ_BUFFER_GVA_START;

        let kind = MappingKind::Basic(PERMISSIONS);
        let first = Mapping {
            phys_base: page,
            virt_base: source,
            len: page,
            kind,
        };

        let pages = [
            first,
            Mapping {
                phys_base: 2 * page,
                virt_base: source + page,
                ..first
            },
            Mapping {
                phys_base: 8 * page,
                virt_base: source + 2 * page,
                ..first
            },
        ];

        validate_source_pages(source..source + 3 * page, pages.iter().copied()).unwrap();

        let updates: Vec<_> = coalesce_mappings(source, alias, pages.iter().copied())
            .map(|m| (m.virt_base, m.phys_base, m.len, m.kind))
            .collect();

        assert_eq!(
            updates,
            [
                (alias, page, 2 * page, kind),
                (alias + 2 * page, 8 * page, page, kind),
            ]
        );
    }

    #[test]
    fn aliases_reuse_and_coalesce_freed_ranges() {
        let mut allocator = AliasAllocator::new();
        let page = PAGE_SIZE as u64;
        let first = allocator.alloc(page).unwrap();
        let middle = allocator.alloc(2 * page).unwrap();
        let last = allocator.alloc(page).unwrap();
        let frontier = allocator.next;

        allocator.dealloc(middle.clone());
        let reused = allocator.alloc(page).unwrap();

        assert_eq!(reused, middle.start..middle.start + page);

        allocator.dealloc(first.clone());
        allocator.dealloc(last.clone());
        allocator.dealloc(reused);

        assert_eq!(allocator.alloc(4 * page).unwrap(), first.start..last.end);
        assert_eq!(allocator.next, frontier);
    }

    #[test]
    fn exhausted_alias_space_still_reuses_freed_ranges() {
        let mut allocator = AliasAllocator::new();
        let whole = allocator
            .alloc(VIRTQ_BUFFER_GVA_END - VIRTQ_BUFFER_GVA_START)
            .unwrap();

        let err = allocator.alloc(PAGE_SIZE as u64);
        assert!(matches!(err, Err(AllocError::NoSpace)));

        allocator.dealloc(whole.clone());

        let reused = allocator.alloc(PAGE_SIZE as u64).unwrap();
        assert_eq!(reused.start, whole.start);
    }

    /// Failed reservations preserve both reusable ranges and the frontier.
    #[test]
    fn invalid_alias_lengths_preserve_allocator_state() {
        let mut allocator = AliasAllocator::new();
        let page = PAGE_SIZE as u64;
        let first = allocator.alloc(page).unwrap();
        let _retained = allocator.alloc(page).unwrap();

        allocator.dealloc(first.clone());
        let free = allocator.free.clone();
        let frontier = allocator.next;

        for len in [0, page - 1, page + 1] {
            let err = allocator.alloc(len);
            assert!(matches!(err, Err(AllocError::InvalidArg)));
        }

        let ov = allocator.alloc(u64::MAX / page * page);
        assert!(matches!(ov, Err(AllocError::Overflow)));

        let ns = allocator.alloc(VIRTQ_BUFFER_GVA_END - VIRTQ_BUFFER_GVA_START);
        assert!(matches!(ns, Err(AllocError::NoSpace)));
        assert_eq!(allocator.free, free);
        assert_eq!(allocator.next, frontier);
        assert_eq!(allocator.alloc(page).unwrap(), first);
    }
}
