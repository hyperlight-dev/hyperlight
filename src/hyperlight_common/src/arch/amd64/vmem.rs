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

//! x86-64 4-level page table manipulation code.
//!
//! This module implements page table setup for x86-64 long mode using 4-level paging:
//! - PML4 (Page Map Level 4) - bits 47:39 - 512 entries, each covering 512GB
//! - PDPT (Page Directory Pointer Table) - bits 38:30 - 512 entries, each covering 1GB
//! - PD (Page Directory) - bits 29:21 - 512 entries, each covering 2MB
//! - PT (Page Table) - bits 20:12 - 512 entries, each covering 4KB pages
//!
//! The code uses an iterator-based approach to walk the page table hierarchy,
//! allocating intermediate tables as needed and setting appropriate flags on leaf PTEs

use crate::vmem::{BasicMapping, Mapping, MappingKind, TableOps};

// Paging Flags
//
// See the following links explaining paging:
//
// * Intel® 64 and IA-32 Architectures Software Developer’s Manual, Volume 3A: System Programming Guide, Part 1
//  - Chapter 5 "Paging"
//
// https://cdrdv2.intel.com/v1/dl/getContent/671200
//
// * AMD64 Architecture Programmer’s Manual, Volume 2: System Programming, Section 5.3: Long-Mode Page Translation
//
// https://docs.amd.com/v/u/en-US/24593_3.43
//
// Or if you prefer something less formal:
//
// * Very basic description: https://stackoverflow.com/a/26945892
// * More in-depth descriptions: https://wiki.osdev.org/Paging
//

/// Page is Present
const PAGE_PRESENT: u64 = 1;
/// Page is Read/Write (if not set page is read only so long as the WP bit in CR0 is set to 1 - which it is in Hyperlight)
const PAGE_RW: u64 = 1 << 1;
/// Execute Disable (if this bit is set then data in the page cannot be executed)`
const PAGE_NX: u64 = 1 << 63;
/// Mask to extract the physical address from a PTE (bits 51:12)
/// This masks out the lower 12 flag bits AND the upper bits including NX (bit 63)
const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
const PAGE_USER_ACCESS_DISABLED: u64 = 0 << 2; // U/S bit not set - supervisor mode only (no code runs in user mode for now)
const PAGE_DIRTY_CLEAR: u64 = 0 << 6; // D - dirty bit cleared (set by CPU when written)
const PAGE_ACCESSED_CLEAR: u64 = 0 << 5; // A - accessed bit cleared (set by CPU when accessed)
const PAGE_CACHE_ENABLED: u64 = 0 << 4; // PCD - page cache disable bit not set (caching enabled)
const PAGE_WRITE_BACK: u64 = 0 << 3; // PWT - page write-through bit not set (write-back caching)
const PAGE_PAT_WB: u64 = 0 << 7; // PAT - page attribute table index bit (0 for write-back memory when PCD=0, PWT=0)

/// Returns PAGE_RW if writable is true, 0 otherwise
#[inline(always)]
const fn page_rw_flag(writable: bool) -> u64 {
    if writable { PAGE_RW } else { 0 }
}

/// Returns PAGE_NX if executable is false (NX = No Execute), 0 otherwise
#[inline(always)]
const fn page_nx_flag(executable: bool) -> u64 {
    if executable { 0 } else { PAGE_NX }
}

/// Read a page table entry and return it if the present bit is set
/// # Safety
/// The caller must ensure that `entry_ptr` points to a valid page table entry.
#[inline(always)]
unsafe fn read_pte_if_present<Op: TableOps>(op: &Op, entry_ptr: Op::TableAddr) -> Option<u64> {
    let pte = unsafe { op.read_entry(entry_ptr) };
    if (pte & PAGE_PRESENT) != 0 {
        Some(pte)
    } else {
        None
    }
}

/// Utility function to extract an (inclusive on both ends) bit range
/// from a quadword.
#[inline(always)]
fn bits<const HIGH_BIT: u8, const LOW_BIT: u8>(x: u64) -> u64 {
    (x & ((1 << (HIGH_BIT + 1)) - 1)) >> LOW_BIT
}

/// Helper function to generate a page table entry that points to another table
#[allow(clippy::identity_op)]
#[allow(clippy::precedence)]
fn pte_for_table<Op: TableOps>(table_addr: Op::TableAddr) -> u64 {
    Op::to_phys(table_addr) |
        PAGE_ACCESSED_CLEAR | // accessed bit cleared (will be set by CPU when page is accessed - but we dont use the access bit for anything at present)
        PAGE_CACHE_ENABLED | // leave caching enabled
        PAGE_WRITE_BACK | // use write-back caching
        PAGE_USER_ACCESS_DISABLED |// dont allow user access (no code runs in user mode for now)
        PAGE_RW | // R/W - we don't use block-level permissions
        PAGE_PRESENT // P   - this entry is present
}

/// Helper function to write a page table entry, updating the whole
/// chain of tables back to the root if necessary
unsafe fn write_entry_updating<Op: TableOps, P: UpdateParent<Op>>(
    op: &Op,
    parent: P,
    addr: Op::TableAddr,
    entry: u64,
) {
    if let Some(again) = unsafe { op.write_entry(addr, entry) } {
        parent.update_parent(op, again);
    }
}

/// A helper trait that allows us to move a page table (e.g. from the
/// snapshot to the scratch region), keeping track of the context that
/// needs to be updated when that is moved (and potentially
/// recursively updating, if necessary)
///
/// This is done via a trait so that the selected impl knows the exact
/// nesting depth of tables, in order to assist
/// inlining/specialisation in generating efficient code.
trait UpdateParent<Op: TableOps>: Copy {
    fn update_parent(self, op: &Op, new_ptr: Op::TableAddr);
}

/// A struct implementing [`UpdateParent`] that keeps track of the
/// fact that the parent table is itself another table, whose own
/// ancestors may need to be recursively updated
struct UpdateParentTable<Op: TableOps, P: UpdateParent<Op>> {
    parent: P,
    entry_ptr: Op::TableAddr,
}
impl<Op: TableOps, P: UpdateParent<Op>> Clone for UpdateParentTable<Op, P> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<Op: TableOps, P: UpdateParent<Op>> Copy for UpdateParentTable<Op, P> {}
impl<Op: TableOps, P: UpdateParent<Op>> UpdateParentTable<Op, P> {
    fn new(parent: P, entry_ptr: Op::TableAddr) -> Self {
        UpdateParentTable { parent, entry_ptr }
    }
}
impl<Op: TableOps, P: UpdateParent<Op>> UpdateParent<Op> for UpdateParentTable<Op, P> {
    fn update_parent(self, op: &Op, new_ptr: Op::TableAddr) {
        let pte = pte_for_table::<Op>(new_ptr);
        unsafe {
            write_entry_updating(op, self.parent, self.entry_ptr, pte);
        }
    }
}

/// A struct implementing [`UpdateParent`] that keeps track of the
/// fact that the parent "table" is actually the CR3 system register.
#[derive(Copy, Clone)]
struct UpdateParentCR3 {}
impl<Op: TableOps> UpdateParent<Op> for UpdateParentCR3 {
    fn update_parent(self, _op: &Op, new_ptr: Op::TableAddr) {
        unsafe {
            core::arch::asm!("mov cr3, {}", in(reg) Op::to_phys(new_ptr));
        }
    }
}

/// A struct implementing [`UpdateParent`] that panics when used, for
/// the occasional situations in which we should never do an update
#[derive(Copy, Clone)]
struct UpdateParentNone {}
impl<Op: TableOps> UpdateParent<Op> for UpdateParentNone {
    // This is only used in contexts which should absolutely never try
    // to update a page table, and so in no case should possibly ever
    // call an update_parent.  Therefore, this is impossible unless an
    // extremely significant invariant violation has occurred.
    #[allow(clippy::panic)]
    fn update_parent(self, _op: &Op, _new_ptr: Op::TableAddr) {
        panic!("UpdateParentNone: tried to update parent");
    }
}

/// A helper structure indicating a mapping operation that needs to be
/// performed
struct MapRequest<Op: TableOps, P: UpdateParent<Op>> {
    table_base: Op::TableAddr,
    vmin: VirtAddr,
    len: u64,
    update_parent: P,
}

/// A helper structure indicating that a particular PTE needs to be
/// modified
struct MapResponse<Op: TableOps, P: UpdateParent<Op>> {
    entry_ptr: Op::TableAddr,
    vmin: VirtAddr,
    len: u64,
    update_parent: P,
}

/// Iterator that walks through page table entries at a specific level.
///
/// Given a virtual address range and a table base, this iterator yields
/// `MapResponse` items for each page table entry that needs to be modified.
/// The const generics `HIGH_BIT` and `LOW_BIT` specify which bits of the
/// virtual address are used to index into this level's table.
///
/// For example:
/// - PML4: HIGH_BIT=47, LOW_BIT=39 (9 bits = 512 entries, each covering 512GB)
/// - PDPT: HIGH_BIT=38, LOW_BIT=30 (9 bits = 512 entries, each covering 1GB)
/// - PD:   HIGH_BIT=29, LOW_BIT=21 (9 bits = 512 entries, each covering 2MB)
/// - PT:   HIGH_BIT=20, LOW_BIT=12 (9 bits = 512 entries, each covering 4KB)
struct ModifyPteIterator<const HIGH_BIT: u8, const LOW_BIT: u8, Op: TableOps, P: UpdateParent<Op>> {
    request: MapRequest<Op, P>,
    n: u64,
}
impl<const HIGH_BIT: u8, const LOW_BIT: u8, Op: TableOps, P: UpdateParent<Op>> Iterator
    for ModifyPteIterator<HIGH_BIT, LOW_BIT, Op, P>
{
    type Item = MapResponse<Op, P>;
    fn next(&mut self) -> Option<Self::Item> {
        // Each page table entry at this level covers a region of size (1 << LOW_BIT) bytes.
        // For example, at the PT level (LOW_BIT=12), each entry covers 4KB (0x1000 bytes).
        // At the PD level (LOW_BIT=21), each entry covers 2MB (0x200000 bytes).
        //
        // This mask isolates the bits below this level's index bits, used for alignment.
        let lower_bits_mask = (1 << LOW_BIT) - 1;

        // Calculate the virtual address for this iteration.
        // On the first iteration (n=0), start at the requested vmin.
        // On subsequent iterations, advance to the next aligned boundary.
        // This handles the case where vmin isn't aligned to this level's entry size.
        let next_vmin = if self.n == 0 {
            self.request.vmin
        } else {
            // Align to the next boundary by adding one entry's worth
            // and masking off lower bits. Masking off before adding
            // is safe, since n << LOW_BIT must always have zeros in
            // these positions.
            let aligned_min = self.request.vmin & !lower_bits_mask;
            // Use checked_add here because going past the end of the
            // address space counts as "the next one would be out of
            // range"
            aligned_min.checked_add(self.n << LOW_BIT)?
        };

        // Check if we've processed the entire requested range
        if next_vmin >= self.request.vmin + self.request.len {
            return None;
        }

        // Calculate the pointer to this level's page table entry.
        // bits::<HIGH_BIT, LOW_BIT> extracts the relevant index bits from the virtual address.
        // Shift left by 3 (multiply by 8) because each entry is 8 bytes (u64).
        let entry_ptr = Op::entry_addr(
            self.request.table_base,
            bits::<HIGH_BIT, LOW_BIT>(next_vmin) << 3,
        );

        // Calculate how many bytes remain to be mapped from this point
        let len_from_here = self.request.len - (next_vmin - self.request.vmin);

        // Calculate the maximum bytes this single entry can cover.
        // If next_vmin is aligned, this is the full entry size (1 << LOW_BIT).
        // If not aligned (only possible on first iteration), it's the remaining
        // space until the next boundary.
        let max_len = (1 << LOW_BIT) - (next_vmin & lower_bits_mask);

        // The actual length for this entry is the smaller of what's needed vs what fits
        let next_len = core::cmp::min(len_from_here, max_len);

        // Advance iteration counter for next call
        self.n += 1;

        Some(MapResponse {
            entry_ptr,
            vmin: next_vmin,
            len: next_len,
            update_parent: self.request.update_parent,
        })
    }
}
fn modify_ptes<const HIGH_BIT: u8, const LOW_BIT: u8, Op: TableOps, P: UpdateParent<Op>>(
    r: MapRequest<Op, P>,
) -> ModifyPteIterator<HIGH_BIT, LOW_BIT, Op, P> {
    ModifyPteIterator { request: r, n: 0 }
}

/// Page-mapping callback to allocate a next-level page table if necessary.
/// # Safety
/// This function modifies page table data structures, and should not be called concurrently
/// with any other operations that modify the page tables.
unsafe fn alloc_pte_if_needed<Op: TableOps, P: UpdateParent<Op>>(
    op: &Op,
    x: MapResponse<Op, P>,
) -> MapRequest<Op, UpdateParentTable<Op, P>> {
    let new_update_parent = UpdateParentTable::new(x.update_parent, x.entry_ptr);
    if let Some(pte) = unsafe { read_pte_if_present(op, x.entry_ptr) } {
        return MapRequest {
            table_base: Op::from_phys(pte & PTE_ADDR_MASK),
            vmin: x.vmin,
            len: x.len,
            update_parent: new_update_parent,
        };
    }

    let page_addr = unsafe { op.alloc_table() };

    let pte = pte_for_table::<Op>(page_addr);
    unsafe {
        write_entry_updating(op, x.update_parent, x.entry_ptr, pte);
    };
    MapRequest {
        table_base: page_addr,
        vmin: x.vmin,
        len: x.len,
        update_parent: new_update_parent,
    }
}

/// Map a normal memory page
/// # Safety
/// This function modifies page table data structures, and should not be called concurrently
/// with any other operations that modify the page tables.
#[allow(clippy::identity_op)]
#[allow(clippy::precedence)]
unsafe fn map_page<Op: TableOps, P: UpdateParent<Op>>(
    op: &Op,
    mapping: &Mapping,
    r: MapResponse<Op, P>,
) {
    let pte = match &mapping.kind {
        MappingKind::BasicMapping(bm) =>
        // TODO: Support not readable
        // NOTE: On x86-64, there is no separate "readable" bit in the page table entry.
        // This means that pages cannot be made write-only or execute-only without also being readable.
        // All pages that are mapped as writable or executable are also implicitly readable.
        // If support for "not readable" mappings is required in the future, it would need to be
        // implemented using additional mechanisms (e.g., page-fault handling or memory protection keys),
        // but for now, this architectural limitation is accepted.
        {
            (mapping.phys_base + (r.vmin - mapping.virt_base)) |
                page_nx_flag(bm.executable) | // NX - no execute unless allowed
                PAGE_PAT_WB | // PAT index bit for write-back memory
                PAGE_DIRTY_CLEAR | // dirty bit (set by CPU when written)
                PAGE_ACCESSED_CLEAR | // accessed bit cleared (will be set by CPU when page is accessed - but we dont use the access bit for anything at present)
                PAGE_CACHE_ENABLED | // leave caching enabled
                PAGE_WRITE_BACK | // use write-back caching
                PAGE_USER_ACCESS_DISABLED | // dont allow user access (no code runs in user mode for now)
                page_rw_flag(bm.writable) | // R/W - set if writable
                PAGE_PRESENT // P   - this entry is present
        }
    };
    unsafe {
        write_entry_updating(op, r.update_parent, r.entry_ptr, pte);
    }
}

// There are no notable architecture-specific safety considerations
// here, and the general conditions are documented in the
// architecture-independent re-export in vmem.rs

/// Maps a contiguous virtual address range to physical memory.
///
/// This function walks the 4-level page table hierarchy (PML4 → PDPT → PD → PT),
/// allocating intermediate tables as needed via `alloc_pte_if_needed`, and finally
/// writing the leaf page table entries with the requested permissions via `map_page`.
///
/// The iterator chain processes each level:
/// 1. PML4 (47:39) - allocate PDPT if needed
/// 2. PDPT (38:30) - allocate PD if needed
/// 3. PD (29:21) - allocate PT if needed
/// 4. PT (20:12) - write final PTE with physical address and flags
#[allow(clippy::missing_safety_doc)]
pub unsafe fn map<Op: TableOps>(op: &Op, mapping: Mapping) {
    modify_ptes::<47, 39, Op, _>(MapRequest {
        table_base: op.root_table(),
        vmin: mapping.virt_base,
        len: mapping.len,
        update_parent: UpdateParentCR3 {},
    })
    .map(|r| unsafe { alloc_pte_if_needed(op, r) })
    .flat_map(modify_ptes::<38, 30, Op, _>)
    .map(|r| unsafe { alloc_pte_if_needed(op, r) })
    .flat_map(modify_ptes::<29, 21, Op, _>)
    .map(|r| unsafe { alloc_pte_if_needed(op, r) })
    .flat_map(modify_ptes::<20, 12, Op, _>)
    .map(|r| unsafe { map_page(op, &mapping, r) })
    .for_each(drop);
}

/// # Safety
/// This function traverses page table data structures, and should not
/// be called concurrently with any other operations that modify the
/// page table.
unsafe fn require_pte_exist<Op: TableOps, P: UpdateParent<Op>>(
    op: &Op,
    x: MapResponse<Op, P>,
) -> Option<MapRequest<Op, UpdateParentTable<Op, P>>> {
    unsafe { read_pte_if_present(op, x.entry_ptr) }.map(|pte| MapRequest {
        table_base: Op::from_phys(pte & PTE_ADDR_MASK),
        vmin: x.vmin,
        len: x.len,
        update_parent: UpdateParentTable::new(x.update_parent, x.entry_ptr),
    })
}

// There are no notable architecture-specific safety considerations
// here, and the general conditions are documented in the
// architecture-independent re-export in vmem.rs

/// Translates a virtual address range to the physical address pages
/// that back it by walking the page tables.
///
/// Returns an iterator with an entry for each mapped page that
/// intersects the given range.
///
/// This takes AsRef<Op> + Copy so that on targets where the
/// operations have little state (e.g. the guest) the operations state
/// can be copied into the closure(s) in the iterator, allowing for a
/// nicer result lifetime.  On targets like the
/// building-an-original-snapshot portion of the host, where the
/// operations structure owns a large buffer, a reference can instead
/// be passed.
#[allow(clippy::missing_safety_doc)]
pub unsafe fn virt_to_phys<'a, Op: TableOps + 'a>(
    op: impl core::convert::AsRef<Op> + Copy + 'a,
    address: u64,
    len: u64,
) -> impl Iterator<Item = (VirtAddr, PhysAddr, BasicMapping)> + 'a {
    // Undo sign-extension, and mask off any sub-page bits
    let vmin = (address & ((1u64 << VA_BITS) - 1)) & !(PAGE_SIZE as u64 - 1);
    let vmax = core::cmp::min(vmin + len, 1u64 << VA_BITS);
    modify_ptes::<47, 39, Op, _>(MapRequest {
        table_base: op.as_ref().root_table(),
        vmin,
        len: vmax - vmin,
        update_parent: UpdateParentNone {},
    })
    .filter_map(move |r| unsafe { require_pte_exist(op.as_ref(), r) })
    .flat_map(modify_ptes::<38, 30, Op, _>)
    .filter_map(move |r| unsafe { require_pte_exist(op.as_ref(), r) })
    .flat_map(modify_ptes::<29, 21, Op, _>)
    .filter_map(move |r| unsafe { require_pte_exist(op.as_ref(), r) })
    .flat_map(modify_ptes::<20, 12, Op, _>)
    .filter_map(move |r| {
        let pte = unsafe { read_pte_if_present(op.as_ref(), r.entry_ptr) }?;
        let phys_addr = pte & PTE_ADDR_MASK;
        // Re-do the sign extension
        let sgn_bit = r.vmin >> (VA_BITS - 1);
        let sgn_bits = 0u64.wrapping_sub(sgn_bit) << VA_BITS;
        let virt_addr = sgn_bits | r.vmin;
        let perms = BasicMapping {
            readable: true,
            writable: (pte & PAGE_RW) != 0,
            executable: (pte & PAGE_NX) == 0,
        };
        Some((virt_addr, phys_addr, perms))
    })
}

const VA_BITS: usize = 48; // We use 48-bit virtual addresses at the moment.

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_TABLE_SIZE: usize = 4096;
pub type PageTableEntry = u64;
pub type VirtAddr = u64;
pub type PhysAddr = u64;

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::RefCell;

    use super::*;
    use crate::vmem::{BasicMapping, Mapping, MappingKind, PAGE_TABLE_ENTRIES_PER_TABLE, TableOps};

    /// A mock TableOps implementation for testing that stores page tables in memory
    /// needed because the `GuestPageTableBuffer` is in hyperlight_host which would cause a circular dependency
    struct MockTableOps {
        tables: RefCell<Vec<[u64; PAGE_TABLE_ENTRIES_PER_TABLE]>>,
    }

    // for virt_to_phys
    impl core::convert::AsRef<MockTableOps> for MockTableOps {
        fn as_ref(&self) -> &Self {
            self
        }
    }

    impl MockTableOps {
        fn new() -> Self {
            // Start with one table (the root/PML4)
            Self {
                tables: RefCell::new(vec![[0u64; PAGE_TABLE_ENTRIES_PER_TABLE]]),
            }
        }

        fn table_count(&self) -> usize {
            self.tables.borrow().len()
        }

        fn get_entry(&self, table_idx: usize, entry_idx: usize) -> u64 {
            self.tables.borrow()[table_idx][entry_idx]
        }
    }

    impl TableOps for MockTableOps {
        type TableAddr = (usize, usize); // (table_index, entry_index)

        unsafe fn alloc_table(&self) -> Self::TableAddr {
            let mut tables = self.tables.borrow_mut();
            let idx = tables.len();
            tables.push([0u64; PAGE_TABLE_ENTRIES_PER_TABLE]);
            (idx, 0)
        }

        fn entry_addr(addr: Self::TableAddr, entry_offset: u64) -> Self::TableAddr {
            // Convert to physical address, add offset, convert back
            let phys = Self::to_phys(addr) + entry_offset;
            Self::from_phys(phys)
        }

        unsafe fn read_entry(&self, addr: Self::TableAddr) -> u64 {
            self.tables.borrow()[addr.0][addr.1]
        }

        unsafe fn write_entry(&self, addr: Self::TableAddr, entry: u64) -> Option<Self::TableAddr> {
            self.tables.borrow_mut()[addr.0][addr.1] = entry;
            None
        }

        fn to_phys(addr: Self::TableAddr) -> PhysAddr {
            // Each table is 4KB, entries are 8 bytes
            (addr.0 as u64 * PAGE_TABLE_SIZE as u64) + (addr.1 as u64 * 8)
        }

        fn from_phys(addr: PhysAddr) -> Self::TableAddr {
            let table_idx = (addr / PAGE_TABLE_SIZE as u64) as usize;
            let entry_idx = ((addr % PAGE_TABLE_SIZE as u64) / 8) as usize;
            (table_idx, entry_idx)
        }

        fn root_table(&self) -> Self::TableAddr {
            (0, 0)
        }
    }

    // ==================== bits() function tests ====================

    #[test]
    fn test_bits_extracts_pml4_index() {
        // PML4 uses bits 47:39
        // Address 0x0000_0080_0000_0000 should have PML4 index 1
        let addr: u64 = 0x0000_0080_0000_0000;
        assert_eq!(bits::<47, 39>(addr), 1);
    }

    #[test]
    fn test_bits_extracts_pdpt_index() {
        // PDPT uses bits 38:30
        // Address with PDPT index 1: bit 30 set = 0x4000_0000 (1GB)
        let addr: u64 = 0x4000_0000;
        assert_eq!(bits::<38, 30>(addr), 1);
    }

    #[test]
    fn test_bits_extracts_pd_index() {
        // PD uses bits 29:21
        // Address 0x0000_0000_0020_0000 (2MB) should have PD index 1
        let addr: u64 = 0x0000_0000_0020_0000;
        assert_eq!(bits::<29, 21>(addr), 1);
    }

    #[test]
    fn test_bits_extracts_pt_index() {
        // PT uses bits 20:12
        // Address 0x0000_0000_0000_1000 (4KB) should have PT index 1
        let addr: u64 = 0x0000_0000_0000_1000;
        assert_eq!(bits::<20, 12>(addr), 1);
    }

    #[test]
    fn test_bits_max_index() {
        // Maximum 9-bit index is 511
        // PML4 index 511 = bits 47:39 all set = 0x0000_FF80_0000_0000
        let addr: u64 = 0x0000_FF80_0000_0000;
        assert_eq!(bits::<47, 39>(addr), 511);
    }

    // ==================== PTE flag tests ====================

    #[test]
    fn test_page_rw_flag_writable() {
        assert_eq!(page_rw_flag(true), PAGE_RW);
    }

    #[test]
    fn test_page_rw_flag_readonly() {
        assert_eq!(page_rw_flag(false), 0);
    }

    #[test]
    fn test_page_nx_flag_executable() {
        assert_eq!(page_nx_flag(true), 0); // Executable = no NX bit
    }

    #[test]
    fn test_page_nx_flag_not_executable() {
        assert_eq!(page_nx_flag(false), PAGE_NX);
    }

    // ==================== map() function tests ====================

    #[test]
    fn test_map_single_page() {
        let ops = MockTableOps::new();
        let mapping = Mapping {
            phys_base: 0x1000,
            virt_base: 0x1000,
            len: PAGE_SIZE as u64,
            kind: MappingKind::BasicMapping(BasicMapping {
                readable: true,
                writable: true,
                executable: false,
            }),
        };

        unsafe { map(&ops, mapping) };

        // Should have allocated: PML4(exists) + PDPT + PD + PT = 4 tables
        assert_eq!(ops.table_count(), 4);

        // Check PML4 entry 0 points to PDPT (table 1) with correct flags
        let pml4_entry = ops.get_entry(0, 0);
        assert_ne!(pml4_entry & PAGE_PRESENT, 0, "PML4 entry should be present");
        assert_ne!(pml4_entry & PAGE_RW, 0, "PML4 entry should be writable");

        // Check the leaf PTE has correct flags
        // PT is table 3, entry 1 (for virt_base 0x1000)
        let pte = ops.get_entry(3, 1);
        assert_ne!(pte & PAGE_PRESENT, 0, "PTE should be present");
        assert_ne!(pte & PAGE_RW, 0, "PTE should be writable");
        assert_ne!(pte & PAGE_NX, 0, "PTE should have NX set (not executable)");
        assert_eq!(pte & PTE_ADDR_MASK, 0x1000, "PTE should map to phys 0x1000");
    }

    #[test]
    fn test_map_executable_page() {
        let ops = MockTableOps::new();
        let mapping = Mapping {
            phys_base: 0x2000,
            virt_base: 0x2000,
            len: PAGE_SIZE as u64,
            kind: MappingKind::BasicMapping(BasicMapping {
                readable: true,
                writable: false,
                executable: true,
            }),
        };

        unsafe { map(&ops, mapping) };

        // PT is table 3, entry 2 (for virt_base 0x2000)
        let pte = ops.get_entry(3, 2);
        assert_ne!(pte & PAGE_PRESENT, 0, "PTE should be present");
        assert_eq!(pte & PAGE_RW, 0, "PTE should be read-only");
        assert_eq!(pte & PAGE_NX, 0, "PTE should NOT have NX set (executable)");
    }

    #[test]
    fn test_map_multiple_pages() {
        let ops = MockTableOps::new();
        let mapping = Mapping {
            phys_base: 0x10000,
            virt_base: 0x10000,
            len: 4 * PAGE_SIZE as u64, // 4 pages = 16KB
            kind: MappingKind::BasicMapping(BasicMapping {
                readable: true,
                writable: true,
                executable: false,
            }),
        };

        unsafe { map(&ops, mapping) };

        // Check all 4 PTEs are present
        for i in 0..4 {
            let entry_idx = 16 + i; // 0x10000 / 0x1000 = 16
            let pte = ops.get_entry(3, entry_idx);
            assert_ne!(pte & PAGE_PRESENT, 0, "PTE {} should be present", i);
            let expected_phys = 0x10000 + (i as u64 * PAGE_SIZE as u64);
            assert_eq!(
                pte & PTE_ADDR_MASK,
                expected_phys,
                "PTE {} should map to correct phys addr",
                i
            );
        }
    }

    #[test]
    fn test_map_reuses_existing_tables() {
        let ops = MockTableOps::new();

        // Map first region
        let mapping1 = Mapping {
            phys_base: 0x1000,
            virt_base: 0x1000,
            len: PAGE_SIZE as u64,
            kind: MappingKind::BasicMapping(BasicMapping {
                readable: true,
                writable: true,
                executable: false,
            }),
        };
        unsafe { map(&ops, mapping1) };
        let tables_after_first = ops.table_count();

        // Map second region in same PT (different page)
        let mapping2 = Mapping {
            phys_base: 0x5000,
            virt_base: 0x5000,
            len: PAGE_SIZE as u64,
            kind: MappingKind::BasicMapping(BasicMapping {
                readable: true,
                writable: true,
                executable: false,
            }),
        };
        unsafe { map(&ops, mapping2) };

        // Should NOT allocate new tables (reuses existing hierarchy)
        assert_eq!(
            ops.table_count(),
            tables_after_first,
            "Should reuse existing page tables"
        );
    }

    // ==================== virt_to_phys() tests ====================

    #[test]
    fn test_virt_to_phys_mapped_address() {
        let ops = MockTableOps::new();
        let mapping = Mapping {
            phys_base: 0x1000,
            virt_base: 0x1000,
            len: PAGE_SIZE as u64,
            kind: MappingKind::BasicMapping(BasicMapping {
                readable: true,
                writable: true,
                executable: false,
            }),
        };

        unsafe { map(&ops, mapping) };

        let result = unsafe { virt_to_phys(&ops, 0x1000, 1).next() };
        assert!(result.is_some(), "Should find mapped address");
        let pte = result.unwrap();
        assert_eq!(pte.1, 0x1000);
    }

    #[test]
    fn test_virt_to_phys_unmapped_address() {
        let ops = MockTableOps::new();
        // Don't map anything

        let result = unsafe { virt_to_phys(&ops, 0x1000, 1).next() };
        assert!(result.is_none(), "Should return None for unmapped address");
    }

    #[test]
    fn test_virt_to_phys_partially_mapped() {
        let ops = MockTableOps::new();
        let mapping = Mapping {
            phys_base: 0x1000,
            virt_base: 0x1000,
            len: PAGE_SIZE as u64,
            kind: MappingKind::BasicMapping(BasicMapping {
                readable: true,
                writable: true,
                executable: false,
            }),
        };

        unsafe { map(&ops, mapping) };

        // Query an address in a different PT entry (unmapped)
        let result = unsafe { virt_to_phys(&ops, 0x5000, 1).next() };
        assert!(
            result.is_none(),
            "Should return None for unmapped address in same PT"
        );
    }

    // ==================== ModifyPteIterator tests ====================

    #[test]
    fn test_modify_pte_iterator_single_page() {
        let ops = MockTableOps::new();
        let request = MapRequest {
            table_base: ops.root_table(),
            vmin: 0x1000,
            len: PAGE_SIZE as u64,
            update_parent: UpdateParentNone {},
        };

        let responses: Vec<_> = modify_ptes::<20, 12, MockTableOps, _>(request).collect();
        assert_eq!(responses.len(), 1, "Single page should yield one response");
        assert_eq!(responses[0].vmin, 0x1000);
        assert_eq!(responses[0].len, PAGE_SIZE as u64);
    }

    #[test]
    fn test_modify_pte_iterator_multiple_pages() {
        let ops = MockTableOps::new();
        let request = MapRequest {
            table_base: ops.root_table(),
            vmin: 0x1000,
            len: 3 * PAGE_SIZE as u64,
            update_parent: UpdateParentNone {},
        };

        let responses: Vec<_> = modify_ptes::<20, 12, MockTableOps, _>(request).collect();
        assert_eq!(responses.len(), 3, "3 pages should yield 3 responses");
    }

    #[test]
    fn test_modify_pte_iterator_zero_length() {
        let ops = MockTableOps::new();
        let request = MapRequest {
            table_base: ops.root_table(),
            vmin: 0x1000,
            len: 0,
            update_parent: UpdateParentNone {},
        };

        let responses: Vec<_> = modify_ptes::<20, 12, MockTableOps, _>(request).collect();
        assert_eq!(responses.len(), 0, "Zero length should yield no responses");
    }

    #[test]
    fn test_modify_pte_iterator_unaligned_start() {
        let ops = MockTableOps::new();
        // Start at 0x1800 (mid-page), map 0x1000 bytes
        // Should cover 0x1800-0x1FFF (first page) and 0x2000-0x27FF (second page)
        let request = MapRequest {
            table_base: ops.root_table(),
            vmin: 0x1800,
            len: 0x1000,
            update_parent: UpdateParentNone {},
        };

        let responses: Vec<_> = modify_ptes::<20, 12, MockTableOps, _>(request).collect();
        assert_eq!(
            responses.len(),
            2,
            "Unaligned mapping spanning 2 pages should yield 2 responses"
        );
        assert_eq!(responses[0].vmin, 0x1800);
        assert_eq!(responses[0].len, 0x800); // Remaining in first page
        assert_eq!(responses[1].vmin, 0x2000);
        assert_eq!(responses[1].len, 0x800); // Continuing in second page
    }

    // ==================== TableOps entry_addr tests ====================

    #[test]
    fn test_entry_addr_from_table_base() {
        // entry_addr is called with a table base (entry_index = 0) and a byte offset
        // offset = entry_index * 8, so offset 40 means entry 5
        let result = MockTableOps::entry_addr((2, 0), 40);
        assert_eq!(result, (2, 5), "Should return (table 2, entry 5)");
    }

    #[test]
    fn test_entry_addr_with_nonzero_base_entry() {
        // Even though entry_addr is typically called with entry_index=0,
        // it should handle non-zero base correctly by adding the offset
        // Base: table 1, entry 10 (phys = 1*4096 + 10*8 = 4176)
        // Offset: 16 bytes (2 entries)
        // Result phys: 4176 + 16 = 4192 = 1*4096 + 12*8 → (1, 12)
        let result = MockTableOps::entry_addr((1, 10), 16);
        assert_eq!(result, (1, 12), "Should add offset to base entry");
    }

    #[test]
    fn test_to_phys_from_phys_roundtrip() {
        // Verify to_phys and from_phys are inverses
        let addr = (3, 42);
        let phys = MockTableOps::to_phys(addr);
        let back = MockTableOps::from_phys(phys);
        assert_eq!(back, addr, "to_phys/from_phys should roundtrip");
    }
}
