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

use crate::vm::{Mapping, MappingKind, TableOps};

#[allow(clippy::identity_op)]
#[allow(clippy::precedence)]
fn pte_for_table<Op: TableOps>(table_addr: Op::TableAddr) -> u64 {
    Op::to_phys(table_addr) |
        1 << 5 | // A   - we don't track accesses at table level
        0 << 4 | // PCD - leave caching enabled
        0 << 3 | // PWT - write-back
        1 << 2 | // U/S - allow user access to everything (for now)
        1 << 1 | // R/W - we don't use block-level permissions
        1 << 0  // P   - this entry is present
}

unsafe fn write_entry_updating<Op: TableOps, P: UpdateParent<Op>>(op: &Op, parent: P, addr: Op::TableAddr, entry: u64) {
    if let Some(again) = unsafe { op.write_entry(addr, entry) } {
        parent.update_parent(op, again);
    }
}

// All the information that we need is in the type system, so
// hopefully this get specialised down into nice efficient code...
trait UpdateParent<Op: TableOps>: Copy {
    fn update_parent(self, op: &Op, new_ptr: Op::TableAddr);
}

struct UpdateParentTable<Op: TableOps, P: UpdateParent<Op>> {
    parent: P,
    entry_ptr: Op::TableAddr,
}
impl<Op: TableOps, P: UpdateParent<Op>> Clone for UpdateParentTable<Op, P> {
    fn clone(&self) -> Self {
        Self {
            parent: self.parent,
            entry_ptr: self.entry_ptr
        }
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
        let old_entry = unsafe { op.read_entry(self.entry_ptr) };
        unsafe { write_entry_updating(op, self.parent, self.entry_ptr, pte); }
    }
}
#[derive(Copy, Clone)]
struct UpdateParentCR3 {}
impl<Op: TableOps> UpdateParent<Op> for UpdateParentCR3 {
    fn update_parent(self, _op: &Op, new_ptr: Op::TableAddr) {
        unsafe {
            core::arch::asm!("mov cr3, {}", in(reg) Op::to_phys(new_ptr));
        }
    }
}

#[inline(always)]
/// Utility function to extract an (inclusive on both ends) bit range
/// from a quadword.
fn bits<const HIGH_BIT: u8, const LOW_BIT: u8>(x: u64) -> u64 {
    (x & ((1 << (HIGH_BIT + 1)) - 1)) >> LOW_BIT
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

struct ModifyPteIterator<const HIGH_BIT: u8, const LOW_BIT: u8, Op: TableOps, P: UpdateParent<Op>> {
    request: MapRequest<Op, P>,
    n: u64,
}
impl<const HIGH_BIT: u8, const LOW_BIT: u8, Op: TableOps, P: UpdateParent<Op>> Iterator
    for ModifyPteIterator<HIGH_BIT, LOW_BIT, Op, P>
{
    type Item = MapResponse<Op, P>;
    fn next(&mut self) -> Option<Self::Item> {
        if (self.n << LOW_BIT) >= self.request.len {
            return None;
        }
        // next stage parameters
        let mut next_vmin = self.request.vmin + (self.n << LOW_BIT);
        let lower_bits_mask = (1 << LOW_BIT) - 1;
        if self.n > 0 {
            next_vmin &= !lower_bits_mask;
        }
        let entry_ptr = Op::entry_addr(
            self.request.table_base,
            bits::<HIGH_BIT, LOW_BIT>(next_vmin) << 3,
        );
        let len_from_here = self.request.len - (next_vmin - self.request.vmin);
        let max_len = (1 << LOW_BIT) - (next_vmin & lower_bits_mask);
        let next_len = core::cmp::min(len_from_here, max_len);

        // update our state
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
    let pte = unsafe { op.read_entry(x.entry_ptr) };
    let present = pte & 0x1;
    if present != 0 {
        return MapRequest {
            table_base: Op::from_phys(pte & !0xfff),
            vmin: x.vmin,
            len: x.len,
            update_parent: new_update_parent,
        };
    }

    let page_addr = unsafe { op.alloc_table() };

    let pte = pte_for_table::<Op>(page_addr);
    unsafe { write_entry_updating(op, x.update_parent, x.entry_ptr, pte); }
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
unsafe fn map_page<Op: TableOps, P: UpdateParent<Op>>(op: &Op, mapping: &Mapping, r: MapResponse<Op, P>) {
    let pte = match &mapping.kind {
        MappingKind::BasicMapping(bm) =>
        // TODO: Support not readable
        {
            (mapping.phys_base + (r.vmin - mapping.virt_base)) |
                (!bm.executable as u64) << 63 | // NX - no execute unless allowed
                1 << 7 | // 1   - RES1 according to manual
                1 << 6 | // D   - we don't presently track dirty state for anything
                1 << 5 | // A   - we don't presently track access for anything
                0 << 4 | // PCD - leave caching enabled
                0 << 3 | // PWT - write-back
                1 << 2 | // U/S - allow user access to everything (for now)
                (bm.writable as u64) << 1 | // R/W - for now make everything r/w
                1 << 0 // P   - this entry is present
        }
    };
    unsafe {
        write_entry_updating(op, r.update_parent, r.entry_ptr, pte);
    }
}

// There are no notable architecture-specific safety considerations
// here, and the general conditions are documented in the
// architecture-independent re-export in vm.rs
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
    let pte = unsafe { op.read_entry(x.entry_ptr) };
    let present = pte & 0x1;
    if present == 0 {
        return None;
    }
    Some(MapRequest {
        table_base: Op::from_phys(pte & !0xfff),
        vmin: x.vmin,
        len: x.len,
        update_parent: UpdateParentTable::new(x.update_parent, x.entry_ptr),
    })
}

// There are no notable architecture-specific safety considerations
// here, and the general conditions are documented in the
// architecture-independent re-export in vm.rs
#[allow(clippy::missing_safety_doc)]
pub unsafe fn vtop<Op: TableOps>(op: &Op, address: u64) -> Option<u64> {
    modify_ptes::<47, 39, Op, _>(MapRequest {
        table_base: op.root_table(),
        vmin: address,
        len: 1,
        update_parent: UpdateParentCR3 {},
    })
    .filter_map(|r| unsafe { require_pte_exist(op, r) })
    .flat_map(modify_ptes::<38, 30, Op, _>)
    .filter_map(|r| unsafe { require_pte_exist(op, r) })
    .flat_map(modify_ptes::<29, 21, Op, _>)
    .filter_map(|r| unsafe { require_pte_exist(op, r) })
    .flat_map(modify_ptes::<20, 12, Op, _>)
    .filter_map(|r| {
        let pte = unsafe { op.read_entry(r.entry_ptr) };
        let present = pte & 0x1;
        if present == 0 { None } else { Some(pte) }
    })
    .next()
}

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_TABLE_SIZE: usize = 4096;
pub type PageTableEntry = u64;
pub type VirtAddr = u64;
pub type PhysAddr = u64;
