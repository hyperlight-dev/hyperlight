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

//! i686 2-level page table manipulation code.
//!
//! - PD (Page Directory) - bits 31:22 - 1024 entries, each covering 4MB
//! - PT (Page Table) - bits 20:12 - 1024 entries, each covering 4KB pages
//!
//! Entries are 4 bytes wide. There is no NX bit; all pages are executable.

use crate::vmem::{
    BasicMapping, CowMapping, MapRequest, MapResponse, Mapping, MappingKind, TableMovabilityBase,
    TableOps, TableReadOps, UpdateParent, UpdateParentNone, modify_ptes, read_pte_if_present,
    require_pte_exist, write_entry_updating,
};

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_TABLE_SIZE: usize = 4096;
pub type PageTableEntry = u32;
pub type VirtAddr = u32;
pub type PhysAddr = u32;

// i686 PTE flags
pub const PAGE_PRESENT: u64 = 1;
const PAGE_RW: u64 = 1 << 1;
pub const PAGE_USER: u64 = 1 << 2;
const PAGE_ACCESSED: u64 = 1 << 5;
pub const PTE_ADDR_MASK: u64 = 0xFFFFF000;
const PTE_AVL_MASK: u64 = 0x0E00;
const PAGE_AVL_COW: u64 = 1 << 9;

const VA_BITS: usize = 32;

pub trait TableMovability<Op: TableReadOps + ?Sized, TableMoveInfo> {
    type RootUpdateParent: UpdateParent<Op, TableMoveInfo = TableMoveInfo>;
    fn root_update_parent() -> Self::RootUpdateParent;
}

impl<Op: TableReadOps> TableMovability<Op, crate::vmem::Void> for crate::vmem::MayNotMoveTable {
    type RootUpdateParent = UpdateParentNone;
    fn root_update_parent() -> Self::RootUpdateParent {
        UpdateParentNone {}
    }
}

#[inline(always)]
const fn page_rw_flag(writable: bool) -> u64 {
    if writable { PAGE_RW } else { 0 }
}

/// Generate a PDE pointing to a page table.
/// Sets PAGE_USER unconditionally so that user-mode leaf PTEs
/// beneath it can function. The leaf PTE controls actual access.
fn pte_for_table<Op: TableOps>(table_addr: Op::TableAddr) -> u64 {
    #[allow(clippy::unnecessary_cast)]
    let phys = Op::to_phys(table_addr) as u64;
    phys | PAGE_USER | PAGE_RW | PAGE_ACCESSED | PAGE_PRESENT
}

// ---- Page table manipulation ----

/// # Safety
/// Must not be called concurrently with other page table modifications.
unsafe fn alloc_pte_if_needed<
    Op: TableOps,
    P: UpdateParent<
            Op,
            TableMoveInfo = <Op::TableMovability as TableMovabilityBase<Op>>::TableMoveInfo,
        >,
>(
    op: &Op,
    x: MapResponse<Op, P>,
) -> MapRequest<Op, P::ChildType>
where
    P::ChildType: UpdateParent<Op>,
{
    let new_update_parent = x.update_parent.for_child_at_entry(x.entry_ptr);
    if let Some(pte) = unsafe { read_pte_if_present(op, x.entry_ptr) } {
        #[allow(clippy::unnecessary_cast)]
        return MapRequest {
            table_base: Op::from_phys((pte & PTE_ADDR_MASK) as super::PhysAddr),
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

/// Write a leaf PTE. i686 has no NX bit so all pages are executable.
///
/// # Safety
/// Must not be called concurrently with other page table modifications.
unsafe fn map_page<
    Op: TableOps,
    P: UpdateParent<
            Op,
            TableMoveInfo = <Op::TableMovability as TableMovabilityBase<Op>>::TableMoveInfo,
        >,
>(
    op: &Op,
    mapping: &Mapping,
    r: MapResponse<Op, P>,
) {
    let user_flag = if mapping.user_accessible {
        PAGE_USER
    } else {
        0
    };
    let pte = match &mapping.kind {
        MappingKind::Basic(bm) => {
            (mapping.phys_base + (r.vmin - mapping.virt_base))
                | user_flag
                | PAGE_ACCESSED
                | page_rw_flag(bm.writable)
                | PAGE_PRESENT
        }
        MappingKind::Cow(_cm) => {
            (mapping.phys_base + (r.vmin - mapping.virt_base))
                | user_flag
                | PAGE_AVL_COW
                | PAGE_ACCESSED
                | PAGE_PRESENT
        }
        MappingKind::Unmapped => 0,
    };
    unsafe {
        write_entry_updating(op, r.update_parent, r.entry_ptr, pte);
    }
}

/// Map a contiguous virtual address range using 2-level paging (PD -> PT).
///
/// # Safety
/// See [`crate::vmem::map`].
#[allow(clippy::missing_safety_doc)]
pub unsafe fn map<Op: TableOps>(op: &Op, mapping: Mapping) {
    modify_ptes::<31, 22, Op, _>(MapRequest {
        table_base: op.root_table(),
        vmin: mapping.virt_base,
        len: mapping.len,
        update_parent: Op::TableMovability::root_update_parent(),
    })
    .map(|r| unsafe { alloc_pte_if_needed(op, r) })
    .flat_map(modify_ptes::<21, 12, Op, _>)
    .map(|r| unsafe { map_page(op, &mapping, r) })
    .for_each(drop);
}

/// Translate a virtual address range to its backing physical pages.
///
/// # Safety
/// See [`crate::vmem::virt_to_phys`].
#[allow(clippy::missing_safety_doc)]
pub unsafe fn virt_to_phys<'a, Op: TableReadOps + 'a>(
    op: impl core::convert::AsRef<Op> + Copy + 'a,
    address: u64,
    len: u64,
) -> impl Iterator<Item = Mapping> + 'a {
    let vmin = address & !(PAGE_SIZE as u64 - 1);
    let vmax = core::cmp::min(address + len, 1u64 << VA_BITS);
    modify_ptes::<31, 22, Op, _>(MapRequest {
        table_base: op.as_ref().root_table(),
        vmin,
        len: vmax.saturating_sub(vmin),
        update_parent: UpdateParentNone {},
    })
    .filter_map(move |r| unsafe { require_pte_exist(op.as_ref(), r) })
    .flat_map(modify_ptes::<21, 12, Op, _>)
    .filter_map(move |r| {
        let pte = unsafe { read_pte_if_present(op.as_ref(), r.entry_ptr) }?;
        let phys_addr = pte & PTE_ADDR_MASK;
        let avl = pte & PTE_AVL_MASK;
        let kind = if avl == PAGE_AVL_COW {
            MappingKind::Cow(CowMapping {
                readable: true,
                executable: true,
            })
        } else {
            MappingKind::Basic(BasicMapping {
                readable: true,
                writable: (pte & PAGE_RW) != 0,
                executable: true,
            })
        };
        Some(Mapping {
            phys_base: phys_addr,
            virt_base: r.vmin,
            len: PAGE_SIZE as u64,
            kind,
            user_accessible: (pte & PAGE_USER) != 0,
        })
    })
}
