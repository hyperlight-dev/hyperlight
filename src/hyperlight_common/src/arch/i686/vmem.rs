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
    BasicMapping, CowMapping, MapRequest, MapResponse, Mapping, MappingKind, SpaceAwareMapping,
    SpaceId, SpaceReferenceMapping, TableMovabilityBase, TableOps, TableReadOps, UpdateParent,
    UpdateParentNone, modify_ptes, write_entry_updating,
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

/// Read a PTE and return it (widened to u64) if the present bit is
/// set. On i686 "present" is a single bit; archs that need richer
/// checks define their own variant.
///
/// # Safety
/// `entry_ptr` must point to a valid page table entry.
#[inline(always)]
#[allow(clippy::useless_conversion)]
pub(super) unsafe fn read_pte_if_present<Op: TableReadOps>(
    op: &Op,
    entry_ptr: Op::TableAddr,
) -> Option<u64> {
    let pte: u64 = unsafe { op.read_entry(entry_ptr) }.into();
    if (pte & PAGE_PRESENT) != 0 {
        Some(pte)
    } else {
        None
    }
}

/// Require that a PTE is present and descend to the next-level table.
///
/// # Safety
/// `op` must provide valid page table memory.
pub(super) unsafe fn require_pte_exist<Op: TableReadOps, P: UpdateParent<Op>>(
    op: &Op,
    x: MapResponse<Op, P>,
) -> Option<MapRequest<Op, P::ChildType>>
where
    P::ChildType: UpdateParent<Op>,
{
    unsafe { read_pte_if_present(op, x.entry_ptr) }.map(|pte| MapRequest {
        #[allow(clippy::unnecessary_cast)]
        table_base: Op::from_phys((pte & PTE_ADDR_MASK) as PhysAddr),
        vmin: x.vmin,
        len: x.len,
        update_parent: x.update_parent.for_child_at_entry(x.entry_ptr),
    })
}

/// Generate a PDE pointing to a page table.
/// Sets PAGE_USER unconditionally so that user-mode leaf PTEs
/// beneath it can function. The leaf PTE controls actual access.
fn pte_for_table<Op: TableOps>(table_addr: Op::TableAddr) -> u64 {
    #[allow(clippy::unnecessary_cast)]
    let phys = Op::to_phys(table_addr) as u64;
    phys | PAGE_USER | PAGE_RW | PAGE_ACCESSED | PAGE_PRESENT
}

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

//==================================================================================================
// Multi-space walk / link (shared intermediate tables)
//==================================================================================================

/// i686 has two levels (PD -> PT). The only sharable thing is a PT,
/// at depth 1 (one level below the root PD).
const SHARED_TABLE_DEPTH: usize = 1;

/// Walk multiple root PDs together, detecting PDEs that point at the
/// same PT PA across roots (i.e. aliased PTs — the standard
/// "kernel-half shared" trick on x86 without KPTI). The first root to
/// visit a given PT PA becomes the "owner"; later roots that alias it
/// receive `AnotherSpace(SpaceReferenceMapping { depth: 1, .. })`
/// entries.
///
/// Generic over `TableAddr` so it works with both the in-guest
/// implementation (`TableAddr = u32`, backed by raw pointers) and the
/// host-side snapshot buffer (`TableAddr = u64`, byte offsets).
///
/// # Safety
/// Same invariants as [`virt_to_phys`]. Callers must not mutate the
/// page tables concurrently.
#[allow(clippy::missing_safety_doc)]
pub unsafe fn walk_va_spaces<Op: TableReadOps>(
    op: &Op,
    roots: &[Op::TableAddr],
    address: u64,
    len: u64,
) -> ::alloc::vec::Vec<(SpaceId, ::alloc::vec::Vec<SpaceAwareMapping>)> {
    use ::alloc::vec::Vec;

    // Map: PT PA -> (owner SpaceId, the VA at which the owner used
    // this PT). Subsequent visits to the same PT PA emit AnotherSpace.
    let mut seen_pts: ::alloc::collections::BTreeMap<u64, (SpaceId, u64)> =
        ::alloc::collections::BTreeMap::new();
    let mut results: Vec<(SpaceId, Vec<SpaceAwareMapping>)> = Vec::with_capacity(roots.len());

    let vmin = address & !(PAGE_SIZE as u64 - 1);
    let vmax = core::cmp::min(address + len, 1u64 << VA_BITS);

    for &root in roots {
        #[allow(clippy::unnecessary_cast)]
        let root_id: SpaceId = Op::to_phys(root) as u64;
        let mut mappings: Vec<SpaceAwareMapping> = Vec::new();

        // Iterate PDEs covering [vmin, vmax) at the PD level (bits 31:22).
        let pde_iter = modify_ptes::<31, 22, Op, _>(MapRequest {
            table_base: root,
            vmin,
            len: vmax.saturating_sub(vmin),
            update_parent: UpdateParentNone {},
        });
        for r in pde_iter {
            let Some(pde) = (unsafe { read_pte_if_present(op, r.entry_ptr) }) else {
                continue;
            };
            let pt_pa: u64 = pde & PTE_ADDR_MASK;

            // Seen this PT via an earlier root? Emit AnotherSpace and
            // don't descend — the sub-tree is fully described by the
            // owner's entries.
            if let Some(&(owner, their_va)) = seen_pts.get(&pt_pa) {
                if owner != root_id {
                    mappings.push(SpaceAwareMapping::AnotherSpace(SpaceReferenceMapping {
                        depth: SHARED_TABLE_DEPTH,
                        space: owner,
                        our_va: r.vmin,
                        their_va,
                    }));
                    continue;
                }
                // Same space saw this PT before (shouldn't happen with
                // the virt_to_phys-style per-PDE iteration, but skip
                // defensively).
                continue;
            }
            seen_pts.insert(pt_pa, (root_id, r.vmin));

            // Descend the PT and emit ThisSpace entries for each live
            // 4KB leaf, mirroring virt_to_phys's leaf-emission logic.
            let pt_request = MapRequest {
                #[allow(clippy::unnecessary_cast)]
                table_base: Op::from_phys(pt_pa as PhysAddr),
                vmin: r.vmin,
                len: r.len,
                update_parent: UpdateParentNone {},
            };
            for leaf in modify_ptes::<21, 12, Op, _>(pt_request) {
                let Some(pte) = (unsafe { read_pte_if_present(op, leaf.entry_ptr) }) else {
                    continue;
                };
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
                mappings.push(SpaceAwareMapping::ThisSpace(Mapping {
                    phys_base: phys_addr,
                    virt_base: leaf.vmin,
                    len: PAGE_SIZE as u64,
                    kind,
                    user_accessible: (pte & PAGE_USER) != 0,
                }));
            }
        }

        results.push((root_id, mappings));
    }

    results
}

/// Install the link described by `ref_map` in `op`'s root PT tree:
/// look up what the owner space's rebuilt root put at `their_va`'s
/// PDE slot, and write that PA into our root's PDE slot for
/// `our_va`. The owner's rebuilt root is found via `built_roots`.
///
/// On i686 `ref_map.depth` must be 1 (PT-level sharing). Other depths
/// are rejected defensively.
///
/// # Safety
/// Same invariants as [`map`]: caller owns the concurrency story and
/// must invalidate the TLB if the page tables are live.
#[allow(clippy::missing_safety_doc)]
pub unsafe fn space_aware_map<Op: TableOps>(
    op: &Op,
    ref_map: SpaceReferenceMapping,
    built_roots: &::alloc::collections::BTreeMap<SpaceId, Op::TableAddr>,
) {
    assert!(
        ref_map.depth == SHARED_TABLE_DEPTH,
        "i686 only supports depth={} sharing; got depth={}",
        SHARED_TABLE_DEPTH,
        ref_map.depth
    );

    // Their rebuilt root — must have been populated earlier in the
    // rebuild loop (walk_va_spaces guarantees topological order).
    let Some(&their_root) = built_roots.get(&ref_map.space) else {
        // Defensive: we have no linkage target. Skip rather than
        // panic. A trace print would live here in a debug build.
        return;
    };

    // Read their PDE at their_va's index to get the rebuilt PT PA.
    let their_pdi = (ref_map.their_va >> 22) & 0x3FF;
    let their_pde_ptr = Op::entry_addr(
        their_root,
        their_pdi * core::mem::size_of::<PageTableEntry>() as u64,
    );
    let Some(their_pde) = (unsafe { read_pte_if_present(op, their_pde_ptr) }) else {
        // Owner didn't end up with a PDE here — nothing to link.
        return;
    };
    let their_pt_pa: u64 = their_pde & PTE_ADDR_MASK;

    // Compose our PDE: point at their PT, preserve their PDE's low
    // bits (PAGE_USER for kernel-accessible, PAGE_RW, etc.) so the
    // hardware still honours sharing semantics uniformly.
    let our_pdi = (ref_map.our_va >> 22) & 0x3FF;
    let our_root = op.root_table();
    let our_pde_ptr = Op::entry_addr(
        our_root,
        our_pdi * core::mem::size_of::<PageTableEntry>() as u64,
    );

    let new_pde: u64 = their_pt_pa | (their_pde & !PTE_ADDR_MASK) | PAGE_PRESENT;
    unsafe {
        write_entry_updating(
            op,
            Op::TableMovability::root_update_parent(),
            our_pde_ptr,
            new_pde,
        );
    }
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
