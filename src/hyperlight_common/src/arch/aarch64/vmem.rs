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

use alloc::collections::BTreeMap;
use alloc::collections::btree_map::Entry;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::vmem::sealed::TableMovabilityBase;
use crate::vmem::{
    BasicMapping, CowMapping, MapRequest, MapResponse, Mapping, MappingKind, SpaceAwareMapping,
    SpaceId, SpaceReferenceMapping, TableOps, TableReadOps, UpdateParent, UpdateParentNone,
    UpdateParentTable, Void, bits, modify_ptes, write_entry_updating,
};

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_TABLE_SIZE: usize = 4096;
pub const PAGE_PRESENT: u64 = 1; // AArch64: bit 0 is the "valid" bit
pub const PTE_ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000; // bits [47:12]
pub type PageTableEntry = u64;
pub type VirtAddr = u64;
pub type PhysAddr = u64;

const VA_BITS: usize = 48;
pub const ATTR_INDEX_NORMAL: u8 = 0;
const SOFTWARE_USE_COW: u8 = 0b1;

// Utility structures
impl<
    Op: TableOps<TableMovability = crate::vmem::MayMoveTable>,
    P: UpdateParent<Op, TableMoveInfo = Op::TableAddr>,
> UpdateParent<Op> for UpdateParentTable<Op, P>
{
    type TableMoveInfo = Op::TableAddr;
    type ChildType = UpdateParentTable<Op, Self>;
    fn update_parent(self, op: &Op, new_ptr: Op::TableAddr) {
        let pte = desc_for_table::<Op>(new_ptr);
        unsafe {
            write_entry_updating(op, self.parent, self.entry_ptr, pte);
        }
    }
    fn for_child_at_entry(self, entry_ptr: Op::TableAddr) -> Self::ChildType {
        Self::ChildType::new(self, entry_ptr)
    }
}
#[derive(Copy, Clone)]
pub(in crate::vmem) struct UpdateParentRoot {}
impl<Op: TableOps<TableMovability = crate::vmem::MayMoveTable>> UpdateParent<Op>
    for UpdateParentRoot
{
    type TableMoveInfo = Op::TableAddr;
    type ChildType = UpdateParentTable<Op, Self>;
    fn update_parent(self, op: &Op, new_ptr: Op::TableAddr) {
        unsafe {
            op.update_root(new_ptr);
        }
    }
    fn for_child_at_entry(self, entry_ptr: Op::TableAddr) -> Self::ChildType {
        Self::ChildType::new(self, entry_ptr)
    }
}
/// This trait is used to select appropriate implementations of
/// [`UpdateParent`] to be used, depending on whether a particular
/// implementation needs the ability to move tables.
pub(in crate::vmem) trait TableMovability<Op: TableReadOps + ?Sized, TableMoveInfo> {
    type RootUpdateParent: UpdateParent<Op, TableMoveInfo = TableMoveInfo>;
    fn root_update_parent() -> Self::RootUpdateParent;
}
impl<Op: TableOps<TableMovability = crate::vmem::MayMoveTable>> TableMovability<Op, Op::TableAddr>
    for crate::vmem::MayMoveTable
{
    type RootUpdateParent = UpdateParentRoot;
    fn root_update_parent() -> Self::RootUpdateParent {
        UpdateParentRoot {}
    }
}
impl<Op: TableReadOps> TableMovability<Op, Void> for crate::vmem::MayNotMoveTable {
    type RootUpdateParent = UpdateParentNone;
    fn root_update_parent() -> Self::RootUpdateParent {
        UpdateParentNone {}
    }
}

#[allow(clippy::identity_op)]
#[allow(clippy::precedence)]
fn desc_for_table<Op: TableOps>(table_addr: Op::TableAddr) -> u64 {
    Op::to_phys(table_addr) |
        // Don't set APTable[1:0] - we don't use hierachical permissions
        // Don't set {U,P,}XNTable - we don't use hierarchical permissions
        // Don't set set Protected - we don't use FEAT_THE
        // We don't need to set AF on a table descriptor to avoid AF
        // faults. Since we don't enable FEAT_HAFT, there is no AF on
        // table descriptors, only on page descriptors.
        0b11 // table descriptor
}

// We do not currently use hugepage mappings in the guest, and so we
// do not need to worry about block descriptors at intermediate
// levels.

#[allow(clippy::identity_op)]
#[allow(clippy::precedence)]
fn desc_for_page(
    page_addr: u64,
    _readable: bool,
    writable: bool,
    executable: bool,
    software_use: u8,
    user_accessible: bool,
) -> u64 {
    // todo: make use of the Contiguous bit to reduce tlb pressure
    let xn = match (executable, user_accessible) {
        (true, true) => 0,
        (true, false) => 0b10,
        (false, _) => 0b11,
    };
    let ap = match (writable, user_accessible) {
        (true, true) => 0b01,
        (true, false) => 0b00,
        (false, true) => 0b11,
        (false, false) => 0b10,
    };
    page_addr |
        ((software_use as u64 & 0xf) << 55) |
        (xn << 53) |
        // we do not use hardware management of the dirty state
        // If we support hugepage block descriptors in the future, we
        // will need to support setting the nT bit here when the
        // hardware supports FEAT_BBM Level 1
        (0b1 << 11) | // always set nG for now, since multi-space
                      // support is not properly reflected in the
                      // mapping API.
        (0b1 << 10) | // we don't need AF tracking, so set it always
        (0b11 << 8) | // Inner Shareable
        (ap << 6) |
        ((ATTR_INDEX_NORMAL as u64) << 2) |
        0b11
}

#[allow(clippy::identity_op)]
#[allow(clippy::precedence)]
// Produces only page descriptors valid at Level 3; there is presently
// no support for block descriptors valid at earlier levels
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
    let presumed_base = mapping.phys_base + (r.vmin - mapping.virt_base);
    let desc = match &mapping.kind {
        MappingKind::Basic(bm) => desc_for_page(
            presumed_base,
            bm.readable,
            bm.writable,
            bm.executable,
            0,
            mapping.user_accessible,
        ),
        MappingKind::Cow(cm) => desc_for_page(
            presumed_base,
            cm.readable,
            false,
            cm.executable,
            SOFTWARE_USE_COW,
            mapping.user_accessible,
        ),
        MappingKind::Unmapped => 0,
    };
    unsafe {
        write_entry_updating(op, r.update_parent, r.entry_ptr, desc);
    }
}

enum FinalLevelDescriptorKind {
    Page,
}
enum EarlyLevelDescriptorKind {
    Block,
    Table,
}
fn final_level_descriptor_kind(desc: u64) -> Option<FinalLevelDescriptorKind> {
    if desc & 3 == 3 {
        Some(FinalLevelDescriptorKind::Page)
    } else {
        None
    }
}
fn early_level_descriptor_kind(desc: u64) -> Option<EarlyLevelDescriptorKind> {
    match desc & 0b11 {
        0b01 => Some(EarlyLevelDescriptorKind::Block),
        0b11 => Some(EarlyLevelDescriptorKind::Table),
        _ => None,
    }
}

unsafe fn next_level_table_if_present<Op: TableReadOps>(
    op: &Op,
    addr: Op::TableAddr,
) -> Option<Op::TableAddr> {
    let desc: u64 = unsafe { op.read_entry(addr) };
    if let Some(EarlyLevelDescriptorKind::Table) = early_level_descriptor_kind(desc) {
        Some(Op::from_phys(bits::<47, 12>(desc) << 12))
    } else {
        None
    }
}

/// Page-mapping callback to allocate a next-level page table if necessary.
///
/// Should only be called on a [`MapResponse`] representing an entry
/// at level < 3, since it allocates a next-level table.
/// # Safety
/// This function modifies page table data structures, and should not be called concurrently
/// with any other operations that modify the page tables.
unsafe fn alloc_table_if_needed<
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
    #[cfg(target_os = "linux")]
    extern crate std;

    let new_update_parent = x.update_parent.for_child_at_entry(x.entry_ptr);
    if let Some(table_base) = unsafe { next_level_table_if_present(op, x.entry_ptr) } {
        return MapRequest {
            table_base,
            vmin: x.vmin,
            len: x.len,
            update_parent: new_update_parent,
        };
    }
    // If we eventually support huge pages, we will need to check if
    // there was a Block descriptor here and follow the
    // break-before-make sequence.

    let page_addr = unsafe { op.alloc_table() };

    let pte = desc_for_table::<Op>(page_addr);
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

unsafe fn require_table_exist<Op: TableReadOps, P: UpdateParent<Op>>(
    op: &Op,
    x: MapResponse<Op, P>,
) -> Option<MapRequest<Op, P::ChildType>>
where
    P::ChildType: UpdateParent<Op>,
{
    unsafe {
        next_level_table_if_present(op, x.entry_ptr).map(|table_base| MapRequest {
            table_base,
            vmin: x.vmin,
            len: x.len,
            update_parent: x.update_parent.for_child_at_entry(x.entry_ptr),
        })
    }
}

enum WalkNextLevelResponse<Op: TableReadOps, P: UpdateParent<Op>> {
    WalkNextLevel(MapResponse<Op, P>),
    AlreadySeen(SpaceReferenceMapping),
}

enum WalkNextLevelRequest<Op: TableReadOps, P: UpdateParent<Op>> {
    WalkNextLevel(MapRequest<Op, P>),
    AlreadySeen(SpaceReferenceMapping),
}
fn walk_check_request_seen<Op: TableReadOps, P: UpdateParent<Op>>(
    seen_pts: &Option<Rc<RefCell<BTreeMap<u64, SpaceReferenceMapping>>>>,
    space: SpaceId,
    depth: usize,
    rq: MapRequest<Op, P>,
) -> WalkNextLevelRequest<Op, P> {
    let Some(seen_pts) = seen_pts else {
        return WalkNextLevelRequest::WalkNextLevel(rq);
    };
    match seen_pts.borrow_mut().entry(Op::to_phys(rq.table_base)) {
        Entry::Vacant(ve) => {
            ve.insert(SpaceReferenceMapping {
                depth,
                space,
                our_va: 0,
                their_va: rq.vmin,
            });
            WalkNextLevelRequest::WalkNextLevel(rq)
        }
        Entry::Occupied(oe) => {
            let mut sm = *oe.get();
            if sm.depth != depth {
                // Sharing a page table at different levels like this
                // is not supported in the Hyperlight memory
                // model. Ignore the "sharing".
                WalkNextLevelRequest::WalkNextLevel(rq)
            } else {
                sm.our_va = rq.vmin;
                WalkNextLevelRequest::AlreadySeen(sm)
            }
        }
    }
}
fn walk_next_level_table<Op: TableReadOps, P: UpdateParent<Op>>(
    op: &Op,
    x: WalkNextLevelResponse<Op, P>,
    next_depth: usize,
    space: SpaceId,
    seen_pts: &Option<Rc<RefCell<BTreeMap<u64, SpaceReferenceMapping>>>>,
) -> Option<WalkNextLevelRequest<Op, P::ChildType>>
where
    P::ChildType: UpdateParent<Op>,
{
    let rq = match x {
        WalkNextLevelResponse::WalkNextLevel(rq) => rq,
        WalkNextLevelResponse::AlreadySeen(sm) => {
            return Some(WalkNextLevelRequest::AlreadySeen(sm));
        }
    };
    let next_base = unsafe { require_table_exist(op, rq)? };
    Some(walk_check_request_seen(
        seen_pts, space, next_depth, next_base,
    ))
}

fn do_walk_next_level<
    const HIGH_BIT: u8,
    const LOW_BIT: u8,
    Op: TableReadOps,
    P: UpdateParent<Op>,
>(
    x: WalkNextLevelRequest<Op, P>,
) -> impl Iterator<Item = WalkNextLevelResponse<Op, P>> {
    let (iter_a, iter_b) = match x {
        WalkNextLevelRequest::WalkNextLevel(rq) => (
            Some(
                modify_ptes::<HIGH_BIT, LOW_BIT, Op, P>(rq)
                    .map(|r| WalkNextLevelResponse::WalkNextLevel(r)),
            ),
            None,
        ),
        WalkNextLevelRequest::AlreadySeen(sm) => (
            None,
            Some(core::iter::once(WalkNextLevelResponse::AlreadySeen(sm))),
        ),
    };
    iter_a
        .into_iter()
        .flatten()
        .chain(iter_b.into_iter().flatten())
}

/// # Safety
/// See `TableOps` documentation.
#[allow(clippy::missing_safety_doc)]
pub unsafe fn map<Op: TableOps>(op: &Op, mapping: Mapping) {
    modify_ptes::<47, 39, Op, _>(MapRequest {
        table_base: op.root_table(),
        vmin: mapping.virt_base,
        len: mapping.len,
        update_parent: Op::TableMovability::root_update_parent(),
    })
    .map(|r| unsafe { alloc_table_if_needed(op, r) })
    .flat_map(modify_ptes::<38, 30, Op, _>)
    .map(|r| unsafe { alloc_table_if_needed(op, r) })
    .flat_map(modify_ptes::<29, 21, Op, _>)
    .map(|r| unsafe { alloc_table_if_needed(op, r) })
    .flat_map(modify_ptes::<20, 12, Op, _>)
    .map(|r| unsafe { map_page(op, &mapping, r) })
    .for_each(drop);
}

/// # Safety
/// See `TableReadOps` documentation.
#[allow(clippy::missing_safety_doc)]
pub unsafe fn virt_to_phys<'a, Op: TableReadOps + 'a>(
    op: impl core::convert::AsRef<Op> + Copy + 'a,
    address: u64,
    len: u64,
) -> impl Iterator<Item = Mapping> + 'a {
    let roots = core::iter::once(op.as_ref().root_table());
    unsafe {
        internal_walk_va_spaces(op, roots, false, address, len)
            .flat_map(|(_, mappings)| mappings)
            .filter_map(|saw| match saw {
                SpaceAwareMapping::ThisSpace(m) => Some(m),
                // this is guaranteed to never actually happen, both since
                // we only passed one root and since we passed do_dedup =
                // false
                SpaceAwareMapping::AnotherSpace(_) => None,
            })
    }
}

#[allow(clippy::missing_safety_doc)]
unsafe fn internal_walk_va_spaces<'a, Op: TableReadOps + 'a>(
    op: impl core::convert::AsRef<Op> + Copy + 'a,
    roots: impl Iterator<Item = Op::TableAddr> + 'a,
    // todo - type magic could unify virt_to_phys and walk_va_spaces
    do_dedup: bool,
    address: u64,
    len: u64,
) -> impl Iterator<
    Item = (
        SpaceId,
        impl Iterator<Item = crate::vmem::SpaceAwareMapping>,
    ),
> + 'a {
    #[cfg(target_os = "linux")]
    extern crate std;
    let addr = address & ((1u64 << VA_BITS) - 1);
    let vmin = addr & !((PAGE_SIZE as u64) - 1);
    let vmax = core::cmp::min(addr + len, 1u64 << VA_BITS);
    let seen_pts: Option<Rc<RefCell<BTreeMap<u64, SpaceReferenceMapping>>>> = if do_dedup {
        Some(Rc::new(RefCell::new(BTreeMap::new())))
    } else {
        None
    };
    roots.into_iter().map(move |root| {
        let root_id = Op::to_phys(root);
        let root_req = walk_check_request_seen(
            &seen_pts,
            root_id,
            0,
            MapRequest {
                table_base: root,
                vmin,
                len: vmax.saturating_sub(vmin),
                update_parent: UpdateParentNone {},
            },
        );
        let seen_pts_1 = seen_pts.clone();
        let seen_pts_2 = seen_pts.clone();
        let seen_pts_3 = seen_pts.clone();
        let iter = do_walk_next_level::<47, 39, Op, _>(root_req)
            .filter_map(move |r| walk_next_level_table(op.as_ref(), r, 1, root_id, &seen_pts_1))
            .flat_map(do_walk_next_level::<38, 30, Op, _>)
            .filter_map(move |r| walk_next_level_table(op.as_ref(), r, 2, root_id, &seen_pts_2))
            .flat_map(do_walk_next_level::<29, 21, Op, _>)
            .filter_map(move |r| walk_next_level_table(op.as_ref(), r, 3, root_id, &seen_pts_3))
            .flat_map(do_walk_next_level::<20, 12, Op, _>)
            .filter_map(move |r| {
                let rq = match r {
                    WalkNextLevelResponse::AlreadySeen(sm) => {
                        return Some(SpaceAwareMapping::AnotherSpace(sm));
                    }
                    WalkNextLevelResponse::WalkNextLevel(rq) => rq,
                };
                let desc = unsafe { op.as_ref().read_entry(rq.entry_ptr) };
                if let Some(FinalLevelDescriptorKind::Page) = final_level_descriptor_kind(desc) {
                    let phys_addr = bits::<47, 12>(desc) << 12;
                    // Don't sign-extend to canonicalise, because we
                    // only uses addresess in the lower half right
                    // now---VA_BITS does not include the bit that
                    // selects between the ttbr0 and ttbr1 spaces.
                    let virt_addr = rq.vmin;
                    // The division of flags in the mapping structure
                    // does not perfectly capture the fact that
                    // user-level data and instruction access
                    // permissions can be different.  For now, we just
                    // assume that the mapping should be marked as
                    // executable if it was executable to the kernel
                    // at all.
                    let executable = bits::<53, 53>(desc) == 0;
                    let user_accessible = bits::<6, 6>(desc) != 0; // AP[1]
                    let kind = if bits::<58, 55>(desc) == SOFTWARE_USE_COW as u64 {
                        MappingKind::Cow(CowMapping {
                            readable: true,
                            executable,
                        })
                    } else {
                        MappingKind::Basic(BasicMapping {
                            readable: true,
                            writable: bits::<7, 7>(desc) == 0, // AP[2]
                            executable,
                        })
                    };
                    Some(SpaceAwareMapping::ThisSpace(Mapping {
                        phys_base: phys_addr,
                        virt_base: virt_addr,
                        len: PAGE_SIZE as u64,
                        kind,
                        user_accessible,
                    }))
                } else {
                    None // do nothing - there is no mapping to record here
                }
            });
        (root_id, iter)
    })
}

#[allow(clippy::missing_safety_doc)]
pub unsafe fn walk_va_spaces<Op: TableReadOps>(
    op: impl core::convert::AsRef<Op> + Copy,
    roots: &[Op::TableAddr],
    address: u64,
    len: u64,
) -> Vec<(SpaceId, Vec<crate::vmem::SpaceAwareMapping>)> {
    unsafe {
        internal_walk_va_spaces(&op, roots.iter().cloned(), true, address, len)
            .map(|(id, mappings)| (id, mappings.collect::<Vec<_>>()))
            .collect::<Vec<_>>()
    }
}

/// Stub — see [`crate::vmem::space_aware_map`].
#[allow(clippy::missing_safety_doc)]
pub unsafe fn space_aware_map<Op: TableOps>(
    _op: &Op,
    _ref_map: crate::vmem::SpaceReferenceMapping,
    _built_roots: &::alloc::collections::BTreeMap<crate::vmem::SpaceId, Op::TableAddr>,
) {
    // in practice, we never construct page tables that would result
    // in reaching this right now. todo: implement this properly
    debug_assert!(false, "space_aware_map is not yet supported on aarch64");
}
