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

// TODO(aarch64): implement real page table operations

use crate::vmem::{Mapping, TableOps, TableReadOps, Void};

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_TABLE_SIZE: usize = 4096;
pub const PAGE_PRESENT: u64 = 1; // AArch64: bit 0 is the "valid" bit
pub const PTE_ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000; // bits [47:12]
pub type PageTableEntry = u64;
pub type VirtAddr = u64;
pub type PhysAddr = u64;

/// # Safety
/// See `TableOps` documentation.
#[allow(clippy::missing_safety_doc)]
pub unsafe fn map<Op: TableOps>(_op: &Op, _mapping: Mapping) {
    unimplemented!("map")
}

/// # Safety
/// See `TableReadOps` documentation.
#[allow(clippy::missing_safety_doc)]
pub unsafe fn virt_to_phys<'a, Op: TableReadOps + 'a>(
    _op: impl core::convert::AsRef<Op> + Copy + 'a,
    _address: u64,
    _len: u64,
) -> impl Iterator<Item = Mapping> + 'a {
    unimplemented!("virt_to_phys");
    #[allow(unreachable_code)]
    core::iter::empty()
}

/// Stub — see [`crate::vmem::walk_va_spaces`].
#[allow(clippy::missing_safety_doc)]
pub unsafe fn walk_va_spaces<Op: TableReadOps>(
    _op: &Op,
    _roots: &[Op::TableAddr],
    _address: u64,
    _len: u64,
) -> ::alloc::vec::Vec<(
    crate::vmem::SpaceId,
    ::alloc::vec::Vec<crate::vmem::SpaceAwareMapping>,
)> {
    ::alloc::vec::Vec::new()
}

/// aarch64 never emits `AnotherSpace` entries, so [`SpaceReferenceMapping`]
/// is [`crate::vmem::Void`] making the `AnotherSpace` match arm statically unreachable.
pub type SpaceReferenceMapping = crate::vmem::Void;

/// Statically unreachable: aarch64 never emits `AnotherSpace`.
#[allow(clippy::missing_safety_doc)]
pub(super) unsafe fn link_shared_table<Op: TableOps>(
    _op: &Op,
    impossible: crate::vmem::Void,
    _built_roots: &::alloc::collections::BTreeMap<crate::vmem::SpaceId, Op::TableAddr>,
) {
    match impossible {}
}

pub trait TableMovability<Op: TableReadOps + ?Sized, TableMoveInfo> {}
impl<Op: TableOps<TableMovability = crate::vmem::MayMoveTable>> TableMovability<Op, Op::TableAddr>
    for crate::vmem::MayMoveTable
{
}
impl<Op: TableReadOps> TableMovability<Op, Void> for crate::vmem::MayNotMoveTable {}
