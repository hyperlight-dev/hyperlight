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

#[cfg_attr(target_arch = "x86", path = "arch/i686/vmem.rs")]
#[cfg_attr(
    all(target_arch = "x86_64", not(feature = "i686-guest")),
    path = "arch/amd64/vmem.rs"
)]
#[cfg_attr(
    all(target_arch = "x86_64", feature = "i686-guest"),
    path = "arch/i686/vmem.rs"
)]
#[cfg_attr(target_arch = "aarch64", path = "arch/aarch64/vmem.rs")]
mod arch;

#[cfg(all(
    feature = "i686-guest",
    not(any(target_arch = "x86", target_arch = "x86_64"))
))]
compile_error!(
    "the `i686-guest` feature is only supported on `target_arch = \"x86\"` (guest) or \
     `target_arch = \"x86_64\"` (host) targets"
);

/// This is always the page size that the /guest/ is being compiled
/// for, which may or may not be the same as the host page size.
pub use arch::PAGE_SIZE;
pub use arch::{PAGE_PRESENT, PAGE_TABLE_SIZE, PageTableEntry, PhysAddr, VirtAddr};
pub const PAGE_TABLE_ENTRIES_PER_TABLE: usize =
    PAGE_TABLE_SIZE / core::mem::size_of::<PageTableEntry>();

// Shared page table iterator infrastructure used by each arch module.

/// Extract bits `[HIGH_BIT:LOW_BIT]` (inclusive) from a u64.
#[inline(always)]
pub(crate) fn bits<const HIGH_BIT: u8, const LOW_BIT: u8>(x: u64) -> u64 {
    (x & ((1 << (HIGH_BIT + 1)) - 1)) >> LOW_BIT
}

/// Read a PTE and return it (widened to u64) if the present bit is set.
///
/// # Safety
/// `entry_ptr` must point to a valid page table entry.
#[inline(always)]
#[allow(clippy::useless_conversion)]
pub(crate) unsafe fn read_pte_if_present<Op: TableReadOps>(
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

/// Write a PTE, recursively updating parent entries if the table was moved.
///
/// # Safety
/// Same requirements as [`TableOps::write_entry`].
pub(crate) unsafe fn write_entry_updating<
    Op: TableOps,
    P: UpdateParent<
            Op,
            TableMoveInfo = <Op::TableMovability as TableMovabilityBase<Op>>::TableMoveInfo,
        >,
>(
    op: &Op,
    parent: P,
    addr: Op::TableAddr,
    entry: u64,
) {
    #[allow(clippy::useless_conversion)]
    if let Some(again) = unsafe { op.write_entry(addr, entry as PageTableEntry) } {
        parent.update_parent(op, again);
    }
}

/// Tracks the chain of ancestor page table entries that need updating
/// when a table is relocated. Implemented as a trait so that the
/// compiler can specialise per nesting depth for inlining.
pub trait UpdateParent<Op: TableReadOps + ?Sized>: Copy {
    /// The type of the information about a moved table which is
    /// needed in order to update its parent.
    type TableMoveInfo;
    /// The [`UpdateParent`] type that should be used when going down
    /// another level in the table, in order to add the current level
    /// to the chain of ancestors to be updated.
    type ChildType: UpdateParent<Op, TableMoveInfo = Self::TableMoveInfo>;
    fn update_parent(self, op: &Op, new_ptr: Self::TableMoveInfo);
    fn for_child_at_entry(self, entry_ptr: Op::TableAddr) -> Self::ChildType;
}

/// Parent is another page table whose ancestors may also need updating.
/// The `MayMoveTable` impl lives in each arch module (needs `pte_for_table`).
#[allow(dead_code)] // used only by archs that support MayMoveTable
pub struct UpdateParentTable<Op: TableOps, P: UpdateParent<Op>> {
    pub(crate) parent: P,
    pub(crate) entry_ptr: Op::TableAddr,
}
impl<Op: TableOps, P: UpdateParent<Op>> Clone for UpdateParentTable<Op, P> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<Op: TableOps, P: UpdateParent<Op>> Copy for UpdateParentTable<Op, P> {}
impl<Op: TableOps, P: UpdateParent<Op>> UpdateParentTable<Op, P> {
    #[allow(dead_code)]
    pub(crate) fn new(parent: P, entry_ptr: Op::TableAddr) -> Self {
        UpdateParentTable { parent, entry_ptr }
    }
}

/// Parent is the root (e.g. CR3). `MayMoveTable` impl lives in each arch module.
#[derive(Copy, Clone)]
pub struct UpdateParentRoot {}

/// No-op parent tracker (tables are never relocated).
#[derive(Copy, Clone)]
pub struct UpdateParentNone {}
impl<Op: TableReadOps> UpdateParent<Op> for UpdateParentNone {
    type TableMoveInfo = Void;
    type ChildType = Self;
    fn update_parent(self, _op: &Op, impossible: Void) {
        match impossible {}
    }
    fn for_child_at_entry(self, _entry_ptr: Op::TableAddr) -> Self {
        self
    }
}

/// A request to map/walk a VA range within a specific page table.
pub(crate) struct MapRequest<Op: TableReadOps, P: UpdateParent<Op>> {
    pub table_base: Op::TableAddr,
    pub vmin: u64,
    pub len: u64,
    pub update_parent: P,
}

/// A single PTE that needs to be examined or modified.
pub(crate) struct MapResponse<Op: TableReadOps, P: UpdateParent<Op>> {
    pub entry_ptr: Op::TableAddr,
    pub vmin: u64,
    pub len: u64,
    pub update_parent: P,
}

/// Iterates over PTEs at one level of the page table hierarchy.
///
/// `HIGH_BIT`/`LOW_BIT` select which VA bits index this level.
/// `PTE_SHIFT` is log2(PTE byte size) (3 for 8-byte, 2 for 4-byte).
pub(crate) struct ModifyPteIterator<
    const HIGH_BIT: u8,
    const LOW_BIT: u8,
    const PTE_SHIFT: u8,
    Op: TableReadOps,
    P: UpdateParent<Op>,
> {
    request: MapRequest<Op, P>,
    n: u64,
}
impl<
    const HIGH_BIT: u8,
    const LOW_BIT: u8,
    const PTE_SHIFT: u8,
    Op: TableReadOps,
    P: UpdateParent<Op>,
> Iterator for ModifyPteIterator<HIGH_BIT, LOW_BIT, PTE_SHIFT, Op, P>
{
    type Item = MapResponse<Op, P>;
    fn next(&mut self) -> Option<Self::Item> {
        let lower_bits_mask = (1u64 << LOW_BIT) - 1;

        // First iteration starts at vmin; subsequent ones advance to
        // the next aligned boundary. checked_add handles overflow at
        // the end of the address space.
        let next_vmin = if self.n == 0 {
            self.request.vmin
        } else {
            let aligned_min = self.request.vmin & !lower_bits_mask;
            aligned_min.checked_add(self.n << LOW_BIT)?
        };

        if next_vmin >= self.request.vmin + self.request.len {
            return None;
        }

        // Compute the byte offset of the PTE within the table.
        let entry_ptr = Op::entry_addr(
            self.request.table_base,
            bits::<HIGH_BIT, LOW_BIT>(next_vmin) << PTE_SHIFT,
        );

        // Length this single entry covers (may be less than a full
        // entry if vmin is unaligned on the first iteration).
        let len_from_here = self.request.len - (next_vmin - self.request.vmin);
        let max_len = (1u64 << LOW_BIT) - (next_vmin & lower_bits_mask);
        let next_len = core::cmp::min(len_from_here, max_len);

        self.n += 1;

        Some(MapResponse {
            entry_ptr,
            vmin: next_vmin,
            len: next_len,
            update_parent: self.request.update_parent,
        })
    }
}

pub(crate) fn modify_ptes<
    const HIGH_BIT: u8,
    const LOW_BIT: u8,
    const PTE_SHIFT: u8,
    Op: TableReadOps,
    P: UpdateParent<Op>,
>(
    r: MapRequest<Op, P>,
) -> ModifyPteIterator<HIGH_BIT, LOW_BIT, PTE_SHIFT, Op, P> {
    ModifyPteIterator { request: r, n: 0 }
}

/// Require that a PTE is present and descend to the next-level table.
/// `PTE_ADDR_MASK` is arch-specific (must mask out flag bits including NX).
///
/// # Safety
/// `op` must provide valid page table memory.
pub(crate) unsafe fn require_pte_exist<
    const PTE_ADDR_MASK: u64,
    Op: TableReadOps,
    P: UpdateParent<Op>,
>(
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

/// The read-only operations used to actually access the page table
/// structures, used to allow the same code to be used in the host and
/// the guest for page table setup.  This is distinct from
/// `TableWriteOps`, since there are some implementations for which
/// writing does not make sense, and only reading is required.
pub trait TableReadOps {
    /// The type of table addresses
    type TableAddr: Copy;

    /// Offset the table address by the given offset in bytes.
    ///
    /// # Parameters
    /// - `addr`: The base address of the table.
    /// - `entry_offset`: The offset in **bytes** within the page table. This is
    ///   not an entry index; callers must multiply the entry index by the size
    ///   of a page table entry (typically 8 bytes) to obtain the correct byte offset.
    ///
    /// # Returns
    /// The address of the entry at the given byte offset from the base address.
    fn entry_addr(addr: Self::TableAddr, entry_offset: u64) -> Self::TableAddr;

    /// Read a u64 from the given address, used to read existing page
    /// table entries
    ///
    /// # Safety
    /// This reads from the given memory address, and so all the usual
    /// Rust things about raw pointers apply. This will also be used
    /// to update guest page tables, so especially in the guest, it is
    /// important to ensure that the page tables updates do not break
    /// invariants. The implementor of the trait should ensure that
    /// nothing else will be reading/writing the address at the same
    /// time as mapping code using the trait.
    unsafe fn read_entry(&self, addr: Self::TableAddr) -> PageTableEntry;

    /// Convert an abstract table address to a concrete physical address (u64)
    /// which can be e.g. written into a page table entry
    fn to_phys(addr: Self::TableAddr) -> PhysAddr;

    /// Convert a concrete physical address (u64) which may have been e.g. read
    /// from a page table entry back into an abstract table address
    fn from_phys(addr: PhysAddr) -> Self::TableAddr;

    /// Return the address of the root page table
    fn root_table(&self) -> Self::TableAddr;
}

/// Our own version of ! until it is stable. Used to avoid needing to
/// implement [`TableOps::update_root`] for ops that never need
/// to move a table.
pub enum Void {}

/// A marker struct, used by an implementation of [`TableOps`] to
/// indicate that it may need to move existing page tables
pub struct MayMoveTable {}
/// A marker struct, used by an implementation of [`TableOps`] to
/// indicate that it will be able to update existing page tables
/// in-place, without moving them.
pub struct MayNotMoveTable {}

mod sealed {
    use super::{MayMoveTable, MayNotMoveTable, TableReadOps, Void};

    /// A (purposefully-not-exposed) internal implementation detail of the
    /// logic around whether a [`TableOps`] implementation may or may not
    /// move page tables.
    pub trait TableMovabilityBase<Op: TableReadOps + ?Sized> {
        type TableMoveInfo;
    }
    impl<Op: TableReadOps> TableMovabilityBase<Op> for MayMoveTable {
        type TableMoveInfo = Op::TableAddr;
    }
    impl<Op: TableReadOps> TableMovabilityBase<Op> for MayNotMoveTable {
        type TableMoveInfo = Void;
    }
}
use sealed::*;

/// Collects information about [`MayMoveTable`] / [`MayNotMoveTable`],
/// including which [`UpdateParent`] type to use at the root level.
/// Implemented in each arch module.
pub trait TableMovability<Op: TableReadOps + ?Sized>: TableMovabilityBase<Op> {
    type RootUpdateParent: UpdateParent<Op, TableMoveInfo = <Self as TableMovabilityBase<Op>>::TableMoveInfo>;
    fn root_update_parent() -> Self::RootUpdateParent;
}

/// The operations used to actually access the page table structures
/// that involve writing to them, used to allow the same code to be
/// used in the host and the guest for page table setup.
pub trait TableOps: TableReadOps {
    /// This marker should be either [`MayMoveTable`] or
    /// [`MayNotMoveTable`], as the case may be.
    ///
    /// If this is [`MayMoveTable`], the return type of
    /// [`Self::write_entry`] and the parameter type of
    /// [`Self::update_root`] will be `<Self as
    /// TableReadOps>::TableAddr`. If it is [`MayNotMoveTable`], those
    /// types will be [`Void`].
    type TableMovability: TableMovability<Self>;

    /// Allocate a zeroed table
    ///
    /// # Safety
    /// The current implementations of this function are not
    /// inherently unsafe, but the guest implementation will likely
    /// become so in the future when a real physical page allocator is
    /// implemented.
    ///
    /// Currently, callers should take care not to call this on
    /// multiple threads at the same time.
    ///
    /// # Panics
    /// This function may panic if:
    /// - The Layout creation fails
    /// - Memory allocation fails
    unsafe fn alloc_table(&self) -> Self::TableAddr;

    /// Write a u64 to the given address, used to write updated page
    /// table entries. In some cases,the page table in which the entry
    /// is located may need to be relocated in order for this to
    /// succeed; if this is the case, the base address of the new
    /// table is returned.
    ///
    /// # Safety
    /// This writes to the given memory address, and so all the usual
    /// Rust things about raw pointers apply. This will also be used
    /// to update guest page tables, so especially in the guest, it is
    /// important to ensure that the page tables updates do not break
    /// invariants. The implementor of the trait should ensure that
    /// nothing else will be reading/writing the address at the same
    /// time as mapping code using the trait.
    unsafe fn write_entry(
        &self,
        addr: Self::TableAddr,
        entry: PageTableEntry,
    ) -> Option<<Self::TableMovability as TableMovabilityBase<Self>>::TableMoveInfo>;

    /// Change the root page table to one at a different address
    ///
    /// # Safety
    /// This function will directly result in a change to virtual
    /// memory translation, and so is inherently unsafe w.r.t. the
    /// Rust memory model.  All the caveats listed on [`map`] apply as
    /// well.
    unsafe fn update_root(
        &self,
        new_root: <Self::TableMovability as TableMovabilityBase<Self>>::TableMoveInfo,
    );
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct BasicMapping {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct CowMapping {
    pub readable: bool,
    pub executable: bool,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum MappingKind {
    Unmapped,
    Basic(BasicMapping),
    Cow(CowMapping),
    /* TODO: What useful things other than basic mappings actually
     * require touching the tables? */
}

#[derive(Debug)]
pub struct Mapping {
    pub phys_base: u64,
    pub virt_base: u64,
    pub len: u64,
    pub kind: MappingKind,
    /// Whether ring-3 (user mode) code can access these pages.
    /// On i686, controls the PAGE_USER bit on PDEs and leaf PTEs.
    /// On amd64/aarch64, currently unused.
    pub user_accessible: bool,
}

/// Assumption: all are page-aligned
///
/// # Safety
/// This function modifies pages backing a virtual memory range which
/// is inherently unsafe w.r.t.  the Rust memory model.
///
/// When using this function, please note:
/// - No locking is performed before touching page table data structures,
///   as such do not use concurrently with any other page table operations
/// - TLB invalidation is not performed, if previously-mapped ranges
///   are being remapped, TLB invalidation may need to be performed
///   afterwards.
pub use arch::map;
/// This function is presently used for reading the tracing data, also
/// it is useful for debugging
///
/// # Safety
/// This function traverses page table data structures, and should not
/// be called concurrently with any other operations that modify the
/// page table.
pub use arch::virt_to_phys;
