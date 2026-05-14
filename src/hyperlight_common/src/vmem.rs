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
pub use arch::{PAGE_PRESENT, PAGE_TABLE_SIZE, PTE_ADDR_MASK, PageTableEntry, PhysAddr, VirtAddr};
pub const PAGE_TABLE_ENTRIES_PER_TABLE: usize =
    PAGE_TABLE_SIZE / core::mem::size_of::<PageTableEntry>();

// Shared page table iterator infrastructure used by each arch module.

/// Utility function to extract an (inclusive on both ends) bit range
/// from a quadword.
#[inline(always)]
pub(in crate::vmem) fn bits<const HIGH_BIT: u8, const LOW_BIT: u8>(x: u64) -> u64 {
    (x & ((1 << (HIGH_BIT + 1)) - 1)) >> LOW_BIT
}

/// Helper function to write a page table entry, updating the whole
/// chain of tables back to the root if necessary.
///
/// # Safety
/// Same requirements as [`TableOps::write_entry`].
pub(in crate::vmem) unsafe fn write_entry_updating<
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

/// A helper trait that allows us to move a page table (e.g. from the
/// snapshot to the scratch region), keeping track of the context that
/// needs to be updated when that is moved (and potentially
/// recursively updating, if necessary).
///
/// This is done via a trait so that the selected impl knows the exact
/// nesting depth of tables, in order to assist
/// inlining/specialisation in generating efficient code.
///
/// The trait definition only bounds its parameter by
/// [`TableReadOps`], since [`UpdateParentNone`] does not need to be
/// able to actually write to the tables.
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

/// A struct implementing [`UpdateParent`] that is impossible to use
/// (since its [`UpdateParent::update_parent`] method takes [`Void`]),
/// used when it is statically known that a table operation cannot
/// result in a need to update ancestors.
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

/// A helper structure indicating a mapping operation that needs to be
/// performed.
pub(in crate::vmem) struct MapRequest<Op: TableReadOps, P: UpdateParent<Op>> {
    pub table_base: Op::TableAddr,
    pub vmin: u64,
    pub len: u64,
    pub update_parent: P,
}

/// A helper structure indicating that a particular PTE needs to be
/// modified.
pub(in crate::vmem) struct MapResponse<Op: TableReadOps, P: UpdateParent<Op>> {
    pub entry_ptr: Op::TableAddr,
    pub vmin: u64,
    pub len: u64,
    pub update_parent: P,
}

/// Iterator that walks through page table entries at a specific level.
///
/// Given a virtual address range and a table base, this iterator yields
/// `MapResponse` items for each page table entry that needs to be modified.
/// The const generics `HIGH_BIT` and `LOW_BIT` specify which bits of the
/// virtual address are used to index into this level's table.
///
/// For example on amd64:
/// - PML4: HIGH_BIT=47, LOW_BIT=39 (9 bits = 512 entries, each covering 512GB)
/// - PDPT: HIGH_BIT=38, LOW_BIT=30 (9 bits = 512 entries, each covering 1GB)
/// - PD:   HIGH_BIT=29, LOW_BIT=21 (9 bits = 512 entries, each covering 2MB)
/// - PT:   HIGH_BIT=20, LOW_BIT=12 (9 bits = 512 entries, each covering 4KB)
///
/// On i686:
/// - PD:   HIGH_BIT=31, LOW_BIT=22 (10 bits = 1024 entries, each covering 4MB)
/// - PT:   HIGH_BIT=21, LOW_BIT=12 (10 bits = 1024 entries, each covering 4KB)
pub(in crate::vmem) struct ModifyPteIterator<
    const HIGH_BIT: u8,
    const LOW_BIT: u8,
    Op: TableReadOps,
    P: UpdateParent<Op>,
> {
    request: MapRequest<Op, P>,
    n: u64,
}
impl<const HIGH_BIT: u8, const LOW_BIT: u8, Op: TableReadOps, P: UpdateParent<Op>> Iterator
    for ModifyPteIterator<HIGH_BIT, LOW_BIT, Op, P>
{
    type Item = MapResponse<Op, P>;
    fn next(&mut self) -> Option<Self::Item> {
        // Each page table entry at this level covers a region of size
        // (1 << LOW_BIT) bytes. For example, at the PT level
        // (LOW_BIT=12), each entry covers 4KB (0x1000 bytes). At the
        // PD level (LOW_BIT=21), each entry covers 2MB (0x200000
        // bytes).
        //
        // This mask isolates the bits below this level's index bits,
        // used for alignment.
        let lower_bits_mask = (1u64 << LOW_BIT) - 1;

        // Calculate the virtual address for this iteration.
        // On the first iteration (n=0), start at the requested vmin.
        // On subsequent iterations, advance to the next aligned boundary.
        // This handles the case where vmin isn't aligned to this level's
        // entry size.
        let next_vmin = if self.n == 0 {
            self.request.vmin
        } else {
            // Align to the next boundary by adding one entry's worth
            // and masking off lower bits. Masking off before adding
            // is safe, since n << LOW_BIT must always have zeros in
            // these positions.
            let aligned_min = self.request.vmin & !lower_bits_mask;
            // Use checked_add because going past the end of the
            // address space counts as "the next one would be out of
            // range"
            aligned_min.checked_add(self.n << LOW_BIT)?
        };

        // Check if we've processed the entire requested range
        if next_vmin >= self.request.vmin + self.request.len {
            return None;
        }

        // Calculate the pointer to this level's page table entry.
        // bits::<HIGH_BIT, LOW_BIT> extracts the relevant index bits
        // from the virtual address. Multiply by the PTE size to get
        // the byte offset.
        let pte_index = bits::<HIGH_BIT, LOW_BIT>(next_vmin);
        let entry_ptr = Op::entry_addr(
            self.request.table_base,
            pte_index * core::mem::size_of::<PageTableEntry>() as u64,
        );

        // Calculate how many bytes remain to be mapped from this point.
        let len_from_here = self.request.len - (next_vmin - self.request.vmin);
        // Calculate the maximum bytes this single entry can cover.
        // If next_vmin is aligned, this is the full entry size (1 << LOW_BIT).
        // If not aligned (only possible on first iteration), it's the
        // remaining space until the next boundary.
        let max_len = (1u64 << LOW_BIT) - (next_vmin & lower_bits_mask);
        // The actual length for this entry is the smaller of what's
        // needed vs what fits.
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

pub(in crate::vmem) fn modify_ptes<
    const HIGH_BIT: u8,
    const LOW_BIT: u8,
    Op: TableReadOps,
    P: UpdateParent<Op>,
>(
    r: MapRequest<Op, P>,
) -> ModifyPteIterator<HIGH_BIT, LOW_BIT, Op, P> {
    ModifyPteIterator { request: r, n: 0 }
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
/// to move a table.  Also used as the `SpaceReferenceMapping` type on
/// architectures that never emit `AnotherSpace` entries, making the
/// corresponding match arm statically unreachable.
#[derive(Debug, Clone, Copy)]
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

/// A sealed trait used to collect some information about the marker structures [`MayMoveTable`] and [`MayNotMoveTable`]
pub trait TableMovability<Op: TableReadOps + ?Sized>:
    TableMovabilityBase<Op>
    + arch::TableMovability<Op, <Self as TableMovabilityBase<Op>>::TableMoveInfo>
{
}
impl<
    Op: TableReadOps,
    T: TableMovabilityBase<Op>
        + arch::TableMovability<Op, <Self as TableMovabilityBase<Op>>::TableMoveInfo>,
> TableMovability<Op> for T
{
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
    /// On architectures that support multiple privilege levels inside
    /// the guest, whether the mapping is accessible to the
    /// lower-privileged level (with the same permissions/behaviour as
    /// the upper-privileged level, for now).
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

//==================================================================================================
// Multi-space (aliased page-table) walking
//==================================================================================================

/// Identifier for a virtual address space, used by the multi-space
/// walker to describe which space "owns" a shared intermediate table.
/// Implementations typically use the physical address of the root
/// page table (which is unique per space).
pub type SpaceId = u64;

/// A reference from one address space to an intermediate page table
/// that lives in a different space. Defined per-arch: on
/// architectures that never emit `AnotherSpace` entries (amd64,
/// aarch64) it is [`Void`], making the `AnotherSpace` variant of
/// [`SpaceAwareMapping`] statically unreachable.
pub use arch::SpaceReferenceMapping;

/// Either a normal leaf mapping in the current space, or a reference
/// to an intermediate table in another space. The compaction loop in
/// the host snapshotting code treats these two cases differently:
///
/// - `ThisSpace(m)` is rebuilt like any other leaf mapping: the
///   backing page is compacted into the new snapshot blob, the PTE is
///   written, and intermediate tables are allocated on demand.
/// - `AnotherSpace(r)` is rebuilt by *linking*: the entry in our
///   rebuilt root for `r.our_va` is made to point at whatever table
///   the owning space ended up with at `r.their_va`.
///   See [`space_aware_map`].
///
/// On architectures where `SpaceReferenceMapping` is [`Void`], the
/// `AnotherSpace` variant is statically unreachable so match arms
/// for it should use `match impossible {}`.
#[derive(Debug)]
pub enum SpaceAwareMapping {
    ThisSpace(Mapping),
    AnotherSpace(SpaceReferenceMapping),
}

/// Install a [`SpaceAwareMapping`] into the page tables managed by
/// `op`.
///
/// Callers must ensure that `built_roots` contains populated page
/// tables for any other space referenced by the mapping.
///
/// # Safety
/// Same invariants as [`map`]: the caller owns the concurrency story
/// around the page tables being written, and must invalidate TLBs
/// afterwards if they were live.
pub unsafe fn space_aware_map<Op: TableOps>(
    op: &Op,
    sam: SpaceAwareMapping,
    built_roots: &::alloc::collections::BTreeMap<SpaceId, Op::TableAddr>,
) {
    match sam {
        SpaceAwareMapping::ThisSpace(mapping) => unsafe { arch::map(op, mapping) },
        SpaceAwareMapping::AnotherSpace(ref_map) => unsafe {
            arch::link_shared_table(op, ref_map, built_roots)
        },
    }
}

/// Walk multiple page-table roots together, emitting either a normal
/// leaf mapping (`ThisSpace`) or a reference to an alias that was
/// already seen via an earlier root (`AnotherSpace`).
///
/// The caller passes `roots` in their preferred order of primacy. The
/// first root to visit a particular intermediate PA becomes the
/// "owner" of that sub-table — subsequent roots that alias it receive
/// `AnotherSpace` entries referencing the owner.
///
/// The returned `Vec` is ordered the same way `roots` was passed — so
/// by construction the result is topologically sorted: every
/// `AnotherSpace` reference points to a space that appears earlier in
/// the list. This lets a rebuilder process roots in iteration order
/// without a separate sort pass, and guarantees that the
/// [`space_aware_map`] invariant is met.
///
/// # Safety
/// Same invariants as [`virt_to_phys`]. Callers must ensure the page
/// tables are not being mutated concurrently.
pub use arch::walk_va_spaces;
