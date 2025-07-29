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

#[cfg_attr(target_arch = "x86_64", path = "arch/amd64/vm.rs")]
mod arch;

pub use arch::{PAGE_SIZE, PAGE_TABLE_SIZE, PageTableEntry, PhysAddr, VirtAddr};
pub const PAGE_TABLE_ENTRIES_PER_TABLE: usize =
    PAGE_TABLE_SIZE / core::mem::size_of::<PageTableEntry>();

/// The operations used to actually access the page table structures,
/// used to allow the same code to be used in the host and the guest
/// for page table setup
pub trait TableOps {
    /// The type of table addresses
    type TableAddr: Copy;

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

    /// Offset the table address by the u64 entry offset
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

    /// Write a u64 to the given address, used to write updated page
    /// table entries
    ///
    /// # Safety
    /// This writes to the given memory address, and so all the usual
    /// Rust things about raw pointers apply. This will also be used
    /// to update guest page tables, so especially in the guest, it is
    /// important to ensure that the page tables updates do not break
    /// invariants. The implementor of the trait should ensure that
    /// nothing else will be reading/writing the address at the same
    /// time as mapping code using the trait.
    unsafe fn write_entry(&self, addr: Self::TableAddr, x: PageTableEntry);

    /// Convert an abstract physical address to a concrete u64 which
    /// can be e.g. written into a table
    fn to_phys(addr: Self::TableAddr) -> PhysAddr;

    /// Convert a concrete u64 which may have been e.g. read from a
    /// table back into an abstract physical address
    fn from_phys(addr: PhysAddr) -> Self::TableAddr;

    /// Return the address of the root page table
    fn root_table(&self) -> Self::TableAddr;
}

#[derive(Debug)]
pub struct BasicMapping {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Debug)]
pub enum MappingKind {
    BasicMapping(BasicMapping),
    /* TODO: What useful things other than basic mappings actually
     * require touching the tables? */
}

#[derive(Debug)]
pub struct Mapping {
    pub phys_base: u64,
    pub virt_base: u64,
    pub len: u64,
    pub kind: MappingKind,
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
/// This function is not presently used for anything, but is useful
/// for debugging
///
/// # Safety
/// This function traverses page table data structures, and should not
/// be called concurrently with any other operations that modify the
/// page table.
pub use arch::vtop;
