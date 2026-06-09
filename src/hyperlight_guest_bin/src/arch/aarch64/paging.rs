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

use hyperlight_common::vmem;
use hyperlight_guest::prim_alloc::alloc_phys_pages;

use crate::arch::{mrs, msr};
// TODO: This is not at all thread-safe atm

#[derive(Copy, Clone)]
struct GuestMappingOperations {
    scratch_base_gpa: u64,
    scratch_base_gva: u64,
}
impl GuestMappingOperations {
    fn new() -> Self {
        Self {
            scratch_base_gpa: hyperlight_guest::layout::scratch_base_gpa(),
            scratch_base_gva: hyperlight_guest::layout::scratch_base_gva(),
        }
    }
    fn try_phys_to_virt(&self, addr: u64) -> Option<*mut u8> {
        if addr >= self.scratch_base_gpa {
            Some((self.scratch_base_gva + (addr - self.scratch_base_gpa)) as *mut u8)
        } else {
            None
        }
    }
    fn phys_to_virt(&self, addr: u64) -> *mut u8 {
        self.try_phys_to_virt(addr)
            .expect("phys_to_virt encountered snapshot non-PT page")
    }
}
// for virt_to_phys
impl core::convert::AsRef<GuestMappingOperations> for GuestMappingOperations {
    fn as_ref(&self) -> &Self {
        self
    }
}
impl vmem::TableReadOps for GuestMappingOperations {
    type TableAddr = u64;
    fn entry_addr(addr: u64, offset: u64) -> u64 {
        addr + offset
    }
    unsafe fn read_entry(&self, addr: u64) -> u64 {
        let addr = self.phys_to_virt(addr);
        unsafe { (addr as *mut u64).read_volatile() }
    }
    fn to_phys(addr: u64) -> u64 {
        addr
    }
    fn from_phys(addr: u64) -> u64 {
        addr
    }
    fn root_table(&self) -> u64 {
        unsafe { mrs!(TTBR0_EL1) & !0xfff }
    }
}

impl vmem::TableOps for GuestMappingOperations {
    // Currently, we don't actually move tables anywhere on amd64
    // because of issues with guest PTs in IPAs that are mapped
    // readonly in Stage 2 translation. However, this code all works
    // and will re-enabled as soon as there is improved
    // architecture/hypervisor support.
    type TableMovability = vmem::MayMoveTable;
    unsafe fn alloc_table(&self) -> u64 {
        let page_addr = unsafe { alloc_phys_pages(1) };
        unsafe {
            self.phys_to_virt(page_addr)
                .write_bytes(0u8, vmem::PAGE_TABLE_SIZE);
            // Make sure that the zero'ing writes are ordered with the
            // subsequent write that will actually link this table
            // into the hierarchy, so that the table walker can never
            // read+cache a stale valid entry. See e.g. litmus test
            // ROT.inv+dmbst in [1]
            //
            // [1] Ben Simner, Alasdair Armstrong, Jean
            //     Pichon-Pharabod, Christopher Pulte, Richard
            //     Grisenthwaite, and Peter Sewell. 2022. Relaxed
            //     virtual memory [extended version]. In: Proceedings
            //     of the 31st European Symposium on Systems
            //     Programming, ESOP 2022.
            core::arch::asm!("dmb st");
        }
        page_addr
    }
    unsafe fn write_entry(&self, addr: u64, entry: u64) -> Option<u64> {
        unsafe {
            (self.phys_to_virt(addr) as *mut u64).write_volatile(entry);
        }
        None
    }
    unsafe fn update_root(&self, new_root: u64) {
        unsafe {
            msr!(TTBR0_EL1, new_root);
        }
    }
}

/// Assumption: all are page-aligned
/// # Safety
/// This function modifies pages backing a virtual memory range which is inherently unsafe w.r.t.
/// the Rust memory model.
/// When using this function note:
/// - No locking is performed before touching page table data structures,
///   as such do not use concurrently with any other page table operations
/// - TLB invalidation is not performed,
///   if previously-unmapped ranges are not being mapped, TLB invalidation may need to be performed afterwards.
pub unsafe fn map_region(phys_base: u64, virt_base: *mut u8, len: u64, kind: vmem::MappingKind) {
    unsafe {
        vmem::map(
            &GuestMappingOperations::new(),
            vmem::Mapping {
                phys_base,
                virt_base: virt_base as u64,
                len,
                kind,
                user_accessible: false,
            },
        );
    }
}

pub fn virt_to_phys(gva: vmem::VirtAddr) -> impl Iterator<Item = vmem::Mapping> {
    unsafe { vmem::virt_to_phys::<_>(GuestMappingOperations::new(), gva, 1) }
}

pub fn phys_to_virt(gpa: vmem::PhysAddr) -> Option<*mut u8> {
    GuestMappingOperations::new().try_phys_to_virt(gpa)
}

pub mod barrier {
    /// # Architecture-specific (aarch64) notes
    ///
    /// I_WZCBG from [1]:
    /// > When a translation table entry that generates a Translation
    /// > fault, Address size fault, or Access flag fault is changed to
    /// > one that does not fault, all of the following apply to
    /// > software:
    /// > - TLB invalidation is not required because an entry that
    /// >   generates one of the listed faults is never cached in a TLB.
    /// > - A Context synchronization event is required to ensure that
    /// >   the completed change to the translation table entry affects
    /// >   subsequent instruction fetches.
    ///
    /// In theory, without FEAT_nTLBPA, there could be some subtlety
    /// here if the physical memory location used for the descriptor
    /// was previously used after the last TLBI to store a valid
    /// descriptor. Hyperlight does not recycle page tables in a way
    /// that would cause problems here.
    ///
    /// [1] Arm Architecture Reference Manual for A-profile architecture
    ///         Chapter D8: The AArch64 Virtual Memory System Architecture
    ///             §D8.17 TLB maintenance
    #[inline(always)]
    pub fn first_valid_same_ctx() {
        unsafe {
            core::arch::asm!(
                "
                dsb ish
                isb
            "
            );
        }
    }
}
