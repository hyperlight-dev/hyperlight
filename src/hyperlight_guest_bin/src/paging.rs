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

use core::arch::asm;

use hyperlight_common::vmem;
use hyperlight_guest::prim_alloc::alloc_phys_pages;

// TODO: This is not at all thread-safe atm
// TODO: A lot of code in this file uses inline assembly to load and
//       store page table entries. It would be nice to use pointer
//       volatile read/writes instead, but unfortunately we have a PTE
//       at physical address 0, which is currently identity-mapped at
//       virtual address 0, and Rust raw pointer operations can't be
//       used to read/write from address 0.

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
    fn fallible_phys_to_virt(&self, addr: u64) -> Option<*mut u8> {
        if addr >= self.scratch_base_gpa {
            Some((self.scratch_base_gva + (addr - self.scratch_base_gpa)) as *mut u8)
        } else {
            None
        }
    }
    fn phys_to_virt(&self, addr: u64) -> *mut u8 {
        self.fallible_phys_to_virt(addr)
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
        let ret: u64;
        unsafe {
            asm!("mov {}, qword ptr [{}]", out(reg) ret, in(reg) addr);
        }
        ret
    }
    fn to_phys(addr: u64) -> u64 {
        addr
    }
    fn from_phys(addr: u64) -> u64 {
        addr
    }
    fn root_table(&self) -> u64 {
        let pml4_base: u64;
        unsafe {
            asm!("mov {}, cr3", out(reg) pml4_base);
        }
        pml4_base & !0xfff
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
                .write_bytes(0u8, vmem::PAGE_TABLE_SIZE)
        };
        page_addr
    }
    unsafe fn write_entry(&self, addr: u64, entry: u64) -> Option<u64> {
        let addr = self.phys_to_virt(addr);
        unsafe {
            asm!("mov qword ptr [{}], {}", in(reg) addr, in(reg) entry);
        }
        None
    }
    unsafe fn update_root(&self, new_root: u64) {
        unsafe {
            core::arch::asm!("mov cr3, {}", in(reg) <Self as vmem::TableReadOps>::to_phys(new_root));
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
            },
        );
    }
}

pub fn virt_to_phys(gva: vmem::VirtAddr) -> impl Iterator<Item = vmem::Mapping> {
    unsafe { vmem::virt_to_phys::<_>(GuestMappingOperations::new(), gva, 1) }
}

pub fn phys_to_virt(gpa: vmem::PhysAddr) -> Option<*mut u8> {
    GuestMappingOperations::new().fallible_phys_to_virt(gpa)
}
