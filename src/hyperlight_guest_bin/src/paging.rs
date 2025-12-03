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

use crate::OS_PAGE_SIZE;
use hyperlight_guest::prim_alloc::alloc_phys_pages;

use core::sync::atomic::{AtomicU64, Ordering};

// TODO: This is not at all thread-safe atm
// TODO: A lot of code in this file uses inline assembly to load and
//       store page table entries. It would be nice to use pointer
//       volatile read/writes instead, but unfortunately we have a PTE
//       at physical address 0, which is currently identity-mapped at
//       virtual address 0, and Rust raw pointer operations can't be
//       used to read/write from address 0.

// Whenever we do a mapping operation, we check CR3 to see if it is
// one of ours. If it is not, we stash the old value here to use to
// recognise page table entries in the snapshot region. If it is, we
// rely on using the cached value here.
static SNAPSHOT_PT_GPA: AtomicU64 = AtomicU64::new(0);

struct GuestMappingOperations {
    snapshot_pt_base_gpa: u64,
    snapshot_pt_base_gva: u64,
    scratch_base_gpa: u64,
    scratch_base_gva: u64,
}
impl GuestMappingOperations {
    fn new() -> Self {
        Self {
            snapshot_pt_base_gpa: unsafe { hyperlight_guest::layout::snapshot_pt_gpa_base_gva().read_volatile() },
            snapshot_pt_base_gva: hyperlight_common::layout::SNAPSHOT_PT_GVA_MIN as u64,
            scratch_base_gpa: hyperlight_guest::layout::scratch_base_gpa(),
            scratch_base_gva: hyperlight_guest::layout::scratch_base_gva(),
        }
    }
    fn fallible_ptov(&self, addr: u64) -> Option<*mut u8> {
        if addr >= self.scratch_base_gpa {
            Some((self.scratch_base_gva + (addr - self.scratch_base_gpa)) as *mut u8)
        } else if addr >= self.snapshot_pt_base_gpa {
            Some((self.snapshot_pt_base_gva + (addr - self.snapshot_pt_base_gpa)) as *mut u8)
        } else {
            None
        }
    }
    fn ptov(&self, addr: u64) -> *mut u8 {
        self.fallible_ptov(addr).unwrap_or_else(|| panic!("ptov encounted snapshot non-PT page: {:x}", addr))
    }
}
impl hyperlight_common::vm::TableOps for GuestMappingOperations {
    type TableAddr = u64;
    unsafe fn alloc_table(&self) -> u64 {
        let page_addr = unsafe { alloc_phys_pages(1) };
        unsafe { self.ptov(page_addr).write_bytes(0u8, hyperlight_common::vm::PAGE_TABLE_SIZE) };
        page_addr
    }
    fn entry_addr(addr: u64, offset: u64) -> u64 {
        addr + offset
    }
    unsafe fn read_entry(&self, addr: u64) -> u64 {
        let addr = self.ptov(addr);
        let ret: u64;
        unsafe {
            asm!("mov {}, qword ptr [{}]", out(reg) ret, in(reg) addr);
        }
        ret
    }
    unsafe fn write_entry(&self, addr: u64, x: u64) -> Option<u64> {
        let mut addr = addr;
        let mut ret = None;
        if addr >= self.snapshot_pt_base_gpa && addr < self.scratch_base_gpa{
            // This needs to be CoW'd over to the scratch region
            unsafe {
                let new_table = alloc_phys_pages(1);
                core::ptr::copy(
                    self.ptov(addr & !0xfff),
                    self.ptov(new_table),
                    hyperlight_common::vm::PAGE_TABLE_SIZE,
                );
                addr = new_table | (addr & 0xfff);
                ret = Some(new_table);
            }
        }
        let addr = self.ptov(addr);
        unsafe {
            asm!("mov qword ptr [{}], {}", in(reg) addr, in(reg) x);
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

/// Assumption: all are page-aligned
/// # Safety
/// This function modifies pages backing a virtual memory range which is inherently unsafe w.r.t.
/// the Rust memory model.
/// When using this function note:
/// - No locking is performed before touching page table data structures,
///   as such do not use concurrently with any other page table operations
/// - TLB invalidation is not performed,
///   if previously-unmapped ranges are not being mapped, TLB invalidation may need to be performed afterwards.
#[hyperlight_guest_tracing::trace_function]
pub unsafe fn map_region(phys_base: u64, virt_base: *mut u8, len: u64) {
    use hyperlight_common::vm;
    unsafe {
        vm::map::<GuestMappingOperations>(
            &GuestMappingOperations::new(),
            vm::Mapping {
                phys_base,
                virt_base: virt_base as u64,
                len,
                kind: vm::MappingKind::BasicMapping(vm::BasicMapping {
                    readable: true,
                    writable: true,
                    executable: true,
                }),
            },
        );
    }
}

pub fn ptov(gpa: u64) -> Option<*mut u8> {
    GuestMappingOperations::new().fallible_ptov(gpa)
}
pub fn vtop(gva: u64) -> Option<u64> {
    use hyperlight_common::vm;
    unsafe {
        vm::vtop::<_>(&GuestMappingOperations::new(), gva)
    }
}

pub fn flush_tlb() {
    // Currently this just always flips CR4.PGE back and forth to
    // trigger a tlb flush. We should use a faster approach where
    // available
    let mut orig_cr4: u64;
    unsafe {
        asm!("mov {}, cr4", out(reg) orig_cr4);
    }
    let tmp_cr4: u64 = orig_cr4 ^ (1 << 7); // CR4.PGE
    unsafe {
        asm!(
            "mov cr4, {}",
            "mov cr4, {}",
            in(reg) tmp_cr4,
            in(reg) orig_cr4
        );
    }
}
