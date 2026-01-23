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

use alloc::alloc::Layout;
use core::arch::asm;

use tracing::instrument;

use crate::OS_PAGE_SIZE;

/// Convert a physical address in main memory to a virtual address
/// through the pysmap
///
/// This is _not guaranteed_ to work with device memory
pub fn ptov(x: u64) -> *mut u8 {
    // Currently, all of main memory is identity mapped
    x as *mut u8
}

// TODO: This is not at all thread-safe atm
// TODO: A lot of code in this file uses inline assembly to load and
//       store page table entries. It would be nice to use pointer
//       volatile read/writes instead, but unfortunately we have a PTE
//       at physical address 0, which is currently identity-mapped at
//       virtual address 0, and Rust raw pointer operations can't be
//       used to read/write from address 0.

// We get this out of CR3 the first time that we do any mapping
// operation. In the future, if snapshot/restore changes to be able to
// change the snapshot pt base, we will need to modify this.
static SNAPSHOT_PT_GPA: spin::Once<u64> = spin::Once::new();

struct GuestMappingOperations {
    snapshot_pt_base_gpa: u64,
    snapshot_pt_base_gva: u64,
}
impl GuestMappingOperations {
    fn new() -> Self {
        Self {
            snapshot_pt_base_gpa: *SNAPSHOT_PT_GPA.call_once(|| {
                let snapshot_pt_base_gpa: u64;
                unsafe {
                    asm!("mov {}, cr3", out(reg) snapshot_pt_base_gpa);
                };
                snapshot_pt_base_gpa
            }),
            snapshot_pt_base_gva: hyperlight_common::layout::SNAPSHOT_PT_GVA as u64,
        }
    }
    fn phys_to_virt(&self, addr: u64) -> u64 {
        if addr >= self.snapshot_pt_base_gpa {
            self.snapshot_pt_base_gva + (addr - self.snapshot_pt_base_gpa)
        } else {
            // Assume for now that any of our own PTs are identity mapped.
            addr
        }
    }
}
impl hyperlight_common::vmem::TableOps for GuestMappingOperations {
    type TableAddr = u64;
    unsafe fn alloc_table(&self) -> u64 {
        let page_addr = unsafe { alloc_phys_pages(1) };
        unsafe { ptov(page_addr).write_bytes(0u8, hyperlight_common::vmem::PAGE_TABLE_SIZE) };
        page_addr
    }
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
    unsafe fn write_entry(&self, addr: u64, entry: u64) {
        let addr = self.phys_to_virt(addr);
        unsafe {
            asm!("mov qword ptr [{}], {}", in(reg) addr, in(reg) entry);
        }
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
#[instrument(skip_all, level = "Trace")]
pub unsafe fn map_region(phys_base: u64, virt_base: *mut u8, len: u64) {
    use hyperlight_common::vmem;
    unsafe {
        vmem::map(
            &GuestMappingOperations::new(),
            vmem::Mapping {
                phys_base,
                virt_base: virt_base as u64,
                len,
                kind: vmem::MappingKind::BasicMapping(vmem::BasicMapping {
                    readable: true,
                    writable: true,
                    executable: true,
                }),
            },
        );
    }
}

/// Allocate n contiguous physical pages and return the physical
/// addresses of the pages in question.
/// # Safety
/// This function is not inherently unsafe but will likely become so in the future
/// when a real physical page allocator is implemented.
/// # Panics
/// This function will panic if:
/// - The Layout creation fails
/// - Memory allocation fails
pub unsafe fn alloc_phys_pages(n: u64) -> u64 {
    // Currently, since all of main memory is idmap'd, we can just
    // allocate any appropriately aligned section of memory.
    unsafe {
        let v = alloc::alloc::alloc_zeroed(
            Layout::from_size_align(n as usize * OS_PAGE_SIZE as usize, OS_PAGE_SIZE as usize)
                .expect("could not create physical page allocation layout"),
        );
        if v.is_null() {
            panic!("could not allocate a physical page");
        }
        v as u64
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
