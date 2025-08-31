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

use tracing::{Span, instrument};

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

/// A helper structure indicating a mapping operation that needs to be
/// performed
struct MapRequest {
    table_base: u64,
    vmin: *mut u8,
    len: u64,
}

/// A helper structure indicating that a particular PTE needs to be
/// modified
struct MapResponse {
    entry_ptr: *mut u64,
    vmin: *mut u8,
    len: u64,
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
#[instrument(skip_all, parent = Span::current(), level= "Trace")]
pub unsafe fn map_region(phys_base: u64, virt_base: *mut u8, len: u64) {
    let mut pml4_base: u64;
    unsafe {
        asm!("mov {}, cr3", out(reg) pml4_base);
    }
    pml4_base &= !0xfff;
    modify_ptes::<47, 39>(MapRequest {
        table_base: pml4_base,
        vmin: virt_base,
        len,
    })
    .map(|r| unsafe { alloc_pte_if_needed(r) })
    .flat_map(modify_ptes::<38, 30>)
    .map(|r| unsafe { alloc_pte_if_needed(r) })
    .flat_map(modify_ptes::<29, 21>)
    .map(|r| unsafe { alloc_pte_if_needed(r) })
    .flat_map(modify_ptes::<20, 12>)
    .map(|r| map_normal(phys_base, virt_base, r))
    .for_each(drop);
}

#[allow(unused)]
/// This function is not presently used for anything, but is useful
/// for debugging
/// # Safety
/// This function traverses page table data structures, and should not be called concurrently
/// with any other operations that modify the page table.
/// # Panics
/// This function will panic if:
/// - A page map request resolves to multiple page table entries
pub unsafe fn dbg_print_address_pte(address: u64) -> u64 {
    let mut pml4_base: u64 = 0;
    unsafe {
        asm!("mov {}, cr3", out(reg) pml4_base);
    }
    pml4_base &= !0xfff;
    let addrs = modify_ptes::<47, 39>(MapRequest {
        table_base: pml4_base,
        vmin: address as *mut u8,
        len: unsafe { OS_PAGE_SIZE as u64 },
    })
    .map(|r| unsafe { require_pte_exist(r) })
    .flat_map(modify_ptes::<38, 30>)
    .map(|r| unsafe { require_pte_exist(r) })
    .flat_map(modify_ptes::<29, 21>)
    .map(|r| unsafe { require_pte_exist(r) })
    .flat_map(modify_ptes::<20, 12>)
    .map(|r| {
        let mut pte: u64 = 0;
        unsafe {
            asm!("mov {}, qword ptr [{}]", out(reg) pte, in(reg) r.entry_ptr);
        }
        pte
    })
    .collect::<alloc::vec::Vec<u64>>();
    if addrs.len() != 1 {
        panic!("impossible: 1 page map request resolved to multiple PTEs");
    }
    addrs[0]
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

/// # Safety
/// This function traverses page table data structures, and should not be called concurrently
/// with any other operations that modify the page table.
unsafe fn require_pte_exist(x: MapResponse) -> MapRequest {
    let mut pte: u64;
    unsafe {
        asm!("mov {}, qword ptr [{}]", out(reg) pte, in(reg) x.entry_ptr);
    }
    let present = pte & 0x1;
    if present == 0 {
        panic!("debugging: found not-present pte");
    }
    MapRequest {
        table_base: pte & !0xfff,
        vmin: x.vmin,
        len: x.len,
    }
}

/// Page-mapping callback to allocate a next-level page table if necessary.
/// # Safety
/// This function modifies page table data structures, and should not be called concurrently
/// with any other operations that modify the page table.
unsafe fn alloc_pte_if_needed(x: MapResponse) -> MapRequest {
    let mut pte: u64;
    unsafe {
        asm!("mov {}, qword ptr [{}]", out(reg) pte, in(reg) x.entry_ptr);
    }
    let present = pte & 0x1;
    if present != 0 {
        return MapRequest {
            table_base: pte & !0xfff,
            vmin: x.vmin,
            len: x.len,
        };
    }
    let page_addr = unsafe { alloc_phys_pages(1) };
    unsafe { ptov(page_addr).write_bytes(0u8, OS_PAGE_SIZE as usize) };

    #[allow(clippy::identity_op)]
    #[allow(clippy::precedence)]
    let pte = page_addr |
        1 << 5 | // A   - we don't track accesses at table level
        0 << 4 | // PCD - leave caching enabled
        0 << 3 | // PWT - write-back
        1 << 2 | // U/S - allow user access to everything (for now)
        1 << 1 | // R/W - we don't use block-level permissions
        1 << 0; // P   - this entry is present
    unsafe {
        asm!("mov qword ptr [{}], {}", in(reg) x.entry_ptr, in(reg) pte);
    }
    MapRequest {
        table_base: page_addr,
        vmin: x.vmin,
        len: x.len,
    }
}

/// Map a normal memory page
///
/// TODO: support permissions; currently mapping is always RWX
fn map_normal(phys_base: u64, virt_base: *mut u8, r: MapResponse) {
    #[allow(clippy::identity_op)]
    #[allow(clippy::precedence)]
    let pte = (phys_base + (r.vmin as u64 - virt_base as u64)) |
        1 << 6 | // D   - we don't presently track dirty state for anything
        1 << 5 | // A   - we don't presently track access for anything
        0 << 4 | // PCD - leave caching enabled
        0 << 3 | // PWT - write-back
        1 << 2 | // U/S - allow user access to everything (for now)
        1 << 1 | // R/W - for now make everything r/w
        1 << 0; // P   - this entry is present
    unsafe {
        r.entry_ptr.write_volatile(pte);
    }
}

#[inline(always)]
/// Utility function to extract an (inclusive on both ends) bit range
/// from a quadword.
fn bits<const HIGH_BIT: u8, const LOW_BIT: u8>(x: u64) -> u64 {
    (x & ((1 << (HIGH_BIT + 1)) - 1)) >> LOW_BIT
}

struct ModifyPteIterator<const HIGH_BIT: u8, const LOW_BIT: u8> {
    request: MapRequest,
    n: u64,
}
impl<const HIGH_BIT: u8, const LOW_BIT: u8> Iterator for ModifyPteIterator<HIGH_BIT, LOW_BIT> {
    type Item = MapResponse;
    fn next(&mut self) -> Option<Self::Item> {
        if (self.n << LOW_BIT) >= self.request.len {
            return None;
        }
        // next stage parameters
        let next_vmin = self.request.vmin.wrapping_add((self.n << LOW_BIT) as usize);
        let entry_ptr = ptov(self.request.table_base)
            .wrapping_add((bits::<HIGH_BIT, LOW_BIT>(next_vmin as u64) << 3) as usize)
            as *mut u64;
        let len_from_here = self.request.len - (self.n << LOW_BIT);
        let next_len = core::cmp::min(len_from_here, 1 << LOW_BIT);

        // update our state
        self.n += 1;

        Some(MapResponse {
            entry_ptr,
            vmin: next_vmin,
            len: next_len,
        })
    }
}
fn modify_ptes<const HIGH_BIT: u8, const LOW_BIT: u8>(
    r: MapRequest,
) -> ModifyPteIterator<HIGH_BIT, LOW_BIT> {
    ModifyPteIterator { request: r, n: 0 }
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
