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
use core::ptr::addr_of;

/// Entry in the Global Descriptor Table (GDT)
/// For reference, see page 3-10 Vol. 3A of Intel 64 and IA-32
/// Architectures Software Developer's Manual, figure 3-8
/// (https://i.imgur.com/1i9xUmx.png).
/// From the bottom, we have:
/// - segment limit 15..0 = limit_low
/// - base address 31..16 = base_low
/// - base 23..16 = base_middle
/// - p dpl s type 15..8 = access
/// - p d/b l avl seg. limit 23..16 = flags_limit
/// - base 31..24 = base_high
#[derive(Copy, Clone)]
#[repr(C, align(8))]
pub struct GdtEntry {
    limit_low: u16,
    base_low: u16,
    base_middle: u8,
    access: u8,
    flags_limit: u8,
    base_high: u8,
}

impl GdtEntry {
    /// Creates a new GDT entry.
    pub const fn new(base: u32, limit: u32, access: u8, flags: u8) -> Self {
        Self {
            base_low: (base & 0xffff) as u16,
            base_middle: ((base >> 16) & 0xff) as u8,
            base_high: ((base >> 24) & 0xff) as u8,
            limit_low: (limit & 0xffff) as u16,
            flags_limit: (((limit >> 16) & 0x0f) as u8) | ((flags & 0x0f) << 4),
            access,
        }
    }
    pub const fn tss(base: u64, limit: u32) -> [Self; 2] {
        [Self {
            limit_low: (limit & 0xffff) as u16,
            base_low: (base & 0xffff) as u16,
            base_middle: ((base >> 16) & 0xff) as u8,
            access: 0x89,
            flags_limit: ((limit >> 16) & 0x0f) as u8,
            base_high: ((base >> 24) & 0xff) as u8,
        }, Self {
            limit_low: ((base >> 32) & 0xffff) as u16,
            base_low: ((base >> 48) & 0xffff) as u16,
            base_middle: 0,
            access: 0,
            flags_limit: 0,
            base_high: 0
        }]
    }
}

// Global Descriptor Table (GDT)
// For reference, see page 2-3 Vol. 3A of Intel 64 and IA-32
// Architectures Software Developer's Manual.
static mut GDT: [GdtEntry; 5] = [
    // Null descriptor
    GdtEntry::new(0, 0, 0, 0),
    // Kernel Code Segment (0x08)
    GdtEntry::new(0, 0, 0x9A, 0xA),
    // Kernel Data Segment (0x10)
    GdtEntry::new(0, 0, 0x92, 0xC),
    // Placeholder for Task State Segment (0x18)
    GdtEntry::new(0, 0, 0, 0),
    // Placeholder for Task State Segment upper half
    GdtEntry::new(0, 0, 0, 0),
];

/// GDTR (GDT pointer)
#[repr(C, packed)]
struct GdtPointer {
    size: u16,
    base: u64,
}

#[repr(C, packed)]
struct TSS {
    _rsvd0: [u8; 4],
    _rsp0: u64,
    _rsp1: u64,
    _rsp2: u64,
    _rsvd1: [u8; 8],
    ist1: u64,
    _ist2: u64,
    _ist3: u64,
    _ist4: u64,
    _ist5: u64,
    _ist6: u64,
    _ist7: u64,
    _rsvd2: [u8; 8],
}
const _: () = assert!(core::mem::offset_of!(TSS, ist1) == 0x24);

/// Load the GDT
#[hyperlight_guest_tracing::trace_function]
pub unsafe fn load_gdt() {

    unsafe {
        let tss_page = hyperlight_guest::prim_alloc::alloc_phys_pages(1);
        let tss_ptr = crate::paging::ptov(tss_page).unwrap();
        tss_ptr.write_bytes(0u8, core::mem::size_of::<TSS>());
        let tss_ptr = tss_ptr as *mut TSS;
        // copy byte by byte to avoid alignment issues
        let ist1_ptr = &raw mut (*tss_ptr).ist1 as *mut [u8; 8];
        let exn_stack = hyperlight_common::layout::MAX_GVA as u64
            - hyperlight_common::layout::SCRATCH_TOP_EXN_STACK_OFFSET + 1;
        ist1_ptr.write_volatile(exn_stack.to_ne_bytes());
        GDT[3..5].copy_from_slice(&GdtEntry::tss(tss_ptr as u64, core::mem::size_of::<TSS>() as u32));

        let gdt_ptr = GdtPointer {
            size: (core::mem::size_of::<[GdtEntry; 5]>() - 1) as u16,
            base: addr_of!(GDT) as *const _ as u64,
        };

        asm!(
        "lgdt [{0}]",
        "mov ax, 0x10",        // Load data segment registers
        "mov ds, ax",
        "mov es, ax",
        "mov fs, ax",
        "mov gs, ax",
        "mov ss, ax",
        "mov ax, 0x18",
        "ltr ax",
        "push 0x08",            // Push CS (kernel code segment)
        "lea rax, [2f + rip]",  // Load the next instruction's address
        "push rax",             // Push address onto stack
        "retfq",                // Far return to update CS
        "2:",                   // Label for continued execution
        in(reg) &gdt_ptr,
        options(nostack, preserves_flags)
        );
    }
}
