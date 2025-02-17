/*
Copyright 2024 The Hyperlight Authors.

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
/// For reference, see: https://wiki.osdev.org/Global_Descriptor_Table
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
}

// Global Descriptor Table (GDT)
// For reference, see: https://wiki.osdev.org/GDT_Tutorial#What_to_Put_In_a_GDT
static mut GDT: [GdtEntry; 3] = [
    // Null descriptor
    GdtEntry::new(0, 0, 0, 0),

    // Kernel Code Segment (0x08)
    GdtEntry::new(0, 0, 0x9A, 0xA),

    // Kernel Data Segment (0x10)
    GdtEntry::new(0, 0, 0x92, 0xC),
];

/// GDTR (GDT pointer)
#[repr(C, packed)]
struct GdtPointer {
    size: u16,
    base: u64,
}

/// Load the GDT
pub unsafe fn load_gdt() {
    let gdt_ptr = GdtPointer {
        size: (core::mem::size_of::<[GdtEntry; 3]>() - 1) as u16,
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
    "push 0x08",            // Push CS (kernel code segment)
    "lea rax, [2f + rip]",  // Load the next instruction's address
    "push rax",             // Push address onto stack
    "retfq",                // Far return to update CS
    "2:",                   // Label for continued execution
    in(reg) &gdt_ptr,
    options(nostack, preserves_flags)
    );
}

