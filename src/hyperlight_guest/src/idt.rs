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

use crate::interrupt_entry::{
    _do_excp0, _do_excp1, _do_excp10, _do_excp11, _do_excp12, _do_excp13, _do_excp14, _do_excp15,
    _do_excp16, _do_excp17, _do_excp18, _do_excp19, _do_excp2, _do_excp20, _do_excp3, _do_excp30,
    _do_excp4, _do_excp5, _do_excp6, _do_excp7, _do_excp8, _do_excp9,
};

// An entry in the Interrupt Descriptor Table (IDT)
// For reference, see page 7-20 Vol. 3A of Intel 64 and IA-32
// Architectures Software Developer's Manual, figure 7-8
// (i.e., https://i.imgur.com/N4rEjHj.png).
// From the bottom, we have:
// - offset 15..0 = offset_low
// - segment selector 31..16 = selector
// - 000 0 0 Interrupt Stack Table 7..0 = interrupt_stack_table_offset
// - p dpl 0 type 15..8 = type_attr
// - offset 31..16 = offset_mid
// - offset 63..32 = offset_high
// - reserved 31..0 = zero
#[repr(C, align(16))]
pub(crate) struct IdtEntry {
    offset_low: u16,                  // Lower 16 bits of handler address
    selector: u16,                    // code segment selector in GDT
    interrupt_stack_table_offset: u8, // Interrupt Stack Table offset
    type_attr: u8,                    // Gate type and flags
    offset_mid: u16,                  // Middle 16 bits of handler address
    offset_high: u32,                 // High 32 bits of handler address
    zero: u32,                        // Reserved (always 0)
}

impl IdtEntry {
    fn new(handler: u64) -> Self {
        Self {
            offset_low: (handler & 0xFFFF) as u16,
            selector: 0x08,                  // Kernel Code Segment
            interrupt_stack_table_offset: 0, // No interrupt stack table used
            type_attr: 0x8E,
            // 0x8E = 10001110b
            // 1 00 0 1110
            // 1 = Present
            // 00 = Descriptor Privilege Level (0)
            // 0 = Storage Segment (0)
            // 1110 = Gate Type (0b1110 = 14 = 0xE)
            // 0xE means it's an interrupt gate
            offset_mid: ((handler >> 16) & 0xFFFF) as u16,
            offset_high: ((handler >> 32) & 0xFFFFFFFF) as u32,
            zero: 0,
        }
    }
}

// The IDT is an array of 256 IDT entries
// (for reference, see page 7-9 Vol. 3A of Intel 64 and IA-32
// Architectures Software Developer's Manual).
pub(crate) static mut IDT: [IdtEntry; 256] = unsafe { core::mem::zeroed() };

pub(crate) fn init_idt() {
    set_idt_entry(0, _do_excp0); // Divide by zero
    set_idt_entry(1, _do_excp1); // Debug
    set_idt_entry(2, _do_excp2); // Non-maskable interrupt
    set_idt_entry(3, _do_excp3); // Breakpoint
    set_idt_entry(4, _do_excp4); // Overflow
    set_idt_entry(5, _do_excp5); // Bound Range Exceeded
    set_idt_entry(6, _do_excp6); // Invalid Opcode
    set_idt_entry(7, _do_excp7); // Device Not Available
    set_idt_entry(8, _do_excp8); // Double Fault
    set_idt_entry(9, _do_excp9); // Coprocessor Segment Overrun
    set_idt_entry(10, _do_excp10); // Invalid TSS
    set_idt_entry(11, _do_excp11); // Segment Not Present
    set_idt_entry(12, _do_excp12); // Stack-Segment Fault
    set_idt_entry(13, _do_excp13); // General Protection Fault
    set_idt_entry(14, _do_excp14); // Page Fault
    set_idt_entry(15, _do_excp15); // Reserved
    set_idt_entry(16, _do_excp16); // x87 Floating-Point Exception
    set_idt_entry(17, _do_excp17); // Alignment Check
    set_idt_entry(18, _do_excp18); // Machine Check
    set_idt_entry(19, _do_excp19); // SIMD Floating-Point Exception
    set_idt_entry(20, _do_excp20); // Virtualization Exception
    set_idt_entry(30, _do_excp30); // Security Exception
}

fn set_idt_entry(index: usize, handler: unsafe extern "sysv64" fn()) {
    let handler_addr = handler as *const () as u64;
    unsafe {
        IDT[index] = IdtEntry::new(handler_addr);
    }
}
