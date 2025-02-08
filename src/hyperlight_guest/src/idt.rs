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
    _do_excp0, _do_excp1, _do_excp2, _do_excp3, _do_excp4, _do_excp5, _do_excp6, _do_excp7,
    _do_excp8, _do_excp9, _do_excp10, _do_excp11, _do_excp12, _do_excp13, _do_excp14, _do_excp15,
    _do_excp16, _do_excp17, _do_excp18, _do_excp19, _do_excp20, _do_excp30,
};

// For reference, see: https://wiki.osdev.org/Interrupt_Descriptor_Table#Structure_on_x86-64
#[repr(C)]
pub(crate) struct IdtEntry {
    offset_low: u16,  // Lower 16 bits of handler address
    selector: u16,    // code segment selector in GDT
    ist: u8,          // Interrupt Stack Table offset
    type_attr: u8,    // Gate type and flags (0x8E)
    offset_mid: u16,  // Middle 16 bits of handler address
    offset_high: u32, // High 32 bits of handler address
    zero: u32,        // Reserved (always 0)
}

impl IdtEntry {
    fn new(handler: u64) -> Self {
        Self {
            offset_low: handler as u16,
            selector: 0x08,
            // ^ this selector equates to the GDT's kernel code segment,
            // we set this manually because, currently, Hyperlight
            // guests only run in kernel mode.
            ist: 0,
            // ^ for now, we don't use the IST feature.
            // This means that the interrupt handler will use the
            // stack that was in use when the interrupt was triggered.
            // For some exceptions (like double faults), this can be
            // a problem, but we'll address that later.
            // TODO: set up IST for exceptions that need it
            type_attr: 0x8E,
            // ^ 0x8E is the type_attr for an interrupt gate
            offset_mid: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            zero: 0,
        }
    }
}

// The IDT is an array of 256 IDT entries
// (as per https://wiki.osdev.org/Interrupt_Descriptor_Table#Structure_on_x86-64)
pub(crate) static mut IDT: [IdtEntry; 256] = unsafe { core::mem::zeroed() };

pub(crate) fn init_idt() {
    set_idt_entry(0, _do_excp0);
    set_idt_entry(1, _do_excp1);
    set_idt_entry(2, _do_excp2);
    set_idt_entry(3, _do_excp3);
    set_idt_entry(4, _do_excp4);
    set_idt_entry(5, _do_excp5);
    set_idt_entry(6, _do_excp6);
    set_idt_entry(7, _do_excp7);
    set_idt_entry(8, _do_excp8);
    set_idt_entry(9, _do_excp9);
    set_idt_entry(10, _do_excp10);
    set_idt_entry(11, _do_excp11);
    set_idt_entry(12, _do_excp12);
    set_idt_entry(13, _do_excp13);
    set_idt_entry(14, _do_excp14);
    set_idt_entry(15, _do_excp15);
    set_idt_entry(16, _do_excp16);
    set_idt_entry(17, _do_excp17);
    set_idt_entry(18, _do_excp18);
    set_idt_entry(19, _do_excp19);
    set_idt_entry(20, _do_excp20);
    set_idt_entry(30, _do_excp30);

    // TODO: set hardware interrupt handlers
    // (i.e., after we have the PIC set up)
}

fn set_idt_entry(index: usize, handler: unsafe extern "sysv64" fn()) {
    let handler_addr = handler as u64;
    unsafe { IDT[index] = IdtEntry::new(handler_addr); }
}
