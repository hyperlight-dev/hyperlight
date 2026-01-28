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
use core::mem;

use super::exception::entry::init_idt;
use super::machine::{GDT, GdtEntry, GdtPointer, ProcCtrl};

#[repr(C)]
struct HyperlightGDT {
    null: GdtEntry,
    kernel_code: GdtEntry,
    kernel_data: GdtEntry,
}
const _: () = assert!(mem::size_of::<HyperlightGDT>() == mem::size_of::<GDT>());
const _: () = assert!(mem::offset_of!(HyperlightGDT, null) == 0x00);
const _: () = assert!(mem::offset_of!(HyperlightGDT, kernel_code) == 0x08);
const _: () = assert!(mem::offset_of!(HyperlightGDT, kernel_data) == 0x10);

unsafe fn init_gdt(pc: *mut ProcCtrl) {
    unsafe {
        let gdt_ptr = &raw mut (*pc).gdt as *mut HyperlightGDT;
        (&raw mut (*gdt_ptr).null).write_volatile(GdtEntry::new(0, 0, 0, 0));
        (&raw mut (*gdt_ptr).kernel_code).write_volatile(GdtEntry::new(0, 0, 0x9A, 0xA));
        (&raw mut (*gdt_ptr).kernel_data).write_volatile(GdtEntry::new(0, 0, 0x92, 0xC));
        let gdtr = GdtPointer {
            limit: (core::mem::size_of::<[GdtEntry; 5]>() - 1) as u16,
            base: gdt_ptr as u64,
        };
        asm!(
            "lgdt [{0}]",
            "mov ds, ax",
            "mov es, ax",
            "mov fs, ax",
            "mov gs, ax",
            "mov ss, ax",
            "push rcx",
            "lea rax, [2f + rip]",
            "push rax",
            "retfq",
            "2:",
            in(reg) &gdtr,
            in("ax") mem::offset_of!(HyperlightGDT, kernel_data),
            in("rcx") mem::offset_of!(HyperlightGDT, kernel_code),
            lateout("rax") _,
            options(nostack, preserves_flags)
        );
    }
}

/// Machine-specific initialisation; calls [`crate::generic_init`]
/// once stack, CoW, etc have been set up.
#[unsafe(no_mangle)]
pub extern "C" fn entrypoint(peb_address: u64, seed: u64, ops: u64, max_log_level: u64) {
    unsafe {
        let pc = ProcCtrl::init();
        init_gdt(pc);
        init_idt(pc);
        call_generic_init(peb_address, seed, ops, max_log_level);
    }
}

unsafe extern "C" {
    unsafe fn call_generic_init(peb_address: u64, seed: u64, ops: u64, max_log_level: u64) -> !;
}

core::arch::global_asm!("
    .global call_generic_init\n
    call_generic_init:\n
    sub rsp, 0x8\n
    call {generic_init}\n
    hlt\n
", generic_init = sym crate::generic_init);
