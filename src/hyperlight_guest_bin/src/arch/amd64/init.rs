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

use hyperlight_guest::layout::MAIN_STACK_TOP_GVA;

use crate::paging;

use super::machine::{ProcCtrl, GdtEntry, GDT, GdtPointer, TSS};
use super::exn::entry::init_idt;

#[repr(C)]
struct HyperlightGDT {
    null: GdtEntry,
    kernel_code: GdtEntry,
    kernel_data: GdtEntry,
    tss: [GdtEntry; 2]
}
const _: () = assert!(mem::size_of::<HyperlightGDT>() == mem::size_of::<GDT>());
const _: () = assert!(mem::offset_of!(HyperlightGDT, null) == 0x00);
const _: () = assert!(mem::offset_of!(HyperlightGDT, kernel_code) == 0x08);
const _: () = assert!(mem::offset_of!(HyperlightGDT, kernel_data) == 0x10);
const _: () = assert!(mem::offset_of!(HyperlightGDT, tss) == 0x18);

unsafe fn init_gdt(pc: *mut ProcCtrl) {
    unsafe {
        hyperlight_guest::exit::debug_print("igdt a\n");
        let gdt_ptr = &raw mut (*pc).gdt as *mut HyperlightGDT;
        hyperlight_guest::exit::debug_print("igdt b\n");
        (&raw mut (*gdt_ptr).null)
            .write_volatile(GdtEntry::new(0, 0, 0, 0));
        hyperlight_guest::exit::debug_print("igdt c\n");
        (&raw mut (*gdt_ptr).kernel_code)
            .write_volatile(GdtEntry::new(0, 0, 0x9A, 0xA));
        hyperlight_guest::exit::debug_print("igdt d\n");
        (&raw mut (*gdt_ptr).kernel_data)
            .write_volatile(GdtEntry::new(0, 0, 0x92, 0xC));
        hyperlight_guest::exit::debug_print("igdt e\n");
        (&raw mut (*gdt_ptr).tss)
            .write_volatile(GdtEntry::tss(
                &raw mut (*pc).tss as u64,
                mem::size_of::<TSS>() as u32
            ));
        hyperlight_guest::exit::debug_print("igdt f\n");
        let gdtr = GdtPointer {
            limit: (core::mem::size_of::<[GdtEntry; 5]>() - 1) as u16,
            base: gdt_ptr as u64,
        };
        hyperlight_guest::exit::debug_print("igdt g\n");
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
        hyperlight_guest::exit::debug_print("igdt h\n");
    }
    hyperlight_guest::exit::debug_print("igdt i\n");
}

unsafe fn init_tss(pc: *mut ProcCtrl) {
    unsafe {
        let tss_ptr = &raw mut (*pc).tss;
        // copy byte by byte to avoid alignment issues
        let ist1_ptr = &raw mut (*tss_ptr).ist1 as *mut [u8; 8];
        let exn_stack = hyperlight_common::layout::MAX_GVA as u64
            - hyperlight_common::layout::SCRATCH_TOP_EXN_STACK_OFFSET + 1;
        ist1_ptr.write_volatile(exn_stack.to_ne_bytes());
        // see init_gdt: 0x18 points to the tss set up above
        asm!(
            "ltr ax",
            in("ax") core::mem::offset_of!(HyperlightGDT, tss),
            options(nostack, preserves_flags)
        );
    }
}

unsafe fn init_stack() -> u64 {
    let stack_top_page_base = (MAIN_STACK_TOP_GVA - 1) & !0xfff;
    unsafe {
        paging::map_region(
            hyperlight_guest::prim_alloc::alloc_phys_pages(1),
            stack_top_page_base as *mut u8,
            hyperlight_common::vm::PAGE_SIZE as u64,
        );
    }
    MAIN_STACK_TOP_GVA
}

unsafe extern "C" {
    fn entrypoint2(peb_address: u64, seed: u64, ops: u64, max_log_level: u64);
}

/// Machine-specific initialisation; calls [`crate::generic_init`]
/// once stack, CoW, etc have been set up.
#[unsafe(no_mangle)]
pub extern "C" fn entrypoint(peb_address: u64, seed: u64, ops: u64, max_log_level: u64) {
    unsafe {
        let pc = ProcCtrl::init();
        init_gdt(pc);
        init_tss(pc);
        init_idt(pc);
        let stack_top = init_stack();
        pivot_stack(peb_address, seed, ops, max_log_level, stack_top);
    }
}

unsafe extern "C" {
    unsafe fn pivot_stack(
        peb_address: u64,
        seed: u64,
        ops: u64,
        max_log_level: u64,
        stack_ptr: u64,
    ) -> !;
}

core::arch::global_asm!("
    .global pivot_stack\n
    pivot_stack:\n
    mov rsp, r8\n
    call {generic_init}\n
    hlt\n
", generic_init = sym crate::generic_init);
