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
use super::machine::{GDT, GdtEntry, GdtPointer, ProcCtrl, TSS};

/// See AMD64 Architecture Programmer's Manual, Volume 2: System Programming
///     Section 4: Segmented Virtual Memory
///         §4.6: Descriptor Tables
/// for the functions of the GDT.
///
/// Hyperlight's GDT consists of:
/// - A null first entry, which is architecturally required
/// - A single code segment descriptor, used for all code accesses
/// - A single data segment descriptor, used for all data accesses
/// - A TSS System descriptor that outlines the location of the TSS
///   (see [`init_tss`], below)
#[repr(C)]
struct HyperlightGDT {
    null: GdtEntry,
    kernel_code: GdtEntry,
    kernel_data: GdtEntry,
    tss: [GdtEntry; 2],
}
const _: () = assert!(mem::size_of::<HyperlightGDT>() == mem::size_of::<GDT>());
const _: () = assert!(mem::offset_of!(HyperlightGDT, null) == 0x00);
const _: () = assert!(mem::offset_of!(HyperlightGDT, kernel_code) == 0x08);
const _: () = assert!(mem::offset_of!(HyperlightGDT, kernel_data) == 0x10);
const _: () = assert!(mem::offset_of!(HyperlightGDT, tss) == 0x18);

unsafe fn init_gdt(pc: *mut ProcCtrl) {
    unsafe {
        let gdt_ptr = &raw mut (*pc).gdt as *mut HyperlightGDT;
        (&raw mut (*gdt_ptr).null).write_volatile(GdtEntry::new(0, 0, 0, 0));
        (&raw mut (*gdt_ptr).kernel_code).write_volatile(GdtEntry::new(0, 0, 0x9A, 0xA));
        (&raw mut (*gdt_ptr).kernel_data).write_volatile(GdtEntry::new(0, 0, 0x92, 0xC));
        (&raw mut (*gdt_ptr).tss).write_volatile(GdtEntry::tss(
            &raw mut (*pc).tss as u64,
            mem::size_of::<TSS>() as u32,
        ));
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

/// Hyperlight's TSS contains only a single IST entry, which is used
/// to set up the stack switch to the exception stack whenever we take
/// an exception (including page faults, which are important, since
/// the fault might be due to needing to grow the stack!)
///
/// This function sets up the TSS and then points the processor at the
/// system segment descriptor, initialized in [`init_gdt`] above,
/// which describes the location of the TSS.
unsafe fn init_tss(pc: *mut ProcCtrl) {
    unsafe {
        let tss_ptr = &raw mut (*pc).tss;
        // copy byte by byte to avoid alignment issues
        let ist1_ptr = &raw mut (*tss_ptr).ist1 as *mut [u8; 8];
        let exn_stack = hyperlight_common::layout::MAX_GVA as u64
            - hyperlight_common::layout::SCRATCH_TOP_EXN_STACK_OFFSET
            + 1;
        ist1_ptr.write_volatile(exn_stack.to_ne_bytes());
        asm!(
            "ltr ax",
            in("ax") core::mem::offset_of!(HyperlightGDT, tss),
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
        init_tss(pc);
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
