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

// Note: this code takes reference from
// https://github.com/nanvix/nanvix/blob/dev/src/kernel/src/hal/arch/x86/hooks.S

use core::arch::{asm, global_asm};

use hyperlight_common::outb::Exception;

use super::super::context;
use super::super::machine::{IDT, IdtEntry, IdtPointer, ProcCtrl};

unsafe extern "C" {
    // Exception handlers
    fn _do_excp0();
    fn _do_excp1();
    fn _do_excp2();
    fn _do_excp3();
    fn _do_excp4();
    fn _do_excp5();
    fn _do_excp6();
    fn _do_excp7();
    fn _do_excp8();
    fn _do_excp9();
    fn _do_excp10();
    fn _do_excp11();
    fn _do_excp12();
    fn _do_excp13();
    fn _do_excp14();
    fn _do_excp15();
    fn _do_excp16();
    fn _do_excp17();
    fn _do_excp18();
    fn _do_excp19();
    fn _do_excp20();
    fn _do_excp30();
}

// Macro to generate exception handlers
// that satisfy the `extern`s at the top of the file.
//
// - Example output from this macro for generate_excp!(0) call:
// ```assembly
// .global _do_excp0
// _do_excp0:
//     context_save!()
//     mov rsi, 0
//     mov rdx, 0
//     jmp _do_excp_common
// ```
macro_rules! generate_excp {
    ($num:expr) => {
        concat!(
            ".global _do_excp",
            stringify!($num),
            "\n",
            "_do_excp",
            stringify!($num),
            ":\n",
            context::save!(),
            // rsi is the exception number.
            "    mov rsi, ",
            stringify!($num),
            "\n",
            // rdx is only used for pagefault exception and
            // contains the address that caused the pagefault.
            "    mov rdx, 0\n",
            "    jmp _do_excp_common\n"
        )
    };
    ($num:expr, pusherrcode) => {
        concat!(
            ".global _do_excp",
            stringify!($num),
            "\n",
            "_do_excp",
            stringify!($num),
            ":\n",
            // Some exceptions push an error code onto the stack.
            // For the ones that don't, we push a 0 to keep the
            // stack aligned.
            "   push 0\n",
            context::save!(),
            // rsi is the exception number.
            "    mov rsi, ",
            stringify!($num),
            "\n",
            // rdx is only used for pagefault exception and
            // contains the address that caused the pagefault.
            "    mov rdx, 0\n",
            "    jmp _do_excp_common\n"
        )
    };
    ($num:expr, pagefault) => {
        concat!(
            ".global _do_excp",
            stringify!($num),
            "\n",
            "_do_excp",
            stringify!($num),
            ":\n",
            context::save!(),
            "    mov rsi, ",
            stringify!($num),
            "\n",
            // In a page fault exception, the cr2 register
            // contains the address that caused the page fault.
            "    mov rdx, cr2\n",
            "    jmp _do_excp_common\n"
        )
    };
}

// Generates exception handlers
macro_rules! generate_exceptions {
    () => {
        concat!(
            // Common exception handler
            ".global _do_excp_common\n",
            "_do_excp_common:\n",
            // the first argument to the Rust handler points to the
            // bottom of the context struct, which happens to be the
            // stack pointer just before it was called.
            "    mov rdi, rsp\n",
            "    call {hl_exception_handler}\n",
            context::restore!(),
            "    add rsp, 8\n", // error code
            "    iretq\n",      // iretq is used to return from exception in x86_64
            generate_excp!(0, pusherrcode),
            generate_excp!(1, pusherrcode),
            generate_excp!(2, pusherrcode),
            generate_excp!(3, pusherrcode),
            generate_excp!(4, pusherrcode),
            generate_excp!(5, pusherrcode),
            generate_excp!(6, pusherrcode),
            generate_excp!(7, pusherrcode),
            generate_excp!(8),
            generate_excp!(9, pusherrcode),
            generate_excp!(10),
            generate_excp!(11),
            generate_excp!(12),
            generate_excp!(13),
            generate_excp!(14, pagefault),
            generate_excp!(15, pusherrcode),
            generate_excp!(16, pusherrcode),
            generate_excp!(17),
            generate_excp!(18, pusherrcode),
            generate_excp!(19, pusherrcode),
            generate_excp!(20, pusherrcode),
            generate_excp!(30),
        )
    };
}

// Output the assembly code
global_asm!(
    generate_exceptions!(),
    hl_exception_handler = sym super::handle::hl_exception_handler,
);

pub(in super::super) fn init_idt(pc: *mut ProcCtrl) {
    let idt = unsafe { &raw mut (*pc).idt };
    let set_idt_entry = |idx, handler: unsafe extern "C" fn()| {
        let handler_addr = handler as *const () as u64;
        unsafe {
            (&raw mut (*idt).entries[idx as usize]).write_volatile(IdtEntry::new(handler_addr));
        }
    };
    set_idt_entry(Exception::DivideByZero, _do_excp0); // Divide by zero
    set_idt_entry(Exception::Debug, _do_excp1); // Debug
    set_idt_entry(Exception::NonMaskableInterrupt, _do_excp2); // Non-maskable interrupt
    set_idt_entry(Exception::Breakpoint, _do_excp3); // Breakpoint
    set_idt_entry(Exception::Overflow, _do_excp4); // Overflow
    set_idt_entry(Exception::BoundRangeExceeded, _do_excp5); // Bound Range Exceeded
    set_idt_entry(Exception::InvalidOpcode, _do_excp6); // Invalid Opcode
    set_idt_entry(Exception::DeviceNotAvailable, _do_excp7); // Device Not Available
    set_idt_entry(Exception::DoubleFault, _do_excp8); // Double Fault
    set_idt_entry(Exception::CoprocessorSegmentOverrun, _do_excp9); // Coprocessor Segment Overrun
    set_idt_entry(Exception::InvalidTSS, _do_excp10); // Invalid TSS
    set_idt_entry(Exception::SegmentNotPresent, _do_excp11); // Segment Not Present
    set_idt_entry(Exception::StackSegmentFault, _do_excp12); // Stack-Segment Fault
    set_idt_entry(Exception::GeneralProtectionFault, _do_excp13); // General Protection Fault
    set_idt_entry(Exception::PageFault, _do_excp14); // Page Fault
    set_idt_entry(Exception::Reserved, _do_excp15); // Reserved
    set_idt_entry(Exception::X87FloatingPointException, _do_excp16); // x87 Floating-Point Exception
    set_idt_entry(Exception::AlignmentCheck, _do_excp17); // Alignment Check
    set_idt_entry(Exception::MachineCheck, _do_excp18); // Machine Check
    set_idt_entry(Exception::SIMDFloatingPointException, _do_excp19); // SIMD Floating-Point Exception
    set_idt_entry(Exception::VirtualizationException, _do_excp20); // Virtualization Exception
    set_idt_entry(Exception::SecurityException, _do_excp30); // Security Exception

    let idtr = IdtPointer {
        limit: (core::mem::size_of::<IDT>() - 1) as u16,
        base: idt as u64,
    };
    unsafe {
        asm!(
            "lidt [{}]",
            in(reg) &idtr,
            options(readonly, nostack, preserves_flags)
        );
    }
}
