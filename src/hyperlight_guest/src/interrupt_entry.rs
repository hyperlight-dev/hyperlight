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

// Note: this code takes reference from
// https://github.com/nanvix/nanvix/tree/dev/src/kernel/src/hal/arch/x86

use core::arch::global_asm;
use crate::interrupt_handlers::{hl_interrupt_handler, hl_exception_handler};

extern "sysv64" {
    // Exception handlers
    pub(crate) fn _do_excp0();
    pub(crate) fn _do_excp1();
    pub(crate) fn _do_excp2();
    pub(crate) fn _do_excp3();
    pub(crate) fn _do_excp4();
    pub(crate) fn _do_excp5();
    pub(crate) fn _do_excp6();
    pub(crate) fn _do_excp7();
    pub(crate) fn _do_excp8();
    pub(crate) fn _do_excp9();
    pub(crate) fn _do_excp10();
    pub(crate) fn _do_excp11();
    pub(crate) fn _do_excp12();
    pub(crate) fn _do_excp13();
    pub(crate) fn _do_excp14();
    pub(crate) fn _do_excp15();
    pub(crate) fn _do_excp16();
    pub(crate) fn _do_excp17();
    pub(crate) fn _do_excp18();
    pub(crate) fn _do_excp19();
    pub(crate) fn _do_excp20();
    pub(crate) fn _do_excp30();

    // Hardware interrupt handlers
    fn _do_hwint0();
    fn _do_hwint1();
    fn _do_hwint2();
    fn _do_hwint3();
    fn _do_hwint4();
    fn _do_hwint5();
    fn _do_hwint6();
    fn _do_hwint7();
    fn _do_hwint8();
    fn _do_hwint9();
    fn _do_hwint10();
    fn _do_hwint11();
    fn _do_hwint12();
    fn _do_hwint13();
    fn _do_hwint14();
    fn _do_hwint15();
}

// Defines `context_save` and `context_restore`
macro_rules! generate_context_saving {
    () => {
        concat!(
            ".global context_save\n",
            ".global context_restore\n",

            "context_save:\n",
            "    push rax\n",
            "    push rbx\n",
            "    push rcx\n",
            "    push rdx\n",
            "    push rsi\n",
            "    push rdi\n",
            "    push r8\n",
            "    push r9\n",
            "    push r10\n",
            "    push r11\n",
            "    push r12\n",
            "    push r13\n",
            "    push r14\n",
            "    push r15\n",
            "    push rbp\n",
            "    mov rdi, rsp\n",
            "    ret\n",

            "context_restore:\n",
            "    pop rbp\n",
            "    pop r15\n",
            "    pop r14\n",
            "    pop r13\n",
            "    pop r12\n",
            "    pop r11\n",
            "    pop r10\n",
            "    pop r9\n",
            "    pop r8\n",
            "    pop rdi\n",
            "    pop rsi\n",
            "    pop rdx\n",
            "    pop rcx\n",
            "    pop rbx\n",
            "    pop rax\n",
            "    ret\n"
        )
    };
}

// Generates exception handlers
macro_rules! generate_exceptions {
    () => {
        concat!(
            ".global _do_excp_common\n",
            "_do_excp_common:\n",
            "    call context_save\n",
            "    call {hl_exception_handler}\n",
            "    call context_restore\n",
            "    add rsp, 8\n",
            "    iretq\n",
            generate_excp!(0, noerr),
            generate_excp!(1, noerr),
            generate_excp!(2, noerr),
            generate_excp!(3, noerr),
            generate_excp!(4, noerr),
            generate_excp!(5, noerr),
            generate_excp!(6, noerr),
            generate_excp!(7, noerr),
            generate_excp!(8, err),
            generate_excp!(9, noerr),
            generate_excp!(10, err),
            generate_excp!(11, err),
            generate_excp!(12, err),
            generate_excp!(13, err),
            generate_excp!(14, err2),
            generate_excp!(15, noerr),
            generate_excp!(16, noerr),
            generate_excp!(17, err),
            generate_excp!(18, noerr),
            generate_excp!(19, noerr),
            generate_excp!(20, noerr),
            generate_excp!(30, err),
        )
    };
}

// Defines an exception handler macro
macro_rules! generate_excp {
    ($num:expr, noerr) => {
        concat!(
            ".global _do_excp", stringify!($num), "\n",
            "_do_excp", stringify!($num), ":\n",
            "    push 0\n",
            "    mov rsi, ", stringify!($num), "\n",
            "    jmp _do_excp_common\n"
        )
    };
    ($num:expr, err) => {
        concat!(
            ".global _do_excp", stringify!($num), "\n",
            "_do_excp", stringify!($num), ":\n",
            "    mov rsi, ", stringify!($num), "\n",
            "    jmp _do_excp_common\n"
        )
    };
    ($num:expr, err2) => {
        concat!(
            ".global _do_excp", stringify!($num), "\n",
            "_do_excp", stringify!($num), ":\n",
            "    mov rsi, ", stringify!($num), "\n",
            "    mov rdx, cr2\n",
            "    jmp _do_excp_common\n"
        )
    };
}

// Defines a hardware interrupt handler macro
macro_rules! generate_hwint {
    ($num:expr) => {
        concat!(
            ".global _do_hwint", stringify!($num), "\n",
            "_do_hwint", stringify!($num), ":\n",
            "    call context_save\n",
            "    mov rsi, ", stringify!($num), "\n",
            "    call {hl_interrupt_handler}\n",
            "    call context_restore\n",
            "    iretq\n"
        )
    };
}

// Generates hardware interrupt handlers
macro_rules! generate_interrupts {
    () => {
        concat!(
            generate_hwint!(0),
            generate_hwint!(1),
            generate_hwint!(2),
            generate_hwint!(3),
            generate_hwint!(4),
            generate_hwint!(5),
            generate_hwint!(6),
            generate_hwint!(7),
            generate_hwint!(8),
            generate_hwint!(9),
            generate_hwint!(10),
            generate_hwint!(11),
            generate_hwint!(12),
            generate_hwint!(13),
            generate_hwint!(14),
            generate_hwint!(15),
        )
    };
}

// Compiles final inline assembly
global_asm!(
    concat!(
        generate_context_saving!(),
        generate_exceptions!(),
        generate_interrupts!()
    ),
    hl_exception_handler = sym hl_exception_handler,
    hl_interrupt_handler = sym hl_interrupt_handler
);
