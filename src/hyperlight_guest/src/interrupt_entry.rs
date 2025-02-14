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
// https://github.com/nanvix/nanvix/blob/dev/src/kernel/src/hal/arch/x86/hooks.S

use core::arch::global_asm;

use crate::interrupt_handlers::hl_exception_handler;

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
}

// Defines `context_save` and `context_restore`
macro_rules! context_save {
    () => {
        concat!(
            // Save general-purpose registers
            "    push rax\n",
            "    push rbx\n",
            "    push rcx\n",
            "    push rdx\n",
            "    push rsi\n",
            "    push rdi\n",
            "    push rbp\n",
            "    push r8\n",
            "    push r9\n",
            "    push r10\n",
            "    push r11\n",
            "    push r12\n",
            "    push r13\n",
            "    push r14\n",
            "    push r15\n",
            // Save segment registers
            "    mov rax, ds\n",
            "    push rax\n",
            "    mov rax, es\n",
            "    push rax\n",
            "    mov rax, fs\n",
            "    push rax\n",
            "    mov rax, gs\n",
            "    push rax\n",
        )
    };
}

macro_rules! context_restore {
    () => {
        concat!(
            // Restore segment registers
            "    pop rax\n",
            "    mov gs, rax\n",
            "    pop rax\n",
            "    mov fs, rax\n",
            "    pop rax\n",
            "    mov es, rax\n",
            "    pop rax\n",
            "    mov ds, rax\n",
            // Restore general-purpose registers
            "    pop r15\n",
            "    pop r14\n",
            "    pop r13\n",
            "    pop r12\n",
            "    pop r11\n",
            "    pop r10\n",
            "    pop r9\n",
            "    pop r8\n",
            "    pop rbp\n",
            "    pop rdi\n",
            "    pop rsi\n",
            "    pop rdx\n",
            "    pop rcx\n",
            "    pop rbx\n",
            "    pop rax\n",
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
            // In SysV ABI, the first argument is passed in rdi
            // rdi is the stack pointer.
            "    mov rdi, rsp\n",
            "    call {hl_exception_handler}\n",
            context_restore!(),
            "    iretq\n", // iretq is used to return from exception in x86_64
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
            context_save!(),
            // In SysV ABI, the second argument is passed in rsi
            // rsi is the exception number.
            "    mov rsi, ",
            stringify!($num),
            "\n",
            // In SysV ABI, the third argument is passed in rdx
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
            context_save!(),
            // In SysV ABI, the second argument is passed in rsi
            // rsi is the exception number.
            "    mov rsi, ",
            stringify!($num),
            "\n",
            // In SysV ABI, the third argument is passed in rdx
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
            context_save!(),
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

// Output the assembly code
global_asm!(
    generate_exceptions!(),
    hl_exception_handler = sym hl_exception_handler,
);
