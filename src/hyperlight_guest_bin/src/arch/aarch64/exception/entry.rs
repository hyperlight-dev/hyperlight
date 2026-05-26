/*
Copyright 2026 The Hyperlight Authors.

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

use core::arch::global_asm;
use core::mem::{offset_of, size_of};

use super::types::*;

const _: () = assert!(2 * size_of::<u64>() == 0x10);
const _: () = assert!(2 * size_of::<u128>() == 0x20);

// sp should already have been lowered to make room for the context
// save structure
//
// x30 should have been saved already
global_asm!("
.global context_save\n
context_save:\n
    stp  x0,  x1, [sp, #{x_off}+0x00]\n
    stp  x2,  x3, [sp, #{x_off}+0x10]\n
    stp  x4,  x5, [sp, #{x_off}+0x20]\n
    stp  x6,  x7, [sp, #{x_off}+0x30]\n
    stp  x8,  x9, [sp, #{x_off}+0x40]\n
    stp x10, x11, [sp, #{x_off}+0x50]\n
    stp x12, x13, [sp, #{x_off}+0x60]\n
    stp x14, x15, [sp, #{x_off}+0x70]\n
    stp x16, x17, [sp, #{x_off}+0x80]\n
    stp x18, x19, [sp, #{x_off}+0x90]\n
    stp x20, x21, [sp, #{x_off}+0xa0]\n
    stp x22, x23, [sp, #{x_off}+0xb0]\n
    stp x24, x25, [sp, #{x_off}+0xc0]\n
    stp x26, x27, [sp, #{x_off}+0xd0]\n
    stp x28, x29, [sp, #{x_off}+0xe0]\n
    mrs x0, fpcr\n
    mrs x1, fpsr\n
    stp x0, x1, [sp, #{fpcr_off}]\n
    stp  q0,  q1, [sp, #{q_off}+0x000]\n
    stp  q2,  q3, [sp, #{q_off}+0x020]\n
    stp  q4,  q5, [sp, #{q_off}+0x040]\n
    stp  q6,  q7, [sp, #{q_off}+0x060]\n
    stp  q8,  q9, [sp, #{q_off}+0x080]\n
    stp q10, q11, [sp, #{q_off}+0x0a0]\n
    stp q12, q13, [sp, #{q_off}+0x0c0]\n
    stp q14, q15, [sp, #{q_off}+0x0e0]\n
    stp q16, q17, [sp, #{q_off}+0x100]\n
    stp q18, q19, [sp, #{q_off}+0x120]\n
    stp q20, q21, [sp, #{q_off}+0x140]\n
    stp q22, q23, [sp, #{q_off}+0x160]\n
    stp q24, q25, [sp, #{q_off}+0x180]\n
    stp q26, q27, [sp, #{q_off}+0x1a0]\n
    stp q28, q29, [sp, #{q_off}+0x1c0]\n
    stp q30, q31, [sp, #{q_off}+0x1e0]\n
    ret
",
    x_off = const offset_of!(ExceptionContext, x),
    fpcr_off = const offset_of!(ExceptionContext, fpcr),
    q_off = const offset_of!(ExceptionContext, q),
);

global_asm!("
.global context_restore\n
context_restore:\n
    ldp x0, x1, [sp, #{fpcr_off}]\n
    msr fpcr, x0\n
    msr fpsr, x1\n
    ldp  x0,  x1, [sp, #{x_off}+0x00]\n
    ldp  x2,  x3, [sp, #{x_off}+0x10]\n
    ldp  x4,  x5, [sp, #{x_off}+0x20]\n
    ldp  x6,  x7, [sp, #{x_off}+0x30]\n
    ldp  x8,  x9, [sp, #{x_off}+0x40]\n
    ldp x10, x11, [sp, #{x_off}+0x50]\n
    ldp x12, x13, [sp, #{x_off}+0x60]\n
    ldp x14, x15, [sp, #{x_off}+0x70]\n
    ldp x16, x17, [sp, #{x_off}+0x80]\n
    ldp x18, x19, [sp, #{x_off}+0x90]\n
    ldp x20, x21, [sp, #{x_off}+0xa0]\n
    ldp x22, x23, [sp, #{x_off}+0xb0]\n
    ldp x24, x25, [sp, #{x_off}+0xc0]\n
    ldp x26, x27, [sp, #{x_off}+0xd0]\n
    ldp x28, x29, [sp, #{x_off}+0xe0]\n
    ldr x30,      [sp, #{x_off}+0xf0]\n
    ldp  q0,  q1, [sp, #{q_off}+0x000]\n
    ldp  q2,  q3, [sp, #{q_off}+0x020]\n
    ldp  q4,  q5, [sp, #{q_off}+0x040]\n
    ldp  q6,  q7, [sp, #{q_off}+0x060]\n
    ldp  q8,  q9, [sp, #{q_off}+0x080]\n
    ldp q10, q11, [sp, #{q_off}+0x0a0]\n
    ldp q12, q13, [sp, #{q_off}+0x0c0]\n
    ldp q14, q15, [sp, #{q_off}+0x0e0]\n
    ldp q16, q17, [sp, #{q_off}+0x100]\n
    ldp q18, q19, [sp, #{q_off}+0x120]\n
    ldp q20, q21, [sp, #{q_off}+0x140]\n
    ldp q22, q23, [sp, #{q_off}+0x160]\n
    ldp q24, q25, [sp, #{q_off}+0x180]\n
    ldp q26, q27, [sp, #{q_off}+0x1a0]\n
    ldp q28, q29, [sp, #{q_off}+0x1c0]\n
    ldp q30, q31, [sp, #{q_off}+0x1e0]\n
    add sp, sp, #{ctx_size}\n
    eret\n
",
    ctx_size = const size_of::<ExceptionContext>(),
    x_off = const offset_of!(ExceptionContext, x),
    fpcr_off = const offset_of!(ExceptionContext, fpcr),
    q_off = const offset_of!(ExceptionContext, q),
);

macro_rules! vbar_entry {
    ($et:literal, $ef:literal) => {
        concat!(
            "
            sub sp, sp, #{ctx_size}\n
            str x30, [sp, #{x30_off}]\n
            bl context_save\n
            mov x0, {ExceptionType_",
            $et,
            "}\n
            mov x1, {ExceptionFrom_",
            $ef,
            "}\n
            mov x2, sp\n
            bl {handler}\n
            b context_restore\n
            .balign 0x80\n
        "
        )
    };
}

global_asm!("
.balign 0x800\n
.global vbar\n
vbar:\n",
    vbar_entry!("Synchronous", "CurrentSP0"),
    vbar_entry!("IRQ", "CurrentSP0"),
    vbar_entry!("FIQ", "CurrentSP0"),
    vbar_entry!("SError", "CurrentSP0"),
    vbar_entry!("Synchronous", "CurrentSPx"),
    vbar_entry!("IRQ", "CurrentSPx"),
    vbar_entry!("FIQ", "CurrentSPx"),
    vbar_entry!("SError", "CurrentSPx"),
    vbar_entry!("Synchronous", "LowerAArch64"),
    vbar_entry!("IRQ", "LowerAArch64"),
    vbar_entry!("FIQ", "LowerAArch64"),
    vbar_entry!("SError", "LowerAArch64"),
    vbar_entry!("Synchronous", "LowerAArch32"),
    vbar_entry!("IRQ", "LowerAArch32"),
    vbar_entry!("FIQ", "LowerAArch32"),
    vbar_entry!("SError", "LowerAArch32"),
    ctx_size = const size_of::<ExceptionContext>(),
    x30_off = const offset_of!(ExceptionContext, x) + 15 * 0x010,
    handler = sym super::handle::handle_exception,
    ExceptionType_Synchronous = const ExceptionType::Synchronous as u64,
    ExceptionType_IRQ = const ExceptionType::IRQ as u64,
    ExceptionType_FIQ = const ExceptionType::FIQ as u64,
    ExceptionType_SError = const ExceptionType::SError as u64,
    ExceptionFrom_CurrentSP0 = const ExceptionFrom::CurrentSP0 as u64,
    ExceptionFrom_CurrentSPx = const ExceptionFrom::CurrentSPx as u64,
    ExceptionFrom_LowerAArch64 = const ExceptionFrom::LowerAArch64 as u64,
    ExceptionFrom_LowerAArch32 = const ExceptionFrom::LowerAArch32 as u64,
);
