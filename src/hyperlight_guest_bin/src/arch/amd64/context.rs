// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use core::arch::global_asm;
use super::machine::ExceptionInfo;

#[repr(C)]
/// Saved context, pushed onto the stack by exception entry code
pub struct Context {
    /// in order: ds, gs, fs, es
    pub segments: [u64; 4],

    /// Extended CPU state (xsave or fxsave area)
    /// Size varies by CPU:
    ///   512  bytes — fxsave (no AVX)
    ///   576  bytes — xsave  (AVX)
    ///   2688 bytes — xsave  (AVX-512)
    /// Always allocated at maximum to keep struct layout fixed.
    pub extended_state: [u8; 2688],

    /// Actual bytes written by xsave/fxsave — set by save_context
    pub extended_size: u64,

    /// no `rsp`, since the processor saved it
    /// `rax` is at the top, `r15` the bottom
    pub gprs: [u64; 15],

    _padding: [u64; 2],
}

const _: () = assert!(size_of::<Context>() == 32 + 2688 + 8 + 120 + 16);

// The combination of ExceptionInfo and Context must be 16-byte aligned
// before calling hl_exception_handler as per x86-64 System V ABI.
const _: () = assert!(
    (size_of::<Context>() + size_of::<ExceptionInfo>()).is_multiple_of(16)
);

global_asm!(
    ".global save_context",
    "save_context:",
    "    sub rsp, 8",
    "    push rax",
    "    push rbx",
    "    push rcx",
    "    push rdx",
    "    push rsi",
    "    push rdi",
    "    push rbp",
    "    push r8",
    "    push r9",
    "    push r10",
    "    push r11",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",

    // CPUID — get xsave area size
    "    mov eax, 0xD",
    "    xor ecx, ecx",
    "    cpuid",
    // ebx = required xsave size
    "    sub rsp, rbx",
    "    and rsp, -64",
    "    push rbx",       // save size for restore

    // check AVX support
    "    mov eax, 1",
    "    cpuid",
    "    bt ecx, 28",
    "    jnc use_fxsave",

    "use_xsave:",
    "    mov eax, 0x7",
    "    xor edx, edx",
    "    xsave [rsp]",
    "    jmp save_done",

    "use_fxsave:",
    "    fxsave [rsp]",

    "save_done:",
    "    mov rax, es",
    "    push rax",
    "    mov rax, fs",
    "    push rax",
    "    mov rax, gs",
    "    push rax",
    "    mov rax, ds",
    "    push rax",
    "    ret",

    ".global restore_context",
    "restore_context:",
    "    pop rax",
    "    mov ds, rax",
    "    pop rax",
    "    mov gs, rax",
    "    pop rax",
    "    mov fs, rax",
    "    pop rax",
    "    mov es, rax",

    "    pop rbx",        // restore saved size
    "    mov eax, 1",
    "    cpuid",
    "    bt ecx, 28",
    "    jnc use_fxrstor",

    "use_xrstor:",
    "    mov eax, 0x7",
    "    xor edx, edx",
    "    xrstor [rsp]",
    "    jmp restore_done",

    "use_fxrstor:",
    "    fxrstor [rsp]",

    "restore_done:",
    "    add rsp, rbx",
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop r11",
    "    pop r10",
    "    pop r9",
    "    pop r8",
    "    pop rbp",
    "    pop rdi",
    "    pop rsi",
    "    pop rdx",
    "    pop rcx",
    "    pop rbx",
    "    pop rax",
    "    add rsp, 8",
    "    ret",
);
