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

use super::machine::ExceptionInfo;

#[repr(C)]
/// Saved context, pushed onto the stack by exception entry code
pub struct Context {
    /// in order: ds, gs, fs, es
    pub segments: [u64; 4],
    pub fxsave: [u8; 512],
    /// no `rsp`, since the processor saved it
    /// `rax` is at the top, `r15` the bottom
    pub gprs: [u64; 15],
    _padding: u64,
}
const _: () = assert!(size_of::<Context>() == 32 + 512 + 120 + 8);
// The combination of the ExceptionInfo (pushed by the CPU) and the
// register Context that we save to the stack must be 16byte aligned
// before calling the hl_exception_handler as specified in the x86-64
// ELF System V psABI specification, Section 3.2.2:
//
// https://gitlab.com/x86-psABIs/x86-64-ABI/-/jobs/artifacts/master/raw/x86-64-ABI/abi.pdf?job=build
const _: () = assert!((size_of::<Context>() + size_of::<ExceptionInfo>()) % 16 == 0);

// Defines `context_save` and `context_restore`
macro_rules! save {
    () => {
        concat!(
            // Save general-purpose registers
            "    sub rsp, 8\n",
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
            // Save floating-point/SSE registers
            // TODO: Don't do this unconditionally: get the exn
            //       handlers compiled without sse
            // TODO: Check if we ever generate code with ymm/zmm in
            //       the handlers and save/restore those as well
            "    sub rsp, 512\n",
            "    mov rax, rsp\n",
            "    fxsave [rax]\n",
            // Save the rest of the segment registers
            "    mov rax, es\n",
            "    push rax\n",
            "    mov rax, fs\n",
            "    push rax\n",
            "    mov rax, gs\n",
            "    push rax\n",
            "    mov rax, ds\n",
            "    push rax\n",
        )
    };
}
pub(super) use save;

macro_rules! restore {
    () => {
        concat!(
            // Restore most segment registers
            "    pop rax\n",
            "    mov ds, rax\n",
            "    pop rax\n",
            "    mov gs, rax\n",
            "    pop rax\n",
            "    mov fs, rax\n",
            "    pop rax\n",
            "    mov es, rax\n",
            // Restore floating-point/SSE registers
            "    mov rax, rsp\n",
            "    fxrstor [rax]\n",
            "    add rsp, 512\n",
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
            "    add rsp, 8\n",
        )
    };
}
pub(super) use restore;
