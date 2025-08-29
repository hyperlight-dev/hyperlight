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

#[cfg(mshv2)]
extern crate mshv_bindings2 as mshv_bindings;
#[cfg(mshv3)]
extern crate mshv_bindings3 as mshv_bindings;

#[cfg(kvm)]
use kvm_bindings::kvm_regs;
#[cfg(any(mshv2, mshv3))]
use mshv_bindings::StandardRegisters;

/// Struct that contains the x86_64 core registers
#[allow(dead_code)]
#[derive(Debug, Default)]
pub(crate) struct X86_64Regs {
    pub(crate) rax: u64,
    pub(crate) rbx: u64,
    pub(crate) rcx: u64,
    pub(crate) rdx: u64,
    pub(crate) rsi: u64,
    pub(crate) rdi: u64,
    pub(crate) rbp: u64,
    pub(crate) rsp: u64,
    pub(crate) r8: u64,
    pub(crate) r9: u64,
    pub(crate) r10: u64,
    pub(crate) r11: u64,
    pub(crate) r12: u64,
    pub(crate) r13: u64,
    pub(crate) r14: u64,
    pub(crate) r15: u64,
    pub(crate) rip: u64,
    pub(crate) rflags: u64,
}

#[cfg(kvm)]
impl From<kvm_regs> for X86_64Regs {
    #[inline(always)]
    fn from(regs: kvm_regs) -> Self {
        X86_64Regs {
            rax: regs.rax,
            rbx: regs.rbx,
            rcx: regs.rcx,
            rdx: regs.rdx,
            rdi: regs.rdi,
            rsi: regs.rsi,
            rsp: regs.rsp,
            rbp: regs.rbp,
            r8: regs.r8,
            r9: regs.r9,
            r10: regs.r10,
            r11: regs.r11,
            r12: regs.r12,
            r13: regs.r13,
            r14: regs.r14,
            r15: regs.r15,
            rip: regs.rip,
            rflags: regs.rflags,
        }
    }
}

#[cfg(mshv)]
impl From<StandardRegisters> for X86_64Regs {
    #[inline(always)]
    fn from(regs: StandardRegisters) -> Self {
        X86_64Regs {
            rax: regs.rax,
            rbx: regs.rbx,
            rcx: regs.rcx,
            rdx: regs.rdx,
            rdi: regs.rdi,
            rsi: regs.rsi,
            rsp: regs.rsp,
            rbp: regs.rbp,
            r8: regs.r8,
            r9: regs.r9,
            r10: regs.r10,
            r11: regs.r11,
            r12: regs.r12,
            r13: regs.r13,
            r14: regs.r14,
            r15: regs.r15,
            rip: regs.rip,
            rflags: regs.rflags,
        }
    }
}

#[cfg(target_os = "windows")]
impl From<WHvGeneralRegisters> for X86_64Regs {
    #[inline(always)]
    fn from(regs: WHvGeneralRegisters) -> Self {
        X86_64Regs {
            rax: regs.rax,
            rbx: regs.rbx,
            rcx: regs.rcx,
            rdx: regs.rdx,
            rdi: regs.rdi,
            rsi: regs.rsi,
            rsp: regs.rsp,
            rbp: regs.rbp,
            r8: regs.r8,
            r9: regs.r9,
            r10: regs.r10,
            r11: regs.r11,
            r12: regs.r12,
            r13: regs.r13,
            r14: regs.r14,
            r15: regs.r15,
            rip: regs.rip,
            rflags: regs.rflags,
        }
    }
}
