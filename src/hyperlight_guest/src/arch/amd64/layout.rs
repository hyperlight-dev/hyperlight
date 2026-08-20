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

// The addresses in this file should be coordinated with
// src/hyperlight_common/src/arch/amd64/layout.rs and
// src/hyperlight_guest_bin/src/arch/amd64/layout.rs

/// Note that the x86-64 ELF psABI requires that the stack be 16-byte
/// aligned before a call instruction; we use the aligned version
/// here, even though this requires adjusting the pointer by 8 bytes
/// when entering the guest without a call instruction to push a
/// return address.
pub const MAIN_STACK_TOP_GVA: u64 = 0xffff_ff00_0000_0000;
pub const MAIN_STACK_LIMIT_GVA: u64 = 0xffff_fe00_0000_0000;

pub fn scratch_size() -> u64 {
    let addr = crate::layout::scratch_size_gva();
    let x: u64;
    unsafe {
        core::arch::asm!("mov {x}, [{addr}]", x = out(reg) x, addr = in(reg) addr);
    }
    x
}

pub fn scratch_base_gpa() -> u64 {
    hyperlight_common::layout::scratch_base_gpa(scratch_size() as usize)
}

pub fn scratch_base_gva() -> u64 {
    hyperlight_common::layout::scratch_base_gva(scratch_size() as usize)
}
