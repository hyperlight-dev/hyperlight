// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

// TODO(aarch64): these values are placeholders copied from amd64
pub const MAIN_STACK_TOP_GVA: u64 = 0x0000_ff00_0000_0000;
pub const MAIN_STACK_LIMIT_GVA: u64 = 0x0000_fe00_0000_0000;

pub fn scratch_size() -> u64 {
    let addr = crate::layout::scratch_size_gva();
    unsafe { addr.read_volatile() }
}

pub fn scratch_base_gpa() -> u64 {
    hyperlight_common::layout::scratch_base_gpa(scratch_size() as usize)
}

pub fn scratch_base_gva() -> u64 {
    hyperlight_common::layout::scratch_base_gva(scratch_size() as usize)
}
