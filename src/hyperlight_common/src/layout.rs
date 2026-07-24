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

use core::mem::{offset_of, size_of};

#[cfg_attr(target_arch = "x86_64", path = "arch/amd64/layout.rs")]
#[cfg_attr(target_arch = "aarch64", path = "arch/aarch64/layout.rs")]
mod arch;

pub use arch::{
    SCRATCH_TOP_GPA, SCRATCH_TOP_GVA, SNAPSHOT_PT_GVA_MAX, SNAPSHOT_PT_GVA_MIN, io_page,
};

const EXN_STACK_ALIGNMENT: usize = 16;

// Fields are listed in ascending-address order. Public offsets are measured
// down from the top of scratch memory.
#[repr(C)]
struct ScratchTopMetadata {
    /// Keep the exception stack pointer aligned 16 bytes aligned.
    _alignment_padding: [u8; 8],
    /// Reserved for future scratch metadata.
    _reserved: u64,
    /// Generation of the snapshot backing the sandbox.
    snapshot_generation: u64,
    /// GPA of the snapshot page-table copy in scratch memory.
    snapshot_pt_gpa_base: u64,
    /// Next GPA available to the dynamic scratch allocator.
    allocator: u64,
    /// Size of the scratch region in bytes.
    scratch_size: u64,
}

const fn scratch_top_offset(field_offset: usize) -> u64 {
    (size_of::<ScratchTopMetadata>() - field_offset) as u64
}

const SCRATCH_TOP_RESERVED_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, _reserved));
pub const SCRATCH_TOP_SIZE_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, scratch_size));
pub const SCRATCH_TOP_ALLOCATOR_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, allocator));
pub const SCRATCH_TOP_SNAPSHOT_PT_GPA_BASE_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, snapshot_pt_gpa_base));
pub const SCRATCH_TOP_SNAPSHOT_GENERATION_OFFSET: u64 =
    scratch_top_offset(offset_of!(ScratchTopMetadata, snapshot_generation));
pub const SCRATCH_TOP_EXN_STACK_OFFSET: u64 = size_of::<ScratchTopMetadata>() as u64;

const _: () = {
    assert!(size_of::<ScratchTopMetadata>().is_multiple_of(EXN_STACK_ALIGNMENT));
    assert!(SCRATCH_TOP_SIZE_OFFSET == 0x08);
    assert!(SCRATCH_TOP_ALLOCATOR_OFFSET == 0x10);
    assert!(SCRATCH_TOP_SNAPSHOT_PT_GPA_BASE_OFFSET == 0x18);
    assert!(SCRATCH_TOP_SNAPSHOT_GENERATION_OFFSET == 0x20);
    assert!(SCRATCH_TOP_RESERVED_OFFSET == 0x28);
    assert!(SCRATCH_TOP_EXN_STACK_OFFSET == 0x30);
};

pub fn scratch_base_gpa(size: usize) -> u64 {
    (SCRATCH_TOP_GPA - size + 1) as u64
}
pub fn scratch_base_gva(size: usize) -> u64 {
    (SCRATCH_TOP_GVA - size + 1) as u64
}

/// Compute the minimum scratch region size needed for a sandbox.
pub use arch::min_scratch_size;
