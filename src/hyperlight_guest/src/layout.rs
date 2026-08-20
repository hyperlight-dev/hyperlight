// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

#[cfg_attr(target_arch = "x86_64", path = "arch/amd64/layout.rs")]
#[cfg_attr(target_arch = "aarch64", path = "arch/aarch64/layout.rs")]
mod arch;

pub use arch::{MAIN_STACK_LIMIT_GVA, MAIN_STACK_TOP_GVA};
pub fn scratch_size_gva() -> *mut u64 {
    use hyperlight_common::layout::{SCRATCH_TOP_GVA, SCRATCH_TOP_SIZE_OFFSET};
    (SCRATCH_TOP_GVA as u64 - SCRATCH_TOP_SIZE_OFFSET + 1) as *mut u64
}
pub fn allocator_gva() -> *mut u64 {
    use hyperlight_common::layout::{SCRATCH_TOP_ALLOCATOR_OFFSET, SCRATCH_TOP_GVA};
    (SCRATCH_TOP_GVA as u64 - SCRATCH_TOP_ALLOCATOR_OFFSET + 1) as *mut u64
}
pub fn snapshot_pt_gpa_base_gva() -> *mut u64 {
    use hyperlight_common::layout::{SCRATCH_TOP_GVA, SCRATCH_TOP_SNAPSHOT_PT_GPA_BASE_OFFSET};
    (SCRATCH_TOP_GVA as u64 - SCRATCH_TOP_SNAPSHOT_PT_GPA_BASE_OFFSET + 1) as *mut u64
}
pub fn snapshot_generation_gva() -> *mut u64 {
    use hyperlight_common::layout::{SCRATCH_TOP_GVA, SCRATCH_TOP_SNAPSHOT_GENERATION_OFFSET};
    (SCRATCH_TOP_GVA as u64 - SCRATCH_TOP_SNAPSHOT_GENERATION_OFFSET + 1) as *mut u64
}
pub fn libc_rng_seed_gva() -> *mut u64 {
    use hyperlight_common::layout::{SCRATCH_TOP_GVA, SCRATCH_TOP_LIBC_RNG_SEED_OFFSET};
    (SCRATCH_TOP_GVA as u64 - SCRATCH_TOP_LIBC_RNG_SEED_OFFSET + 1) as *mut u64
}
pub use arch::{scratch_base_gpa, scratch_base_gva};
