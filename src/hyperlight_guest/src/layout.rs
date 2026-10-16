// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

#[cfg_attr(target_arch = "x86_64", path = "arch/amd64/layout.rs")]
#[cfg_attr(target_arch = "aarch64", path = "arch/aarch64/layout.rs")]
mod arch;

pub use arch::{MAIN_STACK_LIMIT_GVA, MAIN_STACK_TOP_GVA};

fn scratch_top_gva(offset: u64) -> *mut u64 {
    (hyperlight_common::layout::SCRATCH_TOP_GVA as u64 - offset + 1) as *mut u64
}

pub fn scratch_size_gva() -> *mut u64 {
    scratch_top_gva(hyperlight_common::layout::SCRATCH_TOP_SIZE_OFFSET)
}
pub fn allocator_gva() -> *mut u64 {
    scratch_top_gva(hyperlight_common::layout::SCRATCH_TOP_ALLOCATOR_OFFSET)
}
pub fn snapshot_pt_gpa_base_gva() -> *mut u64 {
    scratch_top_gva(hyperlight_common::layout::SCRATCH_TOP_SNAPSHOT_PT_GPA_BASE_OFFSET)
}
pub fn snapshot_generation_gva() -> *mut u64 {
    scratch_top_gva(hyperlight_common::layout::SCRATCH_TOP_SNAPSHOT_GENERATION_OFFSET)
}
pub fn g2h_queue_size_gva() -> *mut u64 {
    scratch_top_gva(hyperlight_common::layout::SCRATCH_TOP_G2H_QUEUE_SIZE_OFFSET)
}
pub fn transport_arena_gpa_gva() -> *mut u64 {
    scratch_top_gva(hyperlight_common::layout::SCRATCH_TOP_TRANSPORT_ARENA_GPA_OFFSET)
}
pub fn g2h_pool_pages_gva() -> *mut u64 {
    scratch_top_gva(hyperlight_common::layout::SCRATCH_TOP_G2H_POOL_PAGES_OFFSET)
}
pub fn g2h_buffer_size_gva() -> *mut u64 {
    scratch_top_gva(hyperlight_common::layout::SCRATCH_TOP_G2H_BUFFER_SIZE_OFFSET)
}
pub fn h2g_queue_size_gva() -> *mut u64 {
    scratch_top_gva(hyperlight_common::layout::SCRATCH_TOP_H2G_QUEUE_SIZE_OFFSET)
}
pub fn h2g_pool_pages_gva() -> *mut u64 {
    scratch_top_gva(hyperlight_common::layout::SCRATCH_TOP_H2G_POOL_PAGES_OFFSET)
}
pub fn h2g_buffer_size_gva() -> *mut u64 {
    scratch_top_gva(hyperlight_common::layout::SCRATCH_TOP_H2G_BUFFER_SIZE_OFFSET)
}
pub fn libc_rng_seed_gva() -> *mut u64 {
    scratch_top_gva(hyperlight_common::layout::SCRATCH_TOP_LIBC_RNG_SEED_OFFSET)
}
pub fn guest_log_level_gva() -> *mut u64 {
    use hyperlight_common::layout::{SCRATCH_TOP_GUEST_LOG_LEVEL_OFFSET, SCRATCH_TOP_GVA};
    (SCRATCH_TOP_GVA as u64 - SCRATCH_TOP_GUEST_LOG_LEVEL_OFFSET + 1) as *mut u64
}
pub use arch::{scratch_base_gpa, scratch_base_gva};

/// Exclusive upper GPA for the scratch page allocator: the transport arena,
/// which sits below the reserved top pages.
///
/// Aborts if the host has not published an arena between the scratch base
/// and the end of the transport range, so allocations never reach the
/// rings.
pub fn allocator_limit_gpa() -> u64 {
    // SAFETY: the host writes the arena GPA into scratch metadata before entry.
    let arena = unsafe { transport_arena_gpa_gva().read_volatile() };
    if arena <= scratch_base_gpa()
        || arena >= hyperlight_common::layout::scratch_transport_end_gpa()
    {
        // SAFETY: aborting is always sound.
        unsafe {
            crate::exit::abort_with_code_and_message(
                &[
                    hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode::MallocFailed
                        as u8,
                ],
                c"Transport arena not published between the scratch base and the transport end"
                    .as_ptr(),
            )
        }
    }
    arena
}
