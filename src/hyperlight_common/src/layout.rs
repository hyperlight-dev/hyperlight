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

#[cfg_attr(target_arch = "x86", path = "arch/i686/layout.rs")]
#[cfg_attr(
    all(target_arch = "x86_64", not(feature = "i686-guest")),
    path = "arch/amd64/layout.rs"
)]
#[cfg_attr(
    all(target_arch = "x86_64", feature = "i686-guest"),
    path = "arch/i686/layout.rs"
)]
#[cfg_attr(target_arch = "aarch64", path = "arch/aarch64/layout.rs")]
mod arch;

pub use arch::{MAX_GPA, MAX_GVA};
#[cfg(any(
    all(target_arch = "x86_64", not(feature = "i686-guest")),
    target_arch = "aarch64"
))]
pub use arch::{SNAPSHOT_PT_GVA_MAX, SNAPSHOT_PT_GVA_MIN};

pub const SCRATCH_TOP_SIZE_OFFSET: u64 = 0x08;
pub const SCRATCH_TOP_ALLOCATOR_OFFSET: u64 = 0x10;
pub const SCRATCH_TOP_SNAPSHOT_PT_GPA_BASE_OFFSET: u64 = 0x18;
pub const SCRATCH_TOP_SNAPSHOT_GENERATION_OFFSET: u64 = 0x20;
pub const SCRATCH_TOP_G2H_RING_GVA_OFFSET: u64 = 0x28;
pub const SCRATCH_TOP_H2G_RING_GVA_OFFSET: u64 = 0x30;
pub const SCRATCH_TOP_G2H_QUEUE_DEPTH_OFFSET: u64 = 0x38;
pub const SCRATCH_TOP_H2G_QUEUE_DEPTH_OFFSET: u64 = 0x3A;
pub const SCRATCH_TOP_G2H_POOL_PAGES_OFFSET: u64 = 0x3C;
pub const SCRATCH_TOP_H2G_POOL_PAGES_OFFSET: u64 = 0x3E;
pub const SCRATCH_TOP_H2G_POOL_GVA_OFFSET: u64 = 0x48;
pub const SCRATCH_TOP_EXN_STACK_OFFSET: u64 = 0x50;

const _: () = {
    assert!(SCRATCH_TOP_ALLOCATOR_OFFSET >= SCRATCH_TOP_SIZE_OFFSET + 8);
    assert!(SCRATCH_TOP_SNAPSHOT_PT_GPA_BASE_OFFSET >= SCRATCH_TOP_ALLOCATOR_OFFSET + 8);
    assert!(SCRATCH_TOP_SNAPSHOT_GENERATION_OFFSET >= SCRATCH_TOP_SNAPSHOT_PT_GPA_BASE_OFFSET + 8);
    assert!(SCRATCH_TOP_G2H_RING_GVA_OFFSET >= SCRATCH_TOP_SNAPSHOT_GENERATION_OFFSET + 8);
    assert!(SCRATCH_TOP_H2G_RING_GVA_OFFSET >= SCRATCH_TOP_G2H_RING_GVA_OFFSET + 8);
    assert!(SCRATCH_TOP_G2H_QUEUE_DEPTH_OFFSET >= SCRATCH_TOP_H2G_RING_GVA_OFFSET + 8);
    assert!(SCRATCH_TOP_H2G_QUEUE_DEPTH_OFFSET >= SCRATCH_TOP_G2H_QUEUE_DEPTH_OFFSET + 2);
    assert!(SCRATCH_TOP_G2H_POOL_PAGES_OFFSET >= SCRATCH_TOP_H2G_QUEUE_DEPTH_OFFSET + 2);
    assert!(SCRATCH_TOP_H2G_POOL_PAGES_OFFSET >= SCRATCH_TOP_G2H_POOL_PAGES_OFFSET + 2);
    assert!(SCRATCH_TOP_H2G_POOL_GVA_OFFSET >= SCRATCH_TOP_H2G_POOL_PAGES_OFFSET + 8);
    assert!(SCRATCH_TOP_EXN_STACK_OFFSET >= SCRATCH_TOP_H2G_POOL_GVA_OFFSET + 8);
    assert!(SCRATCH_TOP_EXN_STACK_OFFSET % 0x10 == 0);
};

/// Offset from the top of scratch memory for a shared host-guest u64 counter.
///
/// This is placed at 0x1008 (rather than the next sequential 0x28) so that the
/// counter falls in scratch page 0xffffe000 instead of the very last page
/// 0xfffff000, which on i686 guests would require frame 0xfffff — exceeding the
/// maximum representable frame number.
#[cfg(feature = "guest-counter")]
pub const SCRATCH_TOP_GUEST_COUNTER_OFFSET: u64 = 0x1008;

pub fn scratch_base_gpa(size: usize) -> u64 {
    (MAX_GPA - size + 1) as u64
}
pub fn scratch_base_gva(size: usize) -> u64 {
    (MAX_GVA - size + 1) as u64
}

pub const fn scratch_top_ptr<T>(offset: u64) -> *mut T {
    (MAX_GVA as u64 - offset + 1) as *mut T
}

/// Compute the byte offset from the scratch base to the G2H ring.
///
/// TODO(virtq): Remove input/output
pub const fn g2h_ring_scratch_offset(input_data_size: usize, output_data_size: usize) -> usize {
    let io_off = input_data_size + output_data_size;
    let align = crate::virtq::Descriptor::ALIGN;

    (io_off + align - 1) & !(align - 1)
}

/// Compute the byte offset from the scratch base to the H2G ring.
///
/// TODO(ring): Remove input/output
pub const fn h2g_ring_scratch_offset(
    input_data_size: usize,
    output_data_size: usize,
    g2h_num_descs: usize,
) -> usize {
    let g2h_offset = g2h_ring_scratch_offset(input_data_size, output_data_size);
    let g2h_size = crate::virtq::Layout::query_size(g2h_num_descs);
    let align = crate::virtq::Descriptor::ALIGN;

    (g2h_offset + g2h_size + align - 1) & !(align - 1)
}

/// Compute the minimum scratch region size needed for a sandbox.
pub use arch::min_scratch_size;
