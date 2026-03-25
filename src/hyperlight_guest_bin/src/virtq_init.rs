/*
Copyright 2026  The Hyperlight Authors.

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

//! Guest-side virtqueue initialization.
//!
//! The host places virtqueue rings at deterministic offsets in the
//! scratch region and writes ring GVAs and queue depths to scratch-top
//! metadata.

use hyperlight_common::layout::{
    self, SCRATCH_TOP_G2H_QUEUE_DEPTH_OFFSET, SCRATCH_TOP_G2H_RING_GVA_OFFSET,
    SCRATCH_TOP_H2G_QUEUE_DEPTH_OFFSET, SCRATCH_TOP_H2G_RING_GVA_OFFSET,
};
use hyperlight_common::virtq::Layout as VirtqLayout;

/// Read a value from a scratch-top metadata slot.
unsafe fn read_scratch_top<T: Copy>(offset: u64) -> T {
    let addr = (layout::MAX_GVA as u64 - offset + 1) as *const T;
    unsafe { core::ptr::read_volatile(addr) }
}

/// Initialize virtqueue ring memory in the scratch region.
pub(crate) fn init_virtqueues() {
    let g2h_gva: u64 = unsafe { read_scratch_top(SCRATCH_TOP_G2H_RING_GVA_OFFSET) };
    let g2h_depth: u16 = unsafe { read_scratch_top(SCRATCH_TOP_G2H_QUEUE_DEPTH_OFFSET) };
    let h2g_gva: u64 = unsafe { read_scratch_top(SCRATCH_TOP_H2G_RING_GVA_OFFSET) };
    let h2g_depth: u16 = unsafe { read_scratch_top(SCRATCH_TOP_H2G_QUEUE_DEPTH_OFFSET) };

    assert!(g2h_depth > 0 && h2g_depth > 0);
    assert!(g2h_gva != 0 && h2g_gva != 0);

    let size = VirtqLayout::query_size(g2h_depth as usize);
    unsafe { core::ptr::write_bytes(g2h_gva as *mut u8, 0, size) };

    let size = VirtqLayout::query_size(h2g_depth as usize);
    unsafe { core::ptr::write_bytes(h2g_gva as *mut u8, 0, size) };
}
