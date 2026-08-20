// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

// TODO(aarch64): implement VM exit mechanism (e.g. hvc instruction)

const IO_PAGE_GVA: u64 = hyperlight_common::layout::io_page().unwrap().1;

/// Trigger a VM exit sending a 32-bit value to the host on the given port.
pub(crate) unsafe fn out32(port: u16, val: u32) {
    if port as usize >= (hyperlight_common::vmem::PAGE_SIZE / core::mem::size_of::<u64>()) {
        panic!("aarch64 mmio: unsupported hypercall number {}", port);
    }
    unsafe {
        (IO_PAGE_GVA as *mut u64)
            .wrapping_add(port as usize)
            .write_volatile(val as u64);
    }
}
