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

const HLT_ADDR: u64 = IO_PAGE_GVA
    + (core::mem::size_of::<u64>() as u64 * hyperlight_common::outb::VmAction::Halt as u64);

// See doc comment in arch-independent reexport
pub(crate) unsafe fn wait_for_host() {
    unsafe {
        core::arch::asm!("
            ldr {temp}, ={hlt_addr}\n
            str xzr, [{temp}]\n
        ",
            temp = out(reg) _,
            hlt_addr = const HLT_ADDR,
        );
    }
}
