// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

#![no_std]
#![no_main]

use hyperlight_common::outb::VmAction;
use hyperlight_guest_bin::main;

/// Halt before the runtime publishes initialization readiness.
#[main]
fn main() {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: The host handles this port as a VM halt.
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") VmAction::Halt as u16,
            in("eax") 0u32,
            options(nostack, preserves_flags),
        );
    }

    #[cfg(target_arch = "aarch64")]
    // SAFETY: The runtime maps the I/O page before user initialization.
    unsafe {
        let page = hyperlight_common::layout::io_page().unwrap().1 as *mut u64;
        page.add(VmAction::Halt as usize).write_volatile(0);
    }

    panic!("initialization resumed after early halt");
}
