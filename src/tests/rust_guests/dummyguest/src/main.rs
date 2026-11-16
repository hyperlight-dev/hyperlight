// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

// It looks like rust-analyzer doesn't correctly manage no_std crates,
// and so it displays an error about a duplicate panic_handler.
// See more here: https://github.com/rust-lang/rust-analyzer/issues/4490
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    halt();
    loop {}
}

fn halt() {
    // VmAction::Halt = 108; using raw constant to avoid pulling in
    // anyhow (via hyperlight_common's TryFrom impl) which requires alloc.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        asm!(
            "out dx, eax",
            "cli",
            "hlt",
            in("dx") 108u16,
            in("eax") 0u32,
        );
        #[cfg(target_arch = "aarch64")]
        asm!(
            "str {val:x}, [{addr}]",
            val = in(reg) 0, addr = in(reg) 0xffff_ffff_e000u64 + 108 * 8,
        );
    }
}

fn mmio_read() {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        asm!("mov al, [0x8000]");

        #[cfg(target_arch = "aarch64")]
        asm!("ldr {0:x}, [{1:x}]", out(reg) _, in(reg) 0x8000);
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn entrypoint(seed: u64, page_size: u64) -> i32 {
    if seed != 1234567890 || page_size != 4096 {
        mmio_read();
    }
    halt();
    0
}
