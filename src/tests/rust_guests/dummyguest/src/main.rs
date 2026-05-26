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
            "str {val}, [{addr}]",
            val = in(reg) 0, addr = in(reg) 0xffff_ffff_e000u64 + 108 * 8,
        );
    }
}

fn mmio_read() {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        asm!("mov al, [0x8000]");

        let mut out: u8;
        #[cfg(target_arch = "aarch64")]
        asm!("ldr {0:x}, [{1}]", out(reg) out, in(reg) 0x8000);
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn entrypoint(a: i64, b: i64, c: i32) -> i32 {
    if a != 0x230000 || b != 1234567890 || c != 4096 {
        mmio_read();
    }
    halt();
    0
}
