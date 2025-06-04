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
    unsafe {
        asm!("hlt");
    }
}

fn mmio_read() {
    unsafe {
        asm!("mov al, [0x8000]");
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "win64" fn entrypoint(a: i64, b: i64, c: i32) -> i32 {
    if a != 0x230000 || b != 1234567890 || c != 4096 {
        mmio_read();
    }
    halt();
    0
}
