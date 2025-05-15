/*
Copyright 2024 The Hyperlight Authors.

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

use core::arch::asm;
use core::ffi::{c_char, CStr};

use hyperlight_common::mem::HyperlightPEB;
use hyperlight_common::outb::OutBAction;
use log::LevelFilter;
use spin::Once;

use crate::gdt::load_gdt;
use crate::guest_function_call::dispatch_function;
use crate::guest_logger::init_logger;
use crate::host_function_call::outb;
use crate::idtr::load_idt;
use crate::{__security_cookie, HEAP_ALLOCATOR, MIN_STACK_ADDRESS, OS_PAGE_SIZE, P_PEB};

#[inline(never)]
pub fn halt() {
    unsafe { asm!("hlt", options(nostack)) }
}

#[no_mangle]
pub extern "C" fn abort() -> ! {
    abort_with_code(&[0, 0xFF])
}

pub fn abort_with_code(code: &[u8]) -> ! {
    outb(OutBAction::Abort as u16, code);
    outb(OutBAction::Abort as u16, &[0xFF]); // send abort terminator (if not included in code)
    unreachable!()
}

/// Aborts the program with a code and a message.
///
/// # Safety
/// This function is unsafe because it dereferences a raw pointer.
pub unsafe fn abort_with_code_and_message(code: &[u8], message_ptr: *const c_char) -> ! {
    // Step 1: Send abort code (typically 1 byte, but `code` allows flexibility)
    outb(OutBAction::Abort as u16, code);

    // Step 2: Convert the C string to bytes
    let message_bytes = CStr::from_ptr(message_ptr).to_bytes(); // excludes null terminator

    // Step 3: Send the message itself in chunks
    outb(OutBAction::Abort as u16, message_bytes);

    // Step 4: Send abort terminator to signal completion (e.g., 0xFF)
    outb(OutBAction::Abort as u16, &[0xFF]);

    // This function never returns
    unreachable!()
}

extern "C" {
    fn hyperlight_main();
    fn srand(seed: u32);
}

static INIT: Once = Once::new();

// Note: entrypoint cannot currently have a stackframe >4KB, as that will invoke __chkstk on msvc
//       target without first having setup global `RUNNING_MODE` variable, which __chkstk relies on.
#[no_mangle]
pub extern "win64" fn entrypoint(peb_address: u64, seed: u64, ops: u64, max_log_level: u64) {
    if peb_address == 0 {
        panic!("PEB address is null");
    }

    INIT.call_once(|| {
        unsafe {
            P_PEB = Some(peb_address as *mut HyperlightPEB);
            let peb_ptr = P_PEB.unwrap();
            __security_cookie = peb_address ^ seed;

            let srand_seed = ((peb_address << 8 ^ seed >> 4) >> 32) as u32;

            // Set the seed for the random number generator for C code using rand;
            srand(srand_seed);

            // set up the logger
            let max_log_level = LevelFilter::iter()
                .nth(max_log_level as usize)
                .expect("Invalid log level");
            init_logger(max_log_level);

            // This static is to make it easier to implement the __chkstk function in assembly.
            // It also means that should we change the layout of the struct in the future, we
            // don't have to change the assembly code.
            MIN_STACK_ADDRESS = (*peb_ptr).gueststackData.minUserStackAddress;

            // Setup GDT and IDT
            load_gdt();
            load_idt();

            let heap_start = (*peb_ptr).guestheapData.guestHeapBuffer as usize;
            let heap_size = (*peb_ptr).guestheapData.guestHeapSize as usize;
            HEAP_ALLOCATOR
                .try_lock()
                .expect("Failed to access HEAP_ALLOCATOR")
                .init(heap_start, heap_size);

            OS_PAGE_SIZE = ops as u32;

            (*peb_ptr).guest_function_dispatch_ptr = dispatch_function as usize as u64;

            hyperlight_main();
        }
    });

    halt();
}
