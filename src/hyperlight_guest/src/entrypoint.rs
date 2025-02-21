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
use core::ffi::{c_char, c_void, CStr};
use core::ptr::copy_nonoverlapping;

use hyperlight_common::mem::{HyperlightPEB, RunMode};
use log::LevelFilter;
use spin::Once;

use crate::gdt::load_gdt;
use crate::guest_error::reset_error;
use crate::guest_function_call::dispatch_function;
use crate::guest_logger::init_logger;
use crate::host_function_call::{outb, OutBAction};
use crate::idtr::load_idt;
use crate::{
    __security_cookie, HEAP_ALLOCATOR, MIN_STACK_ADDRESS, OS_PAGE_SIZE, OUTB_PTR,
    OUTB_PTR_WITH_CONTEXT, P_PEB, RUNNING_MODE,
};

#[inline(never)]
pub fn halt() {
    unsafe {
        if RUNNING_MODE == RunMode::Hypervisor {
            asm!("hlt", options(nostack))
        }
    }
}

#[no_mangle]
pub extern "C" fn abort() -> ! {
    abort_with_code(0)
}

pub fn abort_with_code(code: i32) -> ! {
    outb(OutBAction::Abort as u16, code as u8);
    unreachable!()
}

/// Aborts the program with a code and a message.
///
/// # Safety
/// This function is unsafe because it dereferences a raw pointer.
pub unsafe fn abort_with_code_and_message(code: i32, message_ptr: *const c_char) -> ! {
    let peb_ptr = P_PEB.unwrap();
    copy_nonoverlapping(
        message_ptr,
        (*peb_ptr).guestPanicContextData.guestPanicContextDataBuffer as *mut c_char,
        CStr::from_ptr(message_ptr).count_bytes() + 1, // +1 for null terminator
    );
    outb(OutBAction::Abort as u16, code as u8);
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

            match (*peb_ptr).runMode {
                RunMode::Hypervisor => {
                    RUNNING_MODE = RunMode::Hypervisor;
                    // This static is to make it easier to implement the __chkstk function in assembly.
                    // It also means that should we change the layout of the struct in the future, we
                    // don't have to change the assembly code.
                    MIN_STACK_ADDRESS = (*peb_ptr).gueststackData.minUserStackAddress;

                    // Setup GDT and IDT
                    load_gdt();
                    load_idt();
                }
                RunMode::InProcessLinux | RunMode::InProcessWindows => {
                    RUNNING_MODE = (*peb_ptr).runMode;

                    OUTB_PTR = {
                        let outb_ptr: extern "win64" fn(u16, u8) =
                            core::mem::transmute((*peb_ptr).pOutb);
                        Some(outb_ptr)
                    };

                    if (*peb_ptr).pOutbContext.is_null() {
                        panic!("OutbContext is null");
                    }

                    OUTB_PTR_WITH_CONTEXT = {
                        let outb_ptr_with_context: extern "win64" fn(*mut c_void, u16, u8) =
                            core::mem::transmute((*peb_ptr).pOutb);
                        Some(outb_ptr_with_context)
                    };
                }
                _ => {
                    panic!("Invalid runmode in PEB");
                }
            }

            let heap_start = (*peb_ptr).guestheapData.guestHeapBuffer as usize;
            let heap_size = (*peb_ptr).guestheapData.guestHeapSize as usize;
            HEAP_ALLOCATOR
                .try_lock()
                .expect("Failed to access HEAP_ALLOCATOR")
                .init(heap_start, heap_size);

            OS_PAGE_SIZE = ops as u32;

            (*peb_ptr).guest_function_dispatch_ptr = dispatch_function as usize as u64;

            reset_error();

            hyperlight_main();
        }
    });

    halt();
}
