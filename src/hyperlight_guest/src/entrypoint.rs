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
use core::ptr::copy_nonoverlapping;

use hyperlight_common::outb::{outb, OutBAction};
use hyperlight_common::peb::{HyperlightPEB, RunMode};
use hyperlight_common::{OUTB_HANDLER, OUTB_HANDLER_CTX, PEB, RUNNING_MODE};
use log::LevelFilter;
use spin::Once;

use crate::gdt::load_gdt;
use crate::guest_function_call::dispatch_function;
use crate::guest_logger::init_logger;
use crate::idtr::load_idt;
use crate::{__security_cookie, HEAP_ALLOCATOR, MIN_STACK_ADDRESS};

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
    copy_nonoverlapping(
        message_ptr,
        (*PEB).get_guest_panic_context_address() as *mut c_char,
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
pub extern "win64" fn entrypoint(peb_address: u64, seed: u64, max_log_level: u64) {
    INIT.call_once(|| unsafe {
        PEB = peb_address as *mut HyperlightPEB;
        RUNNING_MODE = (*PEB).clone().get_run_mode();

        // The guest receives an undifferentiated block of memory that it can address as it sees fit.
        // This 'addressing' is done by writing to the PEB the guest's memory layout via this function,
        // or by directly altering the PEB. `set_default_memory_layout` will configure the PEB to
        // with a memory layout that is compatible with the expectations of guests that use the
        // `hyperlight_guest` library (e.g., simpleguest, and callbackguest).
        (*PEB).set_default_memory_layout();

        // The guest sets the address to a "guest function dispatch" function, which is a function
        // that is called by the host to dispatch calls to guest functions.
        (*PEB).set_guest_function_dispatch_ptr(dispatch_function as u64);

        // Set up the guest heap
        HEAP_ALLOCATOR
            .try_lock()
            .expect("Failed to access HEAP_ALLOCATOR")
            .init(
                (*PEB).get_heap_data_address() as usize,
                (*PEB).get_guest_heap_data_size() as usize,
            );

        __security_cookie = peb_address ^ seed;

        // Set the seed for the random number generator for C code using rand;
        let srand_seed = ((peb_address << 8 ^ seed >> 4) >> 32) as u32;
        srand(srand_seed);

        // Set up the logger
        let max_log_level = LevelFilter::iter()
            .nth(max_log_level as usize)
            .expect("Invalid log level");
        init_logger(max_log_level);

        match RUNNING_MODE {
            RunMode::Hypervisor => {
                // This static is to make it easier to implement the __chkstk function in assembly.
                // It also means that, should we change the layout of the struct in the future, we
                // don't have to change the assembly code. Plus, while this could be accessible via
                // the PEB, we don't want to expose it entirely to user code.
                MIN_STACK_ADDRESS = (*PEB).get_stack_data_address();

                // Setup GDT and IDT
                load_gdt();
                load_idt();
            }
            RunMode::InProcessLinux | RunMode::InProcessWindows => {
                OUTB_HANDLER = {
                    let outb_handler: extern "C" fn(u16, u8) =
                        core::mem::transmute((*PEB).get_outb_ptr());
                    Some(outb_handler)
                };

                if (*PEB).get_outb_ptr_ctx() == 0 {
                    panic!("outb_ptr_ctx is null");
                }

                OUTB_HANDLER_CTX = {
                    let outb_handler_ctx: extern "C" fn(*mut core::ffi::c_void, u16, u8) =
                        core::mem::transmute((*PEB).get_outb_ptr());
                    Some(outb_handler_ctx)
                };
            }
            _ => panic!("Invalid runmode in PEB"),
        }

        hyperlight_main();
    });

    halt();
}
