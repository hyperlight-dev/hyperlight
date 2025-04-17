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

#![no_std]
// Deps
use alloc::string::ToString;
use core::hint::unreachable_unchecked;
use core::ptr::copy_nonoverlapping;

use buddy_system_allocator::LockedHeap;
use guest_function_register::GuestFunctionRegister;
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::outb::{outb, OutBAction};
use hyperlight_common::PEB;

extern crate alloc;

// Modules
pub mod entrypoint;
pub mod guest_error;
pub mod guest_function_call;
pub mod guest_function_definition;
pub mod guest_function_register;
// TODO(danbugs:297): bring back
// pub mod host_error;

pub(crate) mod guest_logger;
pub mod memory;
pub(crate) mod security_check;
pub mod setjmp;

pub mod chkstk;
pub mod error;
pub mod gdt;
pub mod idt;
pub mod idtr;
pub mod interrupt_entry;
pub mod interrupt_handlers;
pub mod logging;

// Unresolved symbols
///cbindgen:ignore
#[no_mangle]
pub(crate) extern "C" fn __CxxFrameHandler3() {}
///cbindgen:ignore
#[no_mangle]
pub(crate) static _fltused: i32 = 0;

// It looks like rust-analyzer doesn't correctly manage no_std crates,
// and so it displays an error about a duplicate panic_handler.
// See more here: https://github.com/rust-lang/rust-analyzer/issues/4490
// The cfg_attr attribute is used to avoid clippy failures as test pulls in std which pulls in a panic handler
#[cfg_attr(not(test), panic_handler)]
#[allow(clippy::panic)]
// to satisfy the clippy when cfg == test
#[allow(dead_code)]
fn panic(info: &core::panic::PanicInfo) -> ! {
    unsafe {
        copy_nonoverlapping(
            info.to_string().as_ptr(),
            (*PEB).get_guest_panic_context_address() as *mut u8,
            (*PEB).get_guest_panic_context_size() as usize,
        );
    }
    outb(OutBAction::Abort as u16, ErrorCode::UnknownError as u8);
    unsafe { unreachable_unchecked() }
}

// Globals
#[global_allocator]
pub(crate) static HEAP_ALLOCATOR: LockedHeap<32> = LockedHeap::<32>::empty();

///cbindgen:ignore
#[no_mangle]
pub(crate) static mut __security_cookie: u64 = 0;

pub static mut MIN_STACK_ADDRESS: u64 = 0;

pub(crate) static mut REGISTERED_GUEST_FUNCTIONS: GuestFunctionRegister =
    GuestFunctionRegister::new();
