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

use buddy_system_allocator::LockedHeap;
use guest_function_register::GuestFunctionRegister;
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::mem::HyperlightPEB;

use crate::entrypoint::abort_with_code_and_message;
extern crate alloc;

// Modules
pub mod entrypoint;
pub mod shared_input_data;
pub mod shared_output_data;

pub mod guest_error;
pub mod guest_function_call;
pub mod guest_function_definition;
pub mod guest_function_register;

pub mod host_function_call;

pub(crate) mod guest_logger;
pub mod memory;
pub mod print;
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
#[clippy::allow(clippy::non_upper_case_globals)]
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
    let msg = info.to_string();
    let c_string = alloc::ffi::CString::new(msg)
        .unwrap_or_else(|_| alloc::ffi::CString::new("panic (invalid utf8)").unwrap());

    unsafe { abort_with_code_and_message(&[ErrorCode::UnknownError as u8], c_string.as_ptr()) }
}

// Globals
#[global_allocator]
pub(crate) static HEAP_ALLOCATOR: LockedHeap<32> = LockedHeap::<32>::empty();

///cbindgen:ignore
#[no_mangle]
#[clippy::allow(clippy::non_upper_case_globals)]
pub(crate) static mut __security_cookie: u64 = 0;

pub(crate) static mut P_PEB: Option<*mut HyperlightPEB> = None;
pub static mut MIN_STACK_ADDRESS: u64 = 0;

pub static mut OS_PAGE_SIZE: u32 = 0;

pub(crate) static mut REGISTERED_GUEST_FUNCTIONS: GuestFunctionRegister =
    GuestFunctionRegister::new();
