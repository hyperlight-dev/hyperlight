/*
Copyright 2025 The Hyperlight Authors.

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

use alloc::format;
use core::ffi::c_char;

use hyperlight_common::outb::Exception;
use hyperlight_guest::exit::abort_with_code_and_message;

use crate::ErrorCode;
use super::super::context::Context;
use super::super::machine::ExceptionInfo;

// TODO: This will eventually need to end up in a per-thread context,
// when there are threads.
pub static HANDLERS: [core::sync::atomic::AtomicU64; 31] =
    [const { core::sync::atomic::AtomicU64::new(0) }; 31];
pub type HandlerT = fn(n: u64, info: *mut ExceptionInfo, ctx: *mut Context, pf_addr: u64) -> bool;

/// Exception handler
#[unsafe(no_mangle)]
pub extern "C" fn hl_exception_handler(
    stack_pointer: u64,
    exception_number: u64,
    page_fault_address: u64,
) {
    hyperlight_guest::exit::debug_print("exn");
    crate::paging::flush_tlb();
    // When using the `trace_function` macro, it wraps the function body with create_trace_record
    // call, which generates a warning because of the `abort_with_code_and_message` call which does
    // not return.
    // This is manually added to avoid the warning.
    hyperlight_guest_tracing::trace!("> hl_exception_handler");

    let ctx = stack_pointer as *mut Context;
    let exn_info = (stack_pointer + size_of::<Context>() as u64) as *mut ExceptionInfo;

    let exception = Exception::try_from(exception_number as u8).expect("Invalid exception number");

    let saved_rip = unsafe { (&raw const (*exn_info).rip).read_volatile() };
    let error_code = unsafe { (&raw const (*exn_info).error_code).read_volatile() };

    /* Handle page faults in the stack region by expanding the stack */
    if exception_number == 14 &&
        page_fault_address >= hyperlight_guest::layout::MAIN_STACK_LIMIT_GVA &&
        page_fault_address <= hyperlight_guest::layout::MAIN_STACK_TOP_GVA {
            // TODO: perhaps we should have a sanity check that the
            // stack grows only one page at a time, which should be
            // ensured by our stack probing discipline?
            unsafe {
                let new_page = hyperlight_guest::prim_alloc::alloc_phys_pages(1);
                crate::paging::map_region(
                    new_page,
                    (page_fault_address & !0xfff) as *mut u8,
                    hyperlight_common::vm::PAGE_SIZE as u64,
                );
                hyperlight_guest_tracing::trace!("< hl_exception_handler");
                return;
            }
        }

    let msg = format!(
        "Exception vector: {:#}\n\
         Faulting Instruction: {:#x}\n\
         Page Fault Address: {:#x}\n\
         Error code: {:#x}\n\
         Stack Pointer: {:#x}",
        exception_number, saved_rip, page_fault_address, error_code, stack_pointer
    );

    // We don't presently have any need for user-defined interrupts,
    // so we only support handlers for the architecture-defined
    // vectors (0-31)
    if exception_number < 31 {
        let handler =
            HANDLERS[exception_number as usize].load(core::sync::atomic::Ordering::Acquire);
        if handler != 0
            && unsafe {
                core::mem::transmute::<u64, fn(u64, *mut ExceptionInfo, *mut Context, u64) -> bool>(
                    handler,
                )(exception_number, exn_info, ctx, page_fault_address)
            }
        {
            hyperlight_guest_tracing::trace!("< hl_exception_handler");
            return;
        }
    }

    unsafe {
        abort_with_code_and_message(
            &[ErrorCode::GuestError as u8, exception as u8],
            msg.as_ptr() as *const c_char,
        );
    }
}
