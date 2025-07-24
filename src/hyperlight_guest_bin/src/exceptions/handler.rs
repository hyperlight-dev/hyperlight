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

use alloc::format;
use core::ffi::c_char;

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::outb::Exception;
use hyperlight_guest::exit::abort_with_code_and_message;

/// See AMD64 Architecture Programmer's Manual, Volume 2
///     §8.9.3 Interrupt Stack Frame, pp. 283--284
///       Figure 8-14: Long-Mode Stack After Interrupt---Same Privilege,
///       Figure 8-15: Long-Mode Stack After Interrupt---Higher Privilege
/// Subject to the proviso that we push a dummy error code of 0 for exceptions
/// for which the processor does not provide one
#[repr(C)]
pub struct ExceptionInfo {
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}
const _: () = assert!(core::mem::offset_of!(ExceptionInfo, rip) == 8);
const _: () = assert!(core::mem::offset_of!(ExceptionInfo, rsp) == 32);

#[repr(C)]
/// Saved context, pushed onto the stack by exception entry code
pub struct Context {
    /// in order: gs, fs, es
    pub segments: [u64; 3],
    pub fxsave: [u8; 512],
    pub ds: u64,
    /// no `rsp`, since the processor saved it
    /// `rax` is at the top, `r15` the bottom
    pub gprs: [u64; 15],
}
const _: () = assert!(size_of::<Context>() == 152 + 512);

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
