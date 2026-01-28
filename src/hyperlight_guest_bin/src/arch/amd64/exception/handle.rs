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

use core::fmt::Write;

use hyperlight_common::outb::Exception;
use hyperlight_guest::exit::write_abort;

use super::super::context::Context;
use super::super::machine::ExceptionInfo;
use crate::{ErrorCode, HyperlightAbortWriter};

/// Array of installed exception handlers for vectors 0-30.
///
/// TODO: This will eventually need to be part of a per-thread context when threading is implemented.
pub static HANDLERS: [core::sync::atomic::AtomicU64; 31] =
    [const { core::sync::atomic::AtomicU64::new(0) }; 31];

/// Exception handler function type.
///
/// Handlers receive mutable pointers to the exception information and CPU context,
/// allowing direct access and modification of exception state.
///
/// # Parameters
/// * `exception_number` - Exception vector number (0-30)
/// * `exception_info` - Mutable pointer to exception information (instruction pointer, error code, etc.)
/// * `context` - Mutable pointer to saved CPU context (registers, FPU state, etc.)
/// * `page_fault_address` - Page fault address (only valid for page fault exceptions)
///
/// # Returns
/// * `true` - Suppress the default abort behavior and continue execution
/// * `false` - Allow the default abort to occur
///
/// # Safety
/// This function type uses raw mutable pointers. Handlers must ensure:
/// - Pointers are valid for the duration of the handler
/// - Any modifications to exception state maintain system integrity
/// - Modified values are valid for CPU state (e.g., valid instruction pointers, aligned stack pointers)
pub type ExceptionHandler = fn(
    exception_number: u64,
    exception_info: *mut ExceptionInfo,
    context: *mut Context,
    page_fault_address: u64,
) -> bool;

/// Internal exception handler invoked by the low-level exception entry code.
///
/// This function is called from assembly when an exception occurs. It checks for
/// registered user handlers and either invokes them or aborts with an error message.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn hl_exception_handler(
    stack_pointer: u64,
    exception_number: u64,
    page_fault_address: u64,
) {
    // TODO: is this always needed? surely only needed if CoW
    crate::paging::flush_tlb();

    let ctx = stack_pointer as *mut Context;
    let exn_info = (stack_pointer + size_of::<Context>() as u64) as *mut ExceptionInfo;

    let exception = Exception::try_from(exception_number as u8).expect("Invalid exception number");

    let saved_rip = unsafe { (&raw const (*exn_info).rip).read_volatile() };
    let error_code = unsafe { (&raw const (*exn_info).error_code).read_volatile() };

    // Check for registered user handlers (only for architecture-defined vectors 0-30)
    if exception_number < 31 {
        let handler =
            HANDLERS[exception_number as usize].load(core::sync::atomic::Ordering::Acquire);
        if handler != 0 {
            unsafe {
                let handler = core::mem::transmute::<u64, ExceptionHandler>(handler);
                if handler(exception_number, exn_info, ctx, page_fault_address) {
                    return;
                }
                // Handler returned false, fall through to abort
            };
        }
    }

    let bytes_at_rip = unsafe { (saved_rip as *const [u8; 8]).read_volatile() };

    // begin abort sequence by writing the error code
    let mut w = HyperlightAbortWriter;
    write_abort(&[ErrorCode::GuestError as u8, exception as u8]);
    let write_res = write!(
        w,
        "Exception vector: {}\n\
         Faulting Instruction: {:#x}\n\
         Bytes At Faulting Instruction: {:?}\n\
         Page Fault Address: {:#x}\n\
         Error code: {:#x}\n\
         Stack Pointer: {:#x}",
        exception_number, saved_rip, bytes_at_rip, page_fault_address, error_code, stack_pointer
    );
    if write_res.is_err() {
        write_abort("exception message format failed".as_bytes());
    }

    write_abort(&[0xFF]);
    // At this point, write_abort with the 0xFF terminator is expected to terminate guest execution,
    // so control should never reach beyond this call.
    unreachable!();
}
