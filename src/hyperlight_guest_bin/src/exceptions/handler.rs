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

use core::fmt::Write;

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::outb::Exception;
use hyperlight_guest::exit::write_abort;

use crate::HyperlightAbortWriter;

/// Exception information pushed onto the stack by the CPU during an excpection.
///
/// See AMD64 Architecture Programmer's Manual, Volume 2
///     §8.9.3 Interrupt Stack Frame, pp. 283--284
///       Figure 8-14: Long-Mode Stack After Interrupt---Same Privilege,
///       Figure 8-15: Long-Mode Stack After Interrupt---Higher Privilege
/// Note: For exceptions that don't provide an error code, we push a dummy value of 0.
#[repr(C)]
pub struct ExceptionInfo {
    /// Error code provided by the processor (or 0 if not applicable).
    pub error_code: u64,
    /// Instruction pointer at the time of the exception.
    pub rip: u64,
    /// Code segment selector.
    pub cs: u64,
    /// CPU flags register.
    pub rflags: u64,
    /// Stack pointer at the time of the exception.
    pub rsp: u64,
    /// Stack segment selector.
    pub ss: u64,
}
const _: () = assert!(core::mem::offset_of!(ExceptionInfo, rip) == 8);
const _: () = assert!(core::mem::offset_of!(ExceptionInfo, rsp) == 32);

/// Saved CPU context pushed onto the stack by exception entry code.
///
/// This structure contains all the saved CPU state needed to resume execution
/// after handling an exception. It includes segment registers, floating-point state,
/// and general-purpose registers.
#[repr(C)]
pub struct Context {
    /// Segment registers in order: GS, FS, ES, DS.
    pub segments: [u64; 4],
    /// FPU/SSE state saved via FXSAVE instruction (512 bytes).
    pub fxsave: [u8; 512],
    /// General-purpose registers (RAX through R15, excluding RSP).
    ///
    /// The stack pointer (RSP) is not included here since it's saved
    /// by the processor in the `ExceptionInfo` structure.
    /// R15 is at index 0, RAX is at index 14.
    pub gprs: [u64; 15],
    /// Padding to ensure 16-byte alignment when combined with ExceptionInfo.
    padding: [u64; 1],
}
const _: () = assert!(size_of::<Context>() == 32 + 512 + 120 + 8);
// The combination of the ExceptionInfo (pushed by the CPU) and the register Context
// that we save to the stack must be 16byte aligned before calling the hl_exception_handler
// as specified in the x86-64 ELF System V psABI specification, Section 3.2.2:
//
// https://gitlab.com/x86-psABIs/x86-64-ABI/-/jobs/artifacts/master/raw/x86-64-ABI/abi.pdf?job=build
const _: () = assert!((size_of::<Context>() + size_of::<ExceptionInfo>()) % 16 == 0);

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

    // begin abort sequence by writing the error code
    let mut w = HyperlightAbortWriter;
    write_abort(&[ErrorCode::GuestError as u8, exception as u8]);
    let write_res = write!(
        w,
        "Exception vector: {}\n\
         Faulting Instruction: {:#x}\n\
         Page Fault Address: {:#x}\n\
         Error code: {:#x}\n\
         Stack Pointer: {:#x}",
        exception_number, saved_rip, page_fault_address, error_code, stack_pointer
    );
    if write_res.is_err() {
        write_abort("exception message format failed".as_bytes());
    }

    write_abort(&[0xFF]);
    // At this point, write_abort with the 0xFF terminator is expected to terminate guest execution,
    // so control should never reach beyond this call.
    unreachable!();
}
