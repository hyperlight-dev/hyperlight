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

/// Error type for handler installation failures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallError {
    /// Exception vector must be in range 0-30 (architecture-defined exceptions only)
    InvalidVector,
    /// A handler is already installed for this vector
    HandlerAlreadyInstalled,
}

/// Exception information pushed onto the stack by the Hyperlight exception handler.
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
    /// RAX is at index 0, R15 is at index 14.
    pub gprs: [u64; 15],
    /// Padding to ensure 16-byte alignment when combined with ExceptionInfo.
    padding: [u64; 1],
}
const _: () = assert!(size_of::<Context>() == 32 + 512 + 120 + 8);
const _: () = assert!((size_of::<Context>() + size_of::<ExceptionInfo>()) % 16 == 0);

/// Array of installed exception handlers for vectors 0-30.
///
/// TODO: This will eventually need to be part of a per-thread context when threading is implemented.
static HANDLERS: [core::sync::atomic::AtomicU64; 31] =
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

/// Install a custom exception handler for a specific vector.
///
/// # Arguments
/// * `vector` - Exception vector (0-30). Must be an architecture-defined exception.
/// * `handler` - The handler function to invoke when this exception occurs.
///
/// # Returns
/// * `Ok(())` if the handler was successfully installed.
/// * `Err(InstallError::InvalidVector)` if `vector >= 31`.
/// * `Err(InstallError::HandlerAlreadyInstalled)` if a handler is already registered for this vector.
///
/// # Example
/// ```ignore
/// fn my_exception_handler(
///     exception_number: u64,
///     exception_info: *mut ExceptionInfo,
///     context: *mut Context,
///     page_fault_address: u64,
/// ) -> bool {
///     unsafe {
///         // Read the faulting instruction pointer
///         let faulting_rip = core::ptr::read_volatile(&(*exception_info).rip);
///         
///         // Save the original RIP to R9 register
///         core::ptr::write_volatile(&mut (*context).gprs[8], faulting_rip);
///         
///         // Skip past the faulting instruction
///         core::ptr::write_volatile(&mut (*exception_info).rip, faulting_rip + 2);
///     }
///     
///     true // Return true to suppress abort and continue execution
/// }
///
/// install_handler(3, my_exception_handler)?;  // Install for INT3 (breakpoint)
/// ```
pub fn install_handler(vector: u8, handler: ExceptionHandler) -> Result<(), InstallError> {
    if vector >= 31 {
        return Err(InstallError::InvalidVector);
    }

    // Use compare_exchange to atomically check and set, preventing races
    match HANDLERS[vector as usize].compare_exchange(
        0,
        handler as usize as u64,
        core::sync::atomic::Ordering::AcqRel,
        core::sync::atomic::Ordering::Acquire,
    ) {
        Ok(_) => Ok(()),
        Err(_) => Err(InstallError::HandlerAlreadyInstalled),
    }
}

/// Remove a custom exception handler for a specific vector.
///
/// # Arguments
/// * `vector` - Exception vector (0-30).
///
/// # Returns
/// * `Ok(())` if the handler was successfully removed (or was already uninstalled).
/// * `Err(InstallError::InvalidVector)` if `vector >= 31`.
pub fn uninstall_handler(vector: u8) -> Result<(), InstallError> {
    if vector >= 31 {
        return Err(InstallError::InvalidVector);
    }

    HANDLERS[vector as usize].store(0, core::sync::atomic::Ordering::Release);
    Ok(())
}

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

    let msg = format!(
        "Exception vector: {:#}\n\
         Faulting Instruction: {:#x}\n\
         Page Fault Address: {:#x}\n\
         Error code: {:#x}\n\
         Stack Pointer: {:#x}",
        exception_number, saved_rip, page_fault_address, error_code, stack_pointer
    );

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

    unsafe {
        abort_with_code_and_message(
            &[ErrorCode::GuestError as u8, exception as u8],
            msg.as_ptr() as *const c_char,
        );
    }
}
