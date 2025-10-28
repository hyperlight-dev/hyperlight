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

//! Windows-specific crash handler using vectored exception handling.
//!
//! This module installs a vectored exception handler that catches fatal
//! exceptions before they reach the default handler. When an exception occurs:
//!
//! 1. Generate dumps for all registered sandboxes
//! 2. Return EXCEPTION_CONTINUE_SEARCH to chain to other handlers
//! 3. Allow OS to generate host crash dump (if configured)
//!
//! # Exceptions Handled
//!
//! - EXCEPTION_ACCESS_VIOLATION (0xC0000005): Access violation
//! - EXCEPTION_ILLEGAL_INSTRUCTION (0xC000001D): Illegal instruction
//! - EXCEPTION_INT_DIVIDE_BY_ZERO (0xC0000094): Integer divide by zero
//! - EXCEPTION_STACK_OVERFLOW (0xC00000FD): Stack overflow
//! - EXCEPTION_ARRAY_BOUNDS_EXCEEDED (0xC000008C): Array bounds exceeded
//! - EXCEPTION_FLT_* (various): Floating point exceptions
//!
//! # Why AddVectoredExceptionHandler?
//!
//! We use `AddVectoredExceptionHandler` instead of `SetUnhandledExceptionFilter`
//! because:
//! - It's called BEFORE SEH unwinding starts (we see the exception first)
//! - It properly chains to other handlers
//! - It's more reliable with threads
//! - SetUnhandledExceptionFilter can be bypassed by SEH
//!
//! We don't use `WerRegisterRuntimeExceptionModule` because:
//! - It requires a separate DLL
//! - It's more complex to set up
//! - Our use case is simpler (just dump sandboxes)

use std::sync::atomic::{AtomicBool, Ordering};

use windows::Win32::Foundation::{
    EXCEPTION_ACCESS_VIOLATION, EXCEPTION_ARRAY_BOUNDS_EXCEEDED, EXCEPTION_FLT_DENORMAL_OPERAND,
    EXCEPTION_FLT_DIVIDE_BY_ZERO, EXCEPTION_FLT_INEXACT_RESULT, EXCEPTION_FLT_INVALID_OPERATION,
    EXCEPTION_FLT_OVERFLOW, EXCEPTION_FLT_STACK_CHECK, EXCEPTION_FLT_UNDERFLOW,
    EXCEPTION_ILLEGAL_INSTRUCTION, EXCEPTION_INT_DIVIDE_BY_ZERO, EXCEPTION_INT_OVERFLOW,
    EXCEPTION_PRIV_INSTRUCTION, EXCEPTION_STACK_OVERFLOW, NTSTATUS,
};
use windows::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS, IsDebuggerPresent,
};
use windows::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD, RegCloseKey, RegOpenKeyExW, RegQueryValueExW,
};
use windows::core::PCWSTR;

/// Flag to prevent recursive crash handling.
///
/// If we crash while handling a crash, don't try to handle it again.
static IN_CRASH_HANDLER: AtomicBool = AtomicBool::new(false);

/// Check if crash dumps are likely to be generated on Windows.
///
/// This checks:
/// 1. If a debugger is attached (debugger will handle the crash)
/// 2. Windows Error Reporting (WER) disabled state
///
/// All checks are defensive and handle permission/access errors gracefully.
/// If we can't determine the state, we assume dumps are enabled (fail-open).
///
/// # Returns
///
/// true if crash dumps are likely enabled, false if clearly disabled
fn are_crash_dumps_enabled() -> bool {
    // Check 1: If a debugger is attached, it will handle crashes
    // This is always safe to check
    unsafe {
        if IsDebuggerPresent().as_bool() {
            // Debugger present - it will handle the crash
            return true;
        }
    }

    // Check 2: Check if WER is completely disabled
    // Registry key: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting
    // Value: Disabled (DWORD) - if 1, WER is disabled
    //
    // This check might fail due to permissions, which is fine (fail-open)
    unsafe {
        let key_path: Vec<u16> = "SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\0"
            .encode_utf16()
            .collect();
        let mut hkey = std::mem::zeroed();

        if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(key_path.as_ptr()),
            Some(0),
            KEY_READ,
            &mut hkey,
        )
        .is_ok()
        {
            let value_name: Vec<u16> = "Disabled\0".encode_utf16().collect();
            let mut data: u32 = 0;
            let mut data_size: u32 = std::mem::size_of::<u32>() as u32;
            let mut value_type = std::mem::zeroed();

            let query_result = RegQueryValueExW(
                hkey,
                PCWSTR(value_name.as_ptr()),
                None,
                Some(&mut value_type),
                Some(&mut data as *mut u32 as *mut u8),
                Some(&mut data_size),
            );

            // Close the key before checking results
            let _ = RegCloseKey(hkey);

            if query_result.is_ok() && value_type == REG_DWORD && data == 1 {
                // WER is explicitly disabled
                return false;
            }
        }
        // If we couldn't read the registry (permission denied, key doesn't exist, etc.),
        // fail-open: assume dumps are enabled
    }

    // All checks passed or couldn't determine - assume enabled (fail-open)
    true
}

/// Initialize crash handlers using vectored exception handling.
///
/// Called once on first sandbox registration.
///
/// Only installs handlers if crash dumps are likely to be generated.
/// This checks if WER is disabled or if a debugger is attached.
pub(super) fn init_crash_handlers() {
    // Check if crash dumps are likely to be generated
    if !are_crash_dumps_enabled() {
        log::info!(
            "Crash dumps disabled on this system (WER disabled), skipping crash handler installation"
        );
        return;
    }

    unsafe {
        // Add vectored exception handler
        // First argument: 1 = add to front of chain (we want to see exceptions first)
        // Returns handle on success, null on failure
        let handler = AddVectoredExceptionHandler(1, Some(vectored_exception_handler));

        if handler.is_null() {
            // Failed to install handler - this is bad but not fatal
            log::error!("Failed to install Hyperlight crash handler on Windows");
        }
        // We never remove the handler - it stays installed for the life of the process
    }
}

/// Vectored exception handler for fatal exceptions.
///
/// # Safety
///
/// This function is called by Windows as an exception handler.
/// It's relatively safe to call Rust code here (unlike signal handlers on Linux),
/// but we still need to be careful about locking and potential re-entrancy.
///
/// # Arguments
///
/// * `exception_info` - Pointer to EXCEPTION_POINTERS structure
///
/// # Returns
///
/// EXCEPTION_CONTINUE_SEARCH to allow other handlers to run
unsafe extern "system" fn vectored_exception_handler(
    exception_info: *mut EXCEPTION_POINTERS,
) -> i32 {
    // Prevent recursive crash handling - check this FIRST before doing anything else
    if IN_CRASH_HANDLER.swap(true, Ordering::SeqCst) {
        // We crashed while handling a crash - bail out immediately
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if exception_info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // SAFETY: We've checked that exception_info is not null
    let exception_record = unsafe { (*exception_info).ExceptionRecord };
    if exception_record.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // SAFETY: We've checked that exception_record is not null
    let exception_code = unsafe { (*exception_record).ExceptionCode };

    // Check if this is a fatal exception we care about
    if !is_fatal_exception(exception_code) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Try to write a message to stderr
    eprintln!(
        "Hyperlight: Host process crashed (exception 0x{:X}), generating sandbox dumps...",
        exception_code.0
    );

    // Generate dumps for all registered sandboxes
    // On Windows, this is safer than on Linux because:
    // - We're not in a signal handler (no async-signal-safety restrictions)
    // - Exception handlers can safely allocate, lock mutexes, do I/O, etc.
    // - Still need to be careful about re-entrancy (hence the IN_CRASH_HANDLER flag)
    let dump_count = super::generate_crash_dumps();

    if dump_count > 0 {
        eprintln!("Hyperlight: Generated {} sandbox dump(s)", dump_count);
    }

    // Always return EXCEPTION_CONTINUE_SEARCH to chain to other handlers
    // This allows:
    // - Other vectored exception handlers to run
    // - SEH handlers to run
    // - Windows Error Reporting to generate a minidump
    // - The OS default handler to terminate the process
    EXCEPTION_CONTINUE_SEARCH
}

/// Check if an exception code represents a fatal crash.
///
/// # Arguments
///
/// * `code` - Windows exception code
///
/// # Returns
///
/// true if this exception should trigger dump generation
fn is_fatal_exception(code: NTSTATUS) -> bool {
    matches!(
        code,
        EXCEPTION_ACCESS_VIOLATION
            | EXCEPTION_ILLEGAL_INSTRUCTION
            | EXCEPTION_INT_DIVIDE_BY_ZERO
            | EXCEPTION_STACK_OVERFLOW
            | EXCEPTION_ARRAY_BOUNDS_EXCEEDED
            | EXCEPTION_FLT_DENORMAL_OPERAND
            | EXCEPTION_FLT_DIVIDE_BY_ZERO
            | EXCEPTION_FLT_INEXACT_RESULT
            | EXCEPTION_FLT_INVALID_OPERATION
            | EXCEPTION_FLT_OVERFLOW
            | EXCEPTION_FLT_STACK_CHECK
            | EXCEPTION_FLT_UNDERFLOW
            | EXCEPTION_INT_OVERFLOW
            | EXCEPTION_PRIV_INSTRUCTION
    )
}
