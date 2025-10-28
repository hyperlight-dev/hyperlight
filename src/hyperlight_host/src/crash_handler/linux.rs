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

//! Linux-specific crash handler using signal handlers.
//!
//! This module installs signal handlers for fatal signals that would
//! normally trigger a core dump. When such a signal is received:
//!
//! 1. Generate dumps for all registered sandboxes
//! 2. Chain to the previous signal handler (if any)
//! 3. Re-raise the signal to allow OS to generate host core dump
//!
//! # Signals Handled
//!
//! - SIGSEGV: Segmentation fault
//! - SIGABRT: Abort signal
//! - SIGBUS: Bus error
//! - SIGFPE: Floating point exception
//! - SIGILL: Illegal instruction
//! - SIGQUIT: Quit signal
//! - SIGTRAP: Trace/breakpoint trap
//! - SIGSYS: Bad system call
//!
//! # Async-Signal-Safety
//!
//! Signal handlers should only call async-signal-safe functions.
//! However, we intentionally violate this because:
//! - The process is crashing anyway
//! - We want to generate useful dumps
//! - Silent failure is acceptable
//!
//! The handler is annotated with comments explaining which operations
//! are NOT async-signal-safe.

use std::sync::atomic::{AtomicBool, Ordering};

use libc::{SA_RESTART, SA_SIGINFO, c_int, sigaction, siginfo_t};

/// Flag to prevent recursive crash handling.
///
/// If we crash while handling a crash, don't try to handle it again.
static IN_CRASH_HANDLER: AtomicBool = AtomicBool::new(false);

/// Storage for previous signal handlers.
///
/// We chain to these after generating our dumps.
static mut PREV_SIGSEGV: Option<sigaction> = None;
static mut PREV_SIGABRT: Option<sigaction> = None;
static mut PREV_SIGBUS: Option<sigaction> = None;
static mut PREV_SIGFPE: Option<sigaction> = None;
static mut PREV_SIGILL: Option<sigaction> = None;
static mut PREV_SIGQUIT: Option<sigaction> = None;
static mut PREV_SIGTRAP: Option<sigaction> = None;
static mut PREV_SIGSYS: Option<sigaction> = None;

/// Check if core dumps are enabled on this system.
///
/// Returns true if the OS will generate a core dump for the process on crash.
/// This checks multiple Linux configuration options that can disable core dumps:
///
/// 1. RLIMIT_CORE: Resource limit (ulimit -c)
/// 2. /proc/sys/kernel/core_pattern: Must not be empty or "|/bin/false"
/// 3. Process dumpable flag (prctl PR_GET_DUMPABLE)
///
/// All checks are defensive and handle permission errors gracefully.
/// If we can't determine the state, we assume dumps are enabled (fail-open).
///
/// # Returns
///
/// true if core dumps are likely enabled, false if clearly disabled
fn are_core_dumps_enabled() -> bool {
    // Check 1: RLIMIT_CORE (ulimit -c)
    // This should always work - no special permissions needed
    unsafe {
        let mut rlim: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_CORE, &mut rlim) == 0 && rlim.rlim_cur == 0 {
            // Core size limit is 0 - definitely disabled
            return false;
        }

        // If getrlimit failed continue checking other options
    }

    // Check 2: /proc/sys/kernel/core_pattern
    // This might fail in containers or with restricted permissions
    // If we can't read it, we assume dumps are enabled (fail-open)
    match std::fs::read_to_string("/proc/sys/kernel/core_pattern") {
        Ok(pattern) => {
            let pattern = pattern.trim();
            if pattern.is_empty()
                || pattern == "|/bin/false"
                || pattern == "|/usr/bin/false"
                || pattern.starts_with("|/bin/false ")
                || pattern.starts_with("|/usr/bin/false ")
            {
                // Core pattern is explicitly disabled
                return false;
            }
        }
        Err(_) => {
            // Can't read the file (permission denied, doesn't exist in container, etc.)
            // Fail-open: assume dumps are enabled
        }
    }

    // Check 3: Process dumpable flag
    // This should always work - no special permissions needed
    // Some security policies (like running setuid) disable dumping
    unsafe {
        let dumpable = libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0);
        if dumpable == 0 {
            // Process is marked non-dumpable (0 = non-dumpable)
            return false;
        }
        // dumpable == 1 means normal dumpable
        // dumpable == 2 means dumpable but with restrictions
        // dumpable < 0 means error (very unlikely)
        // In all these cases, continue
    }

    // All checks passed or couldn't determine - assume enabled (fail-open)

    true
}

/// Initialize crash handlers for all fatal signals.
///
/// Called once on first sandbox registration.
///
/// Only installs handlers if the OS will actually generate core dumps.
/// If core dumps are disabled, we don't install handlers since there's
/// no point generating sandbox dumps when the host won't dump.
pub(super) fn init_crash_handlers() {
    // Check if core dumps are enabled
    if !are_core_dumps_enabled() {
        log::info!("Core dumps disabled on this system, skipping crash handler installation");
        return;
    }

    unsafe {
        install_handler(libc::SIGSEGV, &raw mut PREV_SIGSEGV);
        install_handler(libc::SIGABRT, &raw mut PREV_SIGABRT);
        install_handler(libc::SIGBUS, &raw mut PREV_SIGBUS);
        install_handler(libc::SIGFPE, &raw mut PREV_SIGFPE);
        install_handler(libc::SIGILL, &raw mut PREV_SIGILL);
        install_handler(libc::SIGQUIT, &raw mut PREV_SIGQUIT);
        install_handler(libc::SIGTRAP, &raw mut PREV_SIGTRAP);
        install_handler(libc::SIGSYS, &raw mut PREV_SIGSYS);
    }
}

/// Install a signal handler and save the previous handler.
///
/// # Safety
///
/// Calls unsafe libc::sigaction. Caller must ensure `prev_handler`
/// points to valid static storage.
unsafe fn install_handler(signal: c_int, prev_handler: *mut Option<sigaction>) {
    // SAFETY: All operations in this block are guarded by unsafe blocks
    // and are part of the signal handler installation process
    unsafe {
        let mut sa: sigaction = std::mem::zeroed();
        sa.sa_sigaction = crash_signal_handler as usize;
        sa.sa_flags = SA_SIGINFO | SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);

        let mut old_sa: sigaction = std::mem::zeroed();

        if libc::sigaction(signal, &sa, &mut old_sa) == 0 {
            // Only save the previous handler if it was actually set
            // (not SIG_DFL or SIG_IGN)
            if old_sa.sa_sigaction != libc::SIG_DFL && old_sa.sa_sigaction != libc::SIG_IGN {
                *prev_handler = Some(old_sa);
            }
        }
    }
    // If sigaction failed or there was no previous handler, prev_handler stays None (its initial value)
}

/// Signal handler for fatal signals.
///
/// # Safety
///
/// This function is called by the OS as a signal handler.
/// It violates async-signal-safety but this is acceptable during crash.
///
/// # Arguments
///
/// * `signal` - Signal number
/// * `_info` - Signal info (unused)
/// * `_context` - Signal context (unused)
extern "C" fn crash_signal_handler(
    signal: c_int,
    _info: *mut siginfo_t,
    _context: *mut libc::c_void,
) {
    // Prevent recursive crash handling
    if IN_CRASH_HANDLER.swap(true, Ordering::SeqCst) {
        // We crashed while handling a crash - bail out immediately
        // Chain to previous handler or re-raise
        chain_to_previous_handler(signal);
        return;
    }

    // Try to write a message to stderr
    // write() with a string literal is async-signal-safe
    let msg = b"Hyperlight: Host process crashed, generating sandbox dump...\n";
    unsafe {
        libc::write(
            libc::STDERR_FILENO,
            msg.as_ptr() as *const libc::c_void,
            msg.len(),
        );
    }

    // Generate dumps for all registered sandboxes
    // NOTE: This is NOT async-signal-safe! It:
    // - Locks mutexes (SANDBOX_REGISTRY)
    // - Performs file I/O (writing dumps)
    // - May allocate memory
    // - Calls complex Rust code
    //
    // BUT: We're crashing anyway, so this is acceptable.
    // Worst case: We crash again and the recursive check above prevents infinite loop.
    let dump_count = super::generate_crash_dumps();

    // Try to report success to stderr (write is async-signal-safe)
    if dump_count > 0 {
        let success_msg = b"Hyperlight: Generated sandbox dumps\n";
        unsafe {
            libc::write(
                libc::STDERR_FILENO,
                success_msg.as_ptr() as *const libc::c_void,
                success_msg.len(),
            );
        }
    }

    // Chain to previous handler
    chain_to_previous_handler(signal);
}

/// Chain to the previous signal handler, or re-raise the signal.
///
/// This ensures that:
/// 1. Other crash handlers in the chain get invoked
/// 2. The OS default handler runs (generating host core dump if configured)
fn chain_to_previous_handler(signal: c_int) {
    unsafe {
        let prev_ptr = match signal {
            libc::SIGSEGV => &raw const PREV_SIGSEGV,
            libc::SIGABRT => &raw const PREV_SIGABRT,
            libc::SIGBUS => &raw const PREV_SIGBUS,
            libc::SIGFPE => &raw const PREV_SIGFPE,
            libc::SIGILL => &raw const PREV_SIGILL,
            libc::SIGQUIT => &raw const PREV_SIGQUIT,
            libc::SIGTRAP => &raw const PREV_SIGTRAP,
            libc::SIGSYS => &raw const PREV_SIGSYS,
            _ => {
                // Unknown signal - just re-raise
                libc::raise(signal);
                return;
            }
        };

        if let Some(old_sa) = (*prev_ptr).as_ref() {
            // We have a previous handler to chain to
            // Call the previous handler
            if old_sa.sa_flags & SA_SIGINFO != 0 {
                // Previous handler was SA_SIGINFO style
                let handler: extern "C" fn(c_int, *mut siginfo_t, *mut libc::c_void) =
                    std::mem::transmute(old_sa.sa_sigaction);
                handler(signal, std::ptr::null_mut(), std::ptr::null_mut());
            } else {
                // Previous handler was simple signal handler
                let handler: extern "C" fn(c_int) = std::mem::transmute(old_sa.sa_sigaction);
                handler(signal);
            }
            return;
        }

        // No previous handler, or it was SIG_DFL - restore default and re-raise
        let mut sa: sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_DFL;
        libc::sigaction(signal, &sa, std::ptr::null_mut());
        libc::raise(signal);
    }
}
