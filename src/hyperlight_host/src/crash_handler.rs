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

//! Host process crash handler for generating sandbox dumps.
//!
//! This module provides crash detection and dump generation for sandboxes
//! when the host process crashes due to unhandled signals (Linux) or
//! exceptions (Windows).
//!
//! # Architecture
//!
//! - **Registry**: Global map of sandbox ID -> (hypervisor raw pointer, dump enabled flag)
//! - **Linux**: Signal handlers via `sigaction()` for fatal signals
//! - **Windows**: Vectored exception handler via `AddVectoredExceptionHandler()`
//! - **Automatic**: Initialized on first sandbox registration
//! - **Cleanup**: Entries removed on sandbox Drop
//!
//! # Usage
//!
//! The crash handler is automatically initialized when the first sandbox
//! is created. No explicit setup is required. When the host process crashes,
//! dumps are generated for all registered sandboxes that have `guest_core_dump`
//! enabled in their runtime configuration.
//!
//! # Feature Flag
//!
//! This entire module requires the `crashdump` feature to be enabled.

use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, Ordering};

use dashmap::DashMap;
use once_cell::sync::Lazy;

use crate::hypervisor::Hypervisor;
use crate::{Result, new_error};

/// Entry in the sandbox registry.
///
/// Stores a raw pointer to the hypervisor (unsafe!).
/// This is safe during crash handling because:
/// 1. The sandbox owns the hypervisor and won't drop it while registered
/// 2. During a crash, normal thread-safety doesn't matter
/// 3. We only access these pointers during crash (process is dying anyway)
struct SandboxEntry {
    /// Raw pointer to the hypervisor (UNSAFE - only valid while sandbox is alive)
    hypervisor_ptr: *const dyn Hypervisor,
}

// SAFETY: We only access these pointers during crash handling, when the process
// is dying anyway and normal thread-safety rules don't apply
unsafe impl Send for SandboxEntry {}
unsafe impl Sync for SandboxEntry {}

/// Global registry of active sandboxes.
///
/// Maps sandbox ID to hypervisor pointer. Uses DashMap for lock-free concurrent access.
/// Entries are removed when sandboxes are dropped.
static SANDBOX_REGISTRY: Lazy<DashMap<u64, SandboxEntry>> = Lazy::new(DashMap::new);

/// Fast check for whether crash handlers have been initialized.
///
/// This atomic bool allows us to skip the initialization lock on the fast path
/// (after first initialization). We use Acquire/Release ordering to ensure
/// proper synchronization with the initialization code.
static INITIALIZED_FAST: AtomicBool = AtomicBool::new(false);

/// Tracks if initialization failed (poisoned mutex or other error).
///
/// If true, we skip all crash handler operations since they won't work anyway.
static INITIALIZATION_FAILED: AtomicBool = AtomicBool::new(false);

/// Mutex-protected initialization flag (only used during first initialization).
/// We use std::sync::Mutex here (not parking_lot) so we can detect poisoning.
static INITIALIZED: Lazy<StdMutex<bool>> = Lazy::new(|| StdMutex::new(false));

/// Register a sandbox with the crash handler.
///
/// This function:
/// 1. Stores a raw pointer to the hypervisor (unsafe but controlled)
/// 2. Initializes crash handlers on first call (lazy init)
///
/// Only registers the sandbox if crash dumps are enabled. If disabled,
/// this function returns immediately without doing anything.
///
/// # Arguments
///
/// * `sandbox_id` - Unique ID of the sandbox
/// * `hypervisor` - Reference to the hypervisor (we store a raw pointer)
///
/// # Safety
///
/// The caller MUST ensure the sandbox is unregistered before the hypervisor is dropped!
/// This is enforced by MultiUseSandbox::Drop.
///
/// # Errors
///
/// Returns an error if the mutex is poisoned (extremely rare, would indicate
/// a serious issue elsewhere in the program).
pub fn register_sandbox(sandbox_id: u64, hypervisor: &dyn Hypervisor) -> Result<()> {
    // Check if initialization previously failed - no point trying again
    if INITIALIZATION_FAILED.load(Ordering::Acquire) {
        return Err(new_error!(
            "Crash handler initialization previously failed, skipping registration"
        ));
    }

    // Fast path: check if already initialized (lock-free!)
    if !INITIALIZED_FAST.load(Ordering::Acquire) {
        // Slow path: need to initialize (only happens once)
        match INITIALIZED.lock() {
            Ok(mut initialized) => {
                // Double-check inside the lock (another thread might have initialized)
                if !*initialized {
                    platform::init_crash_handlers();
                    *initialized = true;
                    // Mark as initialized atomically (Release ensures all init is visible)
                    INITIALIZED_FAST.store(true, Ordering::Release);
                }
            }
            Err(e) => {
                // Mutex is poisoned - mark as failed and return error
                INITIALIZATION_FAILED.store(true, Ordering::Release);
                return Err(new_error!(
                    "INITIALIZED mutex poisoned during crash handler init: {}",
                    e
                ));
            }
        }
    }

    // Add entry to registry (lock-free with DashMap!)
    let hypervisor_ptr = unsafe {
        std::mem::transmute::<*const dyn Hypervisor, *const dyn Hypervisor>(
            hypervisor as *const dyn Hypervisor,
        )
    };

    SANDBOX_REGISTRY.insert(sandbox_id, SandboxEntry { hypervisor_ptr });

    Ok(())
}

/// Unregister a sandbox from the crash handler.
///
/// Called automatically by MultiUseSandbox::Drop.
///
/// # Arguments
///
/// * `sandbox_id` - Unique ID of the sandbox to unregister
pub fn unregister_sandbox(sandbox_id: u64) {
    // Lock-free removal with DashMap
    SANDBOX_REGISTRY.remove(&sandbox_id);
}

/// Generate dumps for all registered sandboxes.
///
/// Called by platform-specific crash handlers when a fatal signal/exception occurs.
/// Iterates through the registry and generates dumps for all registered sandboxes.
/// Only sandboxes with dumps enabled are registered, so all entries get dumped.
///
/// # Safety
///
/// This function is called during crash handling and:
/// - Dereferences raw pointers (unsafe but acceptable during crash)
/// - May violate async-signal-safety on Linux
/// - Accesses hypervisor state without locks
///
/// All of this is acceptable because the process is crashing anyway.
///
/// # Returns
///
/// Number of dumps successfully generated.
pub(crate) fn generate_crash_dumps() -> usize {
    let mut dump_count = 0;

    // Iterate over the lock-free registry
    for entry_ref in SANDBOX_REGISTRY.iter() {
        let entry = entry_ref.value();

        // SAFETY: This is unsafe! We're dereferencing a raw pointer.
        // This is acceptable because:
        // 1. The sandbox registers/unregisters properly via Drop
        // 2. During a crash, the process is dying anyway
        // 3. We're willing to accept potential UB during crash handling
        unsafe {
            let hypervisor = &*entry.hypervisor_ptr;

            // Try to generate the crash dump
            // This is NOT async-signal-safe (file I/O, allocations, etc.)
            // but we're crashing, so this is acceptable
            //
            // Catch panics: If generating one dump panics, it maybe indicates
            // a systemic issue so we short-circuit
            // rather than risk cascading failures
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                crate::hypervisor::crashdump::generate_crashdump(hypervisor)
            }));

            match result {
                Ok(Ok(())) => {
                    dump_count += 1;
                }
                Ok(Err(_)) => {
                    // Silent failure - dump generation returned an error
                }
                Err(_) => {
                    // Panic during dump generation - abort remaining dumps
                    // This may indicate a systemic issue
                    break;
                }
            }
        }
    }

    dump_count
}

// Platform-specific implementations
#[cfg(target_os = "linux")]
#[path = "crash_handler/linux.rs"]
mod platform;

#[cfg(target_os = "windows")]
#[path = "crash_handler/windows.rs"]
mod platform;
