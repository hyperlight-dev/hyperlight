// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Guest transport context and memory access.
//!
//! Global context is installed once via [`set_global_context`] and accessed via [`with_context`].

pub mod context;
pub mod mem;

use core::cell::RefCell;
use core::sync::atomic::{AtomicU8, Ordering};

pub use context::{GuestContext, QueueConfig};
pub use mem::GuestMemOps;

const UNINITIALIZED: u8 = 0;
const INITIALIZED: u8 = 1;

static INIT_STATE: AtomicU8 = AtomicU8::new(UNINITIALIZED);
static GLOBAL_CONTEXT: SyncWrap<RefCell<Option<GuestContext>>> = SyncWrap(RefCell::new(None));

struct SyncWrap<T>(T);

// SAFETY: Hyperlight guests have one vCPU and serialize guest entry.
unsafe impl<T> Sync for SyncWrap<T> {}

/// Whether the virtqueue context is installed.
pub fn is_initialized() -> bool {
    INIT_STATE.load(Ordering::Acquire) == INITIALIZED
}

/// Run a closure with the global virtqueue context.
///
/// # Panics
///
/// Panics if the context is uninitialized or already borrowed.
pub fn with_context<R>(f: impl FnOnce(&mut GuestContext) -> R) -> R {
    assert!(is_initialized(), "transport context not initialized");
    let mut context = GLOBAL_CONTEXT.0.borrow_mut();
    f(context.as_mut().expect("transport context missing"))
}

/// Install the global transport context.
///
/// # Panics
///
/// Panics if a context was already installed.
pub fn set_global_context(context: GuestContext) {
    assert!(
        INIT_STATE
            .compare_exchange(
                UNINITIALIZED,
                INITIALIZED,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok(),
        "virtqueue context already initialized"
    );
    *GLOBAL_CONTEXT.0.borrow_mut() = Some(context);
}
