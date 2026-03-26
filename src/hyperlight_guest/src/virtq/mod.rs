/*
Copyright 2026  The Hyperlight Authors.

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

//! Guest-side virtqueue support.
//!
//! Global context is installed once via [`set_global_context`] and
//! accessed via [`with_context`].

pub mod context;
pub mod mem;

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};

use context::GuestContext;
use hyperlight_common::layout::{SCRATCH_TOP_SNAPSHOT_GENERATION_OFFSET, scratch_top_ptr};
pub use mem::GuestMemOps;

// Init state machine
const UNINITIALIZED: u8 = 0;
const INITIALIZED: u8 = 1;
static INIT_STATE: AtomicU8 = AtomicU8::new(UNINITIALIZED);

/// Check if the global context has been initialized.
pub fn is_initialized() -> bool {
    INIT_STATE.load(Ordering::Acquire) == INITIALIZED
}

// Storage: UnsafeCell guarded by atomic init state.
struct SyncWrap<T>(T);
unsafe impl<T> Sync for SyncWrap<T> {}

static GLOBAL_CONTEXT: SyncWrap<UnsafeCell<Option<GuestContext>>> = SyncWrap(UnsafeCell::new(None));

/// Access the global guest context via closure.
///
/// # Panics
///
/// Panics if the context has not been initialized.
pub fn with_context<R>(f: impl FnOnce(&mut GuestContext) -> R) -> R {
    assert!(
        INIT_STATE.load(Ordering::Acquire) == INITIALIZED,
        "guest context not initialized"
    );
    let ctx = unsafe { &mut *GLOBAL_CONTEXT.0.get() };
    f(ctx.as_mut().unwrap())
}

/// Install the global guest context. Called once during guest init.
///
/// # Panics
///
/// Panics if called more than once.
pub fn set_global_context(ctx: GuestContext) {
    if INIT_STATE
        .compare_exchange(
            UNINITIALIZED,
            INITIALIZED,
            Ordering::SeqCst,
            Ordering::SeqCst,
        )
        .is_err()
    {
        panic!("guest context already initialized");
    }
    unsafe { *GLOBAL_CONTEXT.0.get() = Some(ctx) };
}

/// Reset the global context if a snapshot restore was detected.
/// Compares the virtq generation counter in scratch-top metadata.
pub fn reset_global_context() {
    if !is_initialized() {
        return;
    }
    let current_gen = read_gen();
    with_context(|ctx| {
        if current_gen != ctx.generation() {
            ctx.reset(current_gen);
        }
    });
}

/// Read the current virtqueue generation from scratch-top metadata.
fn read_gen() -> u64 {
    unsafe { *scratch_top_ptr::<u64>(SCRATCH_TOP_SNAPSHOT_GENERATION_OFFSET) }
}
