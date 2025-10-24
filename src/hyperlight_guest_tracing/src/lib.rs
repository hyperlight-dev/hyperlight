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

#![no_std]

/// Expose invariant TSC module
pub mod invariant_tsc;

/// Defines internal guest state
#[cfg(feature = "trace")]
mod state;

/// Defines guest tracing Subscriber
#[cfg(feature = "trace")]
mod subscriber;

/// Defines a type to iterate over spans/events fields
#[cfg(feature = "trace")]
mod visitor;

/// Type to get the relevant information from the internal state
/// and expose it to the host
#[cfg(feature = "trace")]
pub use state::TraceBatchInfo;
#[cfg(feature = "trace")]
pub use trace::{
    end_trace, flush, init_guest_tracing, is_trace_enabled, new_call, reset, serialized_data,
};

/// This module is gated because some of these types are also used on the host, but we want
/// only the guest to allocate and allow the functionality intended for the guest.
#[cfg(feature = "trace")]
mod trace {
    extern crate alloc;
    use alloc::sync::{Arc, Weak};

    use spin::Mutex;
    use tracing::log::LevelFilter;

    use crate::state::GuestState;
    use crate::subscriber::GuestSubscriber;

    /// Weak reference to the guest state so we can manually trigger flush to host
    /// The `GuestState` is ONLY accessed from two places:
    /// - The tracing subscriber, when spans/events are created in the guest
    /// - The guest tracing API, when we want manual control to flush the events to the host
    ///
    /// The mutex ensures safe access to the state from both places.
    static GUEST_STATE: spin::Once<Weak<Mutex<GuestState>>> = spin::Once::new();

    /// Initialize the guest tracing subscriber as global default.
    pub fn init_guest_tracing(guest_start_tsc: u64, max_log_level: LevelFilter) {
        // Set as global default if not already set.
        if tracing_core::dispatcher::has_been_set() {
            return;
        }
        let sub = GuestSubscriber::new(guest_start_tsc, max_log_level);
        let state = sub.state();
        // Store state Weak<GuestState> to use later at runtime
        GUEST_STATE.call_once(|| Arc::downgrade(state));

        // Set global dispatcher
        let _ = tracing_core::dispatcher::set_global_default(tracing_core::Dispatch::new(sub));
    }

    /// Ends the current trace by ending all active spans in the
    /// internal state and storing the end timestamps.
    ///
    /// This expects an outb call to send the spans to the host.
    /// After calling this function, the internal state is marked
    /// for cleaning on the next access.
    ///
    /// NOTE: Panics if unable to lock the guest state.
    pub fn end_trace() {
        if let Some(w) = GUEST_STATE.get()
            && let Some(state_mutex) = w.upgrade()
        {
            // We want to protect against re-entrancy issues produced by tracing code that locks
            // the state and then causes an exception that tries to lock the state again.
            //
            // For example:
            // - 1. A span is created, locking the state
            // - 2. An exception occurs while the span is being created (e.g. not enough memory, etc.)
            // - 3. The exception handler uses the tracing API to send the trace data to the host
            // or just create spans/events for logging purposes.
            // - 4. The tracing API tries to lock the state again, causing a deadlock.
            // To avoid this, we use try_lock and if we cannot acquire the lock, we panic to signal
            // the issue.
            let mut state = state_mutex
                .try_lock()
                .expect("guest_tracing: Unable to lock guest tracing state in `end_trace`");
            state.end_trace();
        }
    }

    /// Flushes the current trace data to prepare it for reading by the host.
    /// NOTE: Panics if unable to lock the guest state.
    pub fn flush() {
        if let Some(w) = GUEST_STATE.get()
            && let Some(state_mutex) = w.upgrade()
        {
            // We want to protect against re-entrancy issues produced by tracing code that locks
            // the state and then causes an exception that tries to lock the state again.
            //
            // For example:
            // - 1. A span is created, locking the state
            // - 2. An exception occurs while the span is being created (e.g. not enough memory, etc.)
            // - 3. The exception handler uses the tracing API to send the trace data to the host
            // or just create spans/events for logging purposes.
            // - 4. The tracing API tries to lock the state again, causing a deadlock.
            // To avoid this, we use try_lock and if we cannot acquire the lock, we panic to signal
            // the issue.
            let mut state = state_mutex
                .try_lock()
                .expect("Unable to lock GuestState in `flush`");

            state.flush();
        }
    }

    /// Resets the internal trace state for a new guest function call.
    /// This clears any existing spans/events from previous calls ensuring a clean state.
    /// NOTE: Panics if unable to lock the guest state.
    pub fn new_call(guest_start_tsc: u64) {
        if let Some(w) = GUEST_STATE.get()
            && let Some(state_mutex) = w.upgrade()
        {
            // We want to protect against re-entrancy issues produced by tracing code that locks
            // the state and then causes an exception that tries to lock the state again.
            //
            // For example:
            // - 1. A span is created, locking the state
            // - 2. An exception occurs while the span is being created (e.g. not enough memory, etc.)
            // - 3. The exception handler uses the tracing API to send the trace data to the host
            // or just create spans/events for logging purposes.
            // - 4. The tracing API tries to lock the state again, causing a deadlock.
            // To avoid this, we use try_lock and if we cannot acquire the lock, we panic to signal
            // the issue.
            let mut state = state_mutex
                .try_lock()
                .expect("Unable to lock GuestState in `new_call`");

            state.new_call(guest_start_tsc);
        }
    }

    /// Cleans the internal trace state by removing closed spans and events.
    /// This ensures that after a VM exit, we keep the spans that
    /// are still active (in the stack) and remove all other spans and events.
    /// NOTE: Panics if unable to lock the guest state.
    pub fn reset() {
        if let Some(w) = GUEST_STATE.get()
            && let Some(state_mutex) = w.upgrade()
        {
            // We want to protect against re-entrancy issues produced by tracing code that locks
            // the state and then causes an exception that tries to lock the state again.
            //
            // For example:
            // - 1. A span is created, locking the state
            // - 2. An exception occurs while the span is being created (e.g. not enough memory, etc.)
            // - 3. The exception handler uses the tracing API to send the trace data to the host
            // or just create spans/events for logging purposes.
            // - 4. The tracing API tries to lock the state again, causing a deadlock.
            // To avoid this, we use try_lock and if we cannot acquire the lock, we panic to signal
            // the issue.
            let mut state = state_mutex
                .try_lock()
                .expect("Unable to lock GuestState in `reset`");

            state.reset();
        }
    }

    /// Returns information about the current trace state needed by the host to read the spans.
    pub fn serialized_data() -> Option<(u64, u64)> {
        if let Some(w) = GUEST_STATE.get()
            && let Some(state_mutex) = w.upgrade()
        {
            // We want to protect against re-entrancy issues produced by tracing code that locks
            // the state and then causes an exception that tries to lock the state again.
            //
            // For example:
            // - 1. A span is created, locking the state
            // - 2. An exception occurs while the span is being created (e.g. not enough memory, etc.)
            // - 3. The exception handler uses the tracing API to send the trace data to the host
            // or just create spans/events for logging purposes.
            // - 4. The tracing API tries to lock the state again, causing a deadlock.
            // To avoid this, we use try_lock and if we cannot acquire the lock, we panic to signal
            // the issue.
            let state = state_mutex
                .try_lock()
                .expect("Unable to lock GuestState in `serialized_data`");

            state.serialized_data()
        } else {
            None
        }
    }

    /// Returns true if tracing is enabled (the guest tracing state is initialized).
    pub fn is_trace_enabled() -> bool {
        GUEST_STATE
            .get()
            .map(|w| w.upgrade().is_some())
            .unwrap_or(false)
    }
}
