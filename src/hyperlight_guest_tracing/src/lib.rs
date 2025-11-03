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
    clean_trace_state, end_trace, guest_trace_info, init_guest_tracing, is_trace_enabled,
    set_start_tsc,
};

/// This module is gated because some of these types are also used on the host, but we want
/// only the guest to allocate and allow the functionality intended for the guest.
#[cfg(feature = "trace")]
mod trace {
    extern crate alloc;
    use alloc::sync::{Arc, Weak};

    use spin::Mutex;

    use super::*;
    use crate::state::GuestState;
    use crate::subscriber::GuestSubscriber;

    /// Weak reference to the guest state so we can manually trigger flush to host
    static GUEST_STATE: spin::Once<Weak<Mutex<GuestState>>> = spin::Once::new();

    /// Initialize the guest tracing subscriber as global default.
    pub fn init_guest_tracing(guest_start_tsc: u64) {
        // Set as global default if not already set.
        if tracing_core::dispatcher::has_been_set() {
            return;
        }
        let sub = GuestSubscriber::new(guest_start_tsc);
        let state = sub.state();
        // Store state Weak<GuestState> to use later at runtime
        GUEST_STATE.call_once(|| Arc::downgrade(state));

        // Set global dispatcher
        let _ = tracing_core::dispatcher::set_global_default(tracing_core::Dispatch::new(sub));
    }

    /// Sets the guset starting timestamp reported to the host on a VMExit
    pub fn set_start_tsc(guest_start_tsc: u64) {
        if let Some(w) = GUEST_STATE.get()
            && let Some(state) = w.upgrade()
        {
            state.lock().set_start_tsc(guest_start_tsc);
        }
    }

    /// Ends the current trace by ending all active spans in the
    /// internal state and storing the end timestamps.
    ///
    /// This expects an outb call to send the spans to the host.
    /// After calling this function, the internal state is marked
    /// for cleaning on the next access.
    pub fn end_trace() {
        if let Some(w) = GUEST_STATE.get()
            && let Some(state) = w.upgrade()
        {
            state.lock().end_trace();
        }
    }

    /// Cleans the internal trace state by removing closed spans and events.
    /// This ensures that after a VM exit, we keep the spans that
    /// are still active (in the stack) and remove all other spans and events.
    pub fn clean_trace_state() {
        if let Some(w) = GUEST_STATE.get()
            && let Some(state) = w.upgrade()
        {
            state.lock().clean();
        }
    }

    /// Returns information about the current trace state needed by the host to read the spans.
    pub fn guest_trace_info() -> Option<TraceBatchInfo> {
        let mut res = None;
        if let Some(w) = GUEST_STATE.get()
            && let Some(state) = w.upgrade()
        {
            res = Some(state.lock().guest_trace_info());
        }
        res
    }

    /// Returns true if tracing is enabled (the guest tracing state is initialized).
    pub fn is_trace_enabled() -> bool {
        GUEST_STATE
            .get()
            .map(|w| w.upgrade().is_some())
            .unwrap_or(false)
    }
}
