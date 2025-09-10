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
use heapless as hl;

/// Expose invariant TSC module
pub mod invariant_tsc;

/// Defines internal guest state
#[cfg(feature = "trace")]
mod state;

/// Defines guest tracing Subscriber
#[cfg(feature = "trace")]
mod subscriber;

#[cfg(feature = "trace")]
pub use trace::{init_guest_tracing, set_start_tsc};

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
        if let Some(w) = GUEST_STATE.get() {
            if let Some(state) = w.upgrade() {
                state.lock().set_start_tsc(guest_start_tsc);
            }
        }
    }
}
