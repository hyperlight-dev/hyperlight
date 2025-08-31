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
#[cfg(feature = "trace")]
pub use trace::init_guest_tracing;

/// Module for checking invariant TSC support and reading the timestamp counter
pub mod invariant_tsc {
    use core::arch::x86_64::{__cpuid, _rdtsc};

    /// Check if the processor supports invariant TSC
    ///
    /// Returns true if CPUID.80000007H:EDX[8] is set, indicating invariant TSC support
    pub fn has_invariant_tsc() -> bool {
        // Check if extended CPUID functions are available
        let max_extended = unsafe { __cpuid(0x80000000) };
        if max_extended.eax < 0x80000007 {
            return false;
        }

        // Query CPUID.80000007H for invariant TSC support
        let cpuid_result = unsafe { __cpuid(0x80000007) };

        // Check bit 8 of EDX register for invariant TSC support
        (cpuid_result.edx & (1 << 8)) != 0
    }

    /// Read the timestamp counter
    ///
    /// This function provides a high-performance timestamp by reading the TSC.
    /// Should only be used when invariant TSC is supported for reliable timing.
    ///
    /// # Safety
    /// This function uses unsafe assembly instructions but is safe to call.
    /// However, the resulting timestamp is only meaningful if invariant TSC is supported.
    pub fn read_tsc() -> u64 {
        unsafe { _rdtsc() }
    }
}

#[cfg(feature = "trace")]
mod trace {
    extern crate alloc;
    use alloc::sync::{Arc, Weak};
    use tracing_core::span::{Attributes, Id, Record};
    use tracing_core::subscriber::Subscriber;
    use tracing_core::{Event, Metadata};
    use spin::Mutex;

    /// Weak reference to the guest state so we can manually trigger export to host
    static GUEST_STATE: spin::Once<Weak<Mutex<GuestState>>> = spin::Once::new();

    pub struct GuestState {
        guest_start_tsc: u64,
    }

    impl GuestState
    {
        fn new(guest_start_tsc: u64) -> Self {
            Self {
                guest_start_tsc,
            }
        }
    }

    /// The subscriber is used to collect spans and events in the guest.
    struct GuestSubscriber {
        /// Internal state that holds the spans and events
        /// Protected by a Mutex for inner mutability
        /// A reference to this state is stored in a static variable
        state: Arc<Mutex<GuestState>>,
    }

    impl GuestSubscriber {
        fn new(guest_start_tsc: u64) -> Self {
            Self {
                state: Arc::new(Mutex::new(GuestState::new(guest_start_tsc))),
            }
        }
        fn state(&self) -> &Arc<Mutex<GuestState>> {
            &self.state
        }
    }

    impl Subscriber for GuestSubscriber {
        fn enabled(&self, _md: &Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, attrs: &Attributes<'_>) -> Id {
            unimplemented!()
        }

        fn record(&self, id: &Id, values: &Record<'_>) {
            unimplemented!()
        }

        fn event(&self, event: &Event<'_>) {
            unimplemented!()
        }

        fn enter(&self, id: &Id) {
            unimplemented!()
        }

        fn exit(&self, id: &Id) {
            unimplemented!()
        }

        fn try_close(&self, id: Id) -> bool {
            unimplemented!()
        }

        fn record_follows_from(&self, _span: &Id, _follows: &Id) {
            // no-op: we don't track follows-from relationships
        }
    }

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
}
