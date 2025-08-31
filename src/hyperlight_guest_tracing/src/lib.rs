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

const MAX_NO_OF_SPANS: usize = 10;
const MAX_NO_OF_EVENTS: usize = 10;
const MAX_NAME_LENGTH: usize = 64;
const MAX_TARGET_LENGTH: usize = 64;
const MAX_FIELD_KEY_LENGTH: usize = 32;
const MAX_FIELD_VALUE_LENGTH: usize = 96;
const MAX_NO_OF_FIELDS: usize = 8;

pub type Spans = hl::Vec<
    GuestSpan<
        MAX_NO_OF_EVENTS,
        MAX_NAME_LENGTH,
        MAX_TARGET_LENGTH,
        MAX_FIELD_KEY_LENGTH,
        MAX_FIELD_VALUE_LENGTH,
        MAX_NO_OF_FIELDS,
    >,
    MAX_NO_OF_SPANS,
>;

#[derive(Debug, Copy, Clone)]
pub enum TraceLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<tracing::Level> for TraceLevel {
    fn from(value: tracing::Level) -> Self {
        match value {
            tracing::Level::ERROR => Self::Error,
            tracing::Level::WARN => Self::Warn,
            tracing::Level::INFO => Self::Info,
            tracing::Level::DEBUG => Self::Debug,
            tracing::Level::TRACE => Self::Trace,
        }
    }
}
impl Into<tracing::Level> for TraceLevel {
    fn into(self) -> tracing::Level {
        match self {
            Self::Error => tracing::Level::ERROR,
            Self::Warn => tracing::Level::WARN,
            Self::Info => tracing::Level::INFO,
            Self::Debug => tracing::Level::DEBUG,
            Self::Trace => tracing::Level::TRACE,
        }
    }
}

pub struct GuestSpan<
    const EV: usize,
    const N: usize,
    const T: usize,
    const FK: usize,
    const FV: usize,
    const F: usize,
> {
    pub id: u64,
    pub parent_id: Option<u64>,
    pub level: TraceLevel,
    /// Span name
    pub name: hl::String<N>,
    /// Filename
    pub target: hl::String<T>,
    pub start_tsc: u64,
    pub end_tsc: Option<u64>,
    pub fields: hl::Vec<(hl::String<FK>, hl::String<FV>), F>,
    pub events: hl::Vec<GuestEvent<N, FK, FV, F>, EV>,
}

pub struct GuestEvent<const N: usize, const FK: usize, const FV: usize, const F: usize> {
    pub level: TraceLevel,
    pub name: hl::String<N>,
    /// Event name
    pub tsc: u64,
    pub fields: hl::Vec<(hl::String<FK>, hl::String<FV>), F>,
}

#[cfg(feature = "trace")]
mod trace {
    extern crate alloc;
    use alloc::sync::{Arc, Weak};
    use core::sync::atomic::AtomicU64;
    use tracing_core::span::{Attributes, Id, Record};
    use tracing_core::subscriber::Subscriber;
    use tracing_core::{Event, Metadata};
    use spin::Mutex;

    use super::*;

    /// Weak reference to the guest state so we can manually trigger flush to host
    static GUEST_STATE: spin::Once<Weak<Mutex<GuestState>>> = spin::Once::new();

    /// Helper type to define the guest state with the configured constants
    pub type GuestState = TraceState<
        MAX_NO_OF_SPANS,
        MAX_NO_OF_EVENTS,
        MAX_NAME_LENGTH,
        MAX_TARGET_LENGTH,
        MAX_FIELD_KEY_LENGTH,
        MAX_FIELD_VALUE_LENGTH,
        MAX_NO_OF_FIELDS,
    >;

    /// Internal state of the tracing subscriber
    pub struct TraceState<
        const SP: usize,
        const EV: usize,
        const N: usize,
        const T: usize,
        const FK: usize,
        const FV: usize,
        const F: usize,
    > {
        /// The timestamp counter at the start of the guest execution.
        guest_start_tsc: u64,
        /// Next span ID to allocate
        next_id: AtomicU64,
        /// All spans and events collected
        spans: hl::Vec<GuestSpan<EV, N, T, FK, FV, F>, SP>,
        /// Stack of active spans
        stack: hl::Vec<u64, SP>,
    }

    impl<
        const SP: usize,
        const EV: usize,
        const N: usize,
        const T: usize,
        const FK: usize,
        const FV: usize,
        const F: usize,
    > TraceState<SP, EV, N, T, FK, FV, F>
    {
        fn new(guest_start_tsc: u64) -> Self {
            Self {
                guest_start_tsc,
                next_id: AtomicU64::new(1),
                spans: hl::Vec::new(),
                stack: hl::Vec::new(),
            }
        }

        /// Create a new span and push it on the stack
        pub fn new_span(&mut self, attrs: &Attributes) -> Id {
            unimplemented!()
        }

        /// Record an event in the current span (top of the stack)
        pub fn event(&mut self, event: &Event<'_>) {
            unimplemented!()
        }

        /// Record new values for an existing span
        fn record(&mut self, id: &Id, values: &Record<'_>) {
            unimplemented!()
        }

        /// Enter a span (push it on the stack)
        fn enter(&mut self, id: &Id) {
            unimplemented!()
        }

        /// Exit a span (pop it from the stack)
        fn exit(&mut self, _id: &Id) {
            unimplemented!()
        }

        /// Try to close a span by ID, returning true if successful
        /// Records the end timestamp for the span.
        fn try_close(&mut self, id: Id) -> bool {
            unimplemented!()
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
            self.state.lock().new_span(attrs)
        }

        fn record(&self, id: &Id, values: &Record<'_>) {
            self.state.lock().record(id, values)
        }

        fn event(&self, event: &Event<'_>) {
            self.state.lock().event(event)
        }

        fn enter(&self, id: &Id) {
            self.state.lock().enter(id)
        }

        fn exit(&self, id: &Id) {
            self.state.lock().exit(id)
        }

        fn try_close(&self, id: Id) -> bool {
            self.state.lock().try_close(id)
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
