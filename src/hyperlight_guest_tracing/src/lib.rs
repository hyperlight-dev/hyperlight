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
    use core::fmt::Debug;
    use core::sync::atomic::{AtomicU64, Ordering};
    use tracing_core::field::{Field, Visit};
    use tracing_core::span::{Attributes, Id, Record};
    use tracing_core::subscriber::Subscriber;
    use tracing_core::{Event, Metadata};
    use spin::Mutex;

    use super::*;
    use crate::invariant_tsc;

    /// Weak reference to the guest state so we can manually trigger flush to host
    static GUEST_STATE: spin::Once<Weak<Mutex<GuestState>>> = spin::Once::new();

    /// Visitor implementation to collect fields into a vector of key-value pairs
    struct FieldsVisitor<'a, const FK: usize, const FV: usize, const F: usize> {
        out: &'a mut hl::Vec<(hl::String<FK>, hl::String<FV>), F>,
    }

    impl<'a, const FK: usize, const FV: usize, const F: usize> Visit for FieldsVisitor<'a, FK, FV, F> {
        fn record_bytes(&mut self, field: &Field, value: &[u8]) {
            let mut k = hl::String::<FK>::new();
            let mut val = hl::String::<FV>::new();
            // Shorten key and value if they are bigger than the space allocated
            let _ = k.push_str(&field.name()[..usize::min(field.name().len(), k.capacity())]);
            let _ = val
                .push_str(&alloc::format!("{value:?}")[..usize::min(value.len(), val.capacity())]);
            let _ = self.out.push((k, val));
        }
        fn record_str(&mut self, f: &Field, v: &str) {
            let mut k = heapless::String::<FK>::new();
            let mut val = heapless::String::<FV>::new();
            // Shorten key and value if they are bigger than the space allocated
            let _ = k.push_str(&f.name()[..usize::min(f.name().len(), k.capacity())]);
            let _ = val.push_str(&v[..usize::min(v.len(), val.capacity())]);
            let _ = self.out.push((k, val));
        }
        fn record_debug(&mut self, f: &Field, v: &dyn Debug) {
            use heapless::String;
            let mut k = String::<FK>::new();
            let mut val = String::<FV>::new();
            // Shorten key and value if they are bigger than the space allocated
            let _ = k.push_str(&f.name()[..usize::min(f.name().len(), k.capacity())]);
            let v = alloc::format!("{v:?}");
            let _ = val.push_str(&v[..usize::min(v.len(), val.capacity())]);
            let _ = self.out.push((k, val));
        }
    }

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

        fn alloc_id(&self) -> (u64, Id) {
            let n = self.next_id.load(Ordering::Relaxed);
            self.next_id.store(n + 1, Ordering::Relaxed);

            (n, Id::from_u64(n))
        }

        /// Triggers a VM exit to flush the current spans to the host.
        /// This also clears the internal state to start fresh.
        fn send_to_host(&mut self) {
        }

        /// Create a new span and push it on the stack
        pub fn new_span(&mut self, attrs: &Attributes) -> Id {
            let (idn, id) = self.alloc_id();

            let md = attrs.metadata();
            let mut name = hl::String::<N>::new();
            let mut target = hl::String::<T>::new();
            // Shorten name and target if they are bigger than the space allocated
            let _ = name.push_str(&md.name()[..usize::min(md.name().len(), name.capacity())]);
            let _ =
                target.push_str(&md.target()[..usize::min(md.target().len(), target.capacity())]);

            // Visit fields to collect them
            let mut fields = hl::Vec::new();
            attrs.record(&mut FieldsVisitor::<FK, FV, F> { out: &mut fields });

            // Find parent from current stack top (if any)
            let parent_id = self.stack.last().copied();

            let span = GuestSpan::<EV, N, T, FK, FV, F> {
                id: idn,
                parent_id,
                level: (*md.level()).into(),
                name,
                target,
                start_tsc: invariant_tsc::read_tsc(),
                end_tsc: None,
                fields,
                events: hl::Vec::new(),
            };

            let spans = &mut self.spans;
            // Should never fail because we flush when full
            let _ = spans.push(span);

            // In case the spans Vec is full, we need to report them to the host
            if spans.len() == spans.capacity() {
                self.send_to_host();
            }

            id
        }

        /// Record an event in the current span (top of the stack)
        pub fn event(&mut self, event: &Event<'_>) {
            let stack = &mut self.stack;
            let parent_id = stack.last().copied().unwrap_or(0);

            let md = event.metadata();
            let mut name = hl::String::<N>::new();
            // Shorten name and target if they are bigger than the space allocated
            let _ = name.push_str(&md.name()[..usize::min(md.name().len(), name.capacity())]);

            let mut fields = hl::Vec::new();
            event.record(&mut FieldsVisitor::<FK, FV, F> { out: &mut fields });

            let ev = GuestEvent {
                level: (*md.level()).into(),
                name,
                tsc: invariant_tsc::read_tsc(),
                fields,
            };

            let spans = &mut self.spans;
            // Maybe panic is not the best option here, but if we have an event
            // for a span that does not exist, something is very wrong.
            let span = spans
                .iter_mut()
                .find(|s| s.id == parent_id)
                .expect("There should always be a span");

            // Should never fail because we flush when full
            let _ = span.events.push(ev);

            // Flush buffer to host if full
            if span.events.len() >= span.events.capacity() {
                self.send_to_host();
            }
        }

        /// Record new values for an existing span
        fn record(&mut self, id: &Id, values: &Record<'_>) {
            let spans = &mut self.spans;
            if let Some(s) = spans.iter_mut().find(|s| s.id == id.into_u64()) {
                let mut v = hl::Vec::new();
                values.record(&mut FieldsVisitor::<FK, FV, F> { out: &mut v });
                s.fields.extend(v);
            }
        }

        /// Enter a span (push it on the stack)
        fn enter(&mut self, id: &Id) {
            let st = &mut self.stack;
            let _ = st.push(id.into_u64());
        }

        /// Exit a span (pop it from the stack)
        fn exit(&mut self, _id: &Id) {
            let st = &mut self.stack;
            let _ = st.pop();
        }

        /// Try to close a span by ID, returning true if successful
        /// Records the end timestamp for the span.
        fn try_close(&mut self, id: Id) -> bool {
            let spans = &mut self.spans;
            if let Some(s) = spans.iter_mut().find(|s| s.id == id.into_u64()) {
                s.end_tsc = Some(invariant_tsc::read_tsc());
                true
            } else {
                false
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
