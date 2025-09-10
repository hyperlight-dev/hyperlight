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
extern crate alloc;

use core::sync::atomic::{AtomicU64, Ordering};

use heapless as hl;
use hyperlight_common::outb::OutBAction;
use tracing_core::Event;
use tracing_core::span::{Attributes, Id, Record};

use crate::visitor::FieldsVisitor;
use crate::{
    GuestEvent, GuestSpan, MAX_FIELD_KEY_LENGTH, MAX_FIELD_VALUE_LENGTH, MAX_NAME_LENGTH,
    MAX_NO_OF_EVENTS, MAX_NO_OF_FIELDS, MAX_NO_OF_SPANS, MAX_TARGET_LENGTH, invariant_tsc,
};

pub struct TraceBatchInfo {
    /// The timestamp counter at the start of the guest execution.
    pub guest_start_tsc: u64,
    /// Pointer to the spans in the guest memory.
    pub spans_ptr: u64,
    /// Pointer to the events in the guest memory.
    pub events_ptr: u64,
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
pub(crate) struct TraceState<
    const SP: usize,
    const EV: usize,
    const N: usize,
    const T: usize,
    const FK: usize,
    const FV: usize,
    const F: usize,
> {
    /// Whether we need to cleanup the state on next access
    cleanup_needed: bool,
    /// The timestamp counter at the start of the guest execution.
    guest_start_tsc: u64,
    /// Next span ID to allocate
    next_id: AtomicU64,
    /// All spans collected
    spans: hl::Vec<GuestSpan<N, T, FK, FV, F>, SP>,
    /// All events collected
    events: hl::Vec<GuestEvent<N, FK, FV, F>, EV>,
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
    pub(crate) fn new(guest_start_tsc: u64) -> Self {
        Self {
            cleanup_needed: false,
            guest_start_tsc,
            next_id: AtomicU64::new(1),
            spans: hl::Vec::new(),
            stack: hl::Vec::new(),
            events: hl::Vec::new(),
        }
    }

    pub(crate) fn alloc_id(&self) -> (u64, Id) {
        let n = self.next_id.load(Ordering::Relaxed);
        self.next_id.store(n + 1, Ordering::Relaxed);

        (n, Id::from_u64(n))
    }

    /// Cleanup internal state by removing closed spans and events
    /// This ensures that after a VM exit, we keep the spans that
    /// are still active (in the stack) and remove all other spans and events.
    pub fn clean(&mut self) {
        // Remove all spans that have an end timestamp (closed spans)
        self.spans.retain(|s| s.end_tsc.is_none());

        // Remove all events
        self.events.clear();
    }

    #[inline(always)]
    fn verify_and_clean(&mut self) {
        if self.cleanup_needed {
            self.clean();
            self.cleanup_needed = false;
        }
    }

    /// Triggers a VM exit to flush the current spans to the host.
    /// This also clears the internal state to start fresh.
    fn send_to_host(&mut self) {
        let guest_start_tsc = self.guest_start_tsc;
        let spans_ptr = &self.spans as *const _ as u64;
        let events_ptr = &self.events as *const _ as u64;

        unsafe {
            core::arch::asm!("out dx, al",
                // Port value for tracing
                in("dx") OutBAction::TraceBatch as u16,
                // Additional magic number to identify the action
                in("r8") OutBAction::TraceBatch as u64,
                in("r9") guest_start_tsc,
                in("r10") spans_ptr,
                in("r11") events_ptr,
            );
        }

        self.clean();
    }

    /// Set a new guest start tsc
    pub(crate) fn set_start_tsc(&mut self, guest_start_tsc: u64) {
        self.guest_start_tsc = guest_start_tsc;
    }

    /// Closes the trace by ending all spans
    /// NOTE: This expects an outb call to send the spans to the host.
    pub(crate) fn end_trace(&mut self) {
        for span in self.spans.iter_mut() {
            if span.end_tsc.is_none() {
                span.end_tsc = Some(invariant_tsc::read_tsc());
            }
        }

        // Empty the stack
        while self.stack.pop().is_some() {
            // Pop all remaining spans from the stack
        }

        // Mark for clearing when re-entering the VM because we might
        // not enter on the same place as we exited (e.g. halt)
        self.cleanup_needed = true;
    }

    /// Returns information about the information needed by the host to read the spans.
    pub(crate) fn guest_trace_info(&mut self) -> TraceBatchInfo {
        TraceBatchInfo {
            guest_start_tsc: self.guest_start_tsc,
            spans_ptr: &self.spans as *const _ as u64,
            events_ptr: &self.events as *const _ as u64,
        }
    }

    /// Create a new span and push it on the stack
    pub(crate) fn new_span(&mut self, attrs: &Attributes) -> Id {
        self.verify_and_clean();
        let (idn, id) = self.alloc_id();

        let md = attrs.metadata();
        let mut name = hl::String::<N>::new();
        let mut target = hl::String::<T>::new();
        // Shorten name and target if they are bigger than the space allocated
        let _ = name.push_str(&md.name()[..usize::min(md.name().len(), name.capacity())]);
        let _ = target.push_str(&md.target()[..usize::min(md.target().len(), target.capacity())]);

        // Visit fields to collect them
        let mut fields = hl::Vec::new();
        attrs.record(&mut FieldsVisitor::<FK, FV, F> { out: &mut fields });

        // Find parent from current stack top (if any)
        let parent_id = self.stack.last().copied();

        let span = GuestSpan::<N, T, FK, FV, F> {
            id: idn,
            parent_id,
            level: (*md.level()).into(),
            name,
            target,
            start_tsc: invariant_tsc::read_tsc(),
            end_tsc: None,
            fields,
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
    pub(crate) fn event(&mut self, event: &Event<'_>) {
        self.verify_and_clean();
        let stack = &mut self.stack;
        let parent_id = stack.last().copied().unwrap_or(0);

        let md = event.metadata();
        let mut name = hl::String::<N>::new();
        // Shorten name and target if they are bigger than the space allocated
        let _ = name.push_str(&md.name()[..usize::min(md.name().len(), name.capacity())]);

        let mut fields = hl::Vec::new();
        event.record(&mut FieldsVisitor::<FK, FV, F> { out: &mut fields });

        let ev = GuestEvent {
            parent_id,
            level: (*md.level()).into(),
            name,
            tsc: invariant_tsc::read_tsc(),
            fields,
        };

        // Should never fail because we flush when full
        let _ = self.events.push(ev);

        // Flush buffer to host if full
        if self.events.len() >= self.events.capacity() {
            self.send_to_host();
        }
    }

    /// Record new values for an existing span
    pub(crate) fn record(&mut self, id: &Id, values: &Record<'_>) {
        let spans = &mut self.spans;
        if let Some(s) = spans.iter_mut().find(|s| s.id == id.into_u64()) {
            let mut v = hl::Vec::new();
            values.record(&mut FieldsVisitor::<FK, FV, F> { out: &mut v });
            s.fields.extend(v);
        }
    }

    /// Enter a span (push it on the stack)
    pub(crate) fn enter(&mut self, id: &Id) {
        let st = &mut self.stack;
        let _ = st.push(id.into_u64());
    }

    /// Exit a span (pop it from the stack)
    pub(crate) fn exit(&mut self, _id: &Id) {
        let st = &mut self.stack;
        let _ = st.pop();
    }

    /// Try to close a span by ID, returning true if successful
    /// Records the end timestamp for the span.
    pub(crate) fn try_close(&mut self, id: Id) -> bool {
        let spans = &mut self.spans;
        if let Some(s) = spans.iter_mut().find(|s| s.id == id.into_u64()) {
            s.end_tsc = Some(invariant_tsc::read_tsc());
            true
        } else {
            false
        }
    }
}
