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

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use hyperlight_common::flatbuffer_wrappers::guest_trace_data::{GuestEvent, GuestTraceData};
use hyperlight_common::outb::OutBAction;
use tracing_core::Event;
use tracing_core::span::{Attributes, Id, Record};

use crate::invariant_tsc;
use crate::visitor::FieldsVisitor;

pub struct TraceBatchInfo {
    pub serialized_data: Vec<u8>,
}

/// Internal state of the tracing subscriber
pub(crate) struct GuestState {
    /// Whether we need to cleanup the state on next access
    cleanup_needed: bool,
    /// Next span ID to allocate
    next_id: AtomicU64,
    /// Trace information that is exchanged with the host
    data: GuestTraceData,
    /// Stack of active spans
    stack: Vec<u64>,
}

/// TODO: Change these constants to be configurable at runtime by the guest
/// Maybe use a weak symbol that the guest can override at link time?
///
/// Pre-calculated capacity for the events vector
/// This is to avoid reallocations in the guest
/// We allocate space for both spans and events
const EVENTS_VEC_CAPACITY: usize = 30;
/// Maximum number of spans that can be active at the same time
/// This is half of the events capacity because there are two events per span
/// (open and close)
const MAX_NO_OF_SPANS: usize = EVENTS_VEC_CAPACITY / 2;

impl GuestState {
    pub(crate) fn new(guest_start_tsc: u64) -> Self {
        Self {
            cleanup_needed: false,
            next_id: AtomicU64::new(1),
            data: GuestTraceData {
                start_tsc: guest_start_tsc,
                events: Vec::with_capacity(EVENTS_VEC_CAPACITY),
            },
            stack: Vec::with_capacity(MAX_NO_OF_SPANS),
        }
    }

    /// Allocate a new ID for a span
    /// Returns the numeric ID and the tracing ID
    /// This shall return unique IDs for each call
    pub(crate) fn alloc_id(&self) -> (u64, Id) {
        let n = self.next_id.load(Ordering::Relaxed);
        self.next_id.store(n + 1, Ordering::Relaxed);

        (n, Id::from_u64(n))
    }

    /// Cleanup internal state by removing closed spans and events
    /// This ensures that after a VM exit, we keep the spans that
    /// are still active (in the stack) and remove all other spans and events.
    pub fn clean(&mut self) {
        // Remove all events
        self.data.events.clear();
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
        let tb = self.guest_trace_info();

        unsafe {
            core::arch::asm!("out dx, al",
                // Port value for tracing
                in("dx") OutBAction::TraceBatch as u16,
                // Additional magic number to identify the action
                in("r8") OutBAction::TraceBatch as u64,
                in("r9") tb.serialized_data.as_ptr() as u64,
                in("r10") tb.serialized_data.len() as u64,
            );
        }

        self.clean();
    }

    /// Set a new guest start tsc
    pub(crate) fn set_start_tsc(&mut self, guest_start_tsc: u64) {
        self.data.start_tsc = guest_start_tsc;
    }

    /// Closes the trace by ending all spans
    /// NOTE: This expects an outb call to send the spans to the host.
    pub(crate) fn end_trace(&mut self) {
        // Empty the stack
        while let Some(id) = self.stack.pop() {
            // Pop all remaining spans from the stack
            let event = GuestEvent::CloseSpan {
                id,
                tsc: invariant_tsc::read_tsc(),
            };
            let events = &mut self.data.events;
            // Should never fail because we flush when full
            events.push(event);

            if events.len() >= EVENTS_VEC_CAPACITY {
                self.send_to_host();
            }
        }

        // Mark for clearing when re-entering the VM because we might
        // not enter on the same place as we exited (e.g. halt)
        self.cleanup_needed = true;
    }

    /// Returns information about the information needed by the host to read the spans.
    pub(crate) fn guest_trace_info(&mut self) -> TraceBatchInfo {
        let serialized_data: Vec<u8> = Vec::from(&self.data);
        TraceBatchInfo { serialized_data }
    }

    /// Create a new span and push it on the stack
    pub(crate) fn new_span(&mut self, attrs: &Attributes) -> Id {
        self.verify_and_clean();
        let (idn, id) = self.alloc_id();

        let md = attrs.metadata();
        let name = String::from(md.name());
        let target = String::from(md.target());

        // Visit fields to collect them
        let mut fields = Vec::new();
        attrs.record(&mut FieldsVisitor { out: &mut fields });

        // Find parent from current stack top (if any)
        let parent_id = self.stack.last().copied();

        let event = GuestEvent::OpenSpan {
            id: idn,
            parent_id,
            name,
            target,
            tsc: invariant_tsc::read_tsc(),
            fields,
        };

        let events = &mut self.data.events;
        // Should never fail because we flush when full
        events.push(event);

        // In case the spans Vec is full, we need to report them to the host
        if events.len() >= EVENTS_VEC_CAPACITY {
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
        let name = String::from(md.name());

        let mut fields = Vec::new();
        event.record(&mut FieldsVisitor { out: &mut fields });

        let ev = GuestEvent::LogEvent {
            parent_id,
            name,
            tsc: invariant_tsc::read_tsc(),
            fields,
        };

        // Should never fail because we flush when full
        self.data.events.push(ev);

        // Flush buffer to host if full
        if self.data.events.len() >= EVENTS_VEC_CAPACITY {
            self.send_to_host();
        }
    }

    /// Record new values for an existing span
    pub(crate) fn record(&mut self, s_id: &Id, values: &Record<'_>) {
        let spans = &mut self.data.events;
        if let Some(GuestEvent::OpenSpan { fields, .. }) = spans.iter_mut().find(|e| {
            if let GuestEvent::OpenSpan { id, .. } = e {
                *id == s_id.into_u64()
            } else {
                false
            }
        }) {
            let mut v = Vec::new();
            values.record(&mut FieldsVisitor { out: &mut v });
            fields.extend(v);
        }
    }

    /// Enter a span (push it on the stack)
    pub(crate) fn enter(&mut self, id: &Id) {
        let st = &mut self.stack;
        st.push(id.into_u64());
    }

    /// Exit a span (pop it from the stack)
    pub(crate) fn exit(&mut self, _id: &Id) {
        let st = &mut self.stack;
        let _ = st.pop();
    }

    /// Try to close a span by ID, returning true if successful
    /// Records the end timestamp for the span.
    pub(crate) fn try_close(&mut self, id: Id) -> bool {
        let events = &mut self.data.events;

        let event = GuestEvent::CloseSpan {
            id: id.into_u64(),
            tsc: invariant_tsc::read_tsc(),
        };

        // Should never fail because we flush when full
        events.push(event);

        if events.len() >= EVENTS_VEC_CAPACITY {
            self.send_to_host();
        }

        // We do not keep the span data in for the duration of the open span
        // but rather just log the close event.
        true
    }
}
