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

/// Internal state of the tracing subscriber
pub(crate) struct GuestState {
    /// The timestamp counter at the start of the guest execution.
    guest_start_tsc: u64,
}

impl GuestState {
    pub(crate) fn new(guest_start_tsc: u64) -> Self {
        Self { guest_start_tsc }
    }

    /// Set a new guest start tsc
    pub(crate) fn set_start_tsc(&mut self, guest_start_tsc: u64) {
        self.guest_start_tsc = guest_start_tsc;
    }

    /// Create a new span and push it on the stack
    pub(crate) fn new_span(&mut self, attrs: &Attributes) -> Id {
        unimplemented!()
    }

    /// Record an event in the current span (top of the stack)
    pub(crate) fn event(&mut self, event: &Event<'_>) {
        unimplemented!()
    }

    /// Record new values for an existing span
    pub(crate) fn record(&mut self, id: &Id, values: &Record<'_>) {
        unimplemented!()
    }

    /// Enter a span (push it on the stack)
    pub(crate) fn enter(&mut self, id: &Id) {
        unimplemented!()
    }

    /// Exit a span (pop it from the stack)
    pub(crate) fn exit(&mut self, _id: &Id) {
        unimplemented!()
    }

    /// Try to close a span by ID, returning true if successful
    /// Records the end timestamp for the span.
    pub(crate) fn try_close(&mut self, id: Id) -> bool {
        unimplemented!()
    }
}
