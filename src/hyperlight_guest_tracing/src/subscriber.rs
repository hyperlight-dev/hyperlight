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

use alloc::sync::Arc;

use spin::Mutex;
use tracing_core::span::{Attributes, Id, Record};
use tracing_core::subscriber::Subscriber;
use tracing_core::{Event, Metadata};

use crate::state::GuestState;

/// The subscriber is used to collect spans and events in the guest.
pub(crate) struct GuestSubscriber {
    /// Internal state that holds the spans and events
    /// Protected by a Mutex for inner mutability
    /// A reference to this state is stored in a static variable
    state: Arc<Mutex<GuestState>>,
}

impl GuestSubscriber {
    pub(crate) fn new(guest_start_tsc: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(GuestState::new(guest_start_tsc))),
        }
    }
    pub(crate) fn state(&self) -> &Arc<Mutex<GuestState>> {
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
