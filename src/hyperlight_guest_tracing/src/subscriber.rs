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
use tracing_core::{Event, LevelFilter, Metadata};

use crate::state::GuestState;

/// The subscriber is used to collect spans and events in the guest.
pub(crate) struct GuestSubscriber {
    /// Internal state that holds the spans and events
    /// Protected by a Mutex for inner mutability
    /// A reference to this state is stored in a static variable
    /// so it can be accessed from the guest tracing API
    state: Arc<Mutex<GuestState>>,
    /// Maximum log level to record
    max_log_level: LevelFilter,
}

/// Converts a `tracing::log::LevelFilter` to a `tracing_core::LevelFilter`
/// Used to check if an event should be recorded based on the maximum log level
fn convert_level_filter(filter: tracing::log::LevelFilter) -> tracing_core::LevelFilter {
    match filter {
        tracing::log::LevelFilter::Off => tracing_core::LevelFilter::OFF,
        tracing::log::LevelFilter::Error => tracing_core::LevelFilter::ERROR,
        tracing::log::LevelFilter::Warn => tracing_core::LevelFilter::WARN,
        tracing::log::LevelFilter::Info => tracing_core::LevelFilter::INFO,
        tracing::log::LevelFilter::Debug => tracing_core::LevelFilter::DEBUG,
        tracing::log::LevelFilter::Trace => tracing_core::LevelFilter::TRACE,
    }
}

impl GuestSubscriber {
    /// Creates a new `GuestSubscriber` with the given guest start TSC and maximum log level
    pub(crate) fn new(guest_start_tsc: u64, max_log_level: tracing::log::LevelFilter) -> Self {
        Self {
            state: Arc::new(Mutex::new(GuestState::new(guest_start_tsc))),
            max_log_level: convert_level_filter(max_log_level),
        }
    }
    /// Returns a reference to the internal state of the subscriber
    /// This is used to access the spans and events collected by the subscriber
    pub(crate) fn state(&self) -> &Arc<Mutex<GuestState>> {
        &self.state
    }
}

impl Subscriber for GuestSubscriber {
    fn enabled(&self, md: &Metadata<'_>) -> bool {
        // Check if the metadata level is less than or equal to the maximum log level filter
        self.max_log_level >= *md.level()
    }

    fn new_span(&self, attrs: &Attributes<'_>) -> Id {
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
        let mut state = self
            .state
            .try_lock()
            .expect("guest_tracing: Unable to lock guest tracing state in `new_span`");

        state.new_span(attrs)
    }

    fn record(&self, id: &Id, values: &Record<'_>) {
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
        let mut state = self
            .state
            .try_lock()
            .expect("guest_tracing: Unable to lock guest tracing state in `record`");

        state.record(id, values)
    }

    fn event(&self, event: &Event<'_>) {
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
        let mut state = self
            .state
            .try_lock()
            .expect("guest_tracing: Unable to lock guest tracing state in `event`");

        state.event(event)
    }

    fn enter(&self, id: &Id) {
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
        let mut state = self
            .state
            .try_lock()
            .expect("guest_tracing: Unable to lock guest tracing state in `enter`");

        state.enter(id)
    }

    fn exit(&self, id: &Id) {
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
        let mut state = self
            .state
            .try_lock()
            .expect("guest_tracing: Unable to lock guest tracing state in `exit`");

        state.exit(id)
    }

    fn try_close(&self, id: Id) -> bool {
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
        let mut state = self
            .state
            .try_lock()
            .expect("guest_tracing: Unable to lock guest tracing state in `try_close`");

        state.try_close(id)
    }

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {
        // no-op: we don't track follows-from relationships
    }
}
