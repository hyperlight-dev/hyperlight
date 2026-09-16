// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.
extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use hyperlight_common::log_level::GuestLogFilter;
use spin::Mutex;
use tracing_core::span::{Attributes, Id, Record};
use tracing_core::subscriber::Subscriber;
use tracing_core::{Event, Interest, LevelFilter, Metadata};

use crate::state::GuestState;

/// The subscriber is used to collect spans and events in the guest.
pub(crate) struct GuestSubscriber {
    /// Internal state that holds the spans and events
    /// Protected by a Mutex for inner mutability
    /// A reference to this state is stored in a static variable
    /// so it can be accessed from the guest tracing API
    state: Arc<Mutex<GuestState>>,
    /// Maximum log level to record
    max_log_level: AtomicU64,
}

impl GuestSubscriber {
    /// Creates a new `GuestSubscriber` with the given guest start TSC and maximum log level
    pub(crate) fn new(guest_start_tsc: u64, filter: LevelFilter) -> Self {
        Self {
            state: Arc::new(Mutex::new(GuestState::new(guest_start_tsc))),
            max_log_level: AtomicU64::new(u64::from(GuestLogFilter::from(filter))),
        }
    }

    pub(crate) fn set_max_log_level(&self, filter: LevelFilter) {
        self.max_log_level
            .store(u64::from(GuestLogFilter::from(filter)), Ordering::Relaxed);
    }

    pub(crate) fn accepts_trace_events(&self) -> bool {
        self.max_log_level.load(Ordering::Relaxed) == u64::from(GuestLogFilter::Trace)
    }
    /// Returns a reference to the internal state of the subscriber
    /// This is used to access the spans and events collected by the subscriber
    pub(crate) fn state(&self) -> &Arc<Mutex<GuestState>> {
        &self.state
    }
}

impl Subscriber for GuestSubscriber {
    fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }

    fn enabled(&self, md: &Metadata<'_>) -> bool {
        let Ok(filter) = GuestLogFilter::try_from(self.max_log_level.load(Ordering::Relaxed))
        else {
            return false;
        };
        md.level() <= &LevelFilter::from(filter)
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

#[cfg(test)]
mod tests {
    use tracing_core::metadata::LevelFilter;
    use tracing_core::subscriber::Subscriber;

    use super::GuestSubscriber;

    #[test]
    fn filter_can_be_updated() {
        let subscriber = GuestSubscriber::new(0, LevelFilter::ERROR);
        let metadata = tracing_core::metadata! {
            name: "event",
            target: "test",
            level: tracing_core::Level::INFO,
            fields: &[],
            callsite: &CALLSITE,
            kind: tracing_core::metadata::Kind::EVENT,
        };

        assert!(!subscriber.enabled(&metadata));
        subscriber.set_max_log_level(LevelFilter::INFO);
        assert!(subscriber.enabled(&metadata));
    }

    #[test]
    fn callsite_interest_is_rechecked_after_filter_updates() {
        let subscriber = GuestSubscriber::new(0, LevelFilter::ERROR);
        assert!(
            subscriber
                .register_callsite(&CALLSITE_METADATA)
                .is_sometimes()
        );

        subscriber.set_max_log_level(LevelFilter::TRACE);
        assert!(subscriber.enabled(&CALLSITE_METADATA));

        subscriber.set_max_log_level(LevelFilter::ERROR);
        assert!(!subscriber.enabled(&CALLSITE_METADATA));
    }

    static CALLSITE: tracing_core::callsite::DefaultCallsite =
        tracing_core::callsite::DefaultCallsite::new(&CALLSITE_METADATA);
    static CALLSITE_METADATA: tracing_core::Metadata<'static> = tracing_core::metadata! {
        name: "event",
        target: "test",
        level: tracing_core::Level::INFO,
        fields: &[],
        callsite: &CALLSITE,
        kind: tracing_core::metadata::Kind::EVENT,
    };
}
