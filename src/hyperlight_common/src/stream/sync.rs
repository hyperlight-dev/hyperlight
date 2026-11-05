// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! The pipe lock and the session doorbell. The lock uses loom in loom tests, `std` when
//! available, and spins otherwise.

#[cfg(feature = "std")]
extern crate std;

use core::mem;
use core::task::{Context, Poll, Waker};
#[cfg(any(feature = "std", all(test, loom)))]
use std::sync::PoisonError;
#[cfg(all(feature = "std", not(all(test, loom))))]
use std::sync::{Mutex as Inner, MutexGuard};

#[cfg(all(test, loom))]
use loom::sync::{Mutex as Inner, MutexGuard};
#[cfg(not(any(feature = "std", all(test, loom))))]
use spin::{Mutex as Inner, MutexGuard};

/// A mutual exclusion lock that ignores poisoning.
pub(crate) struct Mutex<T>(Inner<T>);

impl<T> Mutex<T> {
    /// Create an unlocked mutex.
    pub(crate) fn new(value: T) -> Self {
        Self(Inner::new(value))
    }

    /// Acquire the lock.
    pub(crate) fn lock(&self) -> MutexGuard<'_, T> {
        #[cfg(any(feature = "std", all(test, loom)))]
        let guard = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        #[cfg(not(any(feature = "std", all(test, loom))))]
        let guard = self.0.lock();

        guard
    }
}

/// Tells the task driving a `Mux` that handles left it work.
///
/// Handles [`ring`](Self::ring) it and the task [`poll`](Self::poll)s it. A ring stays until the
/// next poll, so a ring made while no task waits is kept. Rings between polls count as one.
pub(crate) struct Doorbell(Mutex<DoorbellInner>);

/// The state behind a [`Doorbell`]'s lock.
enum DoorbellInner {
    /// No ring since the last poll, and no task waits.
    Idle,
    /// The doorbell rang since the last poll.
    Notified,
    /// A task waits for a ring.
    Waiting(Waker),
}

impl Doorbell {
    /// Create a doorbell that has not rung.
    pub(crate) fn new() -> Self {
        Self(Mutex::new(DoorbellInner::Idle))
    }

    /// Ring the doorbell and return the waiting task's waker.
    ///
    /// The caller wakes it after releasing its own locks, since waking can run code that takes
    /// them.
    #[must_use]
    pub(crate) fn ring(&self) -> Option<Waker> {
        let mut state = self.0.lock();

        match mem::replace(&mut *state, DoorbellInner::Notified) {
            DoorbellInner::Waiting(waker) => Some(waker),
            _ => None,
        }
    }

    /// Return `Ready` if the doorbell rang since the last poll.
    ///
    /// Otherwise store the task's waker and return `Pending`. The stored waker stays when it
    /// already wakes the same task. A replaced waker drops after the lock is released, since
    /// dropping it can drop streams that ring the doorbell.
    pub(crate) fn poll(&self, cx: &mut Context<'_>) -> Poll<()> {
        let stale = {
            let mut state = self.0.lock();

            match &*state {
                DoorbellInner::Notified => {
                    *state = DoorbellInner::Idle;
                    return Poll::Ready(());
                }
                DoorbellInner::Waiting(old) if old.will_wake(cx.waker()) => return Poll::Pending,
                _ => mem::replace(&mut *state, DoorbellInner::Waiting(cx.waker().clone())),
            }
        };

        drop(stale);
        Poll::Pending
    }
}
