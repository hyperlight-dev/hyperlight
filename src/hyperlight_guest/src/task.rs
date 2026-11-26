// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Guest tasks, which run futures across turns.
//!
//! [`stream::produce`](crate::stream::produce) spawns a task. Each turn polls the ready tasks with
//! [`run_ready`].

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::task::Wake;
use core::cell::RefCell;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};

use hyperlight_common::stream::StatusFlags;

use crate::transport::SyncWrap;

/// Task polls per [`run_ready`]. It bounds a turn, since a task that wakes itself is ready again
/// after each poll.
pub const POLL_BUDGET: usize = 64;

/// The guest's tasks, in poll order.
static TASKS: SyncWrap<RefCell<VecDeque<Task>>> = SyncWrap(RefCell::new(VecDeque::new()));

/// Poll the ready tasks, at most [`POLL_BUDGET`] times.
///
/// Call it outside transport borrows, since tasks can call host functions.
pub fn run_ready() {
    run_ready_in(&TASKS.0, POLL_BUDGET);
}

/// Run `future` as a task. The next [`run_ready`] polls it.
pub fn spawn(future: impl Future<Output = ()> + 'static) {
    TASKS.0.borrow_mut().push_back(Task::new(future));
}

/// The task flags of STATUS. READY while a task is ready to poll, and ACTIVE while any task
/// exists.
pub(crate) fn status() -> StatusFlags {
    status_in(&TASKS.0.borrow())
}

/// The task flags of STATUS for `tasks`.
fn status_in(tasks: &VecDeque<Task>) -> StatusFlags {
    let mut status = StatusFlags::empty();

    if tasks.iter().any(|task| task.ready.is_set()) {
        status |= StatusFlags::READY;
    }

    if !tasks.is_empty() {
        status |= StatusFlags::ACTIVE;
    }

    status
}

/// Poll the ready tasks of `tasks` in round-robin order, at most `budget` times.
///
/// Each poll runs with no borrow of `tasks`, so the task can spawn others. A pending task moves to
/// the back, and a finished task drops.
fn run_ready_in(tasks: &RefCell<VecDeque<Task>>, budget: usize) {
    for _ in 0..budget {
        let Some(mut task) = take_ready(&mut tasks.borrow_mut()) else {
            break;
        };

        if task.poll().is_pending() {
            tasks.borrow_mut().push_back(task);
        }
    }
}

/// Remove the first ready task of `tasks`, and clear its flag.
fn take_ready(tasks: &mut VecDeque<Task>) -> Option<Task> {
    let index = tasks.iter().position(|task| task.ready.take())?;
    tasks.remove(index)
}

/// A future and the waker that sets its ready flag.
struct Task {
    future: Pin<Box<dyn Future<Output = ()>>>,
    ready: Arc<ReadyFlag>,
    waker: Waker,
}

impl Task {
    /// A task that starts ready, so the next pass polls it.
    fn new(future: impl Future<Output = ()> + 'static) -> Self {
        let ready = Arc::new(ReadyFlag(AtomicBool::new(true)));

        Self {
            future: Box::pin(future),
            waker: Waker::from(Arc::clone(&ready)),
            ready,
        }
    }

    fn poll(&mut self) -> Poll<()> {
        self.future
            .as_mut()
            .poll(&mut Context::from_waker(&self.waker))
    }
}

/// A task's ready flag.
struct ReadyFlag(AtomicBool);

impl ReadyFlag {
    /// Clear the flag, and return whether it was set.
    fn take(&self) -> bool {
        self.0.swap(false, Ordering::Acquire)
    }

    /// Whether the task is ready to poll.
    fn is_set(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

impl Wake for ReadyFlag {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use alloc::rc::Rc;
    use core::cell::Cell;
    use core::future::poll_fn;

    use super::*;

    /// A task that never finishes. It counts its polls and wakes itself in the first `self_wakes`.
    fn counting(polls: Rc<Cell<usize>>, self_wakes: usize) -> Task {
        Task::new(poll_fn(move |cx| {
            polls.set(polls.get() + 1);

            if polls.get() <= self_wakes {
                cx.waker().wake_by_ref();
            }

            Poll::Pending
        }))
    }

    #[test]
    fn polls_only_ready_tasks() {
        let polls = Rc::new(Cell::new(0));
        let tasks = RefCell::new(VecDeque::from([
            counting(Rc::clone(&polls), 1),
            Task::new(async {}),
        ]));

        // New tasks start ready, a wake during a poll queues the task again, and a finished task
        // drops.
        run_ready_in(&tasks, POLL_BUDGET);
        assert_eq!(polls.get(), 2);
        assert_eq!(tasks.borrow().len(), 1);

        run_ready_in(&tasks, POLL_BUDGET);
        assert_eq!(polls.get(), 2);

        tasks.borrow()[0].waker.wake_by_ref();
        run_ready_in(&tasks, POLL_BUDGET);
        assert_eq!(polls.get(), 3);
    }

    #[test]
    fn budget_bounds_polls_in_round_robin() {
        let polls: [Rc<Cell<usize>>; 3] = Default::default();
        let tasks = RefCell::new(
            polls
                .iter()
                .map(|polls| counting(Rc::clone(polls), usize::MAX))
                .collect(),
        );

        run_ready_in(&tasks, 2);
        assert_eq!(polls.each_ref().map(|polls| polls.get()), [1, 1, 0]);

        // The third task runs before the first two run again.
        run_ready_in(&tasks, 2);
        assert_eq!(polls.each_ref().map(|polls| polls.get()), [2, 1, 1]);
    }

    #[test]
    fn a_task_spawned_during_a_poll_runs_in_the_same_pass() {
        let tasks = Rc::new(RefCell::new(VecDeque::new()));
        let polls = Rc::new(Cell::new(0));

        let spawner = {
            let tasks = Rc::clone(&tasks);
            let polls = Rc::clone(&polls);

            async move { tasks.borrow_mut().push_back(counting(polls, 0)) }
        };

        tasks.borrow_mut().push_back(Task::new(spawner));
        run_ready_in(&tasks, POLL_BUDGET);
        assert_eq!(polls.get(), 1);
    }

    #[test]
    fn status_reports_ready_and_live_tasks() {
        let polls = Rc::new(Cell::new(0));
        let tasks = RefCell::new(VecDeque::new());
        assert_eq!(status_in(&tasks.borrow()), StatusFlags::empty());

        tasks.borrow_mut().push_back(counting(Rc::clone(&polls), 1));
        let ready = StatusFlags::READY | StatusFlags::ACTIVE;
        assert_eq!(status_in(&tasks.borrow()), ready);

        // The first poll wakes the task again, and the second leaves it waiting.
        run_ready_in(&tasks, 1);
        assert_eq!(status_in(&tasks.borrow()), ready);

        run_ready_in(&tasks, 1);
        assert_eq!(status_in(&tasks.borrow()), StatusFlags::ACTIVE);
    }
}
