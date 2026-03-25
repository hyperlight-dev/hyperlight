/*
Copyright 2026  The Hyperlight Authors.

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

//! Guest-side virtqueue state and initialization.
//!
//! Holds the global VirtqProducer instances for G2H and H2G queues.
//! The producers are created during guest init (from `hyperlight_guest_bin`)
//! and used by the guest host-call path in `host_comm`.

use alloc::rc::Rc;
use core::cell::RefCell;
use core::num::NonZeroU16;

use hyperlight_common::virtq::{BufferPool, Layout, Notifier, QueueStats, VirtqProducer};
use hyperlight_guest::virtq_mem::GuestMemOps;

/// Wrapper to mark types as Sync for single-threaded guest execution.
struct SyncWrap<T>(T);

// SAFETY: guest execution is single-threaded.
unsafe impl<T> Sync for SyncWrap<T> {}

/// Guest-side notifier (no-op).
#[derive(Clone, Copy)]
pub struct GuestNotifier;

impl Notifier for GuestNotifier {
    fn notify(&self, _stats: QueueStats) {}
}

/// Type alias for the guest-side producer.
pub type GuestProducer = VirtqProducer<GuestMemOps, GuestNotifier, Rc<BufferPool>>;
/// Global G2H producer instance, initialized during guest init.
static G2H_PRODUCER: SyncWrap<RefCell<Option<GuestProducer>>> = SyncWrap(RefCell::new(None));

/// Borrow the G2H producer mutably.
///
/// # Panics
///
/// Panics if the G2H producer has not been initialized or is already
/// borrowed.
pub fn with_g2h_producer<R>(f: impl FnOnce(&mut GuestProducer) -> R) -> R {
    let mut guard = G2H_PRODUCER.0.borrow_mut();
    let producer = guard.as_mut().expect("G2H producer not initialized");
    f(producer)
}

/// Initialize the G2H producer
///
/// # Safety
///
/// The ring GVA must point to valid, zeroed ring memory of the
/// appropriate size. The pool GVA must point to valid, zeroed memory.
pub unsafe fn init_g2h_producer(ring_gva: u64, num_descs: u16, pool_gva: u64, pool_size: usize) {
    let nz = NonZeroU16::new(num_descs).expect("G2H queue depth must be non-zero");
    let pool = BufferPool::new(pool_gva, pool_size).expect("failed to create G2H buffer pool");

    let layout = unsafe { Layout::from_base(ring_gva, nz) }.expect("invalid G2H ring layout");
    let producer = VirtqProducer::new(layout, GuestMemOps, GuestNotifier, Rc::new(pool));

    *G2H_PRODUCER.0.borrow_mut() = Some(producer);
}
