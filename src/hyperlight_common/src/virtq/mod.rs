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

//! Packed Virtqueue Implementation
//!
//! This module provides a high-level API for virtio packed virtqueues, built on top of
//! the lower-level ring primitives. It implements the VIRTIO 1.1+ packed ring format
//! with proper memory ordering and event suppression support.
//!
//! # Architecture
//!
//! The implementation is split into layers:
//!
//! - **High-level API** ([`VirtqProducer`], [`VirtqConsumer`]): Manages buffer allocation,
//!   entry/completion lifecycle, and notification decisions. This is the recommended API
//!   for most use cases.
//!
//! - **Ring primitives** ([`RingProducer`], [`RingConsumer`]): Low-level descriptor ring
//!   operations with explicit buffer chain management. Use this when you need full control
//!   over buffer layouts or custom allocation strategies.
//!
//! - **Descriptor and event types** ([`Descriptor`], [`EventSuppression`]): Raw virtio
//!   data structures for direct memory manipulation.
//!
//! # Quick Start
//!
//! ## Single Entry/Completion
//!
//! ```ignore
//! // Producer (driver) side - build entry, submit, get completion
//! let mut entry = producer.chain()
//!     .entry(64)
//!     .completion(128)
//!     .build()?;
//! entry.write_all(b"entry data")?;
//! let token = producer.submit(entry)?;
//! // ... wait for notification ...
//! if let Some(completion) = producer.poll()? {
//!     process(completion.data);
//! }
//!
//! // Consumer (device) side - receive entry, send completion
//! if let Some((entry, completion)) = consumer.poll(max_request_size)? {
//!     let request = entry.data();
//!     match completion {
//!         SendCompletion::Writable(mut wc) => {
//!             let response = handle(request);
//!             wc.write_all(&response)?;
//!             consumer.complete(wc.into())?;
//!         }
//!         SendCompletion::Ack(ack) => {
//!             consumer.complete(ack.into())?;
//!         }
//!     }
//! }
//!
//! // Multiple pending completions (no borrow on consumer)
//! let mut pending = Vec::new();
//! while let Some((entry, completion)) = consumer.poll(max_request_size)? {
//!     pending.push((process(entry), completion));
//! }
//! for (result, completion) in pending {
//!     consumer.complete(completion)?;
//! }
//! ```
//!
//! ## Multiple Entries
//!
//! Each submit checks event suppression and notifies independently:
//!
//! ```ignore
//! for data in entries {
//!     let mut se = producer.chain()
//!         .entry(data.len())
//!         .completion(64)
//!         .build()?;
//!     se.write_all(data)?;
//!     producer.submit(se)?;
//! }
//! ```
//!
//! ## Completion Batching with Event Suppression
//!
//! To receive a single notification when multiple requests complete:
//!
//! ```ignore
//! // Submit entries
//! for data in entries {
//!     let mut se = producer.chain()
//!         .entry(data.len())
//!         .completion(64)
//!         .build()?;
//!     se.write_all(data)?;
//!     producer.submit(se)?;
//! }
//!
//! // Tell device: "notify me only after completing past this cursor"
//! let cursor = producer.used_cursor();
//! producer.set_used_suppression(SuppressionKind::Descriptor(cursor))?;
//!
//! // Wait for single notification, then drain all responses
//! producer.drain(|token, data| {
//!     handle_response(token, data);
//! })?;
//! ```
//!
//! # Event Suppression
//!
//! Both sides can control when they want to be notified using [`SuppressionKind`]:
//!
//! - [`SuppressionKind::Enable`]: Always notify (default, lowest latency)
//! - [`SuppressionKind::Disable`]: Never notify (polling mode, lowest overhead)
//! - [`SuppressionKind::Descriptor`]: Notify at specific ring position (batching)
//!
//! See [`VirtqProducer::set_used_suppression`] and [`VirtqConsumer::set_avail_suppression`].
//!
//! # Low-Level API
//!
//! For advanced use cases, the ring module exposes lower-level primitives:
//!
//! - [`RingProducer`] / [`RingConsumer`]: Direct ring access with [`BufferChain`] submission
//! - [`BufferChainBuilder`]: Construct scatter-gather buffer lists
//! - [`RingCursor`]: Track ring positions for event suppression
//!
//! Example using low-level API:
//!
//! ```ignore
//! let chain = BufferChainBuilder::new()
//!     .readable(header_addr, header_len)
//!     .readable(data_addr, data_len)
//!     .writable(response_addr, response_len)
//!     .build()?;
//!
//! let result = ring_producer.submit_available_with_notify(&chain)?;
//! if result.notify {
//!     kick_device();
//! }
//! ```

mod access;
mod consumer;
mod desc;
mod event;
pub mod msg;
mod pool;
mod producer;
mod ring;

use core::num::NonZeroU16;

pub use access::*;
pub use consumer::*;
pub use desc::*;
pub use event::*;
pub use pool::*;
pub use producer::*;
pub use ring::*;
use thiserror::Error;

/// A trait for notifying about new requests in the virtqueue.
pub trait Notifier {
    fn notify(&self, stats: QueueStats);
}

/// Errors that can occur in the virtqueue operations.
#[derive(Error, Debug)]
pub enum VirtqError {
    #[error("Ring error: {0}")]
    RingError(#[from] RingError),
    #[error("Allocation error: {0}")]
    Alloc(#[from] AllocError),
    #[error("Invalid token")]
    BadToken,
    #[error("Invalid chain received")]
    BadChain,
    #[error("Entry data too large for allocated buffer")]
    EntryTooLarge,
    #[error("Completion data too large for allocated buffer")]
    CqeTooLarge,
    #[error("Internal state error")]
    InvalidState,
    #[error("Memory write error")]
    MemoryWriteError,
    #[error("Memory read error")]
    MemoryReadError,
    #[error("No readable buffer in this entry")]
    NoReadableBuffer,
}

/// Layout of a packed virtqueue ring in shared memory.
///
/// Describes the memory addresses for the descriptor table and event suppression
/// structures. Use [`from_base`](Self::from_base) to compute the layout from a
/// base address, or [`query_size`](Self::query_size) to determine memory requirements.
///
/// # Memory Layout
///
/// The packed ring consists of:
/// 1. Descriptor table: `num_descs` × 16 bytes, aligned to 16 bytes
/// 2. Driver event suppression: 4 bytes, aligned to 4 bytes
/// 3. Device event suppression: 4 bytes, aligned to 4 bytes
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    /// Packed ring descriptor table base in shared memory.
    pub desc_table_addr: u64,
    /// Number of descriptors (ring size, must be power of 2).
    pub desc_table_len: u16,
    /// Driver-written event suppression area in shared memory.
    pub drv_evt_addr: u64,
    /// Device-written event suppression area in shared memory.
    pub dev_evt_addr: u64,
}

#[inline]
const fn align_up(val: usize, align: usize) -> usize {
    (val + align - 1) & !(align - 1)
}

impl Layout {
    /// Create a Layout from a base address and number of descriptors.
    ///
    /// The base address must be aligned to `Descriptor::ALIGN`.
    /// The memory region starting at `base` must be at least `Layout::query_size(num_descs)` bytes.
    ///
    /// # Safety
    /// - `base` must be valid for `Layout::query_size(num_descs)` bytes.
    /// - `base` must be aligned to `Descriptor::ALIGN`.
    /// - Memory must remain valid for the lifetime of the ring.
    pub const unsafe fn from_base(base: u64, num_descs: NonZeroU16) -> Result<Self, RingError> {
        if !base.is_multiple_of(Descriptor::ALIGN as u64) {
            return Err(RingError::InvalidLayout);
        }

        let desc_size = num_descs.get() as usize * Descriptor::SIZE;
        let event_size = EventSuppression::SIZE;
        let event_align = EventSuppression::ALIGN;

        let drv_evt_offset = align_up(desc_size, event_align);
        let dev_evt_offset = align_up(drv_evt_offset + event_size, event_align);

        Ok(Self {
            desc_table_addr: base,
            desc_table_len: num_descs.get(),
            drv_evt_addr: base + drv_evt_offset as u64,
            dev_evt_addr: base + dev_evt_offset as u64,
        })
    }

    /// Calculate the memory size needed for a ring with `num_descs` descriptors,
    /// accounting for alignment requirements.
    pub const fn query_size(num_descs: usize) -> usize {
        let desc_size = num_descs * Descriptor::SIZE;
        let event_size = EventSuppression::SIZE;
        let event_align = EventSuppression::ALIGN;

        // desc table at offset 0, then aligned events
        let drv_evt_offset = align_up(desc_size, event_align);
        let dev_evt_offset = align_up(drv_evt_offset + event_size, event_align);

        dev_evt_offset + event_size
    }
}

/// Statistics about the current virtqueue state.
///
/// Provided to the [`Notifier`] when sending notifications, allowing
/// the notifier to make decisions based on queue pressure.
#[derive(Debug, Clone, Copy)]
pub struct QueueStats {
    /// Number of free descriptor slots available.
    pub num_free: usize,
    /// Number of descriptors currently in-flight (submitted but not completed).
    pub num_inflight: usize,
}

/// Event suppression mode for controlling when notifications are sent.
///
/// This configures when the other side should signal (interrupt/kick) us
/// about new data. Used to optimize batching and reduce interrupt overhead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressionKind {
    /// Always signal after each operation (default behavior).
    Enable,
    /// Never signal.
    Disable,
    /// Signal only when reaching a specific descriptor position.
    Descriptor(RingCursor),
}

/// A token representing a sent entry in the virtqueue.
///
/// Tokens uniquely identify in-flight requests and are used to correlate
/// requests with their responses. The token value corresponds to the
/// descriptor ID in the underlying ring.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Token(pub u16);

impl From<BufferElement> for Allocation {
    fn from(value: BufferElement) -> Self {
        Allocation {
            addr: value.addr,
            len: value.len as usize,
        }
    }
}

const _: () = {
    const fn verify_layout(num_descs: usize) {
        let base = 0x1000u64;

        // Safety: base is aligned and we're only checking layout math
        let layout =
            match unsafe { Layout::from_base(base, NonZeroU16::new(num_descs as u16).unwrap()) } {
                Ok(l) => l,
                Err(_) => panic!("from_base failed"),
            };

        let expected_size = Layout::query_size(num_descs);

        assert!(layout.desc_table_addr == base);
        assert!(layout.desc_table_len as usize == num_descs);
        assert!(
            layout
                .drv_evt_addr
                .is_multiple_of(EventSuppression::ALIGN as u64)
        );
        assert!(
            layout
                .dev_evt_addr
                .is_multiple_of(EventSuppression::ALIGN as u64)
        );

        // Events don't overlap with descriptor table
        let desc_end = base + (num_descs * Descriptor::SIZE) as u64;
        assert!(layout.drv_evt_addr >= desc_end);
        assert!(layout.dev_evt_addr >= layout.drv_evt_addr + EventSuppression::SIZE as u64);

        // Total size from query_size covers entire layout
        let layout_end = layout.dev_evt_addr + EventSuppression::SIZE as u64;
        assert!(base + expected_size as u64 == layout_end);
    }

    verify_layout(1);
    verify_layout(2);
    verify_layout(4);
    verify_layout(8);
    verify_layout(16);
    verify_layout(32);
    verify_layout(64);
    verify_layout(128);
    verify_layout(256);
    verify_layout(512);
    verify_layout(1024);
};

/// Shared test utilities for virtqueue tests.
#[cfg(test)]
pub(crate) mod test_utils {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use super::*;
    use crate::virtq::ring::tests::{OwnedRing, TestMem};

    /// Simple notifier that tracks notification count.
    #[derive(Debug, Clone)]
    pub(crate) struct TestNotifier {
        pub(crate) count: Arc<AtomicUsize>,
    }

    impl TestNotifier {
        pub(crate) fn new() -> Self {
            Self {
                count: Arc::new(AtomicUsize::new(0)),
            }
        }

        pub(crate) fn notification_count(&self) -> usize {
            self.count.load(Ordering::Relaxed)
        }
    }

    impl Notifier for TestNotifier {
        fn notify(&self, _stats: QueueStats) {
            self.count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Simple test buffer pool that allocates from a range.
    #[derive(Clone)]
    pub(crate) struct TestPool {
        base: u64,
        next: Arc<AtomicU64>,
        size: usize,
    }

    impl TestPool {
        pub(crate) fn new(base: u64, size: usize) -> Self {
            Self {
                base,
                next: Arc::new(AtomicU64::new(base)),
                size,
            }
        }
    }

    impl BufferProvider for TestPool {
        fn alloc(&self, len: usize) -> Result<Allocation, AllocError> {
            let addr = self.next.fetch_add(len as u64, Ordering::Relaxed);
            let end = addr + len as u64;
            if end > self.base + self.size as u64 {
                return Err(AllocError::OutOfMemory);
            }
            Ok(Allocation { addr, len })
        }

        fn dealloc(&self, _alloc: Allocation) -> Result<(), AllocError> {
            // Simple pool doesn't track individual allocations
            Ok(())
        }

        fn resize(&self, old_alloc: Allocation, new_len: usize) -> Result<Allocation, AllocError> {
            // Simple implementation: always allocate new
            self.dealloc(old_alloc)?;
            self.alloc(new_len)
        }
    }

    /// Create test infrastructure: a producer, consumer, and notifier backed
    /// by the supplied [`OwnedRing`].
    pub(crate) fn make_test_producer(
        ring: &OwnedRing,
    ) -> (
        VirtqProducer<Arc<TestMem>, TestNotifier, TestPool>,
        VirtqConsumer<Arc<TestMem>, TestNotifier>,
        TestNotifier,
    ) {
        let layout = ring.layout();
        let mem = ring.mem();

        // Pool needs to be in memory accessible via mem - use memory after ring layout
        let pool_base = mem.base_addr() + Layout::query_size(ring.len()) as u64 + 0x100;
        let pool = TestPool::new(pool_base, 0x8000);
        let notifier = TestNotifier::new();

        let producer = VirtqProducer::new(layout, mem.clone(), notifier.clone(), pool);
        let consumer = VirtqConsumer::new(layout, mem, notifier.clone());

        (producer, consumer, notifier)
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::virtq::ring::tests::{TestMem, make_ring};
    use crate::virtq::test_utils::*;

    /// Helper: build and submit an entry+completion chain using the chain() builder.
    fn send_readwrite(
        producer: &mut VirtqProducer<Arc<TestMem>, TestNotifier, TestPool>,
        entry_data: &[u8],
        cqe_cap: usize,
    ) -> Token {
        let mut se = producer
            .chain()
            .entry(entry_data.len())
            .completion(cqe_cap)
            .build()
            .unwrap();
        se.write_all(entry_data).unwrap();
        producer.submit(se).unwrap()
    }

    #[test]
    fn test_submit_notifies() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, notifier) = make_test_producer(&ring);

        let initial_count = notifier.notification_count();

        let token = send_readwrite(&mut producer, b"hello", 64);
        assert!(notifier.notification_count() > initial_count);

        let (entry, _completion) = consumer.poll(1024).unwrap().unwrap();
        assert_eq!(entry.token(), token);
    }

    #[test]
    fn test_multiple_submits() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let tok1 = send_readwrite(&mut producer, b"request1", 64);
        let tok2 = send_readwrite(&mut producer, b"request2", 64);
        let tok3 = send_readwrite(&mut producer, b"request3", 64);

        // Consumer sees all requests
        for _ in 0..3 {
            let (_entry, completion) = consumer.poll(1024).unwrap().unwrap();
            consumer.complete(completion).unwrap();
        }

        // All completions available
        let cqe1 = producer.poll().unwrap().unwrap();
        let cqe2 = producer.poll().unwrap().unwrap();
        let cqe3 = producer.poll().unwrap().unwrap();
        assert!(
            [cqe1.token, cqe2.token, cqe3.token].contains(&tok1)
                && [cqe1.token, cqe2.token, cqe3.token].contains(&tok2)
                && [cqe1.token, cqe2.token, cqe3.token].contains(&tok3)
        );
    }

    #[test]
    fn test_completion_batching_with_suppression() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        // Submit entries
        let tok1 = send_readwrite(&mut producer, b"req1", 64);
        let tok2 = send_readwrite(&mut producer, b"req2", 64);
        let tok3 = send_readwrite(&mut producer, b"req3", 64);

        // Set up completion batching via used suppression
        let cursor = producer.used_cursor();
        producer
            .set_used_suppression(SuppressionKind::Descriptor(cursor))
            .unwrap();

        // Consumer processes requests
        for _ in 0..3 {
            let (_entry, completion) = consumer.poll(1024).unwrap().unwrap();
            let SendCompletion::Writable(mut wc) = completion else {
                panic!("expected writable completion");
            };
            wc.write_all(b"cqe-data").unwrap();
            consumer.complete(wc.into()).unwrap();
        }

        // Producer can drain all responses
        let mut responses = Vec::new();
        producer
            .drain(|tok, _data| {
                responses.push(tok);
            })
            .unwrap();

        assert_eq!(responses.len(), 3);
        assert!(responses.contains(&tok1));
        assert!(responses.contains(&tok2));
        assert!(responses.contains(&tok3));
    }

    #[test]
    fn test_notifier_receives_context() {
        #[derive(Debug, Clone)]
        struct CtxNotifier {
            last_num_free: Arc<AtomicUsize>,
            last_num_inflight: Arc<AtomicUsize>,
            count: Arc<AtomicUsize>,
        }

        impl Notifier for CtxNotifier {
            fn notify(&self, stats: QueueStats) {
                self.last_num_free.store(stats.num_free, Ordering::Relaxed);
                self.last_num_inflight
                    .store(stats.num_inflight, Ordering::Relaxed);
                self.count.fetch_add(1, Ordering::Relaxed);
            }
        }

        let ring = make_ring(16);
        let layout = ring.layout();
        let mem = ring.mem();
        let pool_base = mem.base_addr() + Layout::query_size(ring.len()) as u64 + 0x100;
        let pool = TestPool::new(pool_base, 0x8000);
        let notifier = CtxNotifier {
            last_num_free: Arc::new(AtomicUsize::new(0)),
            last_num_inflight: Arc::new(AtomicUsize::new(0)),
            count: Arc::new(AtomicUsize::new(0)),
        };

        let mut producer = VirtqProducer::new(layout, mem, notifier.clone(), pool);

        let mut se = producer.chain().entry(4).completion(32).build().unwrap();
        se.write_all(b"test").unwrap();
        producer.submit(se).unwrap();
        assert_eq!(notifier.count.load(Ordering::Relaxed), 1);
        assert!(notifier.last_num_inflight.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn test_chain_zero_copy_batch() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, notifier) = make_test_producer(&ring);

        let initial_count = notifier.notification_count();

        // Zero-copy entry via buf_mut
        let mut se1 = producer.chain().entry(64).completion(128).build().unwrap();
        let buf = se1.buf_mut().unwrap();
        buf[..6].copy_from_slice(b"zc-ent");
        se1.set_written(6).unwrap();
        let _tok1 = producer.submit(se1).unwrap();

        // Write-based entry
        let mut se2 = producer.chain().entry(64).completion(64).build().unwrap();
        se2.write_all(b"copy-ent").unwrap();
        let _tok2 = producer.submit(se2).unwrap();

        // Completion-only chain
        let se3 = producer.chain().completion(32).build().unwrap();
        let tok3 = producer.submit(se3).unwrap();

        // Each submit may notify independently
        assert!(notifier.notification_count() > initial_count);

        // Consumer sees all three entries
        let (entry1, completion1) = consumer.poll(1024).unwrap().unwrap();
        assert_eq!(entry1.data().as_ref(), b"zc-ent");
        consumer.complete(completion1).unwrap();

        let (entry2, completion2) = consumer.poll(1024).unwrap().unwrap();
        assert_eq!(entry2.data().as_ref(), b"copy-ent");
        consumer.complete(completion2).unwrap();

        let (_entry3, completion3) = consumer.poll(1024).unwrap().unwrap();
        let SendCompletion::Writable(mut wc) = completion3 else {
            panic!("expected writable completion");
        };
        wc.write_all(b"resp").unwrap();
        consumer.complete(wc.into()).unwrap();

        // Drain completions
        let _ = producer.poll().unwrap().unwrap();
        let _ = producer.poll().unwrap().unwrap();

        let cqe = producer.poll().unwrap().unwrap();
        assert_eq!(cqe.token, tok3);
        assert_eq!(&cqe.data[..], b"resp");
    }

    #[test]
    fn test_chain_zero_copy_send() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        // Zero-copy send: allocate, write directly, submit
        let mut se = producer.chain().entry(64).completion(128).build().unwrap();
        let buf = se.buf_mut().unwrap();
        assert_eq!(buf.len(), 64);
        buf[..5].copy_from_slice(b"hello");
        se.set_written(5).unwrap();
        let token = producer.submit(se).unwrap();

        // Consumer sees the data
        let (entry, completion) = consumer.poll(1024).unwrap().unwrap();
        assert_eq!(entry.token(), token);
        assert_eq!(entry.data().as_ref(), b"hello");

        // Write response
        let SendCompletion::Writable(mut wc) = completion else {
            panic!("expected writable completion");
        };
        wc.write_all(b"world").unwrap();
        consumer.complete(wc.into()).unwrap();
        let cqe = producer.poll().unwrap().unwrap();
        assert_eq!(&cqe.data[..], b"world");
    }

    #[test]
    fn test_full_round_trip() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        // Send an entry
        let token = send_readwrite(&mut producer, b"round-trip-entry", 128);

        // Consumer receives and responds
        let (entry, completion) = consumer.poll(1024).unwrap().unwrap();
        assert_eq!(entry.token(), token);
        assert_eq!(entry.data().as_ref(), b"round-trip-entry");

        let SendCompletion::Writable(mut wc) = completion else {
            panic!("expected writable completion");
        };
        assert!(wc.capacity() >= 128);
        wc.write_all(b"round-trip-rsp").unwrap();
        consumer.complete(wc.into()).unwrap();

        // Producer gets the completion
        let cqe = producer.poll().unwrap().unwrap();
        assert_eq!(cqe.token, token);
        assert_eq!(&cqe.data[..], b"round-trip-rsp");
    }

    #[test]
    fn test_cancel_submits_zero_length() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let token = send_readwrite(&mut producer, b"entry-data", 64);

        let (_entry, completion) = consumer.poll(1024).unwrap().unwrap();
        consumer.complete(completion).unwrap();

        let cqe = producer.poll().unwrap().unwrap();
        assert_eq!(cqe.token, token);
        assert_eq!(cqe.data.len(), 0);
        assert!(cqe.data.is_empty());
    }

    #[test]
    fn test_hold_completion_and_complete() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let token = send_readwrite(&mut producer, b"deferred", 64);

        // Poll and hold the completion
        let (entry, completion) = consumer.poll(1024).unwrap().unwrap();
        assert_eq!(entry.token(), token);
        assert_eq!(entry.data().as_ref(), b"deferred");

        let SendCompletion::Writable(mut wc) = completion else {
            panic!("expected writable completion");
        };
        wc.write_all(b"deferred-cqe").unwrap();
        consumer.complete(wc.into()).unwrap();

        let cqe = producer.poll().unwrap().unwrap();
        assert_eq!(cqe.token, token);
        assert_eq!(&cqe.data[..], b"deferred-cqe");
    }

    #[test]
    fn test_concurrent_pending_completions() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let tok1 = send_readwrite(&mut producer, b"first", 64);
        let tok2 = send_readwrite(&mut producer, b"second", 64);

        // Poll both
        let (entry1, completion1) = consumer.poll(1024).unwrap().unwrap();
        assert_eq!(entry1.token(), tok1);
        assert_eq!(entry1.data().as_ref(), b"first");

        let (entry2, completion2) = consumer.poll(1024).unwrap().unwrap();
        assert_eq!(entry2.token(), tok2);
        assert_eq!(entry2.data().as_ref(), b"second");

        // Complete second first (out of order)
        let SendCompletion::Writable(mut wc2) = completion2 else {
            panic!("expected writable");
        };
        wc2.write_all(b"resp2").unwrap();
        consumer.complete(wc2.into()).unwrap();

        let SendCompletion::Writable(mut wc1) = completion1 else {
            panic!("expected writable");
        };
        wc1.write_all(b"resp1").unwrap();
        consumer.complete(wc1.into()).unwrap();

        let cqe1 = producer.poll().unwrap().unwrap();
        let cqe2 = producer.poll().unwrap().unwrap();
        let mut responses: Vec<_> = vec![
            (cqe1.token, cqe1.data.to_vec()),
            (cqe2.token, cqe2.data.to_vec()),
        ];
        responses.sort_by_key(|(t, _)| t.0);

        let expected_first = responses.iter().find(|(t, _)| *t == tok1).unwrap();
        let expected_second = responses.iter().find(|(t, _)| *t == tok2).unwrap();
        assert_eq!(&expected_first.1[..], b"resp1");
        assert_eq!(&expected_second.1[..], b"resp2");
    }
}
#[cfg(all(test, loom))]
mod fuzz {
    //! Loom-based concurrency testing for the virtqueue implementation.
    //!
    //! Loom will explores all possible thread interleavings to find data races
    //! and other concurrency bugs. However, it has specific requirements that
    //! make our memory model more involved:
    //!
    //! ## Flag-Based Synchronization
    //!
    //! The virtqueue protocol uses flag-based synchronization:
    //! 1. Producer writes descriptor fields (addr, len, id), then writes flags with release semantics
    //! 2. Consumer reads flags with acquire semantics, then reads descriptor fields
    //!
    //! Loom  would see this as concurrent access to the same memory and report a race, even though
    //! acquire/release on flags provides proper synchronization.
    //!
    //! ## Shadow Atomics for Flags
    //!
    //! We maintain shadow atomics that loom tracks for synchronization:
    //!
    //! - `desc_flags`: One `AtomicU16` per descriptor for flags field
    //! - `drv_flags`: `AtomicU16` for driver event suppression flags
    //! - `dev_flags`: `AtomicU16` for device event suppression flags
    //!
    //! The `load_acquire`/`store_release` operations use these loom atomics,
    //! while `read`/`write` access the underlying data directly.
    //!
    //! ## Memory Regions
    //!
    //! We use a `BTreeMap` to map addresses to memory regions:
    //! - `Desc(idx)`: Individual descriptors in the ring
    //! - `DrvEvt`: Driver event suppression structure
    //! - `DevEvt`: Device event suppression structure
    //! - `Pool`: Buffer pool for entry/completion data

    use alloc::collections::BTreeMap;
    use alloc::sync::Arc;
    use alloc::vec;
    use core::num::NonZeroU16;

    use bytemuck::Zeroable;
    use loom::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
    use loom::thread;

    use super::*;
    use crate::virtq::desc::Descriptor;
    use crate::virtq::pool::BufferPoolSync;

    #[derive(Debug)]
    pub struct MemErr;

    #[derive(Debug, Clone, Copy)]
    enum RegionKind {
        Desc(usize),
        DrvEvt,
        DevEvt,
        Pool,
    }

    #[derive(Debug, Clone, Copy)]
    struct RegionInfo {
        kind: RegionKind,
        size: usize,
    }

    #[derive(Debug)]
    pub struct LoomMem {
        descs: Vec<Descriptor>,
        drv: core::cell::UnsafeCell<EventSuppression>,
        dev: core::cell::UnsafeCell<EventSuppression>,
        pool: loom::cell::UnsafeCell<Vec<u8>>,

        desc_flags: Vec<AtomicU16>,
        drv_flags: AtomicU16,
        dev_flags: AtomicU16,

        regions: BTreeMap<u64, RegionInfo>,
        layout: Layout,
    }

    unsafe impl Sync for LoomMem {}
    unsafe impl Send for LoomMem {}

    impl LoomMem {
        pub fn new(ring_base: u64, num_descs: usize, pool_base: u64, pool_size: usize) -> Self {
            let descs_nz = NonZeroU16::new(num_descs as u16).unwrap();
            let layout = unsafe { Layout::from_base(ring_base, descs_nz).unwrap() };

            let descs: Vec<_> = (0..num_descs).map(|_| Descriptor::zeroed()).collect();
            let desc_flags: Vec<_> = (0..num_descs).map(|_| AtomicU16::new(0)).collect();

            let mut regions = BTreeMap::new();

            // Register each descriptor as a separate region
            for i in 0..num_descs {
                let addr = layout.desc_table_addr + (i * Descriptor::SIZE) as u64;
                regions.insert(
                    addr,
                    RegionInfo {
                        kind: RegionKind::Desc(i),
                        size: Descriptor::SIZE,
                    },
                );
            }

            regions.insert(
                layout.drv_evt_addr,
                RegionInfo {
                    kind: RegionKind::DrvEvt,
                    size: EventSuppression::SIZE,
                },
            );

            regions.insert(
                layout.dev_evt_addr,
                RegionInfo {
                    kind: RegionKind::DevEvt,
                    size: EventSuppression::SIZE,
                },
            );

            regions.insert(
                pool_base,
                RegionInfo {
                    kind: RegionKind::Pool,
                    size: pool_size,
                },
            );

            Self {
                descs,
                drv: core::cell::UnsafeCell::new(EventSuppression::zeroed()),
                dev: core::cell::UnsafeCell::new(EventSuppression::zeroed()),
                pool: loom::cell::UnsafeCell::new(vec![0u8; pool_size]),
                desc_flags,
                drv_flags: AtomicU16::new(0),
                dev_flags: AtomicU16::new(0),
                regions,
                layout,
            }
        }

        pub fn layout(&self) -> Layout {
            self.layout
        }

        fn region(&self, addr: u64) -> Option<(RegionInfo, usize)> {
            let (&base, &info) = self.regions.range(..=addr).next_back()?;
            let offset = (addr - base) as usize;

            if offset < info.size {
                Some((info, offset))
            } else {
                None
            }
        }

        fn desc_ptr(&self, idx: usize) -> *mut Descriptor {
            self.descs.as_ptr().cast_mut().wrapping_add(idx)
        }
    }

    impl MemOps for Arc<LoomMem> {
        type Error = MemErr;

        fn read(&self, addr: u64, dst: &mut [u8]) -> Result<usize, Self::Error> {
            let (info, offset) = self.region(addr).ok_or(MemErr)?;

            match info.kind {
                RegionKind::Desc(idx) => {
                    let desc = unsafe { &*self.desc_ptr(idx) };
                    let bytes = bytemuck::bytes_of(desc);
                    dst.copy_from_slice(&bytes[offset..offset + dst.len()]);
                }
                RegionKind::DrvEvt => {
                    let evt = unsafe { &*self.drv.get() };
                    let bytes = bytemuck::bytes_of(evt);
                    dst.copy_from_slice(&bytes[offset..offset + dst.len()]);
                }
                RegionKind::DevEvt => {
                    let evt = unsafe { &*self.dev.get() };
                    let bytes = bytemuck::bytes_of(evt);
                    dst.copy_from_slice(&bytes[offset..offset + dst.len()]);
                }
                RegionKind::Pool => {
                    self.pool.with(|buf| {
                        dst.copy_from_slice(&(unsafe { &*buf })[offset..offset + dst.len()]);
                    });
                }
            }
            Ok(dst.len())
        }

        fn write(&self, addr: u64, src: &[u8]) -> Result<usize, Self::Error> {
            let (info, offset) = self.region(addr).ok_or(MemErr)?;

            match info.kind {
                RegionKind::Desc(idx) => {
                    let desc = unsafe { &mut *self.desc_ptr(idx) };
                    let bytes = bytemuck::bytes_of_mut(desc);
                    bytes[offset..offset + src.len()].copy_from_slice(src);
                }
                RegionKind::DrvEvt => {
                    let evt = unsafe { &mut *self.drv.get() };
                    let bytes = bytemuck::bytes_of_mut(evt);
                    bytes[offset..offset + src.len()].copy_from_slice(src);
                }
                RegionKind::DevEvt => {
                    let evt = unsafe { &mut *self.dev.get() };
                    let bytes = bytemuck::bytes_of_mut(evt);
                    bytes[offset..offset + src.len()].copy_from_slice(src);
                }
                RegionKind::Pool => {
                    self.pool.with_mut(|buf| {
                        (unsafe { &mut *buf })[offset..offset + src.len()].copy_from_slice(src);
                    });
                }
            }
            Ok(src.len())
        }

        fn load_acquire(&self, addr: u64) -> Result<u16, Self::Error> {
            let (info, _offset) = self.region(addr).ok_or(MemErr)?;

            Ok(match info.kind {
                RegionKind::Desc(idx) => self.desc_flags[idx].load(Ordering::Acquire),
                RegionKind::DrvEvt => self.drv_flags.load(Ordering::Acquire),
                RegionKind::DevEvt => self.dev_flags.load(Ordering::Acquire),
                RegionKind::Pool => return Err(MemErr),
            })
        }

        fn store_release(&self, addr: u64, val: u16) -> Result<(), Self::Error> {
            let (info, _offset) = self.region(addr).ok_or(MemErr)?;

            match info.kind {
                RegionKind::Desc(idx) => self.desc_flags[idx].store(val, Ordering::Release),
                RegionKind::DrvEvt => self.drv_flags.store(val, Ordering::Release),
                RegionKind::DevEvt => self.dev_flags.store(val, Ordering::Release),
                RegionKind::Pool => return Err(MemErr),
            }
            Ok(())
        }

        unsafe fn as_slice(&self, addr: u64, len: usize) -> Result<&[u8], Self::Error> {
            let (info, offset) = self.region(addr).ok_or(MemErr)?;

            match info.kind {
                RegionKind::Pool => {
                    // Safety: pool memory is a contiguous Vec<u8>; caller ensures
                    // no concurrent writes for the lifetime of the returned slice.
                    let buf = unsafe { &*self.pool.get() };
                    Ok(&buf[offset..offset + len])
                }
                _ => Err(MemErr),
            }
        }

        unsafe fn as_mut_slice(&self, addr: u64, len: usize) -> Result<&mut [u8], Self::Error> {
            let (info, offset) = self.region(addr).ok_or(MemErr)?;

            match info.kind {
                RegionKind::Pool => {
                    let buf = unsafe { &mut *self.pool.get() };
                    Ok(&mut buf[offset..offset + len])
                }
                _ => Err(MemErr),
            }
        }
    }

    #[derive(Debug)]
    pub struct Notify {
        kicks: AtomicUsize,
    }

    impl Notify {
        pub fn new() -> Self {
            Self {
                kicks: AtomicUsize::new(0),
            }
        }
    }

    impl Notifier for Arc<Notify> {
        fn notify(&self, _stats: QueueStats) {
            self.kicks.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn virtq_ping_pong() {
        loom::model(|| {
            let ring_base = 0x10000;
            let pool_base = 0x40000;
            let pool_size = 0x10000;

            let mem = Arc::new(LoomMem::new(ring_base, 8, pool_base, pool_size));
            let pool = BufferPoolSync::<256, 4096>::new(pool_base, pool_size).unwrap();
            let notify = Arc::new(Notify::new());

            let mut prod = VirtqProducer::new(mem.layout(), mem.clone(), notify.clone(), pool);
            let mut cons = VirtqConsumer::new(mem.layout(), mem.clone(), notify.clone());

            let t_prod = thread::spawn(move || {
                let mut se = prod.chain().entry(4).completion(32).build().unwrap();
                se.write_all(b"ping").unwrap();
                let tok = prod.submit(se).unwrap();
                loop {
                    if let Some(r) = prod.poll().unwrap() {
                        assert_eq!(r.token, tok);
                        assert_eq!(&r.data[..], b"pong");
                        break;
                    }
                    thread::yield_now();
                }
            });

            let t_cons = thread::spawn(move || {
                let (entry, completion) = loop {
                    if let Some(r) = cons.poll(1024).unwrap() {
                        break r;
                    }
                    thread::yield_now();
                };
                assert_eq!(entry.data().as_ref(), b"ping");
                let SendCompletion::Writable(mut wc) = completion else {
                    panic!("expected writable completion");
                };
                wc.write_all(b"pong").unwrap();
                cons.complete(wc.into()).unwrap();
            });

            t_prod.join().unwrap();
            t_cons.join().unwrap();
        });
    }
}
