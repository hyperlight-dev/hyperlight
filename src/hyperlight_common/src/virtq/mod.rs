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
//!   chain lifecycle, and notification decisions. This is the recommended API
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
//! ## Single Readable/Writable Chain
//!
//! ```ignore
//! // Producer (driver) side - build and submit a send chain
//! let mut chain = producer.chain()
//!     .readable(64)
//!     .writable(128)
//!     .build()?;
//! chain.write_all(b"request data")?;
//! let token = producer.submit(chain)?;
//! // ... wait for notification ...
//! if let Some(used) = producer.poll()? {
//!     match used {
//!         UsedChain::Data(_, segments) => process(segments),
//!         UsedChain::Ack(_) => {}
//!     }
//! }
//!
//! // Consumer (device) side - receive a chain and reply/ack it
//! if let Some((chain, reply)) = consumer.poll(max_recv_len)? {
//!     let request = chain.to_bytes();
//!     match reply {
//!         ReplyChain::Writable(mut wc) => {
//!             let response = handle(request);
//!             wc.write_all(&response)?;
//!             consumer.complete(wc)?;
//!         }
//!         ReplyChain::Ack(ack) => {
//!             consumer.complete(ack)?;
//!         }
//!     }
//! }
//!
//! // Multiple pending completions (no borrow on consumer)
//! let mut pending = Vec::new();
//! while let Some((chain, reply)) = consumer.poll(max_recv_len)? {
//!     pending.push((process(chain), reply));
//! }
//! for (result, reply) in pending {
//!     consumer.complete(reply)?;
//! }
//! ```
//!
//! ## Multiple Chains
//!
//! Each submit checks event suppression and notifies independently. Use
//! [`VirtqProducer::batch`] when a higher-level protocol wants to publish
//! multiple chains and kick the queue once.
//!
//! ```ignore
//! let mut batch = producer.batch();
//! for data in entries {
//!     let mut chain = batch.chain()
//!         .readable(data.len())
//!         .writable(64)
//!         .build()?;
//!     chain.write_all(data)?;
//!     batch.submit(chain)?;
//! }
//! batch.finish()?;
//! ```
//!
//! ## Completion Batching with Event Suppression
//!
//! To receive a single notification when multiple requests complete:
//!
//! ```ignore
//! // Submit chains
//! for data in entries {
//!     let mut chain = producer.chain()
//!         .readable(data.len())
//!         .writable(64)
//!         .build()?;
//!     chain.write_all(data)?;
//!     producer.submit(chain)?;
//! }
//!
//! // Tell device: "notify me only after completing past this cursor"
//! let cursor = producer.used_cursor();
//! producer.set_used_suppression(SuppressionKind::Descriptor(cursor))?;
//!
//! // Wait for single notification, then drain all responses
//! producer.drain(|used| {
//!     if let UsedChain::Data(token, data) = used {
//!         handle_response(token, data);
//!     }
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
mod buffer;
mod consumer;
mod desc;
mod event;
pub mod msg;
mod pool;
mod producer;
mod ring;

#[cfg(all(test, loom))]
mod concurrency;

use core::num::NonZeroU16;

pub use access::*;
pub use buffer::*;
pub use consumer::*;
pub use desc::*;
pub use event::*;
pub use pool::*;
pub use producer::*;
pub use ring::*;
use thiserror::Error;

/// A trait for notifying the consumer about virtqueue events.
pub trait Notifier {
    fn notify(&self, stats: QueueStats);
}

/// Errors that can occur in the virtqueue operations.
#[derive(Error, Debug)]
pub enum VirtqError {
    #[error("Ring error: {0}")]
    RingError(RingError),
    #[error("Allocation error: {0}")]
    Alloc(AllocError),
    #[error("Ring or pool temporarily full")]
    Backpressure,
    #[error("Allocation exceeds pool capacity")]
    OutOfMemory,
    #[error("Invalid chain received")]
    BadChain,
    #[error("Payload data too large: received {recv} bytes, limit {limit} bytes")]
    PayloadTooLarge { recv: usize, limit: usize },
    #[error("Reply data too large for allocated buffer")]
    ReplyTooLarge,
    #[error("Internal state error")]
    InvalidState,
    #[error("Memory write error")]
    MemoryWriteError,
    #[error("Memory read error")]
    MemoryReadError,
    #[error("No payload segment in this chain")]
    NoPayloadSegment,
}

impl VirtqError {
    /// Check if this error is transient or unrecoverable.
    #[inline(always)]
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Backpressure)
    }
}

impl From<RingError> for VirtqError {
    fn from(e: RingError) -> Self {
        match e {
            RingError::WouldBlock => Self::Backpressure,
            other => Self::RingError(other),
        }
    }
}

impl From<AllocError> for VirtqError {
    fn from(e: AllocError) -> Self {
        match e {
            AllocError::NoSpace => Self::Backpressure,
            AllocError::OutOfMemory => Self::OutOfMemory,
            other => Self::Alloc(other),
        }
    }
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
    desc_table_addr: u64,
    /// Number of descriptors (ring size, must be power of 2).
    desc_table_len: u16,
    /// Driver-written event suppression area in shared memory.
    drv_evt_addr: u64,
    /// Device-written event suppression area in shared memory.
    dev_evt_addr: u64,
}

#[inline]
const fn align_up(val: usize, align: usize) -> usize {
    val.next_multiple_of(align)
}

impl Layout {
    /// Create a Layout from a base address and number of descriptors.
    ///
    /// The base address must be aligned to `Descriptor::ALIGN`.
    /// The number of descriptors must be a power of 2.
    /// The memory region starting at `base` must be at least `Layout::query_size(num_descs)` bytes.
    ///
    /// # Safety
    /// - `base` must be valid for `Layout::query_size(num_descs)` bytes.
    /// - `base` must be aligned to `Descriptor::ALIGN`.
    /// - Memory must remain valid for the lifetime of the ring.
    pub const unsafe fn from_base(base: u64, num_descs: NonZeroU16) -> Result<Self, RingError> {
        let num_descs = num_descs.get() as usize;
        if !num_descs.is_power_of_two() {
            return Err(RingError::InvalidLayout);
        }

        if !base.is_multiple_of(Descriptor::ALIGN as u64) {
            return Err(RingError::InvalidLayout);
        }

        if base
            .checked_add(Layout::query_size(num_descs) as u64)
            .is_none()
        {
            return Err(RingError::InvalidLayout);
        }

        let desc_size = num_descs * Descriptor::SIZE;
        let event_size = EventSuppression::SIZE;
        let event_align = EventSuppression::ALIGN;

        let drv_evt_offset = align_up(desc_size, event_align);
        let dev_evt_offset = align_up(drv_evt_offset + event_size, event_align);

        Ok(Self {
            desc_table_addr: base,
            desc_table_len: num_descs as u16,
            drv_evt_addr: base + drv_evt_offset as u64,
            dev_evt_addr: base + dev_evt_offset as u64,
        })
    }

    /// Packed ring descriptor table base in shared memory.
    pub const fn desc_table_addr(&self) -> u64 {
        self.desc_table_addr
    }

    /// Number of descriptors in the ring.
    pub const fn desc_table_len(&self) -> u16 {
        self.desc_table_len
    }

    /// Driver-written event suppression area in shared memory.
    pub const fn drv_evt_addr(&self) -> u64 {
        self.drv_evt_addr
    }

    /// Device-written event suppression area in shared memory.
    pub const fn dev_evt_addr(&self) -> u64 {
        self.dev_evt_addr
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

/// A token representing a sent chain in the virtqueue.
///
/// Tokens uniquely identify in-flight requests and are used to correlate
/// requests with their responses.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Token {
    /// Monotonically increasing generation counter.
    pub seq: u32,
    /// Descriptor ID this token maps to.
    pub id: u16,
}

impl From<BufferElement> for Allocation {
    fn from(value: BufferElement) -> Self {
        Allocation {
            addr: value.addr,
            len: value.len as usize,
        }
    }
}

const _: () = {
    #[allow(clippy::unwrap_used)]
    const fn verify_layout(num_descs: usize) {
        let base = 0x1000u64;

        // Safety: base is aligned and we're only checking layout math
        let layout =
            match unsafe { Layout::from_base(base, NonZeroU16::new(num_descs as u16).unwrap()) } {
                Ok(l) => l,
                Err(_) => panic!("from_base failed"),
            };

        let expected_size = Layout::query_size(num_descs);

        assert!(layout.desc_table_addr() == base);
        assert!(layout.desc_table_len() as usize == num_descs);
        assert!(
            layout
                .drv_evt_addr()
                .is_multiple_of(EventSuppression::ALIGN as u64)
        );
        assert!(
            layout
                .dev_evt_addr()
                .is_multiple_of(EventSuppression::ALIGN as u64)
        );

        // Events don't overlap with descriptor table
        let desc_end = base + (num_descs * Descriptor::SIZE) as u64;
        assert!(layout.drv_evt_addr() >= desc_end);
        assert!(layout.dev_evt_addr() >= layout.drv_evt_addr() + EventSuppression::SIZE as u64);

        // Total size from query_size covers entire layout
        let layout_end = layout.dev_evt_addr() + EventSuppression::SIZE as u64;
        assert!(base + expected_size as u64 == layout_end);
    }

    unsafe {
        assert!(Layout::from_base(u64::MAX, NonZeroU16::new(1).unwrap()).is_err());
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
    use alloc::collections::BTreeMap;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Mutex;

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
        max_alloc_len: usize,
        allocations: Arc<Mutex<BTreeMap<u64, usize>>>,
    }

    impl TestPool {
        pub(crate) fn new(base: u64, size: usize) -> Self {
            Self {
                base,
                next: Arc::new(AtomicU64::new(base)),
                size,
                max_alloc_len: usize::MAX,
                allocations: Arc::new(Mutex::new(BTreeMap::new())),
            }
        }

        pub(crate) fn new_with_max_alloc_len(base: u64, size: usize, max_alloc_len: usize) -> Self {
            Self {
                base,
                next: Arc::new(AtomicU64::new(base)),
                size,
                max_alloc_len,
                allocations: Arc::new(Mutex::new(BTreeMap::new())),
            }
        }
    }

    impl BufferProvider for TestPool {
        fn max_alloc_len(&self) -> usize {
            self.max_alloc_len
        }

        fn alloc(&self, len: usize) -> Result<Allocation, AllocError> {
            if len == 0 {
                return Err(AllocError::InvalidArg);
            }

            let addr = self.next.fetch_add(len as u64, Ordering::Relaxed);
            let end = addr + len as u64;
            if end > self.base + self.size as u64 {
                return Err(AllocError::NoSpace);
            }
            self.allocations
                .lock()
                .expect("poisoned mutex")
                .insert(addr, len);
            Ok(Allocation { addr, len })
        }

        fn dealloc(&self, addr: u64) -> Result<(), AllocError> {
            self.allocations
                .lock()
                .expect("poisoned mutex")
                .remove(&addr)
                .map(|_| ())
                .ok_or(AllocError::InvalidFree(addr, 0))
        }
    }

    type TestProducer = VirtqProducer<TestMem, TestNotifier, TestPool>;
    type TestConsumer = VirtqConsumer<TestMem, TestNotifier>;

    /// Create test infrastructure: a producer, consumer, and notifier backed
    /// by the supplied [`OwnedRing`].
    pub(crate) fn make_test_producer(
        ring: &OwnedRing,
    ) -> (TestProducer, TestConsumer, TestNotifier) {
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

    /// Helper: build and submit a readable+writable chain using the chain() builder.
    fn send_readwrite(
        producer: &mut VirtqProducer<TestMem, TestNotifier, TestPool>,
        entry_data: &[u8],
        used_cap: usize,
    ) -> Token {
        let mut se = producer
            .chain()
            .readable(entry_data.len())
            .writable(used_cap)
            .build()
            .unwrap();
        se.write_all(entry_data).unwrap();
        producer.submit(se).unwrap()
    }

    fn poll_received(
        consumer: &mut VirtqConsumer<TestMem, TestNotifier>,
    ) -> (RecvChain, ReplyChain<TestMem>) {
        consumer.poll(1024).unwrap().unwrap()
    }

    #[test]
    fn test_submit_notifies() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, notifier) = make_test_producer(&ring);

        let initial_count = notifier.notification_count();

        let token = send_readwrite(&mut producer, b"hello", 64);
        assert!(notifier.notification_count() > initial_count);

        let (recv, _reply) = poll_received(&mut consumer);
        assert_eq!(recv.token(), token);
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
            let (_recv, reply) = poll_received(&mut consumer);
            consumer.complete(reply).unwrap();
        }

        // All completions available
        let used1 = producer.poll().unwrap().unwrap();
        let used2 = producer.poll().unwrap().unwrap();
        let used3 = producer.poll().unwrap().unwrap();
        assert!(
            [used1.token(), used2.token(), used3.token()].contains(&tok1)
                && [used1.token(), used2.token(), used3.token()].contains(&tok2)
                && [used1.token(), used2.token(), used3.token()].contains(&tok3)
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

        // Set up reply batching via used suppression
        let cursor = producer.used_cursor();
        producer
            .set_used_suppression(SuppressionKind::Descriptor(cursor))
            .unwrap();

        // Consumer processes requests
        for _ in 0..3 {
            let (_recv, reply) = poll_received(&mut consumer);
            let ReplyChain::Writable(mut wc) = reply else {
                panic!("expected writable reply");
            };
            wc.write_all(b"used-data").unwrap();
            consumer.complete(wc).unwrap();
        }

        // Producer can drain all responses
        let mut responses = Vec::new();
        producer
            .drain(|reply| {
                responses.push(reply.token());
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

        let mut se = producer.chain().readable(4).writable(32).build().unwrap();
        se.write_all(b"test").unwrap();
        producer.submit(se).unwrap();
        assert_eq!(notifier.count.load(Ordering::Relaxed), 1);
        assert!(notifier.last_num_inflight.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn test_chain_batch() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, notifier) = make_test_producer(&ring);

        let initial_count = notifier.notification_count();

        // First readable chain
        let mut se1 = producer.chain().readable(64).writable(128).build().unwrap();
        se1.write_all(b"first-ent").unwrap();
        let _tok1 = producer.submit(se1).unwrap();

        // Write-based recv
        let mut se2 = producer.chain().readable(64).writable(64).build().unwrap();
        se2.write_all(b"copy-ent").unwrap();
        let _tok2 = producer.submit(se2).unwrap();

        // Completion-only chain
        let se3 = producer.chain().writable(32).build().unwrap();
        let tok3 = producer.submit(se3).unwrap();

        // Each submit may notify independently
        assert!(notifier.notification_count() > initial_count);

        // Consumer sees all three entries
        let (recv1, reply1) = poll_received(&mut consumer);
        assert_eq!(recv1.to_bytes().as_ref(), b"first-ent");
        consumer.complete(reply1).unwrap();

        let (recv2, reply2) = poll_received(&mut consumer);
        assert_eq!(recv2.to_bytes().as_ref(), b"copy-ent");
        consumer.complete(reply2).unwrap();

        let (_recv3, reply3) = poll_received(&mut consumer);
        let ReplyChain::Writable(mut wc) = reply3 else {
            panic!("expected writable reply");
        };
        wc.write_all(b"resp").unwrap();
        consumer.complete(wc).unwrap();

        // Drain completions
        let _ = producer.poll().unwrap().unwrap();
        let _ = producer.poll().unwrap().unwrap();

        let used = producer.poll().unwrap().unwrap();
        assert_eq!(used.token(), tok3);
        assert_eq!(used.to_bytes().unwrap().as_ref(), b"resp");
    }

    #[test]
    fn test_chain_write_send() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().readable(64).writable(128).build().unwrap();
        se.write_all(b"hello").unwrap();
        let token = producer.submit(se).unwrap();

        // Consumer sees the data
        let (recv, reply) = poll_received(&mut consumer);
        assert_eq!(recv.token(), token);
        assert_eq!(recv.to_bytes().as_ref(), b"hello");

        // Write response
        let ReplyChain::Writable(mut wc) = reply else {
            panic!("expected writable reply");
        };
        wc.write_all(b"world").unwrap();
        consumer.complete(wc).unwrap();
        let used = producer.poll().unwrap().unwrap();
        assert_eq!(used.to_bytes().unwrap().as_ref(), b"world");
    }

    #[test]
    fn test_full_round_trip() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        // Send an recv
        let token = send_readwrite(&mut producer, b"round-trip-recv", 128);

        // Consumer receives and responds
        let (recv, reply) = poll_received(&mut consumer);
        assert_eq!(recv.token(), token);
        assert_eq!(recv.to_bytes().as_ref(), b"round-trip-recv");

        let ReplyChain::Writable(mut wc) = reply else {
            panic!("expected writable reply");
        };
        assert!(wc.capacity() >= 128);
        wc.write_all(b"round-trip-rsp").unwrap();
        consumer.complete(wc).unwrap();

        // Producer gets the reply
        let used = producer.poll().unwrap().unwrap();
        assert_eq!(used.token(), token);
        assert_eq!(used.to_bytes().unwrap().as_ref(), b"round-trip-rsp");
    }

    #[test]
    fn test_cancel_submits_zero_length() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let token = send_readwrite(&mut producer, b"recv-data", 64);

        let (_recv, reply) = poll_received(&mut consumer);
        consumer.complete(reply).unwrap();

        let used = producer.poll().unwrap().unwrap();
        assert_eq!(used.token(), token);
        assert_eq!(used.to_bytes().unwrap().len(), 0);
        assert!(used.to_bytes().unwrap().is_empty());
    }

    #[test]
    fn test_hold_reply_and_complete() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let token = send_readwrite(&mut producer, b"deferred", 64);

        // Poll and hold the reply
        let (recv, reply) = poll_received(&mut consumer);
        assert_eq!(recv.token(), token);
        assert_eq!(recv.to_bytes().as_ref(), b"deferred");

        let ReplyChain::Writable(mut wc) = reply else {
            panic!("expected writable reply");
        };
        wc.write_all(b"deferred-used").unwrap();
        consumer.complete(wc).unwrap();

        let used = producer.poll().unwrap().unwrap();
        assert_eq!(used.token(), token);
        assert_eq!(used.to_bytes().unwrap().as_ref(), b"deferred-used");
    }

    #[test]
    fn test_concurrent_pending_replies() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let tok1 = send_readwrite(&mut producer, b"first", 64);
        let tok2 = send_readwrite(&mut producer, b"second", 64);

        // Poll both
        let (recv1, reply1) = poll_received(&mut consumer);
        assert_eq!(recv1.token(), tok1);
        assert_eq!(recv1.to_bytes().as_ref(), b"first");

        let (recv2, reply2) = poll_received(&mut consumer);
        assert_eq!(recv2.token(), tok2);
        assert_eq!(recv2.to_bytes().as_ref(), b"second");

        // Complete second first (out of order)
        let ReplyChain::Writable(mut wc2) = reply2 else {
            panic!("expected writable");
        };
        wc2.write_all(b"resp2").unwrap();
        consumer.complete(wc2).unwrap();

        let ReplyChain::Writable(mut wc1) = reply1 else {
            panic!("expected writable");
        };
        wc1.write_all(b"resp1").unwrap();
        consumer.complete(wc1).unwrap();

        let used1 = producer.poll().unwrap().unwrap();
        let used2 = producer.poll().unwrap().unwrap();
        let mut responses: Vec<_> = vec![
            (used1.token(), used1.to_bytes().unwrap().to_vec()),
            (used2.token(), used2.to_bytes().unwrap().to_vec()),
        ];
        responses.sort_by_key(|(t, _)| t.seq);

        let expected_first = responses.iter().find(|(t, _)| *t == tok1).unwrap();
        let expected_second = responses.iter().find(|(t, _)| *t == tok2).unwrap();
        assert_eq!(&expected_first.1[..], b"resp1");
        assert_eq!(&expected_second.1[..], b"resp2");
    }

    /// Helper: submit a read-only chain (readable data, no writable reply).
    fn send_readonly(
        producer: &mut VirtqProducer<TestMem, TestNotifier, TestPool>,
        entry_data: &[u8],
    ) -> Token {
        let mut se = producer.chain().readable(entry_data.len()).build().unwrap();
        se.write_all(entry_data).unwrap();
        producer.submit(se).unwrap()
    }

    #[test]
    fn test_reclaim_frees_ring_slots() {
        let ring = make_ring(4);
        let (mut producer, mut consumer, _) = make_test_producer(&ring);

        // Fill the ring with ReadOnly entries
        send_readonly(&mut producer, b"a");
        send_readonly(&mut producer, b"b");
        send_readonly(&mut producer, b"c");
        send_readonly(&mut producer, b"d");

        // Ring is now full - next submit should fail with Backpressure
        let mut se = producer.chain().readable(1).build().unwrap();
        se.write_all(b"e").unwrap();
        let res = producer.submit(se);
        assert!(
            matches!(res, Err(VirtqError::Backpressure)),
            "expected Backpressure from full ring"
        );

        // Consumer acks all entries
        while let Some(result) = consumer.poll(1024).unwrap() {
            let (_, reply) = result;
            consumer.complete(reply).unwrap();
        }

        // Reclaim should free ring slots without losing data
        let count = producer.reclaim().unwrap();
        assert_eq!(count, 4, "expected 4 reclaimed entries");

        // Ring should have space now
        send_readonly(&mut producer, b"e");
    }

    #[test]
    fn test_reclaim_buffers_rw_completions() {
        let ring = make_ring(4);
        let (mut producer, mut consumer, _) = make_test_producer(&ring);

        // Submit a ReadWrite recv
        let tok = send_readwrite(&mut producer, b"request", 64);

        // Consumer processes and writes response
        let (_, reply) = poll_received(&mut consumer);
        let ReplyChain::Writable(mut wc) = reply else {
            panic!("expected writable");
        };
        wc.write_all(b"response-data").unwrap();
        consumer.complete(wc).unwrap();

        // Reclaim buffers the reply (doesn't discard it)
        let count = producer.reclaim().unwrap();
        assert_eq!(count, 1);

        // poll() should return the buffered reply
        let used = producer.poll().unwrap().unwrap();
        assert_eq!(used.token(), tok);
        assert_eq!(used.to_bytes().unwrap().as_ref(), b"response-data");
    }

    #[test]
    fn test_reclaim_discards_readonly_completions() {
        let ring = make_ring(8);
        let (mut producer, mut consumer, _) = make_test_producer(&ring);

        // Submit 3 entries: RO, RW, RO
        let _tok_ro1 = send_readonly(&mut producer, b"log1");
        let tok_rw = send_readwrite(&mut producer, b"call", 64);
        let _tok_ro2 = send_readonly(&mut producer, b"log2");

        // Consumer processes all 3
        let (_, reply1) = poll_received(&mut consumer);
        consumer.complete(reply1).unwrap(); // ack RO

        let (_, reply2) = poll_received(&mut consumer);
        let ReplyChain::Writable(mut wc) = reply2 else {
            panic!("expected writable");
        };
        wc.write_all(b"result").unwrap();
        consumer.complete(wc).unwrap(); // complete RW

        let (_, reply3) = poll_received(&mut consumer);
        consumer.complete(reply3).unwrap(); // ack RO

        // Reclaim all 3 - RO completions are discarded, only RW is buffered
        let count = producer.reclaim().unwrap();
        assert_eq!(count, 3);

        // poll() returns only the RW reply
        let used = producer.poll().unwrap().unwrap();
        assert_eq!(used.token(), tok_rw);
        assert_eq!(used.to_bytes().unwrap().as_ref(), b"result");

        // No more - RO completions were discarded
        assert!(producer.poll().unwrap().is_none());
    }

    #[test]
    fn test_reclaim_mixed_with_poll() {
        let ring = make_ring(8);
        let (mut producer, mut consumer, _) = make_test_producer(&ring);

        // Submit and complete 2 entries
        send_readonly(&mut producer, b"x");
        let tok_rw = send_readwrite(&mut producer, b"y", 64);

        let (_, reply1) = poll_received(&mut consumer);
        consumer.complete(reply1).unwrap();

        let (_, reply2) = poll_received(&mut consumer);
        let ReplyChain::Writable(mut wc) = reply2 else {
            panic!("expected writable");
        };
        wc.write_all(b"reply").unwrap();
        consumer.complete(wc).unwrap();

        // poll() consumes first recv directly from ring
        let used1 = producer.poll().unwrap().unwrap();
        assert!(matches!(used1, UsedChain::Ack(_)));

        // reclaim() buffers second recv
        let count = producer.reclaim().unwrap();
        assert_eq!(count, 1);

        // poll() returns the buffered one
        let used2 = producer.poll().unwrap().unwrap();
        assert_eq!(used2.token(), tok_rw);
        assert_eq!(used2.to_bytes().unwrap().as_ref(), b"reply");
    }

    /// reclaim + submit must not cause token collisions.
    #[test]
    fn test_reclaim_submit_no_token_collision() {
        let ring = make_ring(8);
        let (mut producer, mut consumer, _) = make_test_producer(&ring);

        // Submit and complete a ReadOnly recv
        let tok_old = send_readonly(&mut producer, b"log");

        let (_, reply) = poll_received(&mut consumer);
        consumer.complete(reply).unwrap();

        let count = producer.reclaim().unwrap();
        assert_eq!(count, 1);

        // Submit a new ReadWrite recv - may reuse the same descriptor ID
        let tok_new = send_readwrite(&mut producer, b"call", 64);

        // Tokens must differ even if the descriptor ID was recycled
        assert_ne!(
            tok_old, tok_new,
            "tokens must be unique across reclaim/submit cycles"
        );

        // Complete the ReadWrite recv
        let (_, reply) = poll_received(&mut consumer);
        let ReplyChain::Writable(mut wc) = reply else {
            panic!("expected writable");
        };
        wc.write_all(b"result").unwrap();
        consumer.complete(wc).unwrap();

        // Poll returns only the RW reply (RO was discarded by reclaim)
        let used = producer.poll().unwrap().unwrap();
        assert_eq!(used.token(), tok_new);
        assert_eq!(used.to_bytes().unwrap().as_ref(), b"result");

        // No stale RO reply in the queue
        assert!(producer.poll().unwrap().is_none());
    }

    /// Verify that repeated oneshot submit/reclaim cycles do not accumulate pending completions.
    #[test]
    fn test_reclaim_readonly_does_not_leak_pending() {
        let ring = make_ring(4);
        let (mut producer, mut consumer, _) = make_test_producer(&ring);

        for _ in 0..10 {
            // Fill the ring
            for _ in 0..4 {
                send_readonly(&mut producer, b"msg");
            }

            // Consumer acks all
            while let Some(result) = consumer.poll(1024).unwrap() {
                let (_, reply) = result;
                consumer.complete(reply).unwrap();
            }

            // Reclaim frees ring slots; empty completions are discarded
            let count = producer.reclaim().unwrap();
            assert_eq!(count, 4);

            // No completions should be buffered in pending
            assert!(
                producer.poll().unwrap().is_none(),
                "pending should be empty after reclaiming RO entries"
            );
        }
    }
}
