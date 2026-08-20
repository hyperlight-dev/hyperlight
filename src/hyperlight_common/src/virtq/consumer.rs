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

use alloc::vec;

use bytes::Bytes;
use fixedbitset::FixedBitSet;
use smallvec::SmallVec;

use super::*;

type WritableElems = SmallVec<[BufferElement; 2]>;

/// Payload received from the producer, safely copied out of shared memory.
///
/// Created by [`VirtqConsumer::poll`]. Device-readable segments are eagerly
/// copied during poll using [`MemOps::read`] (volatile on the host side), so
/// accessing data requires no unsafe code and no references into shared
/// memory. Segment boundaries are preserved in [`Segments`].
#[derive(Debug, Clone)]
pub struct RecvChain {
    token: Token,
    segments: Segments,
}

impl RecvChain {
    /// The token identifying this chain.
    pub fn token(&self) -> Token {
        self.token
    }

    /// The chain payload as ordered byte segments.
    pub fn segments(&self) -> &Segments {
        &self.segments
    }

    /// Consume the chain, taking ownership of the segments.
    pub fn into_segments(self) -> Segments {
        self.segments
    }

    /// Return the chain payload as contiguous bytes.
    ///
    /// Returns empty [`Bytes`] when the chain has no readable buffers.
    pub fn to_bytes(&self) -> Bytes {
        self.segments.to_bytes()
    }

    /// Consume the chain and return the payload as contiguous bytes.
    pub fn into_bytes(self) -> Bytes {
        self.segments.into_bytes()
    }
}

/// Consumer-side chain reply, either writable or ack-only.
///
/// Created by [`VirtqConsumer::poll`]. Must be submitted back via
/// [`VirtqConsumer::complete`] to release the descriptor.
#[must_use = "dropping without completing leaks the descriptor"]
pub enum ReplyChain<M: MemOps> {
    /// Reply with writable buffer capacity.
    /// Use the `write*` methods on [`WritableChain`] to fill the
    /// response buffer.
    Writable(WritableChain<M>),
    /// Ack-only reply (for chains with only readable buffers). No response buffer.
    /// Just pass back to [`VirtqConsumer::complete`] to acknowledge.
    Ack(AckChain),
}

impl<M: MemOps> ReplyChain<M> {
    /// The token identifying this reply.
    pub fn token(&self) -> Token {
        match self {
            ReplyChain::Writable(wc) => wc.token(),
            ReplyChain::Ack(ack) => ack.token(),
        }
    }

    /// Number of bytes written (0 for Ack).
    pub fn written(&self) -> usize {
        match self {
            ReplyChain::Writable(wc) => wc.written,
            ReplyChain::Ack(_) => 0,
        }
    }

    /// Convert into the writable form.
    ///
    /// Returns the [`AckChain`] unchanged as `Err` for ack-only replies, so the
    /// completion capability is never silently dropped.
    pub fn into_writable(self) -> Result<WritableChain<M>, AckChain> {
        match self {
            ReplyChain::Writable(wc) => Ok(wc),
            ReplyChain::Ack(ack) => Err(ack),
        }
    }
}

/// A reply chain with writable buffer capacity.
///
/// # Example
///
/// ```ignore
/// if let ReplyChain::Writable(mut wc) = reply {
///     wc.write_all(b"response data")?;
///     consumer.complete(wc)?;
/// }
/// ```
#[must_use = "dropping without completing leaks the descriptor"]
pub struct WritableChain<M: MemOps> {
    mem: M,
    token: Token,
    elems: WritableElems,
    capacity: usize,
    written: usize,
}

impl<M: MemOps> WritableChain<M> {
    fn new(mem: M, token: Token, elems: WritableElems) -> Self {
        let capacity = elems.iter().map(|elem| elem.len as usize).sum();
        Self {
            mem,
            token,
            elems,
            capacity,
            written: 0,
        }
    }

    /// The token identifying this writable reply.
    pub fn token(&self) -> Token {
        self.token
    }

    /// Total reply capacity in bytes.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of bytes written so far.
    pub fn written(&self) -> usize {
        self.written
    }

    /// Remaining reply capacity.
    pub fn remaining(&self) -> usize {
        self.capacity() - self.written()
    }

    /// Write bytes into writable buffers, returning how many were written.
    ///
    /// Appends at the current write position. If `buf` is larger than the
    /// remaining capacity, writes as many bytes as will fit (partial write).
    /// Segmentation is intentionally hidden; host-side writes must go through
    /// [`MemOps::write`].
    ///
    /// # Errors
    ///
    /// - [`VirtqError::MemoryWriteError`] - underlying MemOps write failed
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, VirtqError> {
        let written = write_elements(&self.mem, &self.elems, self.written, buf)
            .map_err(|_| VirtqError::MemoryWriteError)?;
        self.written += written;
        Ok(written)
    }

    /// Write the entire buffer or return an error.
    ///
    /// # Errors
    ///
    /// - [`VirtqError::ReplyTooLarge`] - buf exceeds remaining capacity
    /// - [`VirtqError::MemoryWriteError`] - underlying MemOps write failed
    pub fn write_all(&mut self, buf: &[u8]) -> Result<&mut Self, VirtqError> {
        if buf.len() > self.remaining() {
            return Err(VirtqError::ReplyTooLarge);
        }

        let written = self.write(buf)?;
        debug_assert_eq!(written, buf.len());
        Ok(self)
    }

    /// Rewind the write cursor to the beginning.
    ///
    /// Previously written bytes in shared memory are not zeroed; the
    /// `written` count is simply reset to 0.
    pub fn rewind(&mut self) {
        self.written = 0;
    }
}

/// An ack-only reply for chains with no writable buffers.
///
/// No response buffer - just pass back to [`VirtqConsumer::complete`]
/// to acknowledge processing and release the descriptor.
/// This wrapper keeps ack replies as a must-use completion capability instead
/// of exposing a bare token that could be accidentally ignored.
#[must_use = "dropping without completing leaks the descriptor"]
pub struct AckChain {
    token: Token,
}

impl AckChain {
    fn new(token: Token) -> Self {
        Self { token }
    }

    pub fn token(&self) -> Token {
        self.token
    }
}

/// A high-level virtqueue consumer (device side).
///
/// The consumer receives chains from the producer (driver), processes them,
/// and sends back replies. This is typically used on the device/host side.
///
/// # Example
///
/// ```ignore
/// let mut consumer = VirtqConsumer::new(layout, mem, notifier);
///
/// // Poll and process
/// while let Some((chain, reply)) = consumer.poll(MAX_RECV_LEN)? {
///     let data = chain.to_bytes();
///     match reply {
///         ReplyChain::Writable(mut wc) => {
///             let response = handle_request(data);
///             wc.write_all(&response)?;
///             consumer.complete(wc)?;
///         }
///         ReplyChain::Ack(ack) => {
///             consumer.complete(ack)?;
///         }
///     }
/// }
///
/// // Or defer completions
/// let mut pending = Vec::new();
/// while let Some((chain, reply)) = consumer.poll(MAX_RECV_LEN)? {
///     pending.push((process(chain), reply));
/// }
///
/// for (result, reply) in pending {
///     // ... complete later ...
///     consumer.complete(reply)?;
/// }
/// ```
pub struct VirtqConsumer<M, N> {
    inner: RingConsumer<M>,
    notifier: N,
    inflight: FixedBitSet,
    next_token: u32,
}

impl<M: MemOps + Clone, N: Notifier> VirtqConsumer<M, N> {
    /// Create a new virtqueue consumer.
    ///
    /// # Arguments
    ///
    /// * `layout` - Ring memory layout
    /// * `mem` - Memory ops implementation for reading/writing to shared memory
    /// * `notifier` - Callback for notifying the driver about replies
    pub fn new(layout: Layout, mem: M, notifier: N) -> Self {
        let inner = RingConsumer::new(layout, mem);
        let inflight = FixedBitSet::with_capacity(inner.len());

        Self {
            inner,
            notifier,
            inflight,
            next_token: 0,
        }
    }

    /// Poll for a single incoming chain from the driver.
    ///
    /// Returns a [`RecvChain`] (copied data) and a [`ReplyChain`] (writable reply
    /// capacity or ack token). Both are independent owned values with no borrow
    /// on the consumer.
    ///
    /// On [`VirtqError::BadChain`], [`VirtqError::PayloadTooLarge`], and
    /// [`VirtqError::MemoryReadError`] the descriptor is returned to the driver
    /// (completed with zero length) before the error is propagated, so a
    /// rejected chain does not leak.
    ///
    /// # Arguments
    ///
    /// * `max_recv_len` - Maximum receive payload size to copy. Payloads larger
    ///   than this return [`VirtqError::PayloadTooLarge`].
    ///
    /// # Errors
    ///
    /// - [`VirtqError::BadChain`] - Descriptor chain format not recognized
    /// - [`VirtqError::InvalidState`] - Descriptor ID collision (driver bug)
    /// - [`VirtqError::MemoryReadError`] - Failed to read chain payload from shared memory
    pub fn poll(
        &mut self,
        max_recv_len: usize,
    ) -> Result<Option<(RecvChain, ReplyChain<M>)>, VirtqError> {
        let (id, chain) = match self.inner.poll_available() {
            Ok(x) => x,
            Err(RingError::WouldBlock) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let readables = chain.readables();
        let writables = chain.writables();
        if readables.is_empty() && writables.is_empty() {
            return Err(self.abort_chain(id, VirtqError::BadChain));
        }

        let recv_len = readables
            .iter()
            .fold(0usize, |acc, elem| acc.saturating_add(elem.len as usize));

        // Reserve the inflight slot
        let id_idx = id as usize;
        if id_idx >= self.inflight.len() {
            return Err(VirtqError::InvalidState);
        }

        if self.inflight.contains(id_idx) {
            return Err(VirtqError::InvalidState);
        }

        self.inflight.insert(id_idx);
        let token = Token {
            seq: self.next_token,
            id,
        };
        self.next_token = self.next_token.wrapping_add(1);

        if recv_len > max_recv_len {
            return Err(self.abort_chain(
                id,
                VirtqError::PayloadTooLarge {
                    recv: recv_len,
                    limit: max_recv_len,
                },
            ));
        }

        // Copy chain payload from shared memory
        let data = match self.read_elements(readables) {
            Ok(d) => d,
            Err(e) => return Err(self.abort_chain(id, e)),
        };

        let chain = RecvChain {
            token,
            segments: data,
        };

        let reply = if !writables.is_empty() {
            let mem = self.inner.mem().clone();
            let writable = WritableChain::new(mem, token, writables.iter().copied().collect());
            ReplyChain::Writable(writable)
        } else {
            let ack = AckChain::new(token);
            ReplyChain::Ack(ack)
        };

        Ok(Some((chain, reply)))
    }

    /// Submit a reply/ack for a received chain back to the ring.
    ///
    /// Accepts both [`WritableChain`] (with written byte count) and
    /// [`AckChain`] (zero-length) via the [`ReplyChain`] enum.
    /// Clears the inflight slot and notifies the producer if event
    /// suppression allows.
    pub fn complete(&mut self, reply: impl Into<ReplyChain<M>>) -> Result<(), VirtqError> {
        let reply = reply.into();
        let id = reply.token().id;
        let written = u32::try_from(reply.written()).map_err(|_| VirtqError::ReplyTooLarge)?;

        let id_idx = id as usize;
        let slot_set = id_idx < self.inflight.len() && self.inflight.contains(id_idx);
        if !slot_set {
            return Err(VirtqError::InvalidState);
        }

        self.inflight.set(id_idx, false);

        if self.inner.submit_used_with_notify(id, written)? {
            self.notifier.notify(QueueStats {
                num_free: self.inner.num_free(),
                num_inflight: self.inner.num_inflight(),
            });
        }

        Ok(())
    }

    /// Return a consumed descriptor to the driver with zero written length.
    ///
    /// The ring's `poll_available` removes the descriptor from the available
    /// ring before [`poll`](Self::poll) validates the chain.
    fn abort_chain(&mut self, id: u16, err: VirtqError) -> VirtqError {
        let id_idx = id as usize;
        if id_idx < self.inflight.len() {
            self.inflight.set(id_idx, false);
        }

        // Best effort: failing to return the descriptor means the ring is
        // already in an unrecoverable state, so surface the original error.
        if let Ok(true) = self.inner.submit_used_with_notify(id, 0) {
            self.notifier.notify(QueueStats {
                num_free: self.inner.num_free(),
                num_inflight: self.inner.num_inflight(),
            });
        }

        err
    }

    /// Get the current available cursor position.
    ///
    /// Returns the position where the next available descriptor will be
    /// consumed. Useful for setting up descriptor-based event suppression.
    #[inline]
    pub fn avail_cursor(&self) -> RingCursor {
        self.inner.avail_cursor()
    }

    /// Get the current used cursor position.
    ///
    /// Returns the position where the next used descriptor will be written.
    /// Useful for setting up descriptor-based event suppression.
    #[inline]
    pub fn used_cursor(&self) -> RingCursor {
        self.inner.used_cursor()
    }

    /// Configure event suppression for available buffer notifications.
    ///
    /// This controls when the driver (producer) signals us about new buffers:
    ///
    /// - [`SuppressionKind::Enable`] - Always signal (default) - good for latency
    /// - [`SuppressionKind::Disable`] - Never signal - caller must poll
    /// - [`SuppressionKind::Descriptor`] - Signal only at specific cursor position
    ///
    /// # Example: Polling Mode
    /// ```ignore
    /// consumer.set_avail_suppression(SuppressionKind::Disable)?;
    /// loop {
    ///     while let Some((chain, reply)) = consumer.poll(1024)? {
    ///         process(chain, reply);
    ///     }
    ///     // ... do other work ...
    /// }
    /// ```
    pub fn set_avail_suppression(&mut self, kind: SuppressionKind) -> Result<(), VirtqError> {
        match kind {
            SuppressionKind::Enable => self.inner.enable_avail_notifications()?,
            SuppressionKind::Disable => self.inner.disable_avail_notifications()?,
            SuppressionKind::Descriptor(cursor) => self
                .inner
                .enable_avail_notifications_desc(cursor.head(), cursor.wrap())?,
        }
        Ok(())
    }

    /// Read readable buffer elements from shared memory into `Bytes`.
    fn read_elements(&self, elems: &[BufferElement]) -> Result<Segments, VirtqError> {
        let mut segments = SmallVec::<[Bytes; 4]>::new();

        for elem in elems {
            let mut buf = vec![0u8; elem.len as usize];
            self.inner
                .mem()
                .read(elem.addr, &mut buf)
                .map_err(|_| VirtqError::MemoryReadError)?;
            segments.push(Bytes::from(buf));
        }

        Ok(Segments::from_smallvec(segments))
    }

    /// Reset ring and inflight state to initial values.
    pub fn reset(&mut self) {
        self.inner.reset();
        self.inflight.clear();
    }
}

fn write_elements<M: MemOps>(
    mem: &M,
    elems: &[BufferElement],
    offset: usize,
    buf: &[u8],
) -> Result<usize, M::Error> {
    let capacity: usize = elems.iter().map(|elem| elem.len as usize).sum();
    let mut src = &buf[..buf.len().min(capacity.saturating_sub(offset))];
    let mut written = 0;
    let mut skip = offset;

    for elem in elems {
        if src.is_empty() {
            break;
        }

        let elem_len = elem.len as usize;
        if skip >= elem_len {
            skip -= elem_len;
            continue;
        }

        let elem_offset = skip;
        skip = 0;
        let n = (elem_len - elem_offset).min(src.len());
        let addr = elem.addr + elem_offset as u64;

        mem.write(addr, &src[..n])?;

        written += n;
        src = &src[n..];
    }

    Ok(written)
}

impl<M: MemOps> From<WritableChain<M>> for ReplyChain<M> {
    fn from(wc: WritableChain<M>) -> Self {
        ReplyChain::Writable(wc)
    }
}

impl<M: MemOps> From<AckChain> for ReplyChain<M> {
    fn from(ack: AckChain) -> Self {
        ReplyChain::Ack(ack)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtq::ring::tests::{make_producer, make_ring};
    use crate::virtq::test_utils::*;

    fn poll_data(
        consumer: &mut VirtqConsumer<crate::virtq::ring::tests::TestMem, TestNotifier>,
    ) -> (RecvChain, ReplyChain<crate::virtq::ring::tests::TestMem>) {
        consumer.poll(1024).unwrap().unwrap()
    }

    #[test]
    fn test_write_only_recv_is_empty() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().writable(16).build().unwrap();
        producer.submit(se).unwrap();

        let (recv, reply) = poll_data(&mut consumer);
        assert!(recv.to_bytes().is_empty());
        assert!(matches!(reply, ReplyChain::Writable(_)));

        if let ReplyChain::Writable(mut wc) = reply {
            wc.write_all(b"response").unwrap();
            consumer.complete(wc).unwrap();
        }
    }

    #[test]
    fn test_read_only_ack_reply() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().readable(16).build().unwrap();
        se.write_all(b"hello").unwrap();
        producer.submit(se).unwrap();

        let (recv, reply) = poll_data(&mut consumer);
        assert_eq!(recv.to_bytes().as_ref(), b"hello");
        assert!(matches!(reply, ReplyChain::Ack(_)));

        consumer.complete(reply).unwrap();
    }

    #[test]
    fn test_readwrite_round_trip() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().readable(32).writable(64).build().unwrap();
        se.write_all(b"hello world").unwrap();
        producer.submit(se).unwrap();

        let (recv, reply) = poll_data(&mut consumer);
        assert_eq!(recv.to_bytes().as_ref(), b"hello world");

        if let ReplyChain::Writable(mut wc) = reply {
            assert_eq!(wc.capacity(), 64);
            assert_eq!(wc.written(), 0);
            assert_eq!(wc.remaining(), 64);
            wc.write_all(b"response").unwrap();
            assert_eq!(wc.written(), 8);
            assert_eq!(wc.remaining(), 56);
            consumer.complete(wc).unwrap();
        } else {
            panic!("expected Writable reply for recv+reply chain");
        }
    }

    #[test]
    fn test_writable_partial_write() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().writable(8).build().unwrap();
        producer.submit(se).unwrap();

        let (_recv, reply) = poll_data(&mut consumer);

        if let ReplyChain::Writable(mut wc) = reply {
            let n = wc.write(b"hello world!").unwrap();
            assert_eq!(n, 8);
            assert_eq!(wc.remaining(), 0);
            consumer.complete(wc).unwrap();
        } else {
            panic!("expected Writable");
        }
    }

    #[test]
    fn test_writable_write_all_too_large() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().writable(4).build().unwrap();
        producer.submit(se).unwrap();
        let (_recv, reply) = poll_data(&mut consumer);

        if let ReplyChain::Writable(mut wc) = reply {
            let err = wc.write_all(b"too long").err().unwrap();
            assert!(matches!(err, VirtqError::ReplyTooLarge));
        } else {
            panic!("expected Writable");
        }
    }

    #[test]
    fn test_poll_too_large_returns_payload_error() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().readable(8).writable(16).build().unwrap();
        se.write_all(b"too much").unwrap();
        producer.submit(se).unwrap();

        assert!(matches!(
            consumer.poll(4),
            Err(VirtqError::PayloadTooLarge { recv: 8, limit: 4 })
        ));
    }

    #[test]
    fn test_poll_too_large_returns_descriptor() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().readable(8).writable(16).build().unwrap();
        se.write_all(b"too much").unwrap();
        let token = producer.submit(se).unwrap();

        // Oversized payload is rejected, but the descriptor must be returned to
        // the driver so the ring slot is not leaked.
        assert!(matches!(
            consumer.poll(4),
            Err(VirtqError::PayloadTooLarge { recv: 8, limit: 4 })
        ));

        // The producer can reclaim the rejected chain; the queue is not wedged.
        let used = producer.poll().unwrap().unwrap();
        assert_eq!(used.token(), token);

        // A subsequent normal exchange still round-trips end to end.
        let se2 = producer.chain().writable(16).build().unwrap();
        producer.submit(se2).unwrap();
        let (_recv, reply) = poll_data(&mut consumer);
        consumer.complete(reply).unwrap();
        assert!(producer.poll().unwrap().is_some());
    }

    #[test]
    fn test_villain_indirect_descriptor_does_not_mark_high_level_inflight() {
        let ring = make_ring(16);
        let mem = ring.mem();
        let mut consumer = VirtqConsumer::new(ring.layout(), mem, TestNotifier::new());

        let mut desc = Descriptor::new(0x1000, 16, 0, DescFlags::INDIRECT);
        desc.mark_avail(true);
        ring.write_desc(0, desc);

        assert!(matches!(
            consumer.poll(1024),
            Err(VirtqError::RingError(RingError::BadChain))
        ));
        assert_eq!(consumer.inflight.count_ones(..), 0);
        assert_eq!(consumer.inner.num_inflight(), 0);
    }

    #[test]
    fn test_villain_bad_chain_does_not_mark_high_level_inflight() {
        let ring = make_ring(16);
        let mem = ring.mem();
        let mut consumer = VirtqConsumer::new(ring.layout(), mem, TestNotifier::new());

        let mut first = Descriptor::new(0x1000, 16, 0, DescFlags::NEXT | DescFlags::WRITE);
        first.mark_avail(true);
        ring.write_desc(0, first);

        let mut second = Descriptor::new(0x2000, 16, 0, DescFlags::empty());
        second.mark_avail(true);
        ring.write_desc(1, second);

        assert!(matches!(
            consumer.poll(1024),
            Err(VirtqError::RingError(RingError::BadChain))
        ));
        assert_eq!(consumer.inflight.count_ones(..), 0);
        assert_eq!(consumer.inner.num_inflight(), 0);
    }

    #[test]
    fn test_writable_chain_writes_single_segment() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().writable(16).build().unwrap();
        producer.submit(se).unwrap();
        let (_recv, reply) = poll_data(&mut consumer);

        let ReplyChain::Writable(mut wc) = reply else {
            panic!("expected Writable");
        };
        wc.write_all(b"hello").unwrap();
        consumer.complete(wc).unwrap();

        let used = producer.poll().unwrap().unwrap();
        assert_eq!(used.to_bytes().unwrap().as_ref(), b"hello");
    }

    #[test]
    fn test_writable_rewind() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().writable(16).build().unwrap();
        producer.submit(se).unwrap();

        let (_recv, reply) = poll_data(&mut consumer);

        if let ReplyChain::Writable(mut wc) = reply {
            wc.write_all(b"first").unwrap();
            assert_eq!(wc.written(), 5);
            wc.rewind();
            assert_eq!(wc.written(), 0);
            assert_eq!(wc.remaining(), 16);
            wc.write_all(b"second").unwrap();
            assert_eq!(wc.written(), 6);
            consumer.complete(wc).unwrap();
        } else {
            panic!("expected Writable");
        }
    }

    #[test]
    fn test_writable_reply_scatters_across_segments() {
        let ring = make_ring(16);
        let mem = ring.mem();
        let mut ring_producer = make_producer(&ring);
        let mut consumer = VirtqConsumer::new(ring.layout(), mem.clone(), TestNotifier::new());

        let base = mem.base_addr() + Layout::query_size(ring.len()) as u64 + 0x100;
        let chain = BufferChainBuilder::new()
            .writable(base, 4)
            .writable(base + 4, 4)
            .build()
            .unwrap();
        let id = ring_producer.submit_available(&chain).unwrap();

        let (recv, reply) = poll_data(&mut consumer);
        assert!(recv.to_bytes().is_empty());

        let ReplyChain::Writable(mut wc) = reply else {
            panic!("expected Writable");
        };
        assert_eq!(wc.capacity(), 8);
        wc.write_all(b"abcdefgh").unwrap();
        assert_eq!(wc.written(), 8);
        consumer.complete(wc).unwrap();

        let mut first = [0u8; 4];
        let mut second = [0u8; 4];
        mem.read(base, &mut first).unwrap();
        mem.read(base + 4, &mut second).unwrap();
        assert_eq!(&first, b"abcd");
        assert_eq!(&second, b"efgh");

        let used = ring_producer.poll_used().unwrap();
        assert_eq!(used.id, id);
        assert_eq!(used.len, 8);
    }

    #[test]
    fn test_multiple_pending_replies() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let se1 = producer.chain().writable(16).build().unwrap();
        producer.submit(se1).unwrap();
        let se2 = producer.chain().writable(16).build().unwrap();
        producer.submit(se2).unwrap();

        let (_e1, c1) = poll_data(&mut consumer);
        let (_e2, c2) = poll_data(&mut consumer);

        // Complete in reverse order
        consumer.complete(c2).unwrap();
        consumer.complete(c1).unwrap();
    }

    #[test]
    fn test_recv_into_bytes() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().readable(16).build().unwrap();
        se.write_all(b"abc").unwrap();
        producer.submit(se).unwrap();

        let (recv, reply) = poll_data(&mut consumer);
        let data = recv.into_bytes();
        assert_eq!(data.as_ref(), b"abc");
        consumer.complete(reply).unwrap();
    }

    #[test]
    fn test_virtq_consumer_reset() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        // Submit and poll (but do not complete)
        let se = producer.chain().writable(16).build().unwrap();
        producer.submit(se).unwrap();

        let (_recv, reply) = poll_data(&mut consumer);
        assert!(consumer.inflight.count_ones(..) > 0);

        // Complete first so we do not leak
        consumer.complete(reply).unwrap();

        consumer.reset();

        assert_eq!(consumer.inflight.count_ones(..), 0);
        assert_eq!(consumer.inner.num_inflight(), 0);
    }

    #[test]
    fn test_virtq_consumer_reset_clears_inflight() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        // Submit two entries and poll both
        let se1 = producer.chain().writable(16).build().unwrap();
        producer.submit(se1).unwrap();
        let se2 = producer.chain().writable(16).build().unwrap();
        producer.submit(se2).unwrap();

        let (_e1, c1) = poll_data(&mut consumer);
        let (_e2, c2) = poll_data(&mut consumer);
        // Complete both before reset
        consumer.complete(c1).unwrap();
        consumer.complete(c2).unwrap();

        consumer.reset();

        assert_eq!(consumer.inflight.count_ones(..), 0);
        assert_eq!(consumer.inner.num_inflight(), 0);
    }
}
