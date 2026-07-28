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
use core::fmt;

use bytes::Bytes;
use fixedbitset::FixedBitSet;
use smallvec::SmallVec;

use super::*;

/// Stateful reader over device-readable descriptors received from the producer.
///
/// Reads copy directly from shared memory into caller-provided final storage.
/// The chain must be returned together with its paired [`ReplyChain`] through
/// [`VirtqConsumer::complete`] before the descriptors can be reused.
#[must_use = "dropping without completing leaks the descriptor"]
pub struct RecvChain<M: MemOps> {
    state: ChainState<M>,
}

impl<M: MemOps> fmt::Debug for RecvChain<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecvChain")
            .field("token", &self.state.token)
            .field("elems", &self.state.elems)
            .field("len", &self.state.total)
            .field("consumed", &self.state.position)
            .field("desc_index", &self.state.desc_idx)
            .field("desc_offset", &self.state.desc_off)
            .finish()
    }
}

impl<M: MemOps> RecvChain<M> {
    fn new(mem: M, token: Token, elems: ChainElems, len: usize) -> Self {
        Self {
            state: ChainState::new(mem, token, elems, len),
        }
    }

    /// The token identifying this chain.
    #[inline]
    pub fn token(&self) -> Token {
        self.state.token()
    }

    /// Total readable payload length.
    #[inline]
    pub fn len(&self) -> usize {
        self.state.total()
    }

    /// Whether this chain has no readable payload.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of bytes consumed by the stateful reader.
    #[inline]
    pub fn consumed(&self) -> usize {
        self.state.position()
    }

    /// Number of bytes still available to the stateful reader.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.state.remaining()
    }

    /// Read bytes sequentially across descriptor boundaries.
    ///
    /// Returns the number of bytes copied, which may be smaller than `buf.len()`
    /// at the end of the chain. If a later memory read fails, the cursor remains
    /// advanced past any earlier chunks copied by the same call.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, VirtqError> {
        let len = buf.len().min(self.remaining());
        let mut dst = &mut buf[..len];
        let mut read = 0;

        while !dst.is_empty() {
            let Some(elem) = self.state.current_elem() else {
                break;
            };

            let desc_len = elem.len as usize;
            let desc_offset = self.state.desc_offset();
            let len = (desc_len - desc_offset).min(dst.len());
            let (current, rest) = dst.split_at_mut(len);

            let addr = elem
                .addr
                .checked_add(desc_offset as u64)
                .ok_or(VirtqError::MemoryReadError)?;

            self.state
                .mem
                .read(addr, current)
                .map_err(|_| VirtqError::MemoryReadError)?;

            self.state.advance(len);
            read += len;
            dst = rest;
        }

        Ok(read)
    }

    /// Read exactly `buf.len()` bytes or return an error.
    #[inline]
    pub fn read_exact(&mut self, buf: &mut [u8]) -> Result<&mut Self, VirtqError> {
        if buf.len() > self.remaining() {
            return Err(VirtqError::ReceiveTooShort {
                requested: buf.len(),
                remaining: self.remaining(),
            });
        }

        let read = self.read(buf)?;
        debug_assert_eq!(read, buf.len());
        Ok(self)
    }

    /// Copy the complete payload into descriptor-preserving owned segments.
    ///
    /// This does not change the stateful read position. Each call takes a new
    /// snapshot of shared memory; callers should validate and use the returned
    /// owned value rather than reading the same untrusted payload again.
    pub fn to_segments(&self) -> Result<Segments, VirtqError> {
        let mut segments = SmallVec::<[Bytes; 4]>::new();

        for elem in &self.state.elems {
            let mut buf = vec![0u8; elem.len as usize];
            self.state
                .mem
                .read(elem.addr, &mut buf)
                .map_err(|_| VirtqError::MemoryReadError)?;
            segments.push(Bytes::from(buf));
        }

        Ok(Segments::from_smallvec(segments))
    }

    /// Copy the complete payload directly into one contiguous allocation.
    ///
    /// This does not change the stateful read position. Each call takes a new
    /// snapshot of shared memory; callers should validate and use the returned
    /// owned value rather than reading the same untrusted payload again.
    pub fn to_bytes(&self) -> Result<Bytes, VirtqError> {
        if self.is_empty() {
            return Ok(Bytes::new());
        }

        let mut buf = vec![0u8; self.len()];
        let mut offset = 0;

        for elem in &self.state.elems {
            let end = offset + elem.len as usize;
            self.state
                .mem
                .read(elem.addr, &mut buf[offset..end])
                .map_err(|_| VirtqError::MemoryReadError)?;
            offset = end;
        }

        Ok(Bytes::from(buf))
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
    /// Ack-only reply (for chains with only readable buffers). No response
    /// buffer. Pass it back with the paired [`RecvChain`] through
    /// [`VirtqConsumer::complete`] to acknowledge.
    Ack(AckChain),
}

impl<M: MemOps> ReplyChain<M> {
    /// The token identifying this reply.
    #[inline]
    pub fn token(&self) -> Token {
        match self {
            ReplyChain::Writable(wc) => wc.token(),
            ReplyChain::Ack(ack) => ack.token(),
        }
    }

    /// Number of bytes written (0 for Ack).
    #[inline]
    pub fn written(&self) -> usize {
        match self {
            ReplyChain::Writable(wc) => wc.written(),
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
///     consumer.complete(recv, wc)?;
/// }
/// ```
#[must_use = "dropping without completing leaks the descriptor"]
pub struct WritableChain<M: MemOps> {
    state: ChainState<M>,
}

impl<M: MemOps> WritableChain<M> {
    fn new(mem: M, token: Token, elems: ChainElems) -> Self {
        let capacity = elems.iter().map(|elem| elem.len as usize).sum();
        Self {
            state: ChainState::new(mem, token, elems, capacity),
        }
    }

    /// The token identifying this writable reply.
    #[inline]
    pub fn token(&self) -> Token {
        self.state.token()
    }

    /// Total reply capacity in bytes.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.state.total()
    }

    /// Number of bytes written so far.
    #[inline]
    pub fn written(&self) -> usize {
        self.state.position()
    }

    /// Remaining reply capacity.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.state.remaining()
    }

    /// Write bytes into writable buffers, returning how many were written.
    ///
    /// Appends at the current write position. If `buf` is larger than the
    /// remaining capacity, writes as many bytes as will fit (partial write).
    /// Segmentation is intentionally hidden; host-side writes must go through
    /// [`MemOps::write`]. If a later memory write fails, the cursor and written
    /// length retain any earlier chunks written by the same call.
    ///
    /// # Errors
    ///
    /// - [`VirtqError::MemoryWriteError`] - underlying MemOps write failed
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, VirtqError> {
        let mut src = &buf[..buf.len().min(self.remaining())];
        let mut written = 0;

        while !src.is_empty() {
            let Some(elem) = self.state.current_elem() else {
                break;
            };
            let desc_capacity = elem.len as usize;
            let desc_offset = self.state.desc_offset();
            let len = (desc_capacity - desc_offset).min(src.len());

            let addr = elem
                .addr
                .checked_add(desc_offset as u64)
                .ok_or(VirtqError::MemoryWriteError)?;

            self.state
                .mem
                .write(addr, &src[..len])
                .map_err(|_| VirtqError::MemoryWriteError)?;

            self.state.advance(len);
            written += len;
            src = &src[len..];
        }

        Ok(written)
    }

    /// Write the entire buffer or return an error.
    ///
    /// # Errors
    ///
    /// - [`VirtqError::ReplyTooLarge`] - buf exceeds remaining capacity
    /// - [`VirtqError::MemoryWriteError`] - underlying MemOps write failed
    #[inline]
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
        self.state.rewind();
    }
}

/// An ack-only reply for chains with no writable buffers.
///
/// No response buffer - pass it back with the paired [`RecvChain`] through
/// [`VirtqConsumer::complete`] to acknowledge processing and release the descriptor.
///
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

    #[inline]
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
/// while let Some((recv, reply)) = consumer.poll(MAX_RECV_LEN)? {
///     let data = recv.to_bytes()?;
///     match reply {
///         ReplyChain::Writable(mut wc) => {
///             let response = handle_request(data);
///             wc.write_all(&response)?;
///             consumer.complete(recv, wc)?;
///         }
///         ReplyChain::Ack(ack) => {
///             consumer.complete(recv, ack)?;
///         }
///     }
/// }
///
/// // Or defer completions
/// let mut pending = Vec::new();
/// while let Some((recv, reply)) = consumer.poll(MAX_RECV_LEN)? {
///     let result = process(&recv);
///     pending.push((result, recv, reply));
/// }
///
/// for (result, recv, reply) in pending {
///     // ... complete later ...
///     consumer.complete(recv, reply)?;
/// }
/// ```
pub struct VirtqConsumer<M, N> {
    inner: RingConsumer<M>,
    mem: M,
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
        Self::new_split(layout, mem.clone(), mem, notifier)
    }

    /// Create a consumer with separate ring and buffer memory accessors.
    pub fn new_split(layout: Layout, ring_mem: M, buf_mem: M, notifier: N) -> Self {
        let inner = RingConsumer::new(layout, ring_mem);
        let inflight = FixedBitSet::with_capacity(inner.len());

        Self {
            inner,
            mem: buf_mem,
            notifier,
            inflight,
            next_token: 0,
        }
    }

    /// Poll for a single incoming chain from the driver.
    ///
    /// Returns a stateful [`RecvChain`] reader and a [`ReplyChain`] writable
    /// reply or ack capability. Both are independent owned values with no
    /// borrow on the consumer, but they must be returned together through
    /// [`complete`](Self::complete).
    ///
    /// On [`VirtqError::BadChain`] and [`VirtqError::PayloadTooLarge`] the
    /// descriptor is returned to the driver (completed with zero length) before
    /// the error is propagated, so a rejected chain does not leak.
    ///
    /// # Arguments
    ///
    /// * `max_recv_len` - Maximum readable payload size. Payloads larger
    ///   than this return [`VirtqError::PayloadTooLarge`].
    ///
    /// # Errors
    ///
    /// - [`VirtqError::BadChain`] - Descriptor chain format not recognized
    /// - [`VirtqError::InvalidState`] - Descriptor ID collision (driver bug)
    #[allow(clippy::type_complexity)]
    pub fn poll(
        &mut self,
        max_recv_len: usize,
    ) -> Result<Option<(RecvChain<M>, ReplyChain<M>)>, VirtqError> {
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

        let chain = RecvChain::new(
            self.mem.clone(),
            token,
            readables.iter().copied().collect(),
            recv_len,
        );

        let reply = if !writables.is_empty() {
            let mem = self.mem.clone();
            let elems = writables.iter().copied().collect();
            let writable = WritableChain::new(mem, token, elems);
            ReplyChain::Writable(writable)
        } else {
            let ack = AckChain::new(token);
            ReplyChain::Ack(ack)
        };

        Ok(Some((chain, reply)))
    }

    /// Submit both halves of a received chain back to the ring.
    ///
    /// Consuming the [`RecvChain`] prevents further reads once its descriptors
    /// can be reused by the producer. `reply` accepts both [`WritableChain`]
    /// (with written byte count) and [`AckChain`] (zero-length) through
    /// [`ReplyChain`]. The two halves must have matching tokens.
    ///
    /// A mismatched pair returns [`VirtqError::InvalidState`] without returning
    /// either descriptor. This fails closed: the descriptors remain in flight
    /// because completing either could invalidate another still-live
    /// [`RecvChain`].
    pub fn complete(
        &mut self,
        recv: impl Into<RecvChain<M>>,
        reply: impl Into<ReplyChain<M>>,
    ) -> Result<(), VirtqError> {
        let recv = recv.into();
        let reply = reply.into();

        if recv.token() != reply.token() {
            return Err(VirtqError::InvalidState);
        }

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

    /// Reset ring and inflight state to initial values.
    ///
    /// Fails while a polled chain has not yet been completed, preventing a
    /// live [`RecvChain`] from reading descriptors after reset and reuse.
    ///
    /// # Errors
    ///
    /// - [`VirtqError::InvalidState`] - one or more chains are still in flight
    /// - [`VirtqError::RingError`] - device-event normalization failed
    pub fn reset(&mut self) -> Result<(), VirtqError> {
        if self.inflight.ones().next().is_some() {
            return Err(VirtqError::InvalidState);
        }

        self.inner.reset()?;
        self.inflight.clear();
        Ok(())
    }
}

type ChainElems = SmallVec<[BufferElement; 4]>;

struct ChainState<M: MemOps> {
    mem: M,
    token: Token,
    elems: ChainElems,
    total: usize,
    position: usize,
    desc_idx: usize,
    desc_off: usize,
}

impl<M: MemOps> ChainState<M> {
    fn new(mem: M, token: Token, elems: ChainElems, total: usize) -> Self {
        let mut state = Self {
            mem,
            token,
            elems,
            total,
            position: 0,
            desc_idx: 0,
            desc_off: 0,
        };
        state.rewind();
        state
    }

    #[inline]
    fn token(&self) -> Token {
        self.token
    }

    #[inline]
    fn total(&self) -> usize {
        self.total
    }

    #[inline]
    fn position(&self) -> usize {
        self.position
    }

    #[inline]
    fn remaining(&self) -> usize {
        self.total - self.position
    }

    #[inline(always)]
    fn desc_len(&self) -> usize {
        self.elems
            .get(self.desc_idx)
            .map(|elem| elem.len as usize)
            .unwrap_or(0)
    }

    #[inline(always)]
    fn desc_offset(&self) -> usize {
        self.desc_off
    }

    #[inline(always)]
    fn current_elem(&self) -> Option<BufferElement> {
        self.elems.get(self.desc_idx).copied()
    }

    #[inline(always)]
    fn advance(&mut self, len: usize) {
        debug_assert!(len <= self.desc_len() - self.desc_off);
        self.desc_off += len;
        self.position += len;

        while self.current_elem().is_some() && self.desc_off == self.desc_len() {
            self.desc_idx += 1;
            self.desc_off = 0;
        }
    }

    fn rewind(&mut self) {
        self.position = 0;
        self.desc_off = 0;
        self.desc_idx = self
            .elems
            .iter()
            .position(|elem| elem.len != 0)
            .unwrap_or(self.elems.len());
    }
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
    use crate::virtq::ring::tests::{TestMem, make_producer, make_ring};
    use crate::virtq::test_utils::*;

    fn poll_data(
        consumer: &mut VirtqConsumer<TestMem, TestNotifier>,
    ) -> (RecvChain<TestMem>, ReplyChain<TestMem>) {
        consumer.poll(1024).unwrap().unwrap()
    }

    #[derive(Clone)]
    struct FailingPayloadReadMem {
        inner: TestMem,
        payload_addr: u64,
        payload_len: usize,
    }

    // SAFETY: All operations delegate to TestMem. Reads overlapping the
    // configured payload range return an error before accessing memory.
    unsafe impl MemOps for FailingPayloadReadMem {
        type Error = ();

        fn read(&self, addr: u64, dst: &mut [u8]) -> Result<(), Self::Error> {
            let read_end = addr.saturating_add(dst.len() as u64);
            let payload_end = self.payload_addr.saturating_add(self.payload_len as u64);
            if addr < payload_end && self.payload_addr < read_end {
                return Err(());
            }
            self.inner.read(addr, dst).map_err(|err| match err {})
        }

        fn write(&self, addr: u64, src: &[u8]) -> Result<(), Self::Error> {
            self.inner.write(addr, src).map_err(|err| match err {})
        }

        fn load_acquire(&self, addr: u64) -> Result<u16, Self::Error> {
            self.inner.load_acquire(addr).map_err(|err| match err {})
        }

        fn store_release(&self, addr: u64, val: u16) -> Result<(), Self::Error> {
            self.inner
                .store_release(addr, val)
                .map_err(|err| match err {})
        }

        unsafe fn as_slice(&self, addr: u64, len: usize) -> Result<&[u8], Self::Error> {
            unsafe { self.inner.as_slice(addr, len) }.map_err(|err| match err {})
        }

        unsafe fn as_mut_slice(&self, addr: u64, len: usize) -> Result<&mut [u8], Self::Error> {
            unsafe { self.inner.as_mut_slice(addr, len) }.map_err(|err| match err {})
        }
    }

    #[test]
    fn test_write_only_recv_is_empty() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().writable(16).build().unwrap();
        producer.submit(se).unwrap();

        let (recv, reply) = poll_data(&mut consumer);
        assert!(recv.to_bytes().unwrap().is_empty());
        assert!(matches!(reply, ReplyChain::Writable(_)));

        if let ReplyChain::Writable(mut wc) = reply {
            wc.write_all(b"response").unwrap();
            consumer.complete(recv, wc).unwrap();
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
        assert_eq!(recv.to_bytes().unwrap().as_ref(), b"hello");
        assert!(matches!(reply, ReplyChain::Ack(_)));

        consumer.complete(recv, reply).unwrap();
    }

    #[test]
    fn test_readwrite_round_trip() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().readable(32).writable(64).build().unwrap();
        se.write_all(b"hello world").unwrap();
        producer.submit(se).unwrap();

        let (recv, reply) = poll_data(&mut consumer);
        assert_eq!(recv.to_bytes().unwrap().as_ref(), b"hello world");

        if let ReplyChain::Writable(mut wc) = reply {
            assert_eq!(wc.capacity(), 64);
            assert_eq!(wc.written(), 0);
            assert_eq!(wc.remaining(), 64);
            wc.write_all(b"response").unwrap();
            assert_eq!(wc.written(), 8);
            assert_eq!(wc.remaining(), 56);
            consumer.complete(recv, wc).unwrap();
        } else {
            panic!("expected Writable reply for recv+reply chain");
        }
    }

    #[test]
    fn test_recv_reads_across_descriptor_boundaries() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().readable(4).readable(4).build().unwrap();
        se.write_all(b"abcdefgh").unwrap();
        producer.submit(se).unwrap();

        let (mut recv, reply) = poll_data(&mut consumer);
        assert_eq!(recv.len(), 8);
        assert_eq!(recv.remaining(), 8);
        let mut first = [0u8; 2];
        recv.read_exact(&mut first).unwrap();
        assert_eq!(&first, b"ab");
        assert_eq!(recv.consumed(), 2);
        assert_eq!(recv.remaining(), 6);

        let mut second = [0u8; 3];
        recv.read_exact(&mut second).unwrap();
        assert_eq!(&second, b"cde");

        let mut too_long = [0u8; 4];
        assert!(matches!(
            recv.read_exact(&mut too_long),
            Err(VirtqError::ReceiveTooShort {
                requested: 4,
                remaining: 3
            })
        ));

        let mut final_buf = [0u8; 4];
        assert_eq!(recv.read(&mut final_buf).unwrap(), 3);
        assert_eq!(&final_buf[..3], b"fgh");
        assert_eq!(recv.read(&mut final_buf).unwrap(), 0);
        assert_eq!(recv.to_bytes().unwrap().as_ref(), b"abcdefgh");

        consumer.complete(recv, reply).unwrap();
    }

    #[test]
    fn test_poll_defers_payload_reads() {
        let ring = make_ring(16);
        let mem = ring.mem();
        let mut ring_producer = make_producer(&ring);
        let payload_addr = mem.base_addr() + Layout::query_size(ring.len()) as u64 + 0x100;
        mem.write(payload_addr, b"data").unwrap();

        let chain = BufferChainBuilder::new()
            .readable(payload_addr, 4)
            .build()
            .unwrap();
        ring_producer.submit_available(&chain).unwrap();

        let ring_mem = FailingPayloadReadMem {
            inner: mem.clone(),
            payload_addr,
            payload_len: 0,
        };
        let mem = FailingPayloadReadMem {
            inner: mem,
            payload_addr,
            payload_len: 4,
        };

        let mut consumer =
            VirtqConsumer::new_split(ring.layout(), ring_mem, mem, TestNotifier::new());

        let (recv, reply) = consumer.poll(4).unwrap().unwrap();
        assert!(matches!(recv.to_bytes(), Err(VirtqError::MemoryReadError)));
        consumer.complete(recv, reply).unwrap();
    }

    #[test]
    fn test_writable_partial_write() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().writable(8).build().unwrap();
        producer.submit(se).unwrap();

        let (recv, reply) = poll_data(&mut consumer);

        if let ReplyChain::Writable(mut wc) = reply {
            let n = wc.write(b"hello world!").unwrap();
            assert_eq!(n, 8);
            assert_eq!(wc.remaining(), 0);
            consumer.complete(recv, wc).unwrap();
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
        let (recv, reply) = poll_data(&mut consumer);
        consumer.complete(recv, reply).unwrap();
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
        let (recv, reply) = poll_data(&mut consumer);

        let ReplyChain::Writable(mut wc) = reply else {
            panic!("expected Writable");
        };
        wc.write_all(b"hello").unwrap();
        consumer.complete(recv, wc).unwrap();

        let used = producer.poll().unwrap().unwrap();
        assert_eq!(used.to_bytes().unwrap().as_ref(), b"hello");
    }

    #[test]
    fn test_writable_rewind() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().writable(16).build().unwrap();
        producer.submit(se).unwrap();

        let (recv, reply) = poll_data(&mut consumer);

        if let ReplyChain::Writable(mut wc) = reply {
            wc.write_all(b"first").unwrap();
            assert_eq!(wc.written(), 5);
            wc.rewind();
            assert_eq!(wc.written(), 0);
            assert_eq!(wc.remaining(), 16);
            wc.write_all(b"second").unwrap();
            assert_eq!(wc.written(), 6);
            consumer.complete(recv, wc).unwrap();
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
        assert!(recv.to_bytes().unwrap().is_empty());

        let ReplyChain::Writable(mut wc) = reply else {
            panic!("expected Writable");
        };
        assert_eq!(wc.capacity(), 8);
        wc.write_all(b"abcdefgh").unwrap();
        assert_eq!(wc.written(), 8);
        consumer.complete(recv, wc).unwrap();

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
    fn test_writable_short_write_reports_contiguous_used_length() {
        let ring = make_ring(16);
        let mem = ring.mem();
        let mut ring_producer = make_producer(&ring);
        let base = mem.base_addr() + Layout::query_size(ring.len()) as u64 + 0x100;
        mem.write(base, &[0xff; 8]).unwrap();

        let chain = BufferChainBuilder::new()
            .writable(base, 4)
            .writable(base + 4, 4)
            .build()
            .unwrap();
        let id = ring_producer.submit_available(&chain).unwrap();

        let mut consumer = VirtqConsumer::new(ring.layout(), mem.clone(), TestNotifier::new());
        let (recv, reply) = poll_data(&mut consumer);
        let ReplyChain::Writable(mut writable) = reply else {
            panic!("expected writable reply");
        };

        writable.write_all(b"abc").unwrap();
        writable.write_all(b"def").unwrap();
        assert_eq!(writable.written(), 6);
        assert_eq!(writable.remaining(), 2);

        consumer.complete(recv, writable).unwrap();

        let mut contents = [0u8; 8];
        mem.read(base, &mut contents).unwrap();
        assert_eq!(&contents, b"abcdef\xff\xff");

        let used = ring_producer.poll_used().unwrap();
        assert_eq!(used.id, id);
        assert_eq!(used.len, 6);
    }

    #[test]
    fn test_multiple_pending_replies() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let se1 = producer.chain().writable(16).build().unwrap();
        producer.submit(se1).unwrap();
        let se2 = producer.chain().writable(16).build().unwrap();
        producer.submit(se2).unwrap();

        let (e1, c1) = poll_data(&mut consumer);
        let (e2, c2) = poll_data(&mut consumer);

        // Complete in reverse order
        consumer.complete(e2, c2).unwrap();
        consumer.complete(e1, c1).unwrap();
    }

    #[test]
    fn test_mismatched_completion_fails_closed() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut first = producer.chain().readable(1).build().unwrap();
        first.write_all(b"a").unwrap();
        producer.submit(first).unwrap();

        let mut second = producer.chain().readable(1).build().unwrap();
        second.write_all(b"b").unwrap();
        producer.submit(second).unwrap();

        let (recv1, reply1) = poll_data(&mut consumer);
        let (recv2, reply2) = poll_data(&mut consumer);

        assert!(matches!(
            consumer.complete(recv1, reply2),
            Err(VirtqError::InvalidState)
        ));
        assert_eq!(consumer.inflight.count_ones(..), 2);
        assert!(producer.poll().unwrap().is_none());
        assert!(matches!(consumer.reset(), Err(VirtqError::InvalidState)));

        drop((recv2, reply1));
    }

    #[test]
    fn test_recv_to_bytes_preserves_reader_position() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().readable(16).build().unwrap();
        se.write_all(b"abc").unwrap();
        producer.submit(se).unwrap();

        let (mut recv, reply) = poll_data(&mut consumer);
        let mut first = [0u8; 1];
        recv.read_exact(&mut first).unwrap();
        let data = recv.to_bytes().unwrap();
        assert_eq!(&first, b"a");
        assert_eq!(data.as_ref(), b"abc");
        assert_eq!(recv.consumed(), 1);
        consumer.complete(recv, reply).unwrap();
    }

    #[test]
    fn test_virtq_consumer_reset() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        // Submit and poll (but do not complete)
        let se = producer.chain().writable(16).build().unwrap();
        producer.submit(se).unwrap();

        let (recv, reply) = poll_data(&mut consumer);
        assert!(consumer.inflight.count_ones(..) > 0);
        assert!(matches!(consumer.reset(), Err(VirtqError::InvalidState)));

        // Complete first so we do not leak
        consumer.complete(recv, reply).unwrap();

        consumer.reset().unwrap();

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

        let (e1, c1) = poll_data(&mut consumer);
        let (e2, c2) = poll_data(&mut consumer);
        // Complete both before reset
        consumer.complete(e1, c1).unwrap();
        consumer.complete(e2, c2).unwrap();

        consumer.reset().unwrap();

        assert_eq!(consumer.inflight.count_ones(..), 0);
        assert_eq!(consumer.inner.num_inflight(), 0);
    }
}
