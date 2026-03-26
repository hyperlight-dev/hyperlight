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
use alloc::vec::Vec;

use bytes::Bytes;

use super::*;

/// In-flight entry tracking.
///
/// Stored per descriptor ID while the entry is being processed.
/// Tracks that a descriptor slot is occupied.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Inflight;

/// Data received from the producer, safely copied out of shared memory.
///
/// Created by [`VirtqConsumer::poll`]. The entry data is eagerly copied
/// from shared memory during poll using [`MemOps::read`] (volatile on
/// the host side), so accessing it requires no unsafe code and no
/// references into shared memory.
#[derive(Debug, Clone)]
pub struct RecvEntry {
    token: Token,
    data: Bytes,
}

impl RecvEntry {
    /// The token identifying this entry.
    pub fn token(&self) -> Token {
        self.token
    }

    /// The entry payload, copied from shared memory.
    ///
    /// Returns empty [`Bytes`] when the chain has no readable buffers.
    pub fn data(&self) -> &Bytes {
        &self.data
    }

    /// Consume the entry, taking ownership of the data.
    pub fn into_data(self) -> Bytes {
        self.data
    }
}

/// A pending completion, either writable or ack-only.
///
/// Created by [`VirtqConsumer::poll`]. Must be submitted back via
/// [`VirtqConsumer::complete`] to release the descriptor.
#[must_use = "dropping without completing leaks the descriptor"]
pub enum SendCompletion<M: MemOps> {
    /// Completion with a writable buffer (for chains with a completion buffer).
    /// Use the `write*` methods on [`WritableCompletion`] to fill the
    /// response buffer.
    Writable(WritableCompletion<M>),
    /// Ack-only completion (for chains with only entry buffers). No response buffer.
    /// Just pass back to [`VirtqConsumer::complete`] to acknowledge.
    Ack(AckCompletion),
}

impl<M: MemOps> SendCompletion<M> {
    /// The token identifying this completion.
    pub fn token(&self) -> Token {
        match self {
            SendCompletion::Writable(wc) => wc.token(),
            SendCompletion::Ack(ack) => ack.token(),
        }
    }

    /// Number of bytes written (0 for Ack).
    pub fn written(&self) -> usize {
        match self {
            SendCompletion::Writable(wc) => wc.written(),
            SendCompletion::Ack(_) => 0,
        }
    }

    fn id(&self) -> u16 {
        match self {
            SendCompletion::Writable(wc) => wc.id,
            SendCompletion::Ack(ack) => ack.id,
        }
    }
}

/// A completion with a writable buffer for response data.
///
/// # Example
///
/// ```ignore
/// if let SendCompletion::Writable(mut wc) = completion {
///     wc.write_all(b"response data")?;
///     consumer.complete(wc.into())?;
/// }
/// ```
#[must_use = "dropping without completing leaks the descriptor"]
pub struct WritableCompletion<M: MemOps> {
    mem: M,
    id: u16,
    token: Token,
    elem: BufferElement,
    written: usize,
}

impl<M: MemOps> WritableCompletion<M> {
    fn new(mem: M, id: u16, token: Token, elem: BufferElement) -> Self {
        Self {
            mem,
            id,
            token,
            elem,
            written: 0,
        }
    }

    /// The token identifying this completion.
    pub fn token(&self) -> Token {
        self.token
    }

    /// Total capacity of the completion buffer in bytes.
    pub fn capacity(&self) -> usize {
        self.elem.len as usize
    }

    /// Number of bytes written so far.
    pub fn written(&self) -> usize {
        self.written
    }

    /// Remaining writable capacity.
    pub fn remaining(&self) -> usize {
        self.capacity() - self.written
    }

    /// Write bytes into the completion buffer, returning how many were written.
    ///
    /// Appends at the current write position. If `buf` is larger than the
    /// remaining capacity, writes as many bytes as will fit (partial write).
    ///
    /// Returns the number of bytes actually written.
    ///
    /// # Errors
    ///
    /// - [`VirtqError::MemoryWriteError`] - underlying MemOps write failed
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, VirtqError> {
        let to_write = buf.len().min(self.remaining());
        if to_write == 0 {
            return Ok(0);
        }

        let addr = self.elem.addr + self.written as u64;
        self.mem
            .write(addr, &buf[..to_write])
            .map_err(|_| VirtqError::MemoryWriteError)?;

        self.written += to_write;
        Ok(to_write)
    }

    /// Write the entire buffer or return an error.
    ///
    /// # Errors
    ///
    /// - [`VirtqError::CqeTooLarge`] - buf exceeds remaining capacity
    /// - [`VirtqError::MemoryWriteError`] - underlying MemOps write failed
    pub fn write_all(&mut self, buf: &[u8]) -> Result<(), VirtqError> {
        if buf.len() > self.remaining() {
            return Err(VirtqError::CqeTooLarge);
        }

        let addr = self.elem.addr + self.written as u64;
        self.mem
            .write(addr, buf)
            .map_err(|_| VirtqError::MemoryWriteError)?;

        self.written += buf.len();
        Ok(())
    }

    /// Reset the write cursor to the beginning.
    ///
    /// Previously written bytes in shared memory are not zeroed; the
    /// `written` count is simply reset to 0.
    pub fn reset(&mut self) {
        self.written = 0;
    }
}

/// An ack-only completion for chains with no writable buffers.
///
/// No response buffer - just pass back to [`VirtqConsumer::complete`]
/// to acknowledge processing and release the descriptor.
#[must_use = "dropping without completing leaks the descriptor"]
pub struct AckCompletion {
    id: u16,
    token: Token,
}

impl AckCompletion {
    fn new(id: u16, token: Token) -> Self {
        Self { id, token }
    }

    pub fn token(&self) -> Token {
        self.token
    }
}

/// A high-level virtqueue consumer (device side).
///
/// The consumer receives entries from the producer (driver), processes them,
/// and sends back completions. This is typically used on the device/host side.
///
/// # Example
///
/// ```ignore
/// let mut consumer = VirtqConsumer::new(layout, mem, notifier);
///
/// // Poll and process
/// while let Some((entry, completion)) = consumer.poll(MAX_ENTRY_SIZE)? {
///     let data = entry.data();
///     match completion {
///         SendCompletion::Writable(mut wc) => {
///             let response = handle_request(data);
///             wc.write_all(&response)?;
///             consumer.complete(wc.into())?;
///         }
///         SendCompletion::Ack(ack) => {
///             consumer.complete(ack.into())?;
///         }
///     }
/// }
///
/// // Or defer completions
/// let mut pending = Vec::new();
/// while let Some((entry, completion)) = consumer.poll(MAX_ENTRY_SIZE)? {
///     pending.push((process(entry), completion));
/// }
/// for (result, completion) in pending {
///     // ... complete later ...
///     consumer.complete(completion)?;
/// }
/// ```
pub struct VirtqConsumer<M, N> {
    inner: RingConsumer<M>,
    notifier: N,
    inflight: Vec<Option<Inflight>>,
}

impl<M: MemOps + Clone, N: Notifier> VirtqConsumer<M, N> {
    /// Create a new virtqueue consumer.
    ///
    /// # Arguments
    ///
    /// * `layout` - Ring memory layout (descriptor table and event suppression addresses)
    /// * `mem` - Memory operations implementation for reading/writing to shared memory
    /// * `notifier` - Callback for notifying the driver (producer) about completions
    pub fn new(layout: Layout, mem: M, notifier: N) -> Self {
        let inner = RingConsumer::new(layout, mem);
        let inflight = vec![None; inner.len()];

        Self {
            inner,
            notifier,
            inflight,
        }
    }

    /// Poll for a single incoming entry from the driver.
    ///
    /// Returns a [`RecvEntry`] (data copied from shared memory) and a
    /// [`SendCompletion`] (writable handle or ack token). Both are
    /// independent owned values with no borrow on the consumer.
    ///
    /// # Arguments
    ///
    /// * `max_entry` - Maximum entry size to accept. Entries larger than
    ///   this will return [`VirtqError::EntryTooLarge`].
    ///
    /// # Errors
    ///
    /// - [`VirtqError::EntryTooLarge`] - Entry data exceeds `max_entry` bytes
    /// - [`VirtqError::BadChain`] - Descriptor chain format not recognized
    /// - [`VirtqError::InvalidState`] - Descriptor ID collision (driver bug)
    /// - [`VirtqError::MemoryReadError`] - Failed to read entry from shared memory
    pub fn poll(
        &mut self,
        max_entry: usize,
    ) -> Result<Option<(RecvEntry, SendCompletion<M>)>, VirtqError> {
        let (id, chain) = match self.inner.poll_available() {
            Ok(x) => x,
            Err(RingError::WouldBlock) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let (entry_elem, cqe_elem) = parse_chain(&chain)?;

        // Validate entry size
        if let Some(ref elem) = entry_elem
            && elem.len as usize > max_entry
        {
            return Err(VirtqError::EntryTooLarge);
        }

        // Reserve the inflight slot
        let slot = self
            .inflight
            .get_mut(id as usize)
            .ok_or(VirtqError::InvalidState)?;

        if slot.is_some() {
            return Err(VirtqError::InvalidState);
        }

        *slot = Some(Inflight);
        let token = Token(id);

        // Copy entry data from shared memory
        let data = entry_elem
            .map(|elem| self.read_element(&elem))
            .transpose()?
            .unwrap_or_default();

        let entry = RecvEntry { token, data };

        // Build the appropriate completion handle
        let completion = if let Some(elem) = cqe_elem {
            let mem = self.inner.mem().clone();
            let cqe = WritableCompletion::new(mem, id, token, elem);
            SendCompletion::Writable(cqe)
        } else {
            let ack = AckCompletion::new(id, token);
            SendCompletion::Ack(ack)
        };

        Ok(Some((entry, completion)))
    }

    /// Submit a completed entry back to the ring.
    ///
    /// Accepts both [`WritableCompletion`] (with written byte count) and
    /// [`AckCompletion`] (zero-length) via the [`SendCompletion`] enum.
    /// Clears the inflight slot and notifies the producer if event
    /// suppression allows.
    pub fn complete(&mut self, completion: SendCompletion<M>) -> Result<(), VirtqError> {
        let id = completion.id();
        let written = completion.written() as u32;

        let slot = self
            .inflight
            .get_mut(id as usize)
            .ok_or(VirtqError::InvalidState)?;

        if slot.is_none() {
            return Err(VirtqError::InvalidState);
        }

        *slot = None;

        if self.inner.submit_used_with_notify(id, written)? {
            self.notifier.notify(QueueStats {
                num_free: self.inner.num_free(),
                num_inflight: self.inner.num_inflight(),
            });
        }

        Ok(())
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
    ///     while let Some((entry, completion)) = consumer.poll(1024)? {
    ///         process(entry, completion);
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

    /// Read a buffer element from shared memory into `Bytes`.
    fn read_element(&self, elem: &BufferElement) -> Result<Bytes, VirtqError> {
        let mut buf = vec![0u8; elem.len as usize];
        self.inner
            .mem()
            .read(elem.addr, &mut buf)
            .map_err(|_| VirtqError::MemoryReadError)?;

        Ok(Bytes::from(buf))
    }

    /// Reset ring and inflight state to initial values.
    pub fn reset(&mut self) {
        self.inner.reset();
        self.inflight.fill(None);
    }
}

/// Parse a descriptor chain into entry/completion buffer elements.
///
/// Returns `(entry_element, completion_element)`.
fn parse_chain(
    chain: &BufferChain,
) -> Result<(Option<BufferElement>, Option<BufferElement>), VirtqError> {
    let r = chain.readables();
    let w = chain.writables();

    match (r.len(), w.len()) {
        (1, 1) => Ok((Some(r[0]), Some(w[0]))),
        (0, 1) => Ok((None, Some(w[0]))),
        (1, 0) => Ok((Some(r[0]), None)),
        _ => Err(VirtqError::BadChain),
    }
}

impl<M: MemOps> From<WritableCompletion<M>> for SendCompletion<M> {
    fn from(wc: WritableCompletion<M>) -> Self {
        SendCompletion::Writable(wc)
    }
}

impl<M: MemOps> From<AckCompletion> for SendCompletion<M> {
    fn from(ack: AckCompletion) -> Self {
        SendCompletion::Ack(ack)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtq::ring::tests::make_ring;
    use crate::virtq::test_utils::*;

    #[test]
    fn test_write_only_entry_is_empty() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().completion(16).build().unwrap();
        producer.submit(se).unwrap();

        let (entry, completion) = consumer.poll(1024).unwrap().unwrap();
        assert!(entry.data().is_empty());
        assert!(matches!(completion, SendCompletion::Writable(_)));

        if let SendCompletion::Writable(mut wc) = completion {
            wc.write_all(b"response").unwrap();
            consumer.complete(wc.into()).unwrap();
        }
    }

    #[test]
    fn test_read_only_ack_completion() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().entry(16).build().unwrap();
        se.write_all(b"hello").unwrap();
        producer.submit(se).unwrap();

        let (entry, completion) = consumer.poll(1024).unwrap().unwrap();
        assert_eq!(entry.data().as_ref(), b"hello");
        assert!(matches!(completion, SendCompletion::Ack(_)));

        consumer.complete(completion).unwrap();
    }

    #[test]
    fn test_readwrite_round_trip() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().entry(32).completion(64).build().unwrap();
        se.write_all(b"hello world").unwrap();
        producer.submit(se).unwrap();

        let (entry, completion) = consumer.poll(1024).unwrap().unwrap();
        assert_eq!(entry.data().as_ref(), b"hello world");

        if let SendCompletion::Writable(mut wc) = completion {
            assert_eq!(wc.capacity(), 64);
            assert_eq!(wc.written(), 0);
            assert_eq!(wc.remaining(), 64);
            wc.write_all(b"response").unwrap();
            assert_eq!(wc.written(), 8);
            assert_eq!(wc.remaining(), 56);
            consumer.complete(wc.into()).unwrap();
        } else {
            panic!("expected Writable completion for entry+completion chain");
        }
    }

    #[test]
    fn test_writable_partial_write() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().completion(8).build().unwrap();
        producer.submit(se).unwrap();

        let (_entry, completion) = consumer.poll(1024).unwrap().unwrap();

        if let SendCompletion::Writable(mut wc) = completion {
            let n = wc.write(b"hello world!").unwrap();
            assert_eq!(n, 8);
            assert_eq!(wc.remaining(), 0);
            consumer.complete(wc.into()).unwrap();
        } else {
            panic!("expected Writable");
        }
    }

    #[test]
    fn test_writable_write_all_too_large() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().completion(4).build().unwrap();
        producer.submit(se).unwrap();
        let (_entry, completion) = consumer.poll(1024).unwrap().unwrap();

        if let SendCompletion::Writable(mut wc) = completion {
            let err = wc.write_all(b"too long").unwrap_err();
            assert!(matches!(err, VirtqError::CqeTooLarge));
        } else {
            panic!("expected Writable");
        }
    }

    #[test]
    fn test_writable_reset() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().completion(16).build().unwrap();
        producer.submit(se).unwrap();

        let (_entry, completion) = consumer.poll(1024).unwrap().unwrap();

        if let SendCompletion::Writable(mut wc) = completion {
            wc.write_all(b"first").unwrap();
            assert_eq!(wc.written(), 5);
            wc.reset();
            assert_eq!(wc.written(), 0);
            assert_eq!(wc.remaining(), 16);
            wc.write_all(b"second").unwrap();
            assert_eq!(wc.written(), 6);
            consumer.complete(wc.into()).unwrap();
        } else {
            panic!("expected Writable");
        }
    }

    #[test]
    fn test_multiple_pending_completions() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let se1 = producer.chain().completion(16).build().unwrap();
        producer.submit(se1).unwrap();
        let se2 = producer.chain().completion(16).build().unwrap();
        producer.submit(se2).unwrap();

        let (_e1, c1) = consumer.poll(1024).unwrap().unwrap();
        let (_e2, c2) = consumer.poll(1024).unwrap().unwrap();

        // Complete in reverse order
        consumer.complete(c2).unwrap();
        consumer.complete(c1).unwrap();
    }

    #[test]
    fn test_entry_into_data() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().entry(16).build().unwrap();
        se.write_all(b"abc").unwrap();
        producer.submit(se).unwrap();

        let (entry, completion) = consumer.poll(1024).unwrap().unwrap();
        let data = entry.into_data();
        assert_eq!(data.as_ref(), b"abc");
        consumer.complete(completion).unwrap();
    }

    #[test]
    fn test_virtq_consumer_reset() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        // Submit and poll (but do not complete)
        let se = producer.chain().completion(16).build().unwrap();
        producer.submit(se).unwrap();

        let (_entry, completion) = consumer.poll(1024).unwrap().unwrap();
        assert!(consumer.inflight.iter().any(|s| s.is_some()));

        // Complete first so we do not leak
        consumer.complete(completion).unwrap();

        consumer.reset();

        assert!(consumer.inflight.iter().all(|s| s.is_none()));
        assert_eq!(consumer.inner.num_inflight(), 0);
    }

    #[test]
    fn test_virtq_consumer_reset_clears_inflight() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        // Submit two entries and poll both
        let se1 = producer.chain().completion(16).build().unwrap();
        producer.submit(se1).unwrap();
        let se2 = producer.chain().completion(16).build().unwrap();
        producer.submit(se2).unwrap();

        let (_e1, c1) = consumer.poll(1024).unwrap().unwrap();
        let (_e2, c2) = consumer.poll(1024).unwrap().unwrap();
        // Complete both before reset
        consumer.complete(c1).unwrap();
        consumer.complete(c2).unwrap();

        consumer.reset();

        assert!(consumer.inflight.iter().all(|s| s.is_none()));
        assert_eq!(consumer.inner.num_inflight(), 0);
    }
}
