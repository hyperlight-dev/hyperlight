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

/// A completion received by the driver (producer) side.
///
/// Contains the completion data and metadata about the completed entry.
/// The `data` field is a zero-copy [`Bytes`] backed by a shared-memory
/// pool allocation that is returned when the last `Bytes` clone is dropped.
#[derive(Debug)]
pub struct RecvCompletion {
    /// Token identifying which entry this completion corresponds to.
    pub token: Token,
    /// Completion data from the device.
    pub data: Bytes,
}

/// Allocation tracking for an in-flight descriptor chain.
///
/// Each variant corresponds to a buffer layout submitted by the driver
/// (guest/producer) and consumed by the device (host/consumer).
/// "Readable" and "writable" are from the device's perspective, following
/// the virtio convention.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Inflight {
    /// Driver sends data, device only acknowledges (fire-and-forget).
    /// The readable buffer carries the entry; no writable buffer for a
    /// device response.
    ReadOnly { entry: Allocation },
    /// Driver pre-posts a writable buffer for the device to fill.
    /// No readable entry - the device writes a response into the
    /// completion buffer unprompted (e.g. event delivery).
    WriteOnly { completion: Allocation },
    /// Bidirectional: driver sends an entry, device writes a response.
    /// The readable buffer carries the entry, the writable buffer
    /// receives the completion (typical request/response pattern).
    ReadWrite {
        entry: Allocation,
        completion: Allocation,
    },
}

impl Inflight {
    fn entry(&self) -> Option<Allocation> {
        match self {
            Inflight::ReadOnly { entry } => Some(*entry),
            Inflight::ReadWrite { entry, .. } => Some(*entry),
            Inflight::WriteOnly { .. } => None,
        }
    }

    fn completion(&self) -> Option<Allocation> {
        match self {
            Inflight::WriteOnly { completion } => Some(*completion),
            Inflight::ReadWrite { completion, .. } => Some(*completion),
            Inflight::ReadOnly { .. } => None,
        }
    }

    fn try_into_chain(self, entry_len: usize) -> Result<BufferChain, VirtqError> {
        if let Some(entry) = self.entry()
            && entry_len > entry.len
        {
            return Err(VirtqError::EntryTooLarge);
        }

        Ok(match self {
            Inflight::ReadOnly { entry } => BufferChainBuilder::new()
                .readable(entry.addr, entry_len as u32)
                .build()?,
            Inflight::WriteOnly { completion } => BufferChainBuilder::new()
                .writable(completion.addr, completion.len as u32)
                .build()?,
            Inflight::ReadWrite { entry, completion } => BufferChainBuilder::new()
                .readable(entry.addr, entry_len as u32)
                .writable(completion.addr, completion.len as u32)
                .build()?,
        })
    }
}

/// A high-level virtqueue producer (driver side).
///
/// The producer sends entries to the consumer (device), and receives completions.
/// This is typically used on the driver/guest side.
///
/// # Example
///
/// ```ignore
/// let mut producer = VirtqProducer::new(layout, mem, notifier, pool);
///
/// // Build and submit an entry
/// let mut se = producer.chain().entry(64).completion(64).build()?;
/// se.write_all(b"hello")?;
/// let token = producer.submit(se)?;
///
/// // Later, poll for completion
/// if let Some(cqe) = producer.poll()? {
///     assert_eq!(cqe.token, token);
///     println!("Got completion: {:?}", cqe.data);
/// }
/// ```
pub struct VirtqProducer<M, N, P> {
    inner: RingProducer<M>,
    notifier: N,
    pool: P,
    inflight: Vec<Option<Inflight>>,
}

impl<M, N, P> VirtqProducer<M, N, P>
where
    M: MemOps + Clone,
    N: Notifier,
    P: BufferProvider + Clone,
{
    /// Create a new virtqueue producer.
    ///
    /// # Arguments
    ///
    /// * `layout` - Ring memory layout (descriptor table and event suppression addresses)
    /// * `mem` - Memory operations implementation for reading/writing to shared memory
    /// * `notifier` - Callback for notifying the device (consumer) about new entries
    /// * `pool` - Buffer allocator for entry/completion data
    pub fn new(layout: Layout, mem: M, notifier: N, pool: P) -> Self {
        let inner = RingProducer::new(layout, mem);
        let inflight = vec![None; inner.len()];

        Self {
            inner,
            pool,
            notifier,
            inflight,
        }
    }

    /// Poll for a single completion from the device.
    ///
    /// Returns `Ok(Some(completion))` if a completion is available, `Ok(None)` if no
    /// completions are ready (would block), or an error if the device misbehaved.
    ///
    /// The returned [`RecvCompletion::data`] is a zero-copy [`Bytes`] backed by the
    /// shared-memory allocation via [`BufferOwner`]. The pool allocation is
    /// held alive as long as any `Bytes` clone exists, and is returned to the
    /// pool when the last clone is dropped.
    ///
    /// # Errors
    ///
    /// - [`VirtqError::InvalidState`] - Device returned invalid descriptor ID or
    ///   wrote more data than the completion buffer capacity
    pub fn poll(&mut self) -> Result<Option<RecvCompletion>, VirtqError>
    where
        M: Send + Sync + 'static,
        P: Send + Sync + 'static,
    {
        let used = match self.inner.poll_used() {
            Ok(u) => u,
            Err(RingError::WouldBlock) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let id = used.id as usize;
        let inf = self
            .inflight
            .get_mut(id)
            .ok_or(VirtqError::InvalidState)?
            .take()
            .ok_or(VirtqError::InvalidState)?;

        let written = used.len as usize;

        // Free entry buffers (request data no longer needed)
        if let Some(entry) = inf.entry() {
            self.pool.dealloc(entry)?;
        }

        // Read completion data
        let data = match inf.completion() {
            Some(buf) => {
                if written > buf.len {
                    let _ = self.pool.dealloc(buf);
                    return Err(VirtqError::InvalidState);
                }
                let owner = BufferOwner {
                    pool: self.pool.clone(),
                    mem: self.inner.mem().clone(),
                    alloc: buf,
                    written,
                };
                Bytes::from_owner(owner)
            }
            None => Bytes::new(),
        };

        Ok(Some(RecvCompletion {
            token: Token(used.id),
            data,
        }))
    }

    /// Drain all available completions, calling the provided closure for each.
    ///
    /// This is a convenience method that repeatedly calls [`poll`](Self::poll)
    /// until no more completions are available.
    ///
    /// # Arguments
    ///
    /// * `f` - Closure called for each completion with its token and data
    ///
    /// # Example
    ///
    /// ```ignore
    /// producer.drain(|token, data| {
    ///     println!("Got {:?}: {} bytes", token, data.len());
    /// })?;
    /// ```
    pub fn drain(&mut self, mut f: impl FnMut(Token, Bytes)) -> Result<(), VirtqError>
    where
        M: Send + Sync + 'static,
        P: Send + Sync + 'static,
    {
        while let Some(cqe) = self.poll()? {
            f(cqe.token, cqe.data);
        }

        Ok(())
    }

    /// Begin building a descriptor chain for submission.
    ///
    /// Returns a [`ChainBuilder`] that allocates buffers from the pool.
    /// ```
    pub fn chain(&self) -> ChainBuilder<M, P> {
        ChainBuilder::new(self.inner.mem().clone(), self.pool.clone())
    }

    /// Submit a [`SendEntry`] to the ring.
    ///
    /// Publishes the descriptor chain, stores the in-flight tracking state,
    /// and notifies the consumer if event suppression allows.
    ///
    /// # Errors
    ///
    /// - [`VirtqError::EntryTooLarge`] - written exceeds entry buffer capacity
    /// - [`VirtqError::RingError`] - ring is full
    /// - [`VirtqError::InvalidState`] - descriptor ID collision
    pub fn submit(&mut self, mut entry: SendEntry<M, P>) -> Result<Token, VirtqError> {
        let written = entry.written;
        let inflight = entry.inflight.take().ok_or(VirtqError::InvalidState)?;

        let cursor_before = self.inner.avail_cursor();
        let chain = inflight.try_into_chain(written)?;
        let id = self.inner.submit_available(&chain)?;

        let slot = self
            .inflight
            .get_mut(id as usize)
            .ok_or(VirtqError::InvalidState)?;

        if slot.is_some() {
            return Err(VirtqError::InvalidState);
        }

        *slot = Some(inflight);

        let should_notify = self.inner.should_notify_since(cursor_before)?;

        // TODO(virtq): for now simulate current outb behavior of only
        // notifying on bidirectional (request/response) entries.
        // Eventually this should be decoupled from the buffer layout
        // and driven entirely by event suppression rules.
        let should_notify = should_notify && matches!(inflight, Inflight::ReadWrite { .. });

        if should_notify {
            self.notifier.notify(QueueStats {
                num_free: self.inner.num_free(),
                num_inflight: self.inner.num_inflight(),
            });
        }

        Ok(Token(id))
    }

    /// Signal backpressure to the consumer.
    ///
    /// Bypasses event suppression. Call this when submit fails with a backpressure error and the consumer needs to drain.
    #[inline]
    pub fn notify_backpressure(&self) {
        self.notifier.notify(QueueStats {
            num_free: self.inner.num_free(),
            num_inflight: self.inner.num_inflight(),
        });
    }

    /// Get the current used cursor position.
    ///
    /// Useful for setting up descriptor-based event suppression.
    #[inline]
    pub fn used_cursor(&self) -> RingCursor {
        self.inner.used_cursor()
    }

    /// Configure event suppression for used buffer notifications.
    ///
    /// This controls when the device (consumer) signals us about completed buffers:
    ///
    /// - [`SuppressionKind::Enable`]: Always signal (default) - good for latency
    /// - [`SuppressionKind::Disable`]: Never signal - caller must poll
    /// - [`SuppressionKind::Descriptor`]: Signal only at specific cursor position
    ///
    /// # Example: Completion Batching
    ///
    /// ```ignore
    /// // Submit entries, then suppress notifications until all complete
    /// let mut se = producer.chain().entry(64).completion(128).build()?;
    /// se.write_all(b"entry1")?;
    /// producer.submit(se)?;
    /// let cursor = producer.used_cursor();
    /// producer.set_used_suppression(SuppressionKind::Descriptor(cursor))?;
    /// // Device will notify only after reaching that cursor position
    /// ```
    pub fn set_used_suppression(&mut self, kind: SuppressionKind) -> Result<(), VirtqError> {
        match kind {
            SuppressionKind::Enable => self.inner.enable_used_notifications()?,
            SuppressionKind::Disable => self.inner.disable_used_notifications()?,
            SuppressionKind::Descriptor(cursor) => self
                .inner
                .enable_used_notifications_desc(cursor.head(), cursor.wrap())?,
        }
        Ok(())
    }

    /// Reset ring, inflight, and pool state to initial values.
    ///
    /// # Safety
    ///
    /// All [`RecvCompletion`]s (and their backing [`Bytes`]) from
    /// previous `poll()` calls must have been dropped before calling
    /// this. Outstanding completions hold pool allocations via
    /// `BufferOwner`; resetting the pool while they exist would cause
    /// double-free on drop.
    ///
    /// TODO(virtq): properly restore state after snapshot instead of just resetting everything
    pub fn reset(&mut self) {
        self.inner.reset();
        self.pool.reset();
        self.inflight.fill(None);
    }
}

/// Builder for configuring a descriptor chain's buffer layout.
///
/// If dropped without building, no resources are leaked (allocations are
/// deferred to [`build`](Self::build)).
#[must_use = "call .build() to create a SendEntry"]
pub struct ChainBuilder<M: MemOps, P: BufferProvider + Clone> {
    mem: M,
    pool: P,
    entry_cap: Option<usize>,
    cqe_cap: Option<usize>,
}

impl<M: MemOps, P: BufferProvider + Clone> ChainBuilder<M, P> {
    fn new(mem: M, pool: P) -> Self {
        Self {
            mem,
            pool,
            entry_cap: None,
            cqe_cap: None,
        }
    }

    fn alloc(
        &self,
        size: usize,
    ) -> Result<AllocGuard<impl FnOnce(Allocation) + use<M, P>>, VirtqError> {
        let alloc = self.pool.alloc(size)?;
        let pool = self.pool.clone();

        Ok(AllocGuard::new(alloc, move |a| {
            let _ = pool.dealloc(a);
        }))
    }

    /// Request an entry buffer of `cap` bytes.
    ///
    /// The entry holds data sent from the driver to the consumer (device).
    /// The actual allocation is deferred to [`build`](Self::build).
    pub fn entry(mut self, cap: usize) -> Self {
        self.entry_cap = Some(cap);
        self
    }

    /// Request a completion buffer of `cap` bytes.
    ///
    /// The completion buffer is filled by the consumer and returned via
    /// [`VirtqProducer::poll`] as [`RecvCompletion`].
    pub fn completion(mut self, cap: usize) -> Self {
        self.cqe_cap = Some(cap);
        self
    }

    /// Allocate buffers and return a [`SendEntry`] for writing.
    ///
    /// # Errors
    ///
    /// - [`VirtqError::InvalidState`] - Neither entry nor completion requested
    /// - [`VirtqError::Alloc`] - Pool exhausted
    pub fn build(self) -> Result<SendEntry<M, P>, VirtqError> {
        if self.entry_cap.is_none() && self.cqe_cap.is_none() {
            return Err(VirtqError::InvalidState);
        }

        let entry_alloc = self.entry_cap.map(|cap| self.alloc(cap)).transpose()?;
        let completion_alloc = self.cqe_cap.map(|cap| self.alloc(cap)).transpose()?;

        let inflight = match (entry_alloc, completion_alloc) {
            (Some(entry), Some(cqe)) => Inflight::ReadWrite {
                entry: entry.release(),
                completion: cqe.release(),
            },
            (Some(entry), None) => Inflight::ReadOnly {
                entry: entry.release(),
            },
            (None, Some(cqe)) => Inflight::WriteOnly {
                completion: cqe.release(),
            },
            (None, None) => unreachable!(),
        };

        Ok(SendEntry {
            mem: self.mem,
            pool: self.pool,
            inflight: Some(inflight),
            written: 0,
        })
    }
}

/// A configured entry ready for writing and submission.
///
/// Created by [`ChainBuilder::build`]. Write data into the entry buffer
/// with [`write_all`](Self::write_all),
/// or use [`buf_mut`](Self::buf_mut) for zero-copy direct access.
/// Then submit via [`VirtqProducer::submit`].
///
/// # Examples
///
/// ```ignore
/// let mut se = producer.chain().entry(64).completion(128).build()?;
/// se.write_all(b"header")?;
/// se.write_all(b" body")?;
/// let tok = producer.submit(se)?;
///
/// // Zero-copy direct access
/// let mut se = producer.chain().entry(128).build()?;
/// let buf = se.buf_mut()?;
/// let n = serialize_into(buf);
/// se.set_written(n)?;
/// let tok = producer.submit(se)?;
/// ```
///
/// If dropped without submitting, allocated buffers are returned to the pool.
#[must_use = "dropping without submitting deallocates the buffers"]
pub struct SendEntry<M: MemOps, P: BufferProvider> {
    mem: M,
    pool: P,
    written: usize,
    inflight: Option<Inflight>,
}

impl<M: MemOps, P: BufferProvider> SendEntry<M, P> {
    fn entry(&self) -> Result<Allocation, VirtqError> {
        self.inflight
            .as_ref()
            .and_then(|i| i.entry())
            .ok_or(VirtqError::NoReadableBuffer)
    }

    /// Total entry buffer capacity in bytes.
    ///
    /// Returns 0 when there are no entry buffers.
    pub fn capacity(&self) -> usize {
        self.inflight
            .as_ref()
            .and_then(|i| i.entry())
            .map_or(0, |a| a.len)
    }

    /// Number of bytes written so far via [`write_all`](Self::write_all)
    /// or [`set_written`](Self::set_written).
    pub fn written(&self) -> usize {
        self.written
    }

    /// Set the write cursor to an explicit byte count.
    ///
    /// Use this after [`buf_mut`](Self::buf_mut) where you wrote directly
    /// into the buffer. The value tells the consumer how many bytes of
    /// the entry buffer are valid.
    ///
    /// # Errors
    ///
    /// - [`VirtqError::EntryTooLarge`] - `written` exceeds entry buffer capacity
    pub fn set_written(&mut self, written: usize) -> Result<(), VirtqError> {
        if written > self.capacity() {
            return Err(VirtqError::EntryTooLarge);
        }

        self.written = written;
        Ok(())
    }

    /// Remaining writable capacity in the entry buffer.
    pub fn remaining(&self) -> usize {
        self.capacity() - self.written
    }

    /// Write the entire buffer into the entry.
    ///
    /// Appends at the current write position. Uses [`MemOps::write`]
    /// (volatile on host side).
    ///
    /// # Errors
    ///
    /// - [`VirtqError::EntryTooLarge`] - buf exceeds remaining capacity
    /// - [`VirtqError::NoReadableBuffer`] - no entry buffer allocated
    /// - [`VirtqError::MemoryWriteError`] - underlying write failed
    pub fn write_all(&mut self, buf: &[u8]) -> Result<(), VirtqError> {
        let alloc = self.entry()?;

        if buf.len() > self.remaining() {
            return Err(VirtqError::EntryTooLarge);
        }

        let addr = alloc.addr + self.written as u64;
        self.mem
            .write(addr, buf)
            .map_err(|_| VirtqError::MemoryWriteError)?;

        self.written += buf.len();
        Ok(())
    }

    /// Zero-copy access to the full entry buffer in shared memory.
    ///
    /// Returns `&mut [u8]` pointing directly into the allocated buffer.
    /// This is safe on the guest side (producer). After writing, call
    /// [`set_written`](Self::set_written) to record how many bytes are valid.
    ///
    /// **Note**: This bypasses the write cursor. Use either `buf_mut()` +
    /// `set_written(n)` or the `write_all` method, not both.
    ///
    /// # Errors
    ///
    /// - [`VirtqError::NoReadableBuffer`] - no entry buffer allocated
    /// - [`VirtqError::MemoryWriteError`] - failed to access shared memory
    pub fn buf_mut(&mut self) -> Result<&mut [u8], VirtqError> {
        let alloc = self.entry()?;
        unsafe {
            self.mem
                .as_mut_slice(alloc.addr, alloc.len)
                .map_err(|_| VirtqError::MemoryWriteError)
        }
    }
}

impl<M: MemOps, P: BufferProvider> Drop for SendEntry<M, P> {
    fn drop(&mut self) {
        let inf = match self.inflight.take() {
            Some(i) => i,
            None => return, // already submitted
        };
        if let Some(a) = inf.entry() {
            let _ = self.pool.dealloc(a);
        }
        if let Some(a) = inf.completion() {
            let _ = self.pool.dealloc(a);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtq::ring::tests::make_ring;
    use crate::virtq::test_utils::*;

    #[test]
    fn test_chain_readwrite_build() {
        let ring = make_ring(16);
        let (producer, _consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().entry(64).completion(128).build().unwrap();
        assert_eq!(se.capacity(), 64);
        assert_eq!(se.written(), 0);
        assert_eq!(se.remaining(), 64);
    }

    #[test]
    fn test_chain_entry_only_build() {
        let ring = make_ring(16);
        let (producer, _consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().entry(32).build().unwrap();
        assert_eq!(se.capacity(), 32);
    }

    #[test]
    fn test_chain_completion_only_build() {
        let ring = make_ring(16);
        let (producer, _consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().completion(64).build().unwrap();
        assert_eq!(se.capacity(), 0);
    }

    #[test]
    fn test_chain_empty_build_fails() {
        let ring = make_ring(16);
        let (producer, _consumer, _notifier) = make_test_producer(&ring);

        let result = producer.chain().build();
        assert!(matches!(result, Err(VirtqError::InvalidState)));
    }

    #[test]
    fn test_send_entry_write_all_and_submit() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().entry(64).completion(128).build().unwrap();

        se.write_all(b"hello").unwrap();
        se.write_all(b" world").unwrap();
        assert_eq!(se.written(), 11);
        assert_eq!(se.remaining(), 53);
        let tok = producer.submit(se).unwrap();

        let (entry, completion) = consumer.poll(1024).unwrap().unwrap();
        assert_eq!(entry.token(), tok);
        assert_eq!(entry.data().as_ref(), b"hello world");
        consumer.complete(completion).unwrap();
    }

    #[test]
    fn test_send_entry_buf_mut() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().entry(64).completion(128).build().unwrap();
        let buf = se.buf_mut().unwrap();
        assert_eq!(buf.len(), 64);
        buf[..5].copy_from_slice(b"hello");
        se.set_written(5).unwrap();
        let _tok = producer.submit(se).unwrap();

        let (entry, completion) = consumer.poll(1024).unwrap().unwrap();
        assert_eq!(entry.data().as_ref(), b"hello");
        consumer.complete(completion).unwrap();
    }

    #[test]
    fn test_send_entry_write_too_large() {
        let ring = make_ring(16);
        let (producer, _consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().entry(4).build().unwrap();
        let err = se.write_all(b"too long").unwrap_err();
        assert!(matches!(err, VirtqError::EntryTooLarge));
    }

    #[test]
    fn test_writeonly_has_no_entry_buffer() {
        let ring = make_ring(16);
        let (producer, _consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().completion(32).build().unwrap();
        let err = se.write_all(b"data").unwrap_err();
        assert!(matches!(err, VirtqError::NoReadableBuffer));
    }

    #[test]
    fn test_drop_chain_builder_deallocs() {
        let ring = make_ring(16);
        let (mut producer, _consumer, _notifier) = make_test_producer(&ring);

        {
            let _builder = producer.chain().entry(64).completion(128);
            // dropped without build
        }

        // Ring should still be fully usable
        let se = producer.chain().entry(64).completion(128).build().unwrap();
        let tok = producer.submit(se).unwrap();
        assert!(tok.0 < 16);
    }

    #[test]
    fn test_drop_send_entry_deallocs() {
        let ring = make_ring(16);
        let (mut producer, _consumer, _notifier) = make_test_producer(&ring);

        {
            let _se = producer.chain().entry(64).completion(128).build().unwrap();
            // dropped without submit
        }

        // Ring should still be fully usable
        let se = producer.chain().entry(64).completion(128).build().unwrap();
        let tok = producer.submit(se).unwrap();
        assert!(tok.0 < 16);
    }

    #[test]
    fn test_submit_notifies() {
        let ring = make_ring(16);
        let (mut producer, _consumer, notifier) = make_test_producer(&ring);

        let initial_count = notifier.notification_count();

        let mut se = producer.chain().entry(64).completion(128).build().unwrap();
        se.write_all(b"hello").unwrap();
        producer.submit(se).unwrap();

        assert!(notifier.notification_count() > initial_count);
    }

    #[test]
    fn test_set_written_too_large() {
        let ring = make_ring(16);
        let (producer, _consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().entry(32).completion(64).build().unwrap();
        let err = se.set_written(64).unwrap_err();
        assert!(matches!(err, VirtqError::EntryTooLarge));
    }

    #[test]
    fn test_write_only_round_trip() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().completion(32).build().unwrap();
        let token = producer.submit(se).unwrap();

        let (entry, completion) = consumer.poll(1024).unwrap().unwrap();
        assert_eq!(entry.token(), token);
        assert!(entry.data().is_empty());

        if let SendCompletion::Writable(mut wc) = completion {
            wc.write_all(b"filled-by-consumer").unwrap();
            consumer.complete(wc.into()).unwrap();
        } else {
            panic!("expected Writable");
        }

        let cqe = producer.poll().unwrap().unwrap();
        assert_eq!(cqe.token, token);
        assert_eq!(cqe.data.len(), b"filled-by-consumer".len());
        assert_eq!(&cqe.data[..], b"filled-by-consumer");
    }

    #[test]
    fn test_read_only_round_trip() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().entry(32).build().unwrap();
        se.write_all(b"fire-and-forget").unwrap();
        let token = producer.submit(se).unwrap();

        let (entry, completion) = consumer.poll(1024).unwrap().unwrap();
        assert_eq!(entry.token(), token);
        assert_eq!(entry.data().as_ref(), b"fire-and-forget");
        assert!(matches!(completion, SendCompletion::Ack(_)));
        consumer.complete(completion).unwrap();

        let cqe = producer.poll().unwrap().unwrap();
        assert_eq!(cqe.token, token);
        assert_eq!(cqe.data.len(), 0);
        assert!(cqe.data.is_empty());
    }

    #[test]
    fn test_readwrite_round_trip() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().entry(64).completion(128).build().unwrap();
        se.write_all(b"request data").unwrap();
        let token = producer.submit(se).unwrap();

        let (entry, completion) = consumer.poll(1024).unwrap().unwrap();
        assert_eq!(entry.data().as_ref(), b"request data");
        if let SendCompletion::Writable(mut wc) = completion {
            wc.write_all(b"response data").unwrap();
            consumer.complete(wc.into()).unwrap();
        } else {
            panic!("expected Writable");
        }

        let cqe = producer.poll().unwrap().unwrap();
        assert_eq!(cqe.token, token);
        assert_eq!(&cqe.data[..], b"response data");
    }

    #[test]
    fn test_virtq_producer_reset() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        // Submit and complete a round trip
        let mut se = producer.chain().entry(32).completion(64).build().unwrap();
        se.write_all(b"hello").unwrap();
        producer.submit(se).unwrap();

        let (entry, completion) = consumer.poll(1024).unwrap().unwrap();
        assert_eq!(entry.data().as_ref(), b"hello");
        consumer.complete(completion).unwrap();
        let _ = producer.poll().unwrap().unwrap();

        // Now reset
        producer.reset();

        // All inflight slots should be None
        assert!(producer.inflight.iter().all(|s| s.is_none()));
        // Ring state should be back to initial
        assert_eq!(producer.inner.num_free(), producer.inner.len());
    }

    #[test]
    fn test_virtq_producer_reset_clears_inflight() {
        let ring = make_ring(16);
        let (mut producer, _consumer, _notifier) = make_test_producer(&ring);

        // Submit without completing
        let se = producer.chain().completion(64).build().unwrap();
        producer.submit(se).unwrap();

        assert!(producer.inflight.iter().any(|s| s.is_some()));

        producer.reset();

        assert!(producer.inflight.iter().all(|s| s.is_none()));
        assert_eq!(producer.inner.num_free(), producer.inner.len());
    }
}
