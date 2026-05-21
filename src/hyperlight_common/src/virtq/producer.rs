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

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use bytes::Bytes;
use smallvec::SmallVec;

use super::*;

/// A completion received by the driver (producer) side.
///
/// Read-only chains complete as [`Ack`](Self::Ack). Chains with a writable
/// buffer complete as [`Data`](Self::Data), even when the device wrote zero
/// bytes. The `Bytes` in [`Data`](Self::Data) is backed by a shared-memory
/// pool allocation that is returned when the last clone is dropped.
#[derive(Debug)]
pub enum RecvCompletion {
    /// Acknowledgement for a read-only/fire-and-forget chain.
    Ack(Token),
    /// Data written by the consumer into the chain's writable buffer.
    ///
    /// The payload may be empty when the consumer writes zero bytes; that is
    /// still a data completion because the submitted chain had writable
    /// capacity.
    Data(Token, Bytes),
}

impl RecvCompletion {
    /// Token identifying which submitted chain this completion corresponds to.
    pub fn token(&self) -> Token {
        match self {
            Self::Ack(token) | Self::Data(token, _) => *token,
        }
    }

    /// Data written by the consumer, if this is a data completion.
    pub fn data(&self) -> Option<&Bytes> {
        match self {
            Self::Ack(_) => None,
            Self::Data(_, data) => Some(data),
        }
    }

    /// Consume the completion and return written data, if present.
    pub fn into_data(self) -> Option<Bytes> {
        match self {
            Self::Ack(_) => None,
            Self::Data(_, data) => Some(data),
        }
    }
}

/// Producer-owned readable buffer submitted in a descriptor chain.
///
/// "Readable" is from the device's perspective: the producer writes data
/// here, then the consumer reads it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReadableAlloc {
    alloc: Allocation,
    written: usize,
}

/// Allocation tracking for an in-flight descriptor chain.
///
/// Buffers are stored in virtio order: device-readable buffers first, then
/// device-writable buffers. This is more general than the old entry/completion
/// layout while keeping common one-readable/one-writable chains inline.
#[derive(Debug)]
pub(crate) struct Inflight {
    readables: SmallVec<[ReadableAlloc; 2]>,
    writables: SmallVec<[Allocation; 1]>,
}

impl Inflight {
    fn try_to_chain(&self) -> Result<BufferChain, VirtqError> {
        if self.readables.is_empty() && self.writables.is_empty() {
            return Err(VirtqError::InvalidState);
        }

        // Preserve one descriptor per requested readable segment, even when a
        // segment currently has zero written bytes.
        let readable_elems = self.readables.iter().map(|readable| {
            if readable.written > readable.alloc.len {
                return Err(VirtqError::EntryTooLarge);
            }

            Ok(BufferElement {
                addr: readable.alloc.addr,
                len: readable.written as u32,
                writable: false,
            })
        });

        let writable_elems = self.writables.iter().map(|writable| BufferElement {
            addr: writable.addr,
            len: writable.len as u32,
            writable: true,
        });

        let builder = BufferChainBuilder::new().readables(
            readable_elems.collect::<Result<SmallVec<[BufferElement; 2]>, VirtqError>>()?,
        );

        if self.writables.is_empty() {
            Ok(builder.build()?)
        } else {
            Ok(builder.writables(writable_elems).build()?)
        }
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
/// let mut se = producer.chain().readable(64).writable(64).build()?;
/// se.write_all(b"hello")?;
/// let token = producer.submit(se)?;
///
/// // Later, poll for completion
/// if let Some(cqe) = producer.poll()? {
///     assert_eq!(cqe.token(), token);
///     match cqe {
///         RecvCompletion::Data(_, data) => println!("Got completion: {:?}", data),
///         RecvCompletion::Ack(_) => println!("Got ack"),
///     }
/// }
/// ```
pub struct VirtqProducer<M, N, P> {
    inner: RingProducer<M>,
    notifier: N,
    pool: P,
    next_token: u32,
    inflight: Vec<Option<(Token, Inflight)>>,
    pending: VecDeque<RecvCompletion>,
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
        let ring_len = inner.len();

        Self {
            inner,
            pool,
            notifier,
            next_token: 0,
            inflight: (0..ring_len).map(|_| None).collect(),
            pending: VecDeque::with_capacity(ring_len),
        }
    }

    /// Poll for a single completion from the device.
    ///
    /// Returns buffered completions from prior [`reclaim`](Self::reclaim)
    /// calls first, then checks the ring for new completions.
    ///
    /// Returns `Ok(Some(completion))` if a completion is available, `Ok(None)` if no
    /// completions are ready (would block), or an error if the device misbehaved.
    ///
    /// Data completions contain zero-copy [`Bytes`] backed by the shared-memory
    /// allocation via [`BufferOwner`]. The pool allocation is held alive as long
    /// as any `Bytes` clone exists, and is returned to the pool when the last
    /// clone is dropped.
    ///
    /// # Errors
    ///
    /// - [`VirtqError::InvalidState`] - Device returned invalid descriptor ID or
    ///   wrote more data than the writable buffer capacity
    pub fn poll(&mut self) -> Result<Option<RecvCompletion>, VirtqError>
    where
        M: Send + 'static,
        P: Send + 'static,
    {
        if let Some(cqe) = self.pending.pop_front() {
            return Ok(Some(cqe));
        }
        self.poll_ring()
    }

    /// Reclaim ring slots and pool entries from completed descriptors.
    ///
    /// Processes all available used entries from the ring: frees entry
    /// buffer allocations immediately, and buffers completion data for
    /// later retrieval via [`poll`](Self::poll).
    ///
    /// Read-only ack completions are discarded immediately.
    ///
    /// Use this to free resources under backpressure without losing
    /// completion data. Returns the number of entries reclaimed.
    pub fn reclaim(&mut self) -> Result<usize, VirtqError>
    where
        M: Send + 'static,
        P: Send + 'static,
    {
        let mut count = 0;
        while let Some(cqe) = self.poll_ring()? {
            if matches!(cqe, RecvCompletion::Data(_, _)) {
                debug_assert!(self.pending.len() < self.inner.len());
                self.pending.push_back(cqe);
            }
            count += 1;
        }
        Ok(count)
    }

    /// Poll one completion directly from the ring (bypassing pending buffer).
    fn poll_ring(&mut self) -> Result<Option<RecvCompletion>, VirtqError>
    where
        M: Send + 'static,
        P: Send + 'static,
    {
        let used = match self.inner.poll_used() {
            Ok(u) => u,
            Err(RingError::WouldBlock) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let (token, inf) = self
            .inflight
            .get_mut(used.id as usize)
            .and_then(Option::take)
            .ok_or(VirtqError::InvalidState)?;

        let written = used.len as usize;

        let Inflight {
            readables,
            mut writables,
        } = inf;

        self.dealloc_all(readables.into_iter().map(|readable| readable.alloc))?;

        if writables.len() > 1 {
            // ChainBuilder currently caps producer-side writable buffers at one.
            // If that invariant changes, RecvCompletion needs a segmented data
            // shape before this branch can return completion data safely.
            self.dealloc_all(writables)?;
            return Err(VirtqError::UnsupportedChain);
        }

        // used.len is the aggregate bytes written across writable descriptors.
        // The high-level producer currently supports at most one writable
        // buffer, so the aggregate length is that buffer's length.
        let completion_guard = writables
            .pop()
            .map(|buf| PoolAlloc::new(self.pool.clone(), buf));

        // Read completion data
        let completion = match completion_guard {
            Some(buf) if written > buf.allocation().len => {
                // This is a protocol violation
                return Err(VirtqError::InvalidState);
            }
            Some(buf) => RecvCompletion::Data(
                token,
                Bytes::from_owner(
                    buf.into_buffer_owner(self.inner.mem().clone(), written)
                        .map_err(|_| VirtqError::MemoryReadError)?,
                ),
            ),
            None => RecvCompletion::Ack(token),
        };

        Ok(Some(completion))
    }

    fn dealloc_all(&self, allocs: impl IntoIterator<Item = Allocation>) -> Result<(), VirtqError> {
        let mut first_err = None;
        for alloc in allocs {
            if let Err(err) = self.pool.dealloc(alloc)
                && first_err.is_none()
            {
                first_err = Some(VirtqError::Alloc(err));
            }
        }

        if let Some(err) = first_err {
            return Err(err);
        }

        Ok(())
    }

    /// Drain all available completions, calling the provided closure for each.
    ///
    /// This is a convenience method that repeatedly calls [`poll`](Self::poll)
    /// until no more completions are available.
    ///
    /// # Arguments
    ///
    /// * `f` - Closure called for each completion
    ///
    /// # Example
    ///
    /// ```ignore
    /// producer.drain(|completion| {
    ///     println!("Got completion for {:?}", completion.token());
    /// })?;
    /// ```
    pub fn drain(&mut self, mut f: impl FnMut(RecvCompletion)) -> Result<(), VirtqError>
    where
        M: Send + 'static,
        P: Send + 'static,
    {
        while let Some(cqe) = self.poll()? {
            f(cqe);
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

    /// Begin a batch of submissions.
    ///
    /// Entries submitted through the returned [`SubmitBatch`] are published to
    /// the ring immediately, but the consumer is notified at most once when
    /// [`SubmitBatch::finish`] is called. This mirrors the virtio pattern of
    /// adding multiple buffers and then kicking the queue once.
    pub fn batch(&mut self) -> SubmitBatch<'_, M, N, P> {
        SubmitBatch::new(self)
    }

    /// Submit a [`SendEntry`] to the ring.
    ///
    /// Publishes the descriptor chain, stores the in-flight tracking state,
    /// and notifies the consumer if event suppression allows. Notifications
    /// are layout-neutral; use [`batch`](Self::batch) when a higher-level
    /// protocol wants to publish multiple entries and kick once.
    ///
    /// # Errors
    ///
    /// - [`VirtqError::EntryTooLarge`] - written exceeds readable buffer capacity
    /// - [`VirtqError::RingError`] - ring is full
    /// - [`VirtqError::InvalidState`] - descriptor ID collision
    pub fn submit(&mut self, entry: SendEntry<M, P>) -> Result<Token, VirtqError> {
        let cursor_before = self.inner.avail_cursor();
        let token = self.publish(entry)?;
        self.notify_since(cursor_before)?;
        Ok(token)
    }

    fn publish(&mut self, mut entry: SendEntry<M, P>) -> Result<Token, VirtqError> {
        let chain = entry
            .inflight
            .as_ref()
            .ok_or(VirtqError::InvalidState)?
            .try_to_chain()?;
        let token_id = self.next_token;
        let id = self.inner.submit_available(&chain)?;
        let inflight = entry.inflight.take().ok_or(VirtqError::InvalidState)?;

        let token = Token(token_id, id);
        debug_assert!(self.inflight[id as usize].is_none());
        self.inflight[id as usize] = Some((token, inflight));
        self.next_token = self.next_token.wrapping_add(1);

        Ok(token)
    }

    fn notify_since(&mut self, cursor: RingCursor) -> Result<bool, VirtqError> {
        let should_notify = self.inner.should_notify_since(cursor)?;
        if should_notify {
            self.notify_now();
        }
        Ok(should_notify)
    }

    fn notify_now(&self) {
        self.notifier.notify(QueueStats {
            num_free: self.inner.num_free(),
            num_inflight: self.inner.num_inflight(),
        });
    }

    /// Signal backpressure to the consumer.
    ///
    /// Bypasses event suppression. Call this when submit fails with a
    /// backpressure error and the consumer needs to drain.
    #[inline]
    pub fn notify_backpressure(&self) {
        self.notify_now();
    }

    /// Get the current used cursor position.
    ///
    /// Useful for setting up descriptor-based event suppression.
    #[inline]
    pub fn used_cursor(&self) -> RingCursor {
        self.inner.used_cursor()
    }

    /// Number of free (unsubmitted) descriptors in the ring.
    #[inline]
    pub fn num_free(&self) -> usize {
        self.inner.num_free()
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
    /// let mut se = producer.chain().readable(64).writable(128).build()?;
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
    /// All [`RecvCompletion`]s (and their backing [`Bytes`]) from previous `poll()`
    /// calls must have been dropped before calling this. Outstanding completions
    /// hold pool allocations via `BufferOwner`; resetting the pool while they exist
    /// would cause double-free on drop.
    ///
    /// TODO(virtq): find a way to allow guest to keep completions across resets.
    pub fn reset(&mut self) {
        self.pending.clear();
        self.inflight.iter_mut().for_each(|slot| *slot = None);
        self.inner.reset();
        self.pool.reset();
    }

    /// Replace the pool and reset ring, inflight, and pending state.
    ///
    /// Use this when restoring from a snapshot where the pool has been
    /// relocated or recreated.
    ///
    /// # Safety
    ///
    /// Same as [`reset`](Self::reset) - all outstanding completions
    /// must have been dropped.
    pub fn reset_with_pool(&mut self, pool: P) {
        self.pending.clear();
        self.inflight.iter_mut().for_each(|slot| *slot = None);
        self.inner.reset();
        self.pool = pool;
    }
}

/// A scoped batch of producer submissions.
///
/// Submissions are published immediately, while notification is delayed until
/// [`finish`](Self::finish). `finish` is explicit because the event-suppression
/// check can fail; dropping a batch does not notify.
#[must_use = "call finish to notify the consumer about batched submissions"]
pub struct SubmitBatch<'a, M, N, P> {
    producer: &'a mut VirtqProducer<M, N, P>,
    notify_from: Option<RingCursor>,
}

impl<'a, M, N, P> SubmitBatch<'a, M, N, P>
where
    M: MemOps + Clone,
    N: Notifier,
    P: BufferProvider + Clone,
{
    fn new(producer: &'a mut VirtqProducer<M, N, P>) -> Self {
        Self {
            producer,
            notify_from: None,
        }
    }

    /// Begin building a descriptor chain for this batch.
    pub fn chain(&self) -> ChainBuilder<M, P> {
        self.producer.chain()
    }

    /// Publish an entry as part of this batch without notifying yet.
    pub fn submit(&mut self, entry: SendEntry<M, P>) -> Result<Token, VirtqError> {
        let cursor_before = self.producer.inner.avail_cursor();
        let token = self.producer.publish(entry)?;
        if self.notify_from.is_none() {
            self.notify_from = Some(cursor_before);
        }
        Ok(token)
    }

    /// Finish the batch and notify the consumer once if event suppression
    /// requires it for the whole published range.
    ///
    /// Returns `true` if a notification was sent.
    pub fn finish(mut self) -> Result<bool, VirtqError> {
        let Some(notify_from) = self.notify_from.take() else {
            return Ok(false);
        };

        self.producer.notify_since(notify_from)
    }
}

/// Snapshot restore support for producers backed by [`RecyclePool`].
impl<M, N> VirtqProducer<M, N, RecyclePool>
where
    M: MemOps + Clone,
    N: Notifier,
{
    /// Replace the pool and reconstruct producer state from a prefilled ring.
    ///
    /// The host prefills the H2G ring with `min(ring_size, pool_count)`
    /// descriptors during restore (`restore_h2g_prefill`), writing
    /// descriptors in forward order: position i gets
    /// `addr = pool_base + i * slot_size`.
    ///
    /// Any descriptors already consumed by the host marked used
    /// will be discovered naturally by `poll_used()` after restore.
    pub fn restore_from_ring(&mut self, pool: RecyclePool) -> Result<(), VirtqError> {
        self.reset_with_pool(pool);

        let ring_size = self.inner.len();
        let pool_count = self.pool.count();
        let prefill_count = core::cmp::min(ring_size, pool_count);
        let slot_size = self.pool.slot_size();

        let mut prefilled = SmallVec::<[u16; 64]>::new();
        let mut seen = SmallVec::<[bool; 64]>::from_elem(false, ring_size);
        let mut restored_inflight: Vec<Option<(Token, Inflight)>> =
            (0..ring_size).map(|_| None).collect();

        // Scan descriptors to discover in-flight IDs and set up inflight table
        for pos in 0..prefill_count as u16 {
            let desc_base = self
                .inner
                .desc_table()
                .desc_addr(pos)
                .ok_or(VirtqError::RingError(RingError::InvalidState))?;

            let id = self
                .inner
                .mem()
                .read_val::<u16>(desc_base + Descriptor::ID_OFFSET as u64)
                .map_err(|_| VirtqError::MemoryReadError)?;

            if (id as usize) >= ring_size {
                return Err(VirtqError::InvalidState);
            }

            if seen[id as usize] {
                return Err(VirtqError::InvalidState);
            }
            seen[id as usize] = true;

            let addr = self
                .pool
                .slot_addr(pos as usize)
                .ok_or(VirtqError::InvalidState)?;

            let token_id = self.next_token;
            self.next_token = self.next_token.wrapping_add(1);

            prefilled.push(id);
            restored_inflight[id as usize] = Some((
                Token(token_id, id),
                Inflight {
                    readables: SmallVec::new(),
                    writables: {
                        let mut writables = SmallVec::<[Allocation; 1]>::new();
                        writables.push(Allocation {
                            addr,
                            len: slot_size,
                        });
                        writables
                    },
                },
            ));
        }

        self.inner.reset_prefilled(&prefilled);

        let addrs: SmallVec<[u64; 64]> = (0..prefill_count)
            .map(|i| self.pool.slot_addr(i).ok_or(VirtqError::InvalidState))
            .collect::<Result<_, _>>()?;

        self.pool
            .restore_allocated(&addrs)
            .map_err(|_| VirtqError::InvalidState)?;
        self.inflight = restored_inflight;

        debug_assert!(
            self.inner.num_inflight() == prefill_count,
            "restore_from_ring: expected {} inflight entries, found {}",
            prefill_count,
            self.inner.num_inflight()
        );

        Ok(())
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
    readable_caps: SmallVec<[usize; 2]>,
    writable_caps: SmallVec<[usize; 1]>,
}

impl<M: MemOps, P: BufferProvider + Clone> ChainBuilder<M, P> {
    fn new(mem: M, pool: P) -> Self {
        Self {
            mem,
            pool,
            readable_caps: SmallVec::new(),
            writable_caps: SmallVec::new(),
        }
    }

    fn alloc(&self, size: usize) -> Result<PoolAlloc<P>, VirtqError> {
        Ok(PoolAlloc::allocate(self.pool.clone(), size)?)
    }

    /// Request a device-readable buffer of `cap` bytes.
    ///
    /// The producer writes data into readable buffers before submission; the
    /// consumer reads that data after polling the chain.
    /// The actual allocation is deferred to [`build`](Self::build).
    pub fn readable(mut self, cap: usize) -> Self {
        self.readable_caps.push(cap);
        self
    }

    /// Request a device-writable buffer of `cap` bytes.
    ///
    /// The writable buffer is filled by the consumer and returned via
    /// [`VirtqProducer::poll`] as [`RecvCompletion`].
    ///
    /// The current producer completion type exposes a single contiguous
    /// [`Bytes`], so producer-built chains support at most one writable buffer
    /// until completions grow a segmented shape.
    pub fn writable(mut self, cap: usize) -> Self {
        self.writable_caps.push(cap);
        self
    }

    /// Allocate buffers and return a [`SendEntry`] for writing.
    ///
    /// # Errors
    ///
    /// - [`VirtqError::InvalidState`] - No buffers requested
    /// - [`VirtqError::UnsupportedChain`] - More than one writable buffer requested
    /// - [`VirtqError::Alloc`] - Pool exhausted
    pub fn build(self) -> Result<SendEntry<M, P>, VirtqError> {
        if self.readable_caps.is_empty() && self.writable_caps.is_empty() {
            return Err(VirtqError::InvalidState);
        }

        if self.writable_caps.len() > 1 {
            return Err(VirtqError::UnsupportedChain);
        }

        let mut readable_allocs = SmallVec::<[PoolAlloc<P>; 2]>::new();
        for &cap in &self.readable_caps {
            readable_allocs.push(self.alloc(cap)?);
        }

        let mut writable_allocs = SmallVec::<[PoolAlloc<P>; 1]>::new();
        for &cap in &self.writable_caps {
            writable_allocs.push(self.alloc(cap)?);
        }

        let readables = readable_allocs
            .into_iter()
            .map(|alloc| ReadableAlloc {
                alloc: alloc.into_raw(),
                written: 0,
            })
            .collect();
        let writables = writable_allocs
            .into_iter()
            .map(PoolAlloc::into_raw)
            .collect();

        let inflight = Inflight {
            readables,
            writables,
        };

        Ok(SendEntry {
            mem: self.mem,
            pool: self.pool,
            inflight: Some(inflight),
        })
    }
}

/// A configured entry ready for writing and submission.
///
/// Created by [`ChainBuilder::build`]. Write data into readable buffers
/// with [`write_all`](Self::write_all),
/// or use [`readable_buf_mut`](Self::readable_buf_mut) for zero-copy direct access.
/// Then submit via [`VirtqProducer::submit`].
///
/// # Examples
///
/// ```ignore
/// let mut se = producer.chain().readable(64).writable(128).build()?;
/// se.write_all(b"header")?;
/// se.write_all(b" body")?;
/// let tok = producer.submit(se)?;
///
/// // Zero-copy direct access
/// let mut se = producer.chain().readable(128).build()?;
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
    inflight: Option<Inflight>,
}

impl<M: MemOps, P: BufferProvider> SendEntry<M, P> {
    fn inflight(&self) -> Result<&Inflight, VirtqError> {
        self.inflight.as_ref().ok_or(VirtqError::InvalidState)
    }

    fn inflight_mut(&mut self) -> Result<&mut Inflight, VirtqError> {
        self.inflight.as_mut().ok_or(VirtqError::InvalidState)
    }

    fn readable(&self, index: usize) -> Result<ReadableAlloc, VirtqError> {
        self.inflight()?
            .readables
            .get(index)
            .copied()
            .ok_or(VirtqError::NoReadableBuffer)
    }

    /// Number of device-readable buffers in this chain.
    pub fn readable_count(&self) -> usize {
        self.inflight
            .as_ref()
            .map_or(0, |inflight| inflight.readables.len())
    }

    /// Number of device-writable buffers in this chain.
    pub fn writable_count(&self) -> usize {
        self.inflight
            .as_ref()
            .map_or(0, |inflight| inflight.writables.len())
    }

    /// Capacity of a specific device-readable buffer.
    pub fn readable_capacity(&self, index: usize) -> Option<usize> {
        self.inflight
            .as_ref()
            .and_then(|inflight| inflight.readables.get(index))
            .map(|readable| readable.alloc.len)
    }

    /// Number of bytes written into a specific device-readable buffer.
    pub fn readable_written(&self, index: usize) -> Option<usize> {
        self.inflight
            .as_ref()
            .and_then(|inflight| inflight.readables.get(index))
            .map(|readable| readable.written)
    }

    /// Total device-readable capacity in bytes.
    ///
    /// Returns 0 when there are no readable buffers.
    pub fn capacity(&self) -> usize {
        self.inflight.as_ref().map_or(0, |inflight| {
            inflight.readables.iter().map(|r| r.alloc.len).sum()
        })
    }

    /// Number of readable bytes written so far via [`write_all`](Self::write_all)
    /// or [`set_written`](Self::set_written).
    pub fn written(&self) -> usize {
        self.inflight.as_ref().map_or(0, |inflight| {
            inflight.readables.iter().map(|r| r.written).sum()
        })
    }

    /// Set the aggregate readable write cursor to an explicit byte count.
    ///
    /// Bytes are assigned greedily across readable buffers in chain order. Use
    /// [`set_readable_written`](Self::set_readable_written) when writing
    /// individual readable buffers directly.
    ///
    /// Setting a value smaller than the current aggregate written length
    /// truncates the submitted readable length; bytes beyond the new length may
    /// remain in shared memory, but they will not be exposed through the
    /// descriptor chain.
    ///
    /// # Errors
    ///
    /// - [`VirtqError::EntryTooLarge`] - `written` exceeds readable buffer capacity
    pub fn set_written(&mut self, written: usize) -> Result<(), VirtqError> {
        if written > self.capacity() {
            return Err(VirtqError::EntryTooLarge);
        }

        let mut remaining = written;
        for readable in &mut self.inflight_mut()?.readables {
            readable.written = remaining.min(readable.alloc.len);
            remaining -= readable.written;
        }
        Ok(())
    }

    /// Set the readable byte count for a specific device-readable buffer.
    ///
    /// # Errors
    ///
    /// - [`VirtqError::NoReadableBuffer`] - `index` does not name a readable buffer
    /// - [`VirtqError::EntryTooLarge`] - `written` exceeds that buffer's capacity
    pub fn set_readable_written(&mut self, index: usize, written: usize) -> Result<(), VirtqError> {
        let readable = self
            .inflight_mut()?
            .readables
            .get_mut(index)
            .ok_or(VirtqError::NoReadableBuffer)?;
        if written > readable.alloc.len {
            return Err(VirtqError::EntryTooLarge);
        }

        readable.written = written;
        Ok(())
    }

    /// Remaining capacity across all readable buffers.
    pub fn remaining(&self) -> usize {
        self.capacity() - self.written()
    }

    /// Write the entire buffer into readable buffers.
    ///
    /// Appends at the current aggregate write position and scatters across
    /// readable buffers in chain order. Uses [`MemOps::write`] (volatile on
    /// host side).
    ///
    /// # Errors
    ///
    /// - [`VirtqError::EntryTooLarge`] - buf exceeds remaining capacity
    /// - [`VirtqError::NoReadableBuffer`] - no readable buffer allocated
    /// - [`VirtqError::MemoryWriteError`] - underlying write failed
    pub fn write_all(&mut self, buf: &[u8]) -> Result<(), VirtqError> {
        if self.readable_count() == 0 {
            return Err(VirtqError::NoReadableBuffer);
        }
        if buf.len() > self.remaining() {
            return Err(VirtqError::EntryTooLarge);
        }

        let Self { mem, inflight, .. } = self;
        let inflight = inflight.as_mut().ok_or(VirtqError::InvalidState)?;
        let mut remaining = buf;

        for readable in &mut inflight.readables {
            if remaining.is_empty() {
                break;
            }

            let free = readable.alloc.len - readable.written;
            if free == 0 {
                continue;
            }

            let n = free.min(remaining.len());
            let addr = readable.alloc.addr + readable.written as u64;
            mem.write(addr, &remaining[..n])
                .map_err(|_| VirtqError::MemoryWriteError)?;

            readable.written += n;
            remaining = &remaining[n..];
        }
        Ok(())
    }

    /// Zero-copy access to a specific readable buffer in shared memory.
    ///
    /// Returns `&mut [u8]` pointing directly into the allocated buffer. After
    /// writing, call [`set_readable_written`](Self::set_readable_written) to
    /// record how many bytes are valid.
    ///
    /// # Errors
    ///
    /// - [`VirtqError::NoReadableBuffer`] - `index` does not name a readable buffer
    /// - [`VirtqError::MemoryWriteError`] - failed to access shared memory
    pub fn readable_buf_mut(&mut self, index: usize) -> Result<&mut [u8], VirtqError> {
        let alloc = self.readable(index)?.alloc;
        unsafe {
            self.mem
                .as_mut_slice(alloc.addr, alloc.len)
                .map_err(|_| VirtqError::MemoryWriteError)
        }
    }

    /// Zero-copy access to the only readable buffer in shared memory.
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
    /// - [`VirtqError::NoReadableBuffer`] - no readable buffer allocated
    /// - [`VirtqError::UnsupportedChain`] - the chain has more than one readable buffer
    /// - [`VirtqError::MemoryWriteError`] - failed to access shared memory
    pub fn buf_mut(&mut self) -> Result<&mut [u8], VirtqError> {
        match self.readable_count() {
            0 => Err(VirtqError::NoReadableBuffer),
            1 => self.readable_buf_mut(0),
            _ => Err(VirtqError::UnsupportedChain),
        }
    }
}

impl<M: MemOps, P: BufferProvider> Drop for SendEntry<M, P> {
    fn drop(&mut self) {
        let inf = match self.inflight.take() {
            Some(i) => i,
            None => return, // already submitted
        };
        for readable in inf.readables {
            let _ = self.pool.dealloc(readable.alloc);
        }
        for writable in inf.writables {
            let _ = self.pool.dealloc(writable);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtq::ring::tests::{OwnedRing, TestMem, make_consumer, make_producer, make_ring};
    use crate::virtq::test_utils::*;

    type RecycleProducer = VirtqProducer<TestMem, TestNotifier, RecyclePool>;

    const SLOT_SIZE: usize = 4096;

    fn make_recycle_producer(ring: &OwnedRing, slot_count: usize) -> RecycleProducer {
        let layout = ring.layout();
        let mem = ring.mem();
        let pool = make_pool(ring, slot_count);
        let notifier = TestNotifier::new();

        VirtqProducer::new(layout, mem, notifier, pool)
    }

    fn make_pool(ring: &OwnedRing, slot_count: usize) -> RecyclePool {
        let mem = ring.mem();
        let pool_base = mem.base_addr() + Layout::query_size(ring.len()) as u64 + 0x100;
        RecyclePool::new(pool_base, slot_count * SLOT_SIZE, SLOT_SIZE).unwrap()
    }

    #[derive(Clone)]
    struct NoDirectSliceMem(TestMem);

    // SAFETY: Delegates all non-slice memory operations to TestMem. Direct
    // slices are intentionally unsupported to exercise producer error handling.
    unsafe impl MemOps for NoDirectSliceMem {
        type Error = ();

        fn read(&self, addr: u64, dst: &mut [u8]) -> Result<(), Self::Error> {
            self.0.read(addr, dst).map_err(|e| match e {})
        }

        fn write(&self, addr: u64, src: &[u8]) -> Result<(), Self::Error> {
            self.0.write(addr, src).map_err(|e| match e {})
        }

        fn load_acquire(&self, addr: u64) -> Result<u16, Self::Error> {
            self.0.load_acquire(addr).map_err(|e| match e {})
        }

        fn store_release(&self, addr: u64, val: u16) -> Result<(), Self::Error> {
            self.0.store_release(addr, val).map_err(|e| match e {})
        }

        unsafe fn as_slice(&self, _addr: u64, _len: usize) -> Result<&[u8], Self::Error> {
            Err(())
        }

        unsafe fn as_mut_slice(&self, _addr: u64, _len: usize) -> Result<&mut [u8], Self::Error> {
            Err(())
        }
    }

    #[test]
    fn test_chain_readwrite_build() {
        let ring = make_ring(16);
        let (producer, _consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().readable(64).writable(128).build().unwrap();
        assert_eq!(se.capacity(), 64);
        assert_eq!(se.written(), 0);
        assert_eq!(se.remaining(), 64);
    }

    #[test]
    fn test_chain_readable_writable_names_build() {
        let ring = make_ring(16);
        let (producer, _consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().readable(16).writable(32).build().unwrap();
        assert_eq!(se.readable_count(), 1);
        assert_eq!(se.writable_count(), 1);
        assert_eq!(se.readable_capacity(0), Some(16));
        assert_eq!(se.capacity(), 16);
    }

    #[test]
    fn test_chain_multi_readable_write_all_scatters() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer
            .chain()
            .readable(5)
            .readable(6)
            .writable(32)
            .build()
            .unwrap();
        se.write_all(b"hello world").unwrap();

        assert_eq!(se.written(), 11);
        assert_eq!(se.readable_written(0), Some(5));
        assert_eq!(se.readable_written(1), Some(6));

        let token = producer.submit(se).unwrap();
        let (entry, completion) = consumer.poll(1024).unwrap().unwrap();
        assert_eq!(entry.token(), token);
        assert_eq!(entry.data().as_ref(), b"hello world");
        consumer.complete(completion).unwrap();
    }

    #[test]
    fn test_chain_multi_readable_direct_segments() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().readable(4).readable(4).build().unwrap();
        se.readable_buf_mut(0).unwrap().copy_from_slice(b"head");
        se.set_readable_written(0, 4).unwrap();
        se.readable_buf_mut(1).unwrap().copy_from_slice(b"body");
        se.set_readable_written(1, 4).unwrap();

        assert!(matches!(se.buf_mut(), Err(VirtqError::UnsupportedChain)));

        producer.submit(se).unwrap();
        let (entry, completion) = consumer.poll(1024).unwrap().unwrap();
        assert_eq!(entry.data().as_ref(), b"headbody");
        consumer.complete(completion).unwrap();
    }

    #[test]
    fn test_chain_rejects_multi_writable_until_completion_is_segmented() {
        let ring = make_ring(16);
        let (producer, _consumer, _notifier) = make_test_producer(&ring);

        let result = producer.chain().writable(16).writable(16).build();
        assert!(matches!(result, Err(VirtqError::UnsupportedChain)));
    }

    #[test]
    fn test_chain_entry_only_build() {
        let ring = make_ring(16);
        let (producer, _consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().readable(32).build().unwrap();
        assert_eq!(se.capacity(), 32);
    }

    #[test]
    fn test_chain_completion_only_build() {
        let ring = make_ring(16);
        let (producer, _consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().writable(64).build().unwrap();
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

        let mut se = producer.chain().readable(64).writable(128).build().unwrap();

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

        let mut se = producer.chain().readable(64).writable(128).build().unwrap();
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

        let mut se = producer.chain().readable(4).build().unwrap();
        let err = se.write_all(b"too long").unwrap_err();
        assert!(matches!(err, VirtqError::EntryTooLarge));
    }

    #[test]
    fn test_writeonly_has_no_entry_buffer() {
        let ring = make_ring(16);
        let (producer, _consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().writable(32).build().unwrap();
        let err = se.write_all(b"data").unwrap_err();
        assert!(matches!(err, VirtqError::NoReadableBuffer));
    }

    #[test]
    fn test_drop_chain_builder_deallocs() {
        let ring = make_ring(16);
        let (mut producer, _consumer, _notifier) = make_test_producer(&ring);

        {
            let _builder = producer.chain().readable(64).writable(128);
            // dropped without build
        }

        // Ring should still be fully usable
        let se = producer.chain().readable(64).writable(128).build().unwrap();
        let tok = producer.submit(se).unwrap();
        assert!(tok.1 < 16);
    }

    #[test]
    fn test_drop_send_entry_deallocs() {
        let ring = make_ring(16);
        let (mut producer, _consumer, _notifier) = make_test_producer(&ring);

        {
            let _se = producer.chain().readable(64).writable(128).build().unwrap();
            // dropped without submit
        }

        // Ring should still be fully usable
        let se = producer.chain().readable(64).writable(128).build().unwrap();
        let tok = producer.submit(se).unwrap();
        assert!(tok.1 < 16);
    }

    #[test]
    fn test_submit_notifies() {
        let ring = make_ring(16);
        let (mut producer, _consumer, notifier) = make_test_producer(&ring);

        let initial_count = notifier.notification_count();

        let mut se = producer.chain().readable(64).writable(128).build().unwrap();
        se.write_all(b"hello").unwrap();
        producer.submit(se).unwrap();

        assert!(notifier.notification_count() > initial_count);
    }

    #[test]
    fn test_submit_read_only_notifies_by_default() {
        let ring = make_ring(16);
        let (mut producer, _consumer, notifier) = make_test_producer(&ring);

        let initial_count = notifier.notification_count();

        let mut se = producer.chain().readable(64).build().unwrap();
        se.write_all(b"fire-and-forget").unwrap();
        producer.submit(se).unwrap();

        assert!(notifier.notification_count() > initial_count);
    }

    #[test]
    fn test_submit_write_only_notifies_by_default() {
        let ring = make_ring(16);
        let (mut producer, _consumer, notifier) = make_test_producer(&ring);

        let initial_count = notifier.notification_count();

        let se = producer.chain().writable(128).build().unwrap();
        producer.submit(se).unwrap();

        assert!(notifier.notification_count() > initial_count);
    }

    #[test]
    fn test_batch_notifies_once_on_finish() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, notifier) = make_test_producer(&ring);

        let initial_count = notifier.notification_count();

        let mut batch = producer.batch();

        let mut first = batch.chain().readable(64).build().unwrap();
        first.write_all(b"first").unwrap();
        batch.submit(first).unwrap();

        let mut second = batch.chain().readable(64).build().unwrap();
        second.write_all(b"second").unwrap();
        batch.submit(second).unwrap();

        assert_eq!(notifier.notification_count(), initial_count);
        assert!(batch.finish().unwrap());
        assert_eq!(notifier.notification_count(), initial_count + 1);

        let (entry, completion) = consumer.poll(1024).unwrap().unwrap();
        assert_eq!(entry.data().as_ref(), b"first");
        consumer.complete(completion).unwrap();

        let (entry, completion) = consumer.poll(1024).unwrap().unwrap();
        assert_eq!(entry.data().as_ref(), b"second");
        consumer.complete(completion).unwrap();
    }

    #[test]
    fn test_batch_finish_notifies_from_batch_start_cursor() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, notifier) = make_test_producer(&ring);

        let cursor = consumer.avail_cursor();
        consumer
            .set_avail_suppression(SuppressionKind::Descriptor(cursor))
            .unwrap();

        let mut batch = producer.batch();

        let mut first = batch.chain().readable(64).build().unwrap();
        first.write_all(b"first").unwrap();
        batch.submit(first).unwrap();
        assert_eq!(notifier.notification_count(), 0);

        let mut second = batch.chain().readable(64).writable(64).build().unwrap();
        second.write_all(b"second").unwrap();
        batch.submit(second).unwrap();

        assert!(batch.finish().unwrap());

        assert_eq!(notifier.notification_count(), 1);
    }

    #[test]
    fn test_empty_batch_finish_does_not_notify() {
        let ring = make_ring(16);
        let (mut producer, _consumer, notifier) = make_test_producer(&ring);

        let batch = producer.batch();
        assert!(!batch.finish().unwrap());
        assert_eq!(notifier.notification_count(), 0);
    }

    #[test]
    fn test_set_written_too_large() {
        let ring = make_ring(16);
        let (producer, _consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().readable(32).writable(64).build().unwrap();
        let err = se.set_written(64).unwrap_err();
        assert!(matches!(err, VirtqError::EntryTooLarge));
    }

    #[test]
    fn test_write_only_round_trip() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().writable(32).build().unwrap();
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
        assert_eq!(cqe.token(), token);
        assert_eq!(cqe.data().unwrap().len(), b"filled-by-consumer".len());
        assert_eq!(cqe.data().unwrap().as_ref(), b"filled-by-consumer");
    }

    #[test]
    fn test_read_only_round_trip() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().readable(32).build().unwrap();
        se.write_all(b"fire-and-forget").unwrap();
        let token = producer.submit(se).unwrap();

        let (entry, completion) = consumer.poll(1024).unwrap().unwrap();
        assert_eq!(entry.token(), token);
        assert_eq!(entry.data().as_ref(), b"fire-and-forget");
        assert!(matches!(completion, SendCompletion::Ack(_)));
        consumer.complete(completion).unwrap();

        let cqe = producer.poll().unwrap().unwrap();
        assert!(matches!(cqe, RecvCompletion::Ack(t) if t == token));
    }

    #[test]
    fn test_readwrite_round_trip() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().readable(64).writable(128).build().unwrap();
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
        assert_eq!(cqe.token(), token);
        assert_eq!(cqe.data().unwrap().as_ref(), b"response data");
    }

    #[test]
    fn test_poll_completion_requires_direct_slice() {
        let ring = make_ring(16);
        let layout = ring.layout();
        let test_mem = ring.mem();
        let pool_base = test_mem.base_addr() + Layout::query_size(ring.len()) as u64 + 0x100;
        let pool = TestPool::new(pool_base, 0x8000);
        let notifier = TestNotifier::new();
        let mem = NoDirectSliceMem(test_mem);
        let mut producer = VirtqProducer::new(layout, mem.clone(), notifier.clone(), pool);
        let mut consumer = VirtqConsumer::new(layout, mem, notifier);

        let mut se = producer.chain().readable(64).writable(128).build().unwrap();
        se.write_all(b"request data").unwrap();
        producer.submit(se).unwrap();

        let (_entry, completion) = consumer.poll(1024).unwrap().unwrap();
        if let SendCompletion::Writable(mut wc) = completion {
            wc.write_all(b"response data").unwrap();
            consumer.complete(wc.into()).unwrap();
        } else {
            panic!("expected Writable");
        }

        assert!(matches!(producer.poll(), Err(VirtqError::MemoryReadError)));
    }

    #[test]
    fn test_virtq_producer_reset() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        // Submit and complete a round trip
        let mut se = producer.chain().readable(32).writable(64).build().unwrap();
        se.write_all(b"hello").unwrap();
        producer.submit(se).unwrap();

        let (entry, completion) = consumer.poll(1024).unwrap().unwrap();
        assert_eq!(entry.data().as_ref(), b"hello");
        consumer.complete(completion).unwrap();
        let _ = producer.poll().unwrap().unwrap();

        // Now reset
        producer.reset();

        // All inflight slots should be cleared
        assert_eq!(producer.inner.num_inflight(), 0);
        // Ring state should be back to initial
        assert_eq!(producer.inner.num_free(), producer.inner.len());
    }

    #[test]
    fn test_virtq_producer_reset_clears_inflight() {
        let ring = make_ring(16);
        let (mut producer, _consumer, _notifier) = make_test_producer(&ring);

        // Submit without completing
        let se = producer.chain().writable(64).build().unwrap();
        producer.submit(se).unwrap();

        assert_eq!(producer.inner.num_inflight(), 1);

        producer.reset();

        assert_eq!(producer.inner.num_inflight(), 0);
        assert_eq!(producer.inner.num_free(), producer.inner.len());
    }

    #[test]
    fn test_restore_from_ring_requires_full_prefill() {
        let ring = make_ring(8);
        let mut producer = make_recycle_producer(&ring, 8);

        // Ring has no prefilled descriptors - restore should fail
        // because IDs read from zeroed memory will all be 0 (duplicate)
        assert!(producer.restore_from_ring(make_pool(&ring, 8)).is_err());
    }

    #[test]
    fn test_restore_from_ring_partial_prefill_fails() {
        let ring = make_ring(8);
        let producer = make_recycle_producer(&ring, 8);
        let pool_base = producer.pool.base_addr();

        // Simulate host prefill: write only one descriptor
        let mut writer = make_producer(&ring);
        writer
            .submit_one(pool_base, SLOT_SIZE as u32, true)
            .unwrap();

        // Restore should fail because only 1 of 8 positions has a
        // valid unique ID - remaining positions have id=0 (duplicate)
        let mut restored = make_recycle_producer(&ring, 8);
        assert!(restored.restore_from_ring(make_pool(&ring, 8)).is_err());
    }

    #[test]
    fn test_restore_from_ring_full_prefill() {
        let depth = 8usize;
        let ring = make_ring(depth);
        let producer = make_recycle_producer(&ring, depth);
        let pool_base = producer.pool.base_addr();

        // Simulate host prefill: write all descriptors
        let mut writer = make_producer(&ring);
        for i in 0..depth {
            let addr = pool_base + (i * SLOT_SIZE) as u64;
            writer.submit_one(addr, SLOT_SIZE as u32, true).unwrap();
        }

        let mut restored = make_recycle_producer(&ring, depth);
        restored.restore_from_ring(make_pool(&ring, depth)).unwrap();

        // All inflight slots should be populated
        assert_eq!(restored.inner.num_inflight(), depth);

        // Pool should be fully allocated
        assert_eq!(restored.pool.num_free(), 0);
    }

    #[test]
    fn test_restore_from_ring_forward_order() {
        let depth = 4usize;
        let ring = make_ring(depth);
        let producer = make_recycle_producer(&ring, depth);
        let pool_base = producer.pool.base_addr();

        // Forward order prefill
        let mut writer = make_producer(&ring);
        for i in 0..depth {
            writer
                .submit_one(pool_base + (i * SLOT_SIZE) as u64, SLOT_SIZE as u32, true)
                .unwrap();
        }

        let mut restored = make_recycle_producer(&ring, depth);
        restored.restore_from_ring(make_pool(&ring, depth)).unwrap();
    }

    #[test]
    fn test_restore_from_ring_reverse_order() {
        let depth = 4usize;
        let ring = make_ring(depth);
        let producer = make_recycle_producer(&ring, depth);
        let pool_base = producer.pool.base_addr();

        // Reverse order prefill (current host behavior)
        let mut writer = make_producer(&ring);
        for i in (0..depth).rev() {
            writer
                .submit_one(pool_base + (i * SLOT_SIZE) as u64, SLOT_SIZE as u32, true)
                .unwrap();
        }

        let mut restored = make_recycle_producer(&ring, depth);
        restored.restore_from_ring(make_pool(&ring, depth)).unwrap();
    }

    #[test]
    fn test_restore_from_ring_pool_state_correct() {
        let depth = 8usize;
        let ring = make_ring(depth);
        let producer = make_recycle_producer(&ring, depth);
        let pool_base = producer.pool.base_addr();

        // Full prefill
        let mut writer = make_producer(&ring);
        for i in 0..depth {
            writer
                .submit_one(pool_base + (i * SLOT_SIZE) as u64, SLOT_SIZE as u32, true)
                .unwrap();
        }

        let mut restored = make_recycle_producer(&ring, depth);
        restored.restore_from_ring(make_pool(&ring, depth)).unwrap();
        // All slots are allocated after full-prefill restore
        assert_eq!(restored.pool.num_free(), 0);
    }

    #[test]
    fn test_restore_from_ring_idempotent() {
        let depth = 4usize;
        let ring = make_ring(depth);
        let producer = make_recycle_producer(&ring, depth);
        let pool_base = producer.pool.base_addr();

        let mut writer = make_producer(&ring);
        for i in 0..depth {
            writer
                .submit_one(pool_base + (i * SLOT_SIZE) as u64, SLOT_SIZE as u32, true)
                .unwrap();
        }

        let mut restored = make_recycle_producer(&ring, depth);
        restored.restore_from_ring(make_pool(&ring, depth)).unwrap();
        restored.restore_from_ring(make_pool(&ring, depth)).unwrap();
        assert_eq!(restored.pool.num_free(), 0);
    }

    #[test]
    fn test_restore_from_ring_then_poll_used() {
        let depth = 4usize;
        let ring = make_ring(depth);
        let producer = make_recycle_producer(&ring, depth);
        let pool_base = producer.pool.base_addr();

        // Simulate host prefill
        let mut writer = make_producer(&ring);
        for i in 0..depth {
            writer
                .submit_one(pool_base + (i * SLOT_SIZE) as u64, SLOT_SIZE as u32, true)
                .unwrap();
        }

        // Restore producer and use ring-level consumer to complete one entry
        let mut restored = make_recycle_producer(&ring, depth);
        restored.restore_from_ring(make_pool(&ring, depth)).unwrap();

        // Ring-level consumer reads available descriptors
        let mut consumer = make_consumer(&ring);
        let (id, chain) = consumer.poll_available().unwrap();
        let writable = chain.writables();
        assert_eq!(writable.len(), 1);

        // Write some data into the writable buffer
        let payload = b"test payload";
        consumer.mem().write(writable[0].addr, payload).unwrap();
        consumer.submit_used(id, payload.len() as u32).unwrap();

        // Producer polls for the completion
        let cqe = restored.poll().unwrap().unwrap();
        assert_eq!(&cqe.data().unwrap()[..payload.len()], payload);

        // Pool slot should be returned after data is dropped
        drop(cqe);
        assert_eq!(restored.pool.num_free(), 1);
    }
}
