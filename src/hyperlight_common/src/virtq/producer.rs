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

/// A used chain observed by the driver (producer) side.
///
/// Read-only chains are returned as [`Ack`](Self::Ack). Chains with a writable
/// buffer complete as [`Data`](Self::Data), even when the device wrote zero
/// bytes. Non-empty segments in [`Data`](Self::Data) are backed by
/// shared-memory pool allocations that are returned when the last clone is
/// dropped.
#[derive(Debug)]
pub enum UsedChain {
    /// Acknowledgement for a read-only/fire-and-forget chain.
    Ack(Token),
    /// Data written by the consumer into the chain's writable buffers.
    ///
    /// The payload may contain zero bytes when the consumer writes zero bytes;
    /// that is still a data used chain because the submitted chain had
    /// writable capacity.
    Data(Token, Segments),
}

impl UsedChain {
    /// Token identifying which submitted chain this used chain corresponds to.
    pub fn token(&self) -> Token {
        match self {
            Self::Ack(token) | Self::Data(token, _) => *token,
        }
    }

    /// Data written by the consumer as contiguous bytes, if this chain has data.
    pub fn to_bytes(&self) -> Option<Bytes> {
        match self {
            Self::Ack(_) => None,
            Self::Data(_, segments) => Some(segments.to_bytes()),
        }
    }

    /// Segments written by the consumer, if this chain has data.
    pub fn segments(&self) -> Option<&Segments> {
        match self {
            Self::Ack(_) => None,
            Self::Data(_, segments) => Some(segments),
        }
    }

    /// Consume the used chain and return written data as contiguous bytes, if present.
    pub fn into_bytes(self) -> Option<Bytes> {
        match self {
            Self::Ack(_) => None,
            Self::Data(_, segments) => Some(segments.into_bytes()),
        }
    }

    /// Consume the used chain and return written segments, if present.
    pub fn into_segments(self) -> Option<Segments> {
        match self {
            Self::Ack(_) => None,
            Self::Data(_, segments) => Some(segments),
        }
    }
}

/// Allocation tracking for an in-flight descriptor chain.
///
/// Descriptor lengths have already been published to the ring, so in-flight
/// state only needs the completion token and allocation ownership for later
/// reclaim.
#[derive(Debug)]
pub(crate) struct Inflight {
    token: Token,
    chain: BufferChain,
}

/// A high-level virtqueue producer (driver side).
///
/// The producer sends chains to the consumer (device), and receives used chains.
/// This is used on the driver/guest side.
///
/// # Threading
///
/// The producer is intended for single-threaded, guest-side use. Reply payloads
/// are exposed as zero-copy [`Bytes`] via [`Bytes::from_owner`](bytes::Bytes::from_owner),
/// which requires the owning pool to be `Send + Sync`. Do not move the producer
/// or its replies across threads, and do not instantiate it on the multi-threaded
/// host with those pools.
///
/// # Example
///
/// ```ignore
/// let mut producer = VirtqProducer::new(layout, mem, notifier, pool);
///
/// // Build and submit a chain
/// let mut chain = producer.chain().readable(64).writable(64).build()?;
/// chain.write_all(b"hello")?;
/// let token = producer.submit(chain)?;
///
/// // Later, poll for the used chain
/// if let Some(used) = producer.poll()? {
///     assert_eq!(used.token(), token);
///     match used {
///         UsedChain::Data(_, segments) => println!("Got used chain: {:?}", segments),
///         UsedChain::Ack(_) => println!("Got ack"),
///     }
/// }
/// ```
pub struct VirtqProducer<M, N, P> {
    inner: RingProducer<M>,
    notifier: N,
    pool: P,
    next_token: u32,
    inflight: Vec<Option<Inflight>>,
    pending: VecDeque<UsedChain>,
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
    /// * `notifier` - Callback for notifying the device (consumer) about new chains
    /// * `pool` - Buffer allocator for chain payload and reply data
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

    fn dealloc_elems(
        &self,
        elems: impl IntoIterator<Item = BufferElement>,
    ) -> Result<(), VirtqError> {
        let mut first_err = None;
        for elem in elems {
            if let Err(err) = self.pool.dealloc(elem.addr)
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

    /// Begin building a descriptor chain for submission.
    ///
    /// Returns a [`ChainBuilder`] that allocates buffers from the pool.
    pub fn chain(&self) -> ChainBuilder<M, P> {
        ChainBuilder::new(self.inner.mem().clone(), self.pool.clone())
    }

    /// Begin a batch of submissions.
    ///
    /// Chains submitted through the returned [`SubmitBatch`] are published to
    /// the ring immediately, but the consumer is notified at most once when
    /// [`SubmitBatch::finish`] is called. This mirrors the virtio pattern of
    /// adding multiple buffers and then kicking the queue once.
    pub fn batch(&mut self) -> SubmitBatch<'_, M, N, P> {
        SubmitBatch::new(self)
    }

    /// Submit a [`SendChain`] to the ring.
    ///
    /// Publishes the descriptor chain, stores the in-flight tracking state,
    /// and notifies the consumer if event suppression allows. Notifications
    /// are layout-neutral; use [`batch`](Self::batch) when a higher-level
    /// protocol wants to publish multiple chains and kick once.
    ///
    /// # Errors
    ///
    /// - [`VirtqError::PayloadTooLarge`] - written exceeds readable buffer capacity
    /// - [`VirtqError::RingError`] - ring is full
    /// - [`VirtqError::InvalidState`] - descriptor ID collision
    pub fn submit(&mut self, chain: SendChain<M, P>) -> Result<Token, VirtqError> {
        let cursor_before = self.inner.avail_cursor();
        let token = self.publish(chain)?;
        self.notify_since(cursor_before)?;
        Ok(token)
    }

    fn publish(&mut self, send: SendChain<M, P>) -> Result<Token, VirtqError> {
        let token_id = self.next_token;
        let id = self.inner.submit_available(send.chain())?;
        let token = Token { seq: token_id, id };

        // A free descriptor id must never already be tracked as inflight.
        if self.inflight[id as usize].is_some() {
            return Err(VirtqError::InvalidState);
        }

        let inf = send.into_inflight(token);
        self.inflight[id as usize] = Some(inf);
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
    /// # Example: Used-chain batching
    ///
    /// ```ignore
    /// // Submit chains, then suppress notifications until all are used
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
    /// No outstanding [`UsedChain::Data`] buffers, borrowed segment views, or
    /// peer accesses to previously submitted descriptors may exist. Resetting
    /// recycles the same backing addresses, so outstanding zero-copy buffers or
    /// stale descriptor users could alias memory that is handed out again.
    ///
    /// TODO(virtq): find a way to allow guest to keep used chains across resets.
    pub unsafe fn reset(&mut self) {
        self.inflight.iter_mut().for_each(|slot| *slot = None);
        self.pending.clear();
        self.inner.reset();
        self.pool.reset();
    }

    /// Replace the pool and reset ring, inflight, and pending state.
    ///
    /// # Safety
    ///
    /// No outstanding [`UsedChain::Data`] buffers, borrowed segment views, or
    /// peer accesses to previously submitted descriptors may exist. The new pool
    /// may manage the same shared-memory addresses as the old pool, so old
    /// zero-copy buffers must not outlive this transition.
    pub unsafe fn reset_with_pool(&mut self, pool: P) {
        self.pending.clear();
        self.inflight.iter_mut().for_each(|slot| *slot = None);
        self.inner.reset();
        self.pool = pool;
        self.pool.reset();
    }
}

impl<M, N, P> VirtqProducer<M, N, P>
where
    M: MemOps + Clone + Send + 'static,
    N: Notifier,
    P: BufferProvider + Clone + Send + 'static,
{
    /// Poll for a single used chain from the device.
    ///
    /// Returns buffered used chains from prior [`reclaim`](Self::reclaim)
    /// calls first, then checks the ring for newly used chains.
    ///
    /// Returns `Ok(Some(used))` if a used chain is available, `Ok(None)` if no
    /// used chains are ready (would block), or an error if the device misbehaved.
    ///
    /// Data used chains contain zero-copy [`Bytes`] backed by the shared-memory
    /// allocation via [`BufferOwner`]. The pool allocation is held alive as long
    /// as any `Bytes` clone exists, and is returned to the pool when the last
    /// clone is dropped.
    ///
    /// # Errors
    ///
    /// - [`VirtqError::InvalidState`] - Device returned invalid descriptor ID or
    ///   wrote more data than the writable buffer capacity
    pub fn poll(&mut self) -> Result<Option<UsedChain>, VirtqError> {
        if let Some(chain) = self.pending.pop_front() {
            return Ok(Some(chain));
        }
        self.poll_ring()
    }

    /// Reclaim ring slots and pool allocations from used descriptors.
    ///
    /// Processes all available used chains from the ring: frees readable
    /// buffer allocations immediately, and buffers writable data for
    /// later retrieval via [`poll`](Self::poll).
    ///
    /// Read-only ack used chains are discarded immediately.
    ///
    /// Use this to free resources under backpressure without losing
    /// writable data. Returns the number of chains reclaimed.
    pub fn reclaim(&mut self) -> Result<usize, VirtqError> {
        let mut count = 0;
        while let Some(chain) = self.poll_ring()? {
            if matches!(chain, UsedChain::Data(_, _)) {
                debug_assert!(self.pending.len() < self.inner.len());
                self.pending.push_back(chain);
            }
            count += 1;
        }
        Ok(count)
    }

    /// Poll one used chain directly from the ring (bypassing pending buffer).
    fn poll_ring(&mut self) -> Result<Option<UsedChain>, VirtqError> {
        let used = match self.inner.poll_used() {
            Ok(u) => u,
            Err(RingError::WouldBlock) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let inf = self
            .inflight
            .get_mut(used.id as usize)
            .and_then(Option::take)
            .ok_or(VirtqError::InvalidState)?;

        let written = used.len as usize;
        let Inflight { token, chain } = inf;

        self.dealloc_elems(chain.readables().iter().copied())?;

        let used = if chain.writables().is_empty() {
            UsedChain::Ack(token)
        } else {
            UsedChain::Data(token, self.recv_segments(chain.writables(), written)?)
        };

        Ok(Some(used))
    }

    fn recv_segments(
        &self,
        writables: &[BufferElement],
        written: usize,
    ) -> Result<Segments, VirtqError> {
        let mut owned = SmallVec::<[(BufferElement, usize); 4]>::new();
        let mut free = SmallVec::<[BufferElement; 4]>::new();
        let mut remaining = written;

        for &alloc in writables {
            if remaining == 0 {
                free.push(alloc);
                continue;
            }

            let len = remaining.min(alloc.len as usize);
            owned.push((alloc, len));
            remaining -= len;
        }

        if remaining != 0 {
            let elems = owned.iter().map(|(elem, _)| *elem).chain(free);
            self.dealloc_elems(elems)?;
            return Err(VirtqError::InvalidState);
        }

        for (elem, len) in &owned {
            if unsafe { self.inner.mem().as_slice(elem.addr, *len) }.is_err() {
                let elems = owned.iter().map(|(elem, _)| *elem).chain(free);
                let _ = self.dealloc_elems(elems);
                return Err(VirtqError::MemoryReadError);
            }
        }

        let mut sgs = SmallVec::<[Bytes; 4]>::new();
        for (elem, written) in owned {
            let alloc = OwnedAlloc::new(
                self.pool.clone(),
                Allocation {
                    addr: elem.addr,
                    len: elem.len as usize,
                },
            );
            let mem = self.inner.mem().clone();
            let owner = BufferOwner {
                alloc,
                mem,
                written,
            };
            sgs.push(Bytes::from_owner(owner));
        }

        self.dealloc_elems(free)?;

        Ok(Segments::from_smallvec(sgs))
    }

    /// Drain all available used chains, calling the provided closure for each.
    ///
    /// This is a convenience method that repeatedly calls [`poll`](Self::poll)
    /// until no more used chains are available.
    ///
    /// # Arguments
    ///
    /// * `f` - Closure called for each used chain
    ///
    /// # Example
    ///
    /// ```ignore
    /// producer.drain(|used| {
    ///     println!("Got used chain for {:?}", used.token());
    /// })?;
    /// ```
    pub fn drain(&mut self, mut f: impl FnMut(UsedChain)) -> Result<(), VirtqError> {
        while let Some(chain) = self.poll()? {
            f(chain);
        }

        Ok(())
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

    /// Publish a chain as part of this batch without notifying yet.
    pub fn submit(&mut self, chain: SendChain<M, P>) -> Result<Token, VirtqError> {
        let cursor_before = self.producer.inner.avail_cursor();
        let token = self.producer.publish(chain)?;

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

/// Builder for configuring a descriptor chain's buffer layout.
///
/// If dropped without building, no resources are leaked (allocations are
/// deferred to [`build`](Self::build)).
#[must_use = "call .build() to create a SendChain"]
pub struct ChainBuilder<M: MemOps, P: BufferProvider + Clone> {
    mem: M,
    pool: P,
    rd_caps: SmallVec<[usize; 4]>,
    wr_caps: SmallVec<[usize; 4]>,
}

impl<M: MemOps, P: BufferProvider + Clone> ChainBuilder<M, P> {
    fn new(mem: M, pool: P) -> Self {
        Self {
            mem,
            pool,
            rd_caps: SmallVec::new(),
            wr_caps: SmallVec::new(),
        }
    }

    /// Request a device-readable buffer of `cap` bytes.
    ///
    /// The producer writes data into readable buffers before submission; the
    /// consumer reads that data after polling the chain.
    /// The actual allocation is deferred to [`build`](Self::build).
    pub fn readable(mut self, cap: usize) -> Self {
        self.rd_caps.push(cap);
        self
    }

    /// Request a device-writable buffer of `cap` bytes.
    ///
    /// The writable buffer is filled by the consumer and returned via
    /// [`VirtqProducer::poll`] as [`UsedChain`].
    ///
    /// Multiple writable buffers are completed as ordered [`Segments`]. The
    /// consumer writes them sequentially, because the virtio used ring reports
    /// one aggregate written length rather than per-descriptor lengths.
    pub fn writable(mut self, cap: usize) -> Self {
        self.wr_caps.push(cap);
        self
    }

    /// Allocate buffers and return a [`SendChain`] for writing.
    ///
    /// # Errors
    ///
    /// - [`VirtqError::InvalidState`] - No buffers requested
    /// - [`VirtqError::Alloc`] - Pool exhausted
    pub fn build(self) -> Result<SendChain<M, P>, VirtqError> {
        if self.rd_caps.is_empty() && self.wr_caps.is_empty() {
            return Err(VirtqError::InvalidState);
        }

        let mut rollback = Rollback::new(&self.pool);
        let mut rd_caps = SmallVec::<[usize; 4]>::new();
        let mut rd_elems = SmallVec::<[BufferElement; 4]>::new();
        let mut wr_elems = SmallVec::<[BufferElement; 4]>::new();

        // Allocate readable buffers, splitting into multiple descriptors if needed.
        // The buffer element lengths are initialized to zero and updated as the
        // `SendChain` writes.
        for &cap in &self.rd_caps {
            let sgs = self.pool.alloc_sg(cap)?;
            let mut remaining = cap;

            for alloc in sgs {
                let _ = checked_descriptor_len(alloc.len)?;
                let seg_cap = remaining.min(alloc.len);

                rd_caps.push(seg_cap);
                rd_elems.push(BufferElement {
                    addr: alloc.addr,
                    len: 0,
                    writable: false,
                });
                remaining -= seg_cap;
                rollback.allocs.push(alloc);
            }

            if remaining != 0 {
                return Err(VirtqError::InvalidState);
            }
        }

        // Allocate writable buffers, with the same caveat about splitting as readable buffers.
        // Writable buffer elements are initialized with their full capacity for the device to
        // write into.
        for &cap in &self.wr_caps {
            let sgs = self.pool.alloc_sg(cap)?;
            for alloc in sgs {
                let len = checked_descriptor_len(alloc.len)?;
                wr_elems.push(BufferElement {
                    addr: alloc.addr,
                    len,
                    writable: true,
                });
                rollback.allocs.push(alloc);
            }
        }

        let chain = BufferChainBuilder::new()
            .readables(rd_elems)
            .writables(wr_elems)
            .build()?;

        rollback.release();

        Ok(SendChain {
            mem: self.mem,
            pool: self.pool,
            chain: Some(chain),
            rd_caps,
            rd_capacity: self.rd_caps.iter().sum(),
            rd_written: 0,
            write_mode: WriteMode::Unset,
        })
    }
}

struct Rollback<'a, P: BufferProvider> {
    pool: &'a P,
    allocs: SmallVec<[Allocation; 8]>,
}

impl<'a, P: BufferProvider> Rollback<'a, P> {
    fn new(pool: &'a P) -> Self {
        Self {
            pool,
            allocs: SmallVec::new(),
        }
    }

    fn release(mut self) {
        self.allocs.clear();
    }
}

impl<P: BufferProvider> Drop for Rollback<'_, P> {
    fn drop(&mut self) {
        for alloc in self.allocs.drain(..) {
            let result = self.pool.dealloc(alloc.addr);
            debug_assert!(result.is_ok(), "rollback dealloc failed: {result:?}");
        }
    }
}

/// Tracks which write API a [`SendChain`] payload uses, so the two paths are
/// not mixed.
///
/// Copy writes ([`SendChain::write`]/[`SendChain::write_all`]) append at an
/// aggregate cursor, while direct writes
/// ([`SendChain::write_seg`]/[`SendChain::with_seg`]) set per-segment lengths
/// absolutely. Mixing them would corrupt the written-length accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteMode {
    Unset,
    Append,
    Direct,
}

/// A configured send chain ready for writing and submission.
///
/// Created by [`ChainBuilder::build`]. Write readable payload bytes directly on
/// the chain, then submit via [`VirtqProducer::submit`].
///
/// # Examples
///
/// ```ignore
/// let mut sc = producer.chain().readable(64).writable(128).build()?;
/// sc.write_all(b"header")?.write_all(b" body")?;
/// let tok = producer.submit(sc)?;
///
/// let mut sc = producer.chain().readable(128).build()?;
/// sc.with_seg(0, |buf| serialize_into(buf))?;
/// let tok = producer.submit(sc)?;
/// ```
///
/// Copy writes (`write`/`write_all`) and direct writes (`write_seg`/`with_seg`)
/// must not be mixed on the same chain; doing so panics in debug builds.
///
/// If dropped without submitting, allocated buffers are returned to the pool.
#[must_use = "dropping without submitting deallocates the buffers"]
pub struct SendChain<M: MemOps, P: BufferProvider> {
    mem: M,
    pool: P,
    chain: Option<BufferChain>,
    rd_caps: SmallVec<[usize; 4]>,
    rd_capacity: usize,
    rd_written: usize,
    write_mode: WriteMode,
}

// `chain` is wrapped in `Option` only so `into_inflight` can `take()` it
// without moving out of this `Drop` type; it stays `Some` for a chain's whole
// public lifetime, so these `expect`s cannot fail.
#[allow(clippy::expect_used)]
impl<M: MemOps, P: BufferProvider> SendChain<M, P> {
    fn chain(&self) -> &BufferChain {
        self.chain.as_ref().expect("SendChain missing BufferChain")
    }

    fn chain_mut(&mut self) -> &mut BufferChain {
        self.chain.as_mut().expect("SendChain missing BufferChain")
    }

    /// Record that this chain uses `mode`, asserting it is not mixed with the
    /// other write path.
    fn note_write_mode(&mut self, mode: WriteMode) {
        debug_assert!(
            self.write_mode == WriteMode::Unset || self.write_mode == mode,
            "SendChain mixes copy writes (write/write_all) with direct writes (write_seg/with_seg)"
        );
        self.write_mode = mode;
    }

    fn into_inflight(mut self, token: Token) -> Inflight {
        let chain = self.chain.take().expect("SendChain missing BufferChain");
        Inflight { token, chain }
    }

    /// Number of producer-written readable segments in this chain.
    pub fn segment_count(&self) -> usize {
        self.chain().readables().len()
    }

    /// Total producer-written readable capacity in bytes.
    pub fn capacity(&self) -> usize {
        self.rd_capacity
    }

    /// Number of producer-written readable bytes written so far.
    pub fn written(&self) -> usize {
        self.rd_written
    }

    /// Remaining producer-written readable capacity.
    pub fn remaining(&self) -> usize {
        self.capacity() - self.written()
    }

    /// Write bytes into payload segments, returning how many bytes were written.
    ///
    /// Appends at the current aggregate write position and scatters across
    /// readable segments in chain order. Uses [`MemOps::write`] (volatile on
    /// host side). If `buf` is larger than the remaining capacity, writes as
    /// many bytes as will fit.
    ///
    /// # Errors
    ///
    /// - [`VirtqError::NoPayloadSegment`] - no readable buffer allocated
    /// - [`VirtqError::MemoryWriteError`] - underlying write failed
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, VirtqError> {
        if self.segment_count() == 0 {
            return Err(VirtqError::NoPayloadSegment);
        }

        self.note_write_mode(WriteMode::Append);

        let mut remaining = &buf[..buf.len().min(self.remaining())];
        let mut written = 0;

        let SendChain {
            mem,
            chain,
            rd_caps,
            ..
        } = self;

        let readables = chain
            .as_mut()
            .expect("SendChain missing BufferChain")
            .readables_mut();

        for (readable, &cap) in readables.iter_mut().zip(rd_caps.iter()) {
            if remaining.is_empty() {
                break;
            }

            let written_len = readable.len as usize;
            let free = cap - written_len;
            if free == 0 {
                continue;
            }

            let n = free.min(remaining.len());
            let addr = readable.addr + written_len as u64;
            mem.write(addr, &remaining[..n])
                .map_err(|_| VirtqError::MemoryWriteError)?;

            readable.len += n as u32;
            written += n;
            remaining = &remaining[n..];
        }

        self.rd_written += written;
        Ok(written)
    }

    /// Write the entire buffer into payload segments.
    ///
    /// Appends at the current aggregate write position and scatters across
    /// readable segments in chain order. Uses [`MemOps::write`] (volatile on
    /// host side).
    ///
    /// # Errors
    ///
    /// - [`VirtqError::PayloadTooLarge`] - buf exceeds remaining capacity
    /// - [`VirtqError::NoPayloadSegment`] - no readable buffer allocated
    /// - [`VirtqError::MemoryWriteError`] - underlying write failed
    pub fn write_all(&mut self, buf: &[u8]) -> Result<&mut Self, VirtqError> {
        if self.segment_count() == 0 {
            return Err(VirtqError::NoPayloadSegment);
        }

        if buf.len() > self.remaining() {
            return Err(VirtqError::PayloadTooLarge {
                recv: buf.len(),
                limit: self.remaining(),
            });
        }

        let written = self.write(buf)?;
        debug_assert_eq!(written, buf.len());
        Ok(self)
    }

    /// Write bytes into one readable segment by index.
    ///
    /// Writes from the start of the selected segment and records `buf.len()` as
    /// that segment's descriptor length.
    ///
    /// # Errors
    ///
    /// - [`VirtqError::NoPayloadSegment`] - `index` does not name a payload segment
    /// - [`VirtqError::PayloadTooLarge`] - `buf` exceeds the segment capacity
    /// - [`VirtqError::MemoryWriteError`] - underlying write failed
    pub fn write_seg(&mut self, index: usize, buf: &[u8]) -> Result<&mut Self, VirtqError> {
        self.note_write_mode(WriteMode::Direct);

        let cap = *self
            .rd_caps
            .get(index)
            .ok_or(VirtqError::NoPayloadSegment)?;

        if buf.len() > cap {
            return Err(VirtqError::PayloadTooLarge {
                recv: buf.len(),
                limit: cap,
            });
        }

        let addr = self
            .chain()
            .readables()
            .get(index)
            .ok_or(VirtqError::NoPayloadSegment)?
            .addr;

        self.mem
            .write(addr, buf)
            .map_err(|_| VirtqError::MemoryWriteError)?;

        let previous = self.chain().readables()[index].len as usize;
        self.chain_mut().readables_mut()[index].len = checked_descriptor_len(buf.len())?;
        self.rd_written = self.rd_written - previous + buf.len();
        Ok(self)
    }

    /// Serialize directly into one readable segment by index.
    ///
    /// The closure returns the number of valid bytes it wrote. The written
    /// length for that segment is recorded on success.
    ///
    /// # Errors
    ///
    /// - [`VirtqError::NoPayloadSegment`] - `index` does not name a payload segment
    /// - [`VirtqError::PayloadTooLarge`] - closure reports more bytes than segment capacity
    /// - [`VirtqError::MemoryWriteError`] - the memory backend cannot expose a mutable slice
    pub fn with_seg<E>(
        &mut self,
        index: usize,
        f: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Result<&mut Self, E>
    where
        E: From<VirtqError>,
    {
        self.note_write_mode(WriteMode::Direct);

        let cap = *self
            .rd_caps
            .get(index)
            .ok_or_else(|| E::from(VirtqError::NoPayloadSegment))?;

        let addr = self
            .chain()
            .readables()
            .get(index)
            .ok_or_else(|| E::from(VirtqError::NoPayloadSegment))?
            .addr;

        let buf = unsafe {
            self.mem
                .as_mut_slice(addr, cap)
                .map_err(|_| E::from(VirtqError::MemoryWriteError))?
        };

        let written = f(buf)?;
        if written > buf.len() {
            return Err(E::from(VirtqError::PayloadTooLarge {
                recv: written,
                limit: buf.len(),
            }));
        }

        let previous = self.chain().readables()[index].len as usize;
        // SAFETY: index was validated by the earlier get() call, so the readable element exists.
        self.chain_mut().readables_mut()[index].len =
            checked_descriptor_len(written).map_err(E::from)?;
        self.rd_written = self.rd_written - previous + written;

        Ok(self)
    }
}

impl<M: MemOps, P: BufferProvider> Drop for SendChain<M, P> {
    fn drop(&mut self) {
        if let Some(chain) = self.chain.take() {
            for elem in chain.elems() {
                let result = self.pool.dealloc(elem.addr);
                debug_assert!(result.is_ok(), "SendChain drop dealloc failed: {result:?}");
            }
        }
    }
}

fn checked_descriptor_len(len: usize) -> Result<u32, VirtqError> {
    if len > u32::MAX as usize {
        return Err(VirtqError::PayloadTooLarge {
            recv: len,
            limit: u32::MAX as usize,
        });
    }
    Ok(len as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtq::ring::tests::{TestMem, make_ring};
    use crate::virtq::test_utils::*;

    fn poll_received<M: MemOps + Clone, N: Notifier>(
        consumer: &mut VirtqConsumer<M, N>,
    ) -> (RecvChain, ReplyChain<M>) {
        consumer.poll(1024).unwrap().unwrap()
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
        assert_eq!(se.segment_count(), 1);
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

        let token = producer.submit(se).unwrap();
        let (recv, reply) = poll_received(&mut consumer);
        assert_eq!(recv.token(), token);
        assert_eq!(recv.to_bytes().as_ref(), b"hello world");
        assert_eq!(recv.segments().segment_count(), 2);
        assert_eq!(recv.segments().as_slice()[0].as_ref(), b"hello");
        assert_eq!(recv.segments().as_slice()[1].as_ref(), b" world");
        consumer.complete(reply).unwrap();
    }

    #[test]
    fn test_chain_readable_splits_logical_capacity() {
        let ring = make_ring(16);
        let layout = ring.layout();
        let mem = ring.mem();
        let pool_base = mem.base_addr() + Layout::query_size(ring.len()) as u64 + 0x100;
        let pool = TestPool::new_with_max_alloc_len(pool_base, 0x8000, 4);
        let notifier = TestNotifier::new();
        let mut producer = VirtqProducer::new(layout, mem.clone(), notifier.clone(), pool);
        let mut consumer = VirtqConsumer::new(layout, mem, notifier);

        let mut se = producer.chain().readable(10).writable(32).build().unwrap();

        assert_eq!(se.segment_count(), 3);
        assert_eq!(se.capacity(), 10);

        se.write_all(b"abcdefghij").unwrap();
        assert_eq!(se.written(), 10);

        let token = producer.submit(se).unwrap();
        let (recv, reply) = poll_received(&mut consumer);
        assert_eq!(recv.token(), token);
        assert_eq!(recv.to_bytes().as_ref(), b"abcdefghij");
        assert_eq!(recv.segments().segment_count(), 3);
        assert_eq!(recv.segments().as_slice()[0].as_ref(), b"abcd");
        assert_eq!(recv.segments().as_slice()[1].as_ref(), b"efgh");
        assert_eq!(recv.segments().as_slice()[2].as_ref(), b"ij");
        consumer.complete(reply).unwrap();
    }

    #[test]
    fn test_chain_readable_rejects_zero_capacity_on_build() {
        let ring = make_ring(16);
        let (producer, _consumer, _notifier) = make_test_producer(&ring);

        assert!(matches!(
            producer.chain().readable(0).build(),
            Err(VirtqError::Alloc(AllocError::InvalidArg))
        ));
    }

    #[test]
    fn test_chain_writable_splits_logical_capacity() {
        let ring = make_ring(16);
        let layout = ring.layout();
        let mem = ring.mem();
        let pool_base = mem.base_addr() + Layout::query_size(ring.len()) as u64 + 0x100;
        let pool = TestPool::new_with_max_alloc_len(pool_base, 0x8000, 4);
        let notifier = TestNotifier::new();
        let mut producer = VirtqProducer::new(layout, mem.clone(), notifier.clone(), pool);
        let mut consumer = VirtqConsumer::new(layout, mem, notifier);

        let se = producer.chain().writable(10).build().unwrap();
        let token = producer.submit(se).unwrap();

        let (_recv, reply) = poll_received(&mut consumer);
        let ReplyChain::Writable(mut wc) = reply else {
            panic!("expected writable reply");
        };
        assert_eq!(wc.capacity(), 10);

        wc.write_all(b"abcdefghij").unwrap();
        consumer.complete(wc).unwrap();

        let used = producer.poll().unwrap().unwrap();
        assert_eq!(used.token(), token);
        let segments = used.segments().unwrap();
        assert_eq!(segments.segment_count(), 3);
        assert_eq!(segments.as_slice()[0].as_ref(), b"abcd");
        assert_eq!(segments.as_slice()[1].as_ref(), b"efgh");
        assert_eq!(segments.as_slice()[2].as_ref(), b"ij");
    }

    #[test]
    fn test_chain_writable_rejects_zero_capacity_on_build() {
        let ring = make_ring(16);
        let (producer, _consumer, _notifier) = make_test_producer(&ring);

        assert!(matches!(
            producer.chain().writable(0).build(),
            Err(VirtqError::Alloc(AllocError::InvalidArg))
        ));
    }

    #[test]
    fn test_chain_multi_readable_write_all_preserves_segments() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().readable(4).readable(4).build().unwrap();
        se.write_all(b"headbody").unwrap();

        producer.submit(se).unwrap();
        let (recv, reply) = poll_received(&mut consumer);
        assert_eq!(recv.to_bytes().as_ref(), b"headbody");
        consumer.complete(reply).unwrap();
    }

    #[test]
    fn test_chain_payload_segment_writer_serializes_directly() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().readable(4).readable(4).build().unwrap();
        se.with_seg(0, |segment| {
            segment.copy_from_slice(b"head");
            Ok::<usize, VirtqError>(4)
        })
        .unwrap();
        se.with_seg(1, |segment| {
            segment.copy_from_slice(b"body");
            Ok::<usize, VirtqError>(4)
        })
        .unwrap();

        producer.submit(se).unwrap();
        let (recv, reply) = poll_received(&mut consumer);
        assert_eq!(recv.to_bytes().as_ref(), b"headbody");
        assert_eq!(recv.segments().segment_count(), 2);
        consumer.complete(reply).unwrap();
    }

    #[test]
    fn test_chain_payload_segment_write_copies_directly() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().readable(4).readable(4).build().unwrap();
        se.write_seg(0, b"head").unwrap();
        se.write_seg(1, b"body").unwrap();

        producer.submit(se).unwrap();
        let (recv, reply) = poll_received(&mut consumer);
        assert_eq!(recv.to_bytes().as_ref(), b"headbody");
        assert_eq!(recv.segments().segment_count(), 2);
        consumer.complete(reply).unwrap();
    }

    #[test]
    fn test_chain_multi_writable_used_returns_segments() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().writable(5).writable(6).build().unwrap();
        let token = producer.submit(se).unwrap();

        let (_recv, reply) = poll_received(&mut consumer);
        let ReplyChain::Writable(mut wc) = reply else {
            panic!("expected writable reply");
        };
        assert_eq!(wc.capacity(), 11);

        wc.write_all(b"hello world").unwrap();
        consumer.complete(wc).unwrap();

        let used = producer.poll().unwrap().unwrap();
        assert_eq!(used.token(), token);
        let segments = used.segments().unwrap();
        assert_eq!(segments.segment_count(), 2);
        assert_eq!(segments.as_slice()[0].as_ref(), b"hello");
        assert_eq!(segments.as_slice()[1].as_ref(), b" world");
        assert_eq!(segments.to_bytes().as_ref(), b"hello world");
    }

    #[test]
    fn test_chain_multi_writable_short_used_truncates_last_segment() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().writable(5).writable(6).build().unwrap();
        producer.submit(se).unwrap();

        let (_recv, reply) = poll_received(&mut consumer);
        let ReplyChain::Writable(mut wc) = reply else {
            panic!("expected writable reply");
        };

        wc.write_all(b"hello wo").unwrap();
        consumer.complete(wc).unwrap();

        let used = producer.poll().unwrap().unwrap();
        let segments = used.segments().unwrap();
        assert_eq!(segments.segment_count(), 2);
        assert_eq!(segments.as_slice()[0].as_ref(), b"hello");
        assert_eq!(segments.as_slice()[1].as_ref(), b" wo");
        assert_eq!(segments.to_bytes().as_ref(), b"hello wo");
    }

    #[test]
    fn test_chain_multi_writable_zero_used_returns_empty_segments() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().writable(5).writable(6).build().unwrap();
        producer.submit(se).unwrap();

        let (_recv, reply) = poll_received(&mut consumer);
        consumer.complete(reply).unwrap();

        let used = producer.poll().unwrap().unwrap();
        let segments = used.segments().unwrap();
        assert_eq!(segments.segment_count(), 0);
        assert!(segments.is_empty());
        assert!(segments.to_bytes().is_empty());
    }

    #[test]
    fn test_chain_readable_only_build() {
        let ring = make_ring(16);
        let (producer, _consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().readable(32).build().unwrap();
        assert_eq!(se.capacity(), 32);
    }

    #[test]
    fn test_chain_writable_only_build() {
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
    fn test_send_chain_write_all_and_submit() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().readable(64).writable(128).build().unwrap();

        se.write_all(b"hello")
            .unwrap()
            .write_all(b" world")
            .unwrap();
        assert_eq!(se.written(), 11);
        assert_eq!(se.remaining(), 53);
        let tok = producer.submit(se).unwrap();

        let (recv, reply) = poll_received(&mut consumer);
        assert_eq!(recv.token(), tok);
        assert_eq!(recv.to_bytes().as_ref(), b"hello world");
        consumer.complete(reply).unwrap();
    }

    #[test]
    fn test_send_payload_write_all_fluent() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().readable(64).writable(128).build().unwrap();
        se.write_all(b"hello")
            .unwrap()
            .write_all(b" world")
            .unwrap();
        assert_eq!(se.written(), 11);
        assert_eq!(se.remaining(), 53);
        let tok = producer.submit(se).unwrap();

        let (recv, reply) = poll_received(&mut consumer);
        assert_eq!(recv.token(), tok);
        assert_eq!(recv.to_bytes().as_ref(), b"hello world");
        consumer.complete(reply).unwrap();
    }

    #[test]
    fn test_send_payload_partial_write() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().readable(8).build().unwrap();
        let written = se.write(b"hello world").unwrap();
        assert_eq!(written, 8);
        assert_eq!(se.remaining(), 0);

        producer.submit(se).unwrap();
        let (recv, reply) = poll_received(&mut consumer);
        assert_eq!(recv.to_bytes().as_ref(), b"hello wo");
        consumer.complete(reply).unwrap();
    }

    #[test]
    fn test_send_payload_write_with_serializes_directly() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().readable(64).writable(128).build().unwrap();
        se.with_seg(0, |buf| {
            buf[..5].copy_from_slice(b"hello");
            Ok::<usize, VirtqError>(5)
        })
        .unwrap();

        let _tok = producer.submit(se).unwrap();

        let (recv, reply) = poll_received(&mut consumer);
        assert_eq!(recv.to_bytes().as_ref(), b"hello");
        consumer.complete(reply).unwrap();
    }

    #[test]
    fn test_send_chain_single_segment_writer_serializes_directly() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().readable(64).writable(128).build().unwrap();
        se.with_seg(0, |segment| {
            assert_eq!(segment.len(), 64);
            segment[..5].copy_from_slice(b"hello");
            Ok::<usize, VirtqError>(5)
        })
        .unwrap();

        let _tok = producer.submit(se).unwrap();

        let (recv, reply) = poll_received(&mut consumer);
        assert_eq!(recv.to_bytes().as_ref(), b"hello");
        consumer.complete(reply).unwrap();
    }

    #[test]
    fn test_send_chain_single_segment_writer_rejects_multi_segment() {
        let ring = make_ring(16);
        let (producer, _consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().readable(4).readable(4).build().unwrap();
        assert!(matches!(
            se.with_seg(2, |_| Ok::<usize, VirtqError>(0)),
            Err(VirtqError::NoPayloadSegment)
        ));
    }

    #[test]
    fn test_send_chain_single_segment_writer_rejects_auto_split_chain() {
        let ring = make_ring(16);
        let layout = ring.layout();
        let mem = ring.mem();
        let pool_base = mem.base_addr() + Layout::query_size(ring.len()) as u64 + 0x100;
        let pool = TestPool::new_with_max_alloc_len(pool_base, 0x8000, 4);
        let notifier = TestNotifier::new();
        let producer = VirtqProducer::new(layout, mem, notifier, pool);

        let mut se = producer.chain().readable(8).build().unwrap();
        assert_eq!(se.segment_count(), 2);
        assert!(matches!(
            se.with_seg(2, |_| Ok::<usize, VirtqError>(0)),
            Err(VirtqError::NoPayloadSegment)
        ));
    }

    #[test]
    fn test_send_payload_segment_set_written_too_large() {
        let ring = make_ring(16);
        let (producer, _consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().readable(32).writable(64).build().unwrap();
        let err = se
            .with_seg(0, |_| Ok::<usize, VirtqError>(64))
            .err()
            .unwrap();
        assert!(matches!(
            err,
            VirtqError::PayloadTooLarge {
                recv: 64,
                limit: 32
            }
        ));
    }

    #[test]
    fn test_send_chain_write_too_large() {
        let ring = make_ring(16);
        let (producer, _consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().readable(4).build().unwrap();
        let err = se.write_all(b"too long").err().unwrap();
        assert!(matches!(
            err,
            VirtqError::PayloadTooLarge { recv: 8, limit: 4 }
        ));
    }

    #[test]
    fn test_writeonly_has_no_readable_buffer() {
        let ring = make_ring(16);
        let (producer, _consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().writable(32).build().unwrap();
        let err = se.write_all(b"data").err().unwrap();
        assert!(matches!(err, VirtqError::NoPayloadSegment));
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
        assert!(tok.id < 16);
    }

    #[test]
    fn test_drop_send_chain_deallocs() {
        let ring = make_ring(16);
        let (mut producer, _consumer, _notifier) = make_test_producer(&ring);

        {
            let _se = producer.chain().readable(64).writable(128).build().unwrap();
            // dropped without submit
        }

        // Ring should still be fully usable
        let se = producer.chain().readable(64).writable(128).build().unwrap();
        let tok = producer.submit(se).unwrap();
        assert!(tok.id < 16);
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

        let (recv, reply) = poll_received(&mut consumer);
        assert_eq!(recv.to_bytes().as_ref(), b"first");
        consumer.complete(reply).unwrap();

        let (recv, reply) = poll_received(&mut consumer);
        assert_eq!(recv.to_bytes().as_ref(), b"second");
        consumer.complete(reply).unwrap();
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
    fn test_write_only_round_trip() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().writable(32).build().unwrap();
        let token = producer.submit(se).unwrap();

        let (recv, reply) = poll_received(&mut consumer);
        assert_eq!(recv.token(), token);
        assert!(recv.to_bytes().is_empty());

        if let ReplyChain::Writable(mut wc) = reply {
            wc.write_all(b"filled-by-consumer").unwrap();
            consumer.complete(wc).unwrap();
        } else {
            panic!("expected Writable");
        }

        let used = producer.poll().unwrap().unwrap();
        assert_eq!(used.token(), token);
        assert_eq!(used.to_bytes().unwrap().len(), b"filled-by-consumer".len());
        assert_eq!(used.to_bytes().unwrap().as_ref(), b"filled-by-consumer");
    }

    #[test]
    fn test_read_only_round_trip() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().readable(32).build().unwrap();
        se.write_all(b"fire-and-forget").unwrap();
        let token = producer.submit(se).unwrap();

        let (recv, reply) = poll_received(&mut consumer);
        assert_eq!(recv.token(), token);
        assert_eq!(recv.to_bytes().as_ref(), b"fire-and-forget");
        assert!(matches!(reply, ReplyChain::Ack(_)));
        consumer.complete(reply).unwrap();

        let used = producer.poll().unwrap().unwrap();
        assert!(matches!(used, UsedChain::Ack(t) if t == token));
    }

    #[test]
    fn test_readwrite_round_trip() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let mut se = producer.chain().readable(64).writable(128).build().unwrap();
        se.write_all(b"request data").unwrap();
        let token = producer.submit(se).unwrap();

        let (recv, reply) = poll_received(&mut consumer);
        assert_eq!(recv.to_bytes().as_ref(), b"request data");
        if let ReplyChain::Writable(mut wc) = reply {
            wc.write_all(b"response data").unwrap();
            consumer.complete(wc).unwrap();
        } else {
            panic!("expected Writable");
        }

        let used = producer.poll().unwrap().unwrap();
        assert_eq!(used.token(), token);
        assert_eq!(used.to_bytes().unwrap().as_ref(), b"response data");
    }

    #[test]
    fn test_poll_used_requires_direct_slice() {
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

        let (_recv, reply) = poll_received(&mut consumer);
        if let ReplyChain::Writable(mut wc) = reply {
            wc.write_all(b"response data").unwrap();
            consumer.complete(wc).unwrap();
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

        let (recv, reply) = poll_received(&mut consumer);
        assert_eq!(recv.to_bytes().as_ref(), b"hello");
        consumer.complete(reply).unwrap();
        let _ = producer.poll().unwrap().unwrap();

        // Now reset
        // SAFETY: the used chain was dropped before reset and no peer can
        // access the reset test ring concurrently.
        unsafe {
            producer.reset();
        }

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

        // SAFETY: no peer can access the reset test ring concurrently.
        unsafe {
            producer.reset();
        }

        assert_eq!(producer.inner.num_inflight(), 0);
        assert_eq!(producer.inner.num_free(), producer.inner.len());
    }
}
