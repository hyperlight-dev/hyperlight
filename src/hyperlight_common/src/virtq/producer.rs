// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::ManuallyDrop;

use bytes::Bytes;
use smallvec::SmallVec;

use super::*;

/// A used chain observed by the driver (producer) side.
///
/// Read-only chains are returned as [`Ack`](Self::Ack). Chains with a writable
/// buffer complete as [`Data`](Self::Data), even when the device wrote zero
/// bytes. Non-empty segments use backend-owned mappings. Borrowed mappings
/// keep their pool slots allocated until the last [`Bytes`] owner drops.
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

struct Inflight<M> {
    token: Token,
    // Automatic cleanup could recycle buffers still accessible to the peer.
    // Only completion or a stopped reset permits releasing this owner.
    chain: ManuallyDrop<OwnedChain<M>>,
}

/// Compact in-flight chains with constant-time descriptor-ID lookup.
///
/// Descriptor IDs span the full ring, but live chains are normally bounded by
/// the much smaller buffer pool. `by_id` maps each descriptor ID to a packed
/// `live` index. Removal uses `swap_remove` and repairs the moved entry's map.
struct InflightTable<M> {
    by_id: Vec<u16>,
    live: Vec<Inflight<M>>,
}

impl<M> InflightTable<M> {
    const VACANT: u16 = u16::MAX;

    fn new(ring_len: usize) -> Self {
        Self {
            by_id: vec![Self::VACANT; ring_len],
            live: Vec::new(),
        }
    }

    fn try_reserve_one(&mut self) -> Result<(), VirtqError> {
        if self.live.len() > self.by_id.len() {
            return Err(VirtqError::InvalidState);
        }

        if self.live.len() == self.by_id.len() {
            return Err(VirtqError::Backpressure);
        }

        // Producers with one live chain should not pay for four large inline
        // chain records.
        let result = if self.live.capacity() == 0 {
            self.live.try_reserve_exact(1)
        } else {
            self.live.try_reserve(1)
        };

        result.map_err(|_| VirtqError::Bookkeeping)
    }

    fn contains(&self, id: u16) -> bool {
        self.by_id
            .get(id as usize)
            .is_some_and(|slot| *slot != Self::VACANT)
    }

    fn insert(&mut self, inflight: Inflight<M>) {
        let id = inflight.token.id;
        debug_assert!(!self.contains(id));
        debug_assert!(self.live.len() < Self::VACANT as usize);

        let slot = self.live.len() as u16;
        self.live.push(inflight);
        self.by_id[id as usize] = slot;
    }

    fn remove(&mut self, id: u16) -> Option<Inflight<M>> {
        let slot = self.by_id.get_mut(id as usize)?;
        if *slot == Self::VACANT {
            return None;
        }

        let index = usize::from(*slot);
        *slot = Self::VACANT;

        let removed = self.live.swap_remove(index);
        if let Some(moved) = self.live.get(index) {
            self.by_id[moved.token.id as usize] = index as u16;
        }

        Some(removed)
    }

    fn pop(&mut self) -> Option<Inflight<M>> {
        let inflight = self.live.pop()?;
        self.by_id[inflight.token.id as usize] = Self::VACANT;
        Some(inflight)
    }
}

/// A high-level virtqueue producer (driver side).
///
/// The producer sends chains to the consumer (device), and receives used chains.
/// This is used on the driver/guest side.
///
/// # Threading
///
/// The producer and its pool use single-threaded allocation state.
/// [`BufferMap`] supplies the complete `Send` owner for returned [`Bytes`].
///
/// # Cleanup
///
/// Dropping a producer does not stop its peer, so inflight owners are
/// deliberately leaked to avoid freeing buffers the peer may still use.
/// Drain completions for all submitted chains, or stop the peer and call
/// [`reset`](Self::reset), before dropping the producer.
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
pub struct VirtqProducer<M, N> {
    inner: RingProducer<M>,
    notifier: N,
    pool: SlotPool,
    next_token: u32,
    inflight: InflightTable<M>,
    pending: VecDeque<UsedChain>,
}

impl<M, N> VirtqProducer<M, N>
where
    M: MemOps + Clone,
    N: Notifier,
{
    /// Create a new virtqueue producer.
    ///
    /// # Arguments
    ///
    /// * `layout` - Ring memory layout (descriptor table and event suppression addresses)
    /// * `mem` - Memory operations implementation for reading/writing to shared memory
    /// * `notifier` - Callback for notifying the device (consumer) about new chains
    /// * `pool` - Buffer allocator for chain payload and reply data
    pub fn new(layout: Layout, mem: M, notifier: N, pool: SlotPool) -> Self {
        let inner = RingProducer::new(layout, mem);
        let ring_len = inner.len();
        let inflight = InflightTable::new(ring_len);

        Self {
            inner,
            pool,
            notifier,
            inflight,
            next_token: 0,
            pending: VecDeque::new(),
        }
    }

    /// Borrow the pool used for new chains.
    pub fn pool(&self) -> &SlotPool {
        &self.pool
    }

    /// Borrow the backend used for ring access and new chains.
    pub fn memory(&self) -> &M {
        self.inner.mem()
    }

    /// Begin building a descriptor chain for submission.
    ///
    /// The builder captures the current free-descriptor budget.
    /// Submission checks capacity again.
    pub fn chain(&self) -> ChainBuilder<M> {
        ChainBuilder::new(
            self.inner.mem().clone(),
            self.pool.clone(),
            self.inner.num_free(),
        )
    }

    /// Preferred size of one bulk payload segment.
    pub fn preferred_segment_len(&self) -> usize {
        self.pool.slot_size()
    }

    /// Begin a batch of submissions.
    ///
    /// Chains submitted through the returned [`SubmitBatch`] are published to
    /// the ring immediately, but the consumer is notified at most once when
    /// [`SubmitBatch::finish`] is called. This mirrors the virtio pattern of
    /// adding multiple buffers and then kicking the queue once.
    pub fn batch(&mut self) -> SubmitBatch<'_, M, N> {
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
    /// * [`VirtqError::Backpressure`] - ring or in-flight tracking is full
    /// * [`VirtqError::RingError`] - publication or notification memory access failed
    /// * [`VirtqError::InvalidState`] - descriptor ID collision
    pub fn submit(&mut self, chain: SendChain<M>) -> Result<Token, VirtqError> {
        let cursor_before = self.inner.avail_cursor();
        let token = self.publish(chain)?;
        self.notify_since(cursor_before)?;
        Ok(token)
    }

    fn publish(&mut self, send: SendChain<M>) -> Result<Token, VirtqError> {
        self.inflight.try_reserve_one()?;

        if send.desc_count() > self.inner.num_free() {
            return Err(VirtqError::Backpressure);
        }
        let token_id = self.next_token;
        let id = self.inner.next_id()?;
        let token = Token { seq: token_id, id };

        // A free descriptor id must never already be tracked as inflight.
        if self.inflight.contains(id) {
            return Err(VirtqError::InvalidState);
        }

        let mut descriptors = send.owned.descriptors();
        let mut builder = BufferChainBuilder::new();

        builder.reserve_exact(send.desc_count());
        let chain = builder
            .readables(descriptors.by_ref().take(send.rd_desc_count()))
            .writables(descriptors)
            .build()?;

        let published = self.inner.submit_available(&chain);

        // A failed write can still publish descriptors. Keep their allocations
        // until a stopped reset, including when submission reports an error.
        let inf = Inflight {
            token,
            chain: ManuallyDrop::new(send.owned),
        };
        self.inflight.insert(inf);
        self.next_token = self.next_token.wrapping_add(1);

        let published_id = published?;
        debug_assert_eq!(published_id, id);
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

    /// Number of submitted descriptors not yet polled as used.
    #[inline]
    pub fn num_inflight(&self) -> usize {
        self.inner.num_inflight()
    }

    /// Reset a stopped producer and release transport-owned allocations.
    ///
    /// The peer must not access the ring until its consumer is reset. Buffered
    /// writable completions are guest-owned and make this operation fail.
    /// Owner-backed payloads already returned to callers are not tracked as
    /// in-flight and remain allocated.
    pub fn reset(&mut self) -> Result<(), VirtqError> {
        if !self.pending.is_empty() {
            return Err(VirtqError::InvalidState);
        }

        self.inner.reset()?;
        self.next_token = 0;

        let mut maybe_err = None;

        while let Some(inflight) = self.inflight.pop() {
            let ret = ManuallyDrop::into_inner(inflight.chain).release();
            if let Err(err) = ret
                && maybe_err.is_none()
            {
                maybe_err = Some(err);
            }
        }

        match maybe_err {
            Some(error) => Err(error.into()),
            None => Ok(()),
        }
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
}

impl<M, N> VirtqProducer<M, N>
where
    M: BufferMap + Clone,
    N: Notifier,
{
    /// Poll for a single used chain from the device.
    ///
    /// Returns buffered used chains from prior [`reclaim`](Self::reclaim)
    /// calls first, then checks the ring for newly used chains.
    ///
    /// Returns `Ok(Some(used))` if a used chain is available, `Ok(None)` if no
    /// used chains are ready (would block), or an error if the device misbehaved.
    ///
    /// Data used chains contain [`Bytes`] owned by the [`BufferMap`] backend.
    /// Borrowed views retain their pool allocations until the last clone drops.
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
                self.pending
                    .try_reserve(1)
                    .map_err(|_| VirtqError::Bookkeeping)?;
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
            .remove(used.id)
            .ok_or(VirtqError::InvalidState)?;

        let written = used.len as usize;
        let Inflight { token, chain } = inf;

        let chain = ManuallyDrop::into_inner(chain);
        let used = if chain.readable == chain.buffers.len() {
            chain.release()?;
            UsedChain::Ack(token)
        } else {
            UsedChain::Data(token, chain.into_segments(written)?)
        };

        Ok(Some(used))
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
/// [`finish`](Self::finish). [`finish_without_notify`](Self::finish_without_notify)
/// supports protocols whose peer is already scheduled to inspect the queue.
#[must_use = "finish the batch explicitly"]
pub struct SubmitBatch<'a, M, N> {
    producer: &'a mut VirtqProducer<M, N>,
    notify_from: Option<RingCursor>,
}

impl<'a, M, N> SubmitBatch<'a, M, N>
where
    M: MemOps + Clone,
    N: Notifier,
{
    fn new(producer: &'a mut VirtqProducer<M, N>) -> Self {
        Self {
            producer,
            notify_from: None,
        }
    }

    /// Begin building a descriptor chain for this batch.
    pub fn chain(&self) -> ChainBuilder<M> {
        self.producer.chain()
    }

    /// Publish a chain as part of this batch without notifying yet.
    pub fn submit(&mut self, chain: SendChain<M>) -> Result<Token, VirtqError> {
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

    /// Finish the batch without notifying the consumer.
    ///
    /// Use this only when another protocol event guarantees that the consumer
    /// will inspect the published descriptors.
    pub fn finish_without_notify(self) {}
}

/// Builder for configuring a descriptor chain's buffer layout.
///
/// If dropped without building, no resources are leaked (allocations are
/// deferred to [`build`](Self::build)).
#[must_use = "call .build() to create a SendChain"]
pub struct ChainBuilder<M: MemOps> {
    mem: M,
    pool: SlotPool,
    rd_caps: SmallVec<[usize; 4]>,
    wr_caps: SmallVec<[usize; 4]>,
    writable_avail: bool,
    max_descs: usize,
}

impl<M: MemOps> ChainBuilder<M> {
    fn new(mem: M, pool: SlotPool, max_descs: usize) -> Self {
        Self {
            mem,
            pool,
            rd_caps: SmallVec::new(),
            wr_caps: SmallVec::new(),
            writable_avail: false,
            max_descs,
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

    /// Request available upper-tier buffers within the ring budget.
    ///
    /// [`build`](Self::build) allocates these after all explicit requests.
    /// This may add zero buffers. The complete chain must be nonempty.
    pub fn writable_avail(mut self) -> Self {
        self.writable_avail = true;
        self
    }

    /// Allocate buffers and return a [`SendChain`] for writing.
    ///
    /// # Errors
    ///
    /// * [`VirtqError::InvalidState`] - no buffers requested
    /// * [`VirtqError::Backpressure`] - insufficient pool slots or ring descriptors
    /// * [`VirtqError::Bookkeeping`] - buffer record storage allocation failed
    /// * [`VirtqError::Alloc`] - zero-length request or buffer allocation failed
    pub fn build(self) -> Result<SendChain<M>, VirtqError> {
        if self.rd_caps.is_empty() && self.wr_caps.is_empty() && !self.writable_avail {
            return Err(VirtqError::InvalidState);
        }

        // Count explicit descriptors against the captured ring budget.
        let slot_size = self.pool.slot_size();
        let rd_capacity = self.rd_caps.iter().try_fold(0usize, |total, &cap| {
            total.checked_add(cap).ok_or(AllocError::Overflow)
        })?;

        let mut caps = self.rd_caps.iter().chain(&self.wr_caps);
        let desc_count = caps.try_fold(0usize, |total, &cap| {
            if cap == 0 {
                return Err(AllocError::InvalidArg);
            }
            total
                .checked_add(cap.div_ceil(slot_size))
                .ok_or(AllocError::Overflow)
        })?;

        let remaining_descs = self
            .max_descs
            .checked_sub(desc_count)
            .ok_or(VirtqError::Backpressure)?;

        // Reserve explicit records before taking slots. OwnedChain handles rollback.
        let mut buffers = SmallVec::new();
        buffers
            .try_reserve_exact(desc_count)
            .map_err(|_| VirtqError::Bookkeeping)?;

        let mut owned = OwnedChain {
            mem: self.mem,
            pool: self.pool,
            buffers,
            readable: 0,
        };

        // Allocate readable regions before writable ones, splitting each at the upper slot size.
        let regions = self
            .rd_caps
            .iter()
            .map(|&len| (len, false))
            .chain(self.wr_caps.iter().map(|&len| (len, true)));

        for (total_len, wr) in regions {
            let mut remaining = total_len;

            while remaining > 0 {
                let len = remaining.min(slot_size);
                let alloc = owned.pool.alloc(len)?;
                let capacity = if wr { alloc.len } else { len as u32 };

                let ent = BufferEntry {
                    addr: alloc.addr,
                    capacity,
                    written: 0,
                };

                owned.buffers.push(ent);
                owned.readable += usize::from(!wr);

                remaining -= len;
            }
        }

        // Use spare descriptors for upper-tier slots left after the explicit allocations.
        if self.writable_avail {
            let extra = owned.pool.num_free_upper().min(remaining_descs);
            owned
                .buffers
                .try_reserve_exact(extra)
                .map_err(|_| VirtqError::Bookkeeping)?;

            for _ in 0..extra {
                let alloc = owned.pool.alloc(slot_size)?;
                let ent = BufferEntry {
                    addr: alloc.addr,
                    capacity: alloc.len,
                    written: 0,
                };

                owned.buffers.push(ent);
            }
        }

        // An availability-only request can leave no buffers to publish.
        if owned.buffers.is_empty() {
            return Err(VirtqError::Backpressure);
        }

        Ok(SendChain {
            owned,
            rd_capacity,
            rd_written: 0,
            write_mode: WriteMode::Unset,
        })
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
pub struct SendChain<M> {
    owned: OwnedChain<M>,
    rd_capacity: usize,
    rd_written: usize,
    write_mode: WriteMode,
}

impl<M: MemOps> SendChain<M> {
    /// Record that this chain uses `mode`, asserting it is not mixed with the
    /// other write path.
    fn note_write_mode(&mut self, mode: WriteMode) {
        debug_assert!(
            self.write_mode == WriteMode::Unset || self.write_mode == mode,
            "SendChain mixes copy writes (write/write_all) with direct writes (write_seg/with_seg)"
        );
        self.write_mode = mode;
    }

    /// Total number of descriptors in this chain.
    #[inline]
    pub fn desc_count(&self) -> usize {
        self.owned.buffers.len()
    }

    /// Number of readable descriptors in this chain.
    #[inline]
    pub fn rd_desc_count(&self) -> usize {
        self.owned.readable
    }

    /// Number of writable descriptors in this chain.
    #[inline]
    pub fn wr_desc_count(&self) -> usize {
        self.desc_count() - self.rd_desc_count()
    }

    /// Total producer-written readable capacity in bytes.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.rd_capacity
    }

    /// Number of producer-written readable bytes written so far.
    #[inline]
    pub fn written(&self) -> usize {
        self.rd_written
    }

    /// Remaining producer-written readable capacity.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.capacity() - self.written()
    }

    /// Write bytes into payload segments, returning how many bytes were written.
    ///
    /// Appends at the current aggregate write position and scatters across
    /// readable segments in chain order. Uses [`MemOps::write`] (volatile on
    /// host side). If `buf` is larger than the remaining capacity, writes as
    /// many bytes as will fit. If a later memory write fails, the cursor and
    /// written length retain any earlier chunks written by the same call.
    ///
    /// # Errors
    ///
    /// - [`VirtqError::NoPayloadSegment`] - no readable buffer allocated
    /// - [`VirtqError::MemoryWriteError`] - underlying write failed
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, VirtqError> {
        if self.rd_desc_count() == 0 {
            return Err(VirtqError::NoPayloadSegment);
        }

        self.note_write_mode(WriteMode::Append);

        let mut remaining = &buf[..buf.len().min(self.remaining())];
        let mut written = 0;

        for buffer in &mut self.owned.buffers[..self.owned.readable] {
            if remaining.is_empty() {
                break;
            }

            let cap = buffer.capacity as usize;
            let desc_off = buffer.written as usize;
            let len = (cap - desc_off).min(remaining.len());
            if len == 0 {
                continue;
            }

            let addr = buffer
                .addr
                .checked_add(desc_off as u64)
                .ok_or(VirtqError::MemoryWriteError)?;

            self.owned
                .mem
                .write(addr, &remaining[..len])
                .map_err(|_| VirtqError::MemoryWriteError)?;

            buffer.written += len as u32;
            self.rd_written += len;
            written += len;
            remaining = &remaining[len..];
        }

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
    #[inline]
    pub fn write_all(&mut self, buf: &[u8]) -> Result<&mut Self, VirtqError> {
        if self.rd_desc_count() == 0 {
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

        let buffer = self.owned.buffers[..self.owned.readable]
            .get_mut(index)
            .ok_or(VirtqError::NoPayloadSegment)?;

        let cap = buffer.capacity as usize;
        if buf.len() > cap {
            return Err(VirtqError::PayloadTooLarge {
                recv: buf.len(),
                limit: cap,
            });
        }

        self.owned
            .mem
            .write(buffer.addr, buf)
            .map_err(|_| VirtqError::MemoryWriteError)?;

        let previous = buffer.written as usize;
        buffer.written = checked_descriptor_len(buf.len())?;
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

        let buffer = self.owned.buffers[..self.owned.readable]
            .get_mut(index)
            .ok_or_else(|| E::from(VirtqError::NoPayloadSegment))?;

        let cap = buffer.capacity as usize;

        // SAFETY: This unpublished chain owns the allocation exclusively.
        let buf = unsafe {
            self.owned
                .mem
                .as_mut_slice(buffer.addr, cap)
                .map_err(|_| E::from(VirtqError::MemoryWriteError))?
        };

        let written = f(buf)?;
        if written > buf.len() {
            return Err(E::from(VirtqError::PayloadTooLarge {
                recv: written,
                limit: buf.len(),
            }));
        }

        let previous = buffer.written as usize;
        buffer.written = checked_descriptor_len(written).map_err(E::from)?;
        self.rd_written = self.rd_written - previous + written;

        Ok(self)
    }
}

/// Tracks a pool slot's capacity and initialized length for writes and reply mappings.
///
/// [`BufferElement::len`] carries only the length published to the peer.
#[derive(Debug)]
struct BufferEntry {
    /// Buffer base address used for memory access and release through the pool.
    addr: u64,
    /// Usable bytes,
    capacity: u32,
    /// Initialized prefix length
    written: u32,
}

/// Buffer ownership passed from [`SendChain`] to [`Inflight`] at publication.
///
/// Keeps the original memory backend and pool for reply mappings and slot release.
struct OwnedChain<M> {
    /// Original backend for writing payloads and mapping completed replies.
    mem: M,
    /// Shared allocator.
    pool: SlotPool,
    /// Allocation records in descriptor order.
    buffers: SmallVec<[BufferEntry; 4]>,
    /// Number of leading device readable buffers.
    readable: usize,
}

impl<M> OwnedChain<M> {
    /// One [`BufferElement`] per direct descriptor, in chain order.
    ///
    /// The ring adds the descriptor IDs and flags that link the buffers.
    fn descriptors(&self) -> impl ExactSizeIterator<Item = BufferElement> + Clone + '_ {
        self.buffers.iter().enumerate().map(|(i, buf)| {
            let wr = i >= self.readable;
            let len = if wr { buf.capacity } else { buf.written };

            BufferElement {
                addr: buf.addr,
                len,
                writable: wr,
            }
        })
    }

    fn release(mut self) -> Result<(), AllocError> {
        self.release_all()
    }

    fn release_all(&mut self) -> Result<(), AllocError> {
        let mut maybe_err = None;
        while let Some(buf) = self.buffers.pop() {
            if let Err(error) = self.pool.dealloc(buf.addr)
                && maybe_err.is_none()
            {
                maybe_err = Some(error);
            }
        }

        self.readable = 0;
        maybe_err.map_or(Ok(()), Err)
    }
}

impl<M: BufferMap> OwnedChain<M> {
    fn into_segments(mut self, written: usize) -> Result<Segments, VirtqError> {
        let mut remaining = written;
        let mut nonempty = 0;

        for buf in &mut self.buffers[self.readable..] {
            let len = remaining.min(buf.capacity as usize);
            buf.written = len as u32;

            nonempty += usize::from(len != 0);
            remaining -= len;
        }

        if remaining != 0 {
            self.release()?;
            return Err(VirtqError::InvalidState);
        }

        let mut segments = SmallVec::<[Bytes; 4]>::new();
        segments
            .try_reserve_exact(nonempty)
            .map_err(|_| VirtqError::Bookkeeping)?;

        while let Some(buf) = self.buffers.last() {
            if self.buffers.len() <= self.readable || buf.written == 0 {
                let addr = buf.addr;
                self.buffers.pop();
                self.pool.dealloc(addr)?;

                continue;
            }

            let alloc = Allocation {
                addr: buf.addr,
                len: buf.capacity,
            };

            let written = buf.written as usize;
            let lease = BufferLease::new(self.pool.clone(), alloc);
            self.buffers.pop();

            // SAFETY: Completion returns exclusive ownership of the initialized
            // prefix. The mapper owns the slot until its borrowed view drops.
            let mapping = unsafe { self.mem.map_buffer(lease, written) }
                .map_err(|_| VirtqError::MemoryReadError)?;

            segments.push(Bytes::from_owner(mapping));
        }

        segments.reverse();
        Ok(Segments::from_smallvec(segments))
    }
}

impl<M> Drop for OwnedChain<M> {
    fn drop(&mut self) {
        // best effort: if the pool deallocation fails, we can't do much about it here
        if let Err(error) = self.release_all() {
            log::error!("Failed to release virtqueue buffers: {error}");
            debug_assert!(false, "OwnedChain deallocation failed: {error}");
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
    use alloc::rc::Rc;
    use alloc::sync::Arc;
    use core::sync::atomic::Ordering;

    use super::*;
    use crate::virtq::ring::tests::{FaultMem, OwnedRing, TestMem, make_consumer, make_ring};
    use crate::virtq::test_utils::*;

    fn poll_received<M: MemOps + Clone, N: Notifier>(
        consumer: &mut VirtqConsumer<M, N>,
    ) -> (RecvChain<M>, ReplyChain<M>) {
        consumer.poll(1024).unwrap().unwrap()
    }

    #[derive(Clone)]
    struct CopyingMem<'a>(&'a Rc<TestMem>);

    // SAFETY: All bounded operations delegate to TestMem.
    unsafe impl MemOps for CopyingMem<'_> {
        type Error = core::convert::Infallible;

        fn read(&self, addr: u64, dst: &mut [u8]) -> Result<(), Self::Error> {
            self.0.read(addr, dst)
        }

        fn write(&self, addr: u64, src: &[u8]) -> Result<(), Self::Error> {
            self.0.write(addr, src)
        }

        fn load_acquire(&self, addr: u64) -> Result<u16, Self::Error> {
            self.0.load_acquire(addr)
        }

        fn store_release(&self, addr: u64, val: u16) -> Result<(), Self::Error> {
            self.0.store_release(addr, val)
        }

        unsafe fn as_slice(&self, addr: u64, len: usize) -> Result<&[u8], Self::Error> {
            // SAFETY: The caller supplies TestMem's slice preconditions.
            unsafe { self.0.as_slice(addr, len) }
        }

        unsafe fn as_mut_slice(&self, addr: u64, len: usize) -> Result<&mut [u8], Self::Error> {
            // SAFETY: The caller supplies exclusive access to this range.
            unsafe { self.0.as_mut_slice(addr, len) }
        }
    }

    impl BufferMap for CopyingMem<'_> {
        type Mapping = Vec<u8>;

        unsafe fn map_buffer(
            &self,
            lease: BufferLease,
            written: usize,
        ) -> Result<Self::Mapping, Self::Error> {
            assert!(written <= lease.allocation().len as usize);
            let mut bytes = vec![0; written];
            self.read(lease.allocation().addr, &mut bytes)?;
            Ok(bytes)
        }
    }

    fn make_virtq_pair(
        ring: &OwnedRing,
        slot_size: usize,
    ) -> (
        VirtqProducer<TestMem, TestNotifier>,
        VirtqConsumer<TestMem, TestNotifier>,
    ) {
        let mem = ring.mem();
        let pool_base = mem.base_addr() + Layout::query_size(ring.len()) as u64 + 0x100;

        let lower = SlotLayout::new(pool_base, slot_size / 2, ring.len());
        let upper = SlotLayout::new(lower.end_addr().unwrap(), slot_size, ring.len());
        let pool = SlotPool::new_tiered(lower, upper).unwrap();

        let notifier = TestNotifier::new();
        let producer = VirtqProducer::new(ring.layout(), mem.clone(), notifier.clone(), pool);
        let consumer = VirtqConsumer::new(ring.layout(), mem, notifier);
        (producer, consumer)
    }

    fn make_chain(
        lower_count: usize,
        upper_count: usize,
        slot_size: usize,
        max_descs: usize,
    ) -> ChainBuilder<TestMem> {
        let mem = TestMem::new(lower_count * 256 + upper_count * slot_size);
        let lower = SlotLayout::new(mem.base_addr(), 256, lower_count);
        let upper = SlotLayout::new(lower.end_addr().unwrap(), slot_size, upper_count);

        let pool = if lower_count == 0 {
            SlotPool::new(upper)
        } else {
            SlotPool::new_tiered(lower, upper)
        }
        .unwrap();

        ChainBuilder::new(mem, pool, max_descs)
    }

    fn inflight(seq: u32, id: u16) -> Inflight<TestMem> {
        let mem = TestMem::new(8);
        let pool = SlotPool::new(SlotLayout::new(mem.base_addr(), 8, 1)).unwrap();
        let chain = ChainBuilder::new(mem, pool, 1).readable(8).build().unwrap();
        Inflight {
            token: Token { seq, id },
            chain: ManuallyDrop::new(chain.owned),
        }
    }

    #[test]
    fn inflight_table_repairs_moved_entry_after_removal() {
        let mut table = InflightTable::new(16);
        for (seq, id) in [(0, 3), (1, 7), (2, 5)] {
            table.try_reserve_one().unwrap();
            table.insert(inflight(seq, id));
        }

        let removed = table.remove(7).unwrap();
        assert_eq!(removed.token.seq, 1);

        ManuallyDrop::into_inner(removed.chain).release().unwrap();
        assert!(!table.contains(7));

        for (id, seq) in [(5, 2), (3, 0)] {
            let removed = table.remove(id).unwrap();
            assert_eq!(removed.token.seq, seq);
            ManuallyDrop::into_inner(removed.chain).release().unwrap();
        }
        assert!(table.live.is_empty());
        assert!(table.remove(7).is_none());
    }

    #[test]
    fn producer_bookkeeping_starts_compact_and_lazy() {
        let ring = make_ring(64);
        let (producer, _consumer, _notifier) = make_test_producer(&ring);

        assert_eq!(producer.inflight.by_id.len(), ring.len());
        assert!(producer.inflight.live.is_empty());
        assert_eq!(producer.inflight.live.capacity(), 0);
        assert_eq!(producer.pending.capacity(), 0);
    }

    #[test]
    fn full_ring_still_reports_backpressure() {
        let ring = make_ring(4);
        let (mut producer, _consumer, _notifier) = make_test_producer(&ring);

        for _ in 0..ring.len() {
            let chain = producer.chain().readable(1).build().unwrap();
            producer.submit(chain).unwrap();
        }

        assert!(matches!(
            producer.chain().readable(1).build(),
            Err(VirtqError::Backpressure)
        ));
        producer.reset().unwrap();
    }

    #[test]
    fn submission_rechecks_capacity_after_reservation() {
        let ring = make_ring(2);
        let (mut producer, mut consumer) = make_virtq_pair(&ring, 64);
        let pool = producer.pool.clone();

        let chain = producer.chain().writable(64).build().unwrap();
        for _ in 0..ring.len() {
            let other = producer.chain().writable(32).build().unwrap();
            producer.submit(other).unwrap();
        }

        assert_eq!(pool.num_live(), 3);
        assert!(matches!(
            producer.submit(chain),
            Err(VirtqError::Backpressure)
        ));
        assert_eq!(pool.num_live(), 2);

        producer.reset().unwrap();
        consumer.reset().unwrap();

        assert_eq!(pool.num_live(), 0);
    }

    #[test]
    fn publication_failure_keeps_allocations_until_stopped_reset() {
        for failed_write in 0..4 {
            let ring = make_ring(4);
            let orig_mem = FaultMem::new(ring.mem());
            let orig_gen = Arc::downgrade(&orig_mem.0);

            let base = ring.mem().base_addr() + Layout::query_size(ring.len()) as u64 + 0x100;
            let pool = SlotPool::new(SlotLayout::new(base, 64, 4)).unwrap();
            let notif = TestNotifier::new();

            let source = VirtqProducer::new(ring.layout(), orig_mem, notif.clone(), pool.clone());

            let chain = source.chain().writable(64).build().unwrap();
            drop(source);

            let mem = FaultMem::new(ring.mem());
            let mut producer =
                VirtqProducer::new(ring.layout(), mem.clone(), notif.clone(), pool.clone());

            mem.fail_write_at(failed_write);

            let res = producer.submit(chain);
            assert!(matches!(
                res,
                Err(VirtqError::RingError(RingError::MemError { .. }))
            ));
            assert_eq!(pool.num_live(), 1);
            assert_eq!(producer.inflight.live.len(), 1);
            assert!(orig_gen.upgrade().is_some());

            mem.allow_writes();
            producer.reset().unwrap();

            assert_eq!(pool.num_live(), 0);
            assert!(orig_gen.upgrade().is_none());
        }
    }

    #[test]
    fn chain_clones_pool_only_for_independent_owners() {
        let ring = make_ring(8);
        let mem = ring.mem();
        let base = mem.base_addr() + Layout::query_size(ring.len()) as u64 + 0x100;
        let pool = SlotPool::new(SlotLayout::new(base, 64, 8)).unwrap();

        let notif = TestNotifier::new();
        let mapping = FaultMem::new(mem.clone());

        let mut producer =
            VirtqProducer::new(ring.layout(), mapping.clone(), notif.clone(), pool.clone());

        let mut consumer = VirtqConsumer::new(ring.layout(), mem, TestNotifier::new());

        assert_eq!(pool.strong_count(), 2);

        let mut chain = producer
            .chain()
            .readable(192)
            .writable(192)
            .build()
            .unwrap();

        chain.write_all(b"request").unwrap();

        assert_eq!(pool.num_live(), 6);
        assert_eq!(pool.strong_count(), 3);
        assert!(chain.owned.buffers.spilled());

        let buffers = chain.owned.buffers.as_ptr();
        producer.submit(chain).unwrap();

        assert_eq!(pool.strong_count(), 3);
        assert_eq!(producer.inflight.live[0].chain.buffers.as_ptr(), buffers);

        let (recv, reply) = poll_received(&mut consumer);
        let ReplyChain::Writable(mut reply) = reply else {
            panic!("expected writable reply");
        };
        reply.write_all(&[0xa5; 70]).unwrap();
        consumer.complete(recv, reply).unwrap();

        let segments = producer.poll().unwrap().unwrap().into_segments().unwrap();

        assert_eq!(segments.segment_count(), 2);
        assert_eq!(mapping.0.map_calls.load(Ordering::Relaxed), 2);
        assert_eq!(pool.strong_count(), 4);
        assert_eq!(pool.num_live(), 2);

        let retained = segments.as_slice()[0].slice(1..);
        let cloned = retained.clone();

        drop(segments);

        assert_eq!(pool.num_live(), 1);
        assert_eq!(pool.strong_count(), 3);

        producer.reset().unwrap();
        consumer.reset().unwrap();

        drop(producer);

        assert_eq!(pool.strong_count(), 2);
        assert_eq!(retained.as_ref(), &[0xa5; 63]);

        drop(retained);

        assert_eq!(pool.num_live(), 1);

        drop(cloned);

        assert_eq!(pool.num_live(), 0);
        assert_eq!(pool.strong_count(), 1);
        assert_eq!(mapping.0.map_calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn copied_mapping_crosses_threads_without_its_pool_or_borrowed_backend() {
        let ring = make_ring(4);
        let mem = Rc::new(ring.mem());
        let base = mem.base_addr() + Layout::query_size(ring.len()) as u64 + 0x100;
        let pool = SlotPool::new(SlotLayout::new(base, 64, 1)).unwrap();
        let notif = TestNotifier::new();

        let mut producer =
            VirtqProducer::new(ring.layout(), CopyingMem(&mem), notif.clone(), pool.clone());
        let mut consumer = VirtqConsumer::new(ring.layout(), ring.mem(), notif);

        let chain = producer.chain().writable(64).build().unwrap();
        producer.submit(chain).unwrap();

        let (recv, reply) = poll_received(&mut consumer);
        let ReplyChain::Writable(mut reply) = reply else {
            panic!("expected writable reply");
        };
        reply.write_all(b"copied").unwrap();
        consumer.complete(recv, reply).unwrap();

        let bytes = producer.poll().unwrap().unwrap().into_bytes().unwrap();

        assert_eq!(pool.num_live(), 0);
        assert_eq!(pool.strong_count(), 2);

        let mut reused = producer.chain().readable(64).build().unwrap();
        reused.write_all(b"reused").unwrap();

        std::thread::spawn(move || assert_eq!(bytes.as_ref(), b"copied"))
            .join()
            .unwrap();

        assert_eq!(pool.num_live(), 1);
        assert_eq!(pool.strong_count(), 3);

        drop(reused);

        assert_eq!(pool.num_live(), 0);
    }

    #[test]
    fn completion_uses_its_original_memory_and_allocating_pool() {
        let ring = make_ring(4);
        let mem = FaultMem::new(ring.mem());
        let orig_gen = Arc::downgrade(&mem.0);
        let base = ring.mem().base_addr() + Layout::query_size(ring.len()) as u64 + 0x100;

        let notifier = TestNotifier::new();
        let original = SlotPool::new(SlotLayout::new(base, 64, 4)).unwrap();
        let source = VirtqProducer::new(ring.layout(), mem, TestNotifier::new(), original.clone());

        let chain = source.chain().writable(64).build().unwrap();
        drop(source);

        assert!(orig_gen.upgrade().is_some());

        let replacement =
            SlotPool::new(SlotLayout::new(original.base_addr() + 0x1000, 64, 4)).unwrap();

        let replacement_mem = FaultMem::new(ring.mem());
        replacement_mem.fail_mapping_at(0);

        let mut producer = VirtqProducer::new(
            ring.layout(),
            replacement_mem.clone(),
            notifier.clone(),
            replacement.clone(),
        );
        let mut consumer = VirtqConsumer::new(ring.layout(), ring.mem(), TestNotifier::new());

        producer.submit(chain).unwrap();

        assert!(orig_gen.upgrade().is_some());

        let (recv, reply) = poll_received(&mut consumer);
        let ReplyChain::Writable(mut reply) = reply else {
            panic!("expected writable reply");
        };

        reply.write_all(b"retained").unwrap();
        consumer.complete(recv, reply).unwrap();

        let data = producer.poll().unwrap().unwrap().into_bytes().unwrap();

        assert_eq!(data.as_ref(), b"retained");
        assert_eq!(original.num_live(), 1);
        assert_eq!(replacement.num_live(), 0);
        assert_eq!(replacement_mem.0.map_calls.load(Ordering::Relaxed), 0);

        let map_calls = orig_gen
            .upgrade()
            .unwrap()
            .map_calls
            .load(Ordering::Relaxed);
        assert_eq!(map_calls, 1);

        drop(producer);

        assert_eq!(data.as_ref(), b"retained");

        drop(data);

        assert_eq!(original.num_live(), 0);
        assert!(orig_gen.upgrade().is_none());
    }

    #[test]
    fn mapping_failure_releases_returned_and_unmapped_slots() {
        for fail_at in 0..2 {
            let ring = make_ring(8);
            let mem = FaultMem::new(ring.mem());
            mem.fail_mapping_at(fail_at);

            let base = ring.mem().base_addr() + Layout::query_size(ring.len()) as u64 + 0x100;
            let pool = SlotPool::new(SlotLayout::new(base, 64, 8)).unwrap();
            let notif = TestNotifier::new();
            let mut producer =
                VirtqProducer::new(ring.layout(), mem.clone(), notif.clone(), pool.clone());

            let mut consumer = make_consumer(&ring);

            let chain = producer
                .chain()
                .readable(192)
                .writable(256)
                .build()
                .unwrap();

            let mut addresses: Vec<_> = chain
                .owned
                .buffers
                .iter()
                .map(|buffer| buffer.addr)
                .collect();

            producer.submit(chain).unwrap();

            let (id, _) = consumer.poll_available().unwrap();
            // TestMem's zeroed backing supplies initialized bytes for the mapped prefix.
            consumer.submit_used(id, 70).unwrap();

            assert!(matches!(producer.poll(), Err(VirtqError::MemoryReadError)));
            assert_eq!(mem.0.map_calls.load(Ordering::Relaxed), fail_at + 1);
            assert_eq!(pool.num_live(), 0);
            assert_eq!(pool.strong_count(), 2);
            assert_eq!(producer.num_inflight(), 0);

            if fail_at == 1 {
                // The mapper releases the failed lease before completed owners unwind.
                addresses.swap(3, 4);
            }

            let repeated = producer
                .chain()
                .readable(192)
                .writable(256)
                .build()
                .unwrap();

            assert_eq!(
                repeated
                    .owned
                    .buffers
                    .iter()
                    .map(|buffer| buffer.addr)
                    .collect::<Vec<_>>(),
                addresses
            );
        }
    }

    #[test]
    fn empty_and_malformed_completions_skip_mapping_and_release_every_slot() {
        let ring = make_ring(4);
        let mem = FaultMem::new(ring.mem());
        mem.fail_mapping_at(0);

        let base = ring.mem().base_addr() + Layout::query_size(ring.len()) as u64 + 0x100;
        let pool = SlotPool::new(SlotLayout::new(base, 64, 4)).unwrap();
        let notif = TestNotifier::new();

        let mut producer =
            VirtqProducer::new(ring.layout(), mem.clone(), notif.clone(), pool.clone());

        let mut consumer = make_consumer(&ring);

        for (writable, written) in [(false, 0), (true, 0), (true, 129)] {
            let builder = producer.chain().readable(64);
            let builder = if writable {
                builder.writable(128)
            } else {
                builder
            };

            let token = producer.submit(builder.build().unwrap()).unwrap();
            let (id, _) = consumer.poll_available().unwrap();
            consumer.submit_used(id, written).unwrap();

            match producer.poll() {
                Ok(Some(UsedChain::Ack(returned))) if !writable => assert_eq!(returned, token),
                Ok(Some(UsedChain::Data(returned, segments))) if writable && written == 0 => {
                    assert_eq!(returned, token);
                    assert_eq!(segments.segment_count(), 0);
                }
                Err(VirtqError::InvalidState) if written == 129 => {}
                other => panic!("unexpected completion: {other:?}"),
            }

            assert_eq!(mem.0.map_calls.load(Ordering::Relaxed), 0);
            assert_eq!(pool.num_live(), 0);
            assert_eq!(pool.strong_count(), 2);
            assert_eq!(producer.num_inflight(), 0);
        }
    }

    #[test]
    fn cancelling_a_chain_preserves_slot_order_after_a_partial_write_error() {
        let storage = TestMem::new(16);
        let base = storage.base_addr();
        let mem = FaultMem::new(storage);
        let t1 = SlotLayout::new(base, 2, 2);
        let t2 = SlotLayout::new(base + 4, 4, 3);
        let pool = SlotPool::new_tiered(t1, t2).unwrap();

        let mut chain = ChainBuilder::new(mem.clone(), pool.clone(), 8)
            .readable(9)
            .writable_avail()
            .build()
            .unwrap();

        let addresses: Vec<_> = chain
            .owned
            .buffers
            .iter()
            .map(|buffer| buffer.addr)
            .collect();

        mem.fail_write_at(1);
        assert!(matches!(
            chain.write_all(b"abcdefghi"),
            Err(VirtqError::MemoryWriteError)
        ));
        assert_eq!(chain.written(), 4);

        drop(chain);

        assert_eq!(pool.num_live(), 0);
        assert_eq!(pool.strong_count(), 1);

        mem.allow_writes();
        let repeated = ChainBuilder::new(mem, pool.clone(), 8)
            .readable(9)
            .writable_avail()
            .build()
            .unwrap();

        assert_eq!(
            repeated
                .owned
                .buffers
                .iter()
                .map(|buffer| buffer.addr)
                .collect::<Vec<_>>(),
            addresses
        );
    }

    #[test]
    fn reset_reclaims_inflight_slots_and_reuses_ring() {
        let ring = make_ring(8);
        let mem = ring.mem();
        let pool_base = mem.base_addr() + Layout::query_size(ring.len()) as u64 + 0x100;
        let pool = SlotPool::new(SlotLayout::new(pool_base, 64, ring.len())).unwrap();
        let notifier = TestNotifier::new();
        let mut producer = VirtqProducer::new(ring.layout(), mem, notifier, pool.clone());

        for _ in 0..ring.len() {
            let chain = producer.chain().writable(64).build().unwrap();
            producer.submit(chain).unwrap();
        }

        assert_eq!(pool.num_free(), 0);

        producer.reset().unwrap();

        assert_eq!(producer.num_inflight(), 0);
        assert_eq!(producer.num_free(), ring.len());
        assert_eq!(pool.num_free(), ring.len());
        assert!(producer.inflight.live.is_empty());
        assert!(
            producer
                .inflight
                .by_id
                .iter()
                .all(|slot| *slot == InflightTable::<TestMem>::VACANT)
        );

        for _ in 0..ring.len() {
            let chain = producer.chain().writable(64).build().unwrap();
            producer.submit(chain).unwrap();
        }
        producer.reset().unwrap();
    }

    #[test]
    fn reset_rejects_buffered_writable_completion() {
        let ring = make_ring(8);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);
        let chain = producer.chain().writable(64).build().unwrap();
        producer.submit(chain).unwrap();

        let (recv, reply) = poll_received(&mut consumer);
        let ReplyChain::Writable(mut reply) = reply else {
            panic!("expected writable reply");
        };

        reply.write_all(b"retained").unwrap();
        consumer.complete(recv, reply).unwrap();
        producer.reclaim().unwrap();

        assert!(matches!(producer.reset(), Err(VirtqError::InvalidState)));

        drop(producer.poll().unwrap().unwrap());
        producer.reset().unwrap();
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
        assert_eq!(se.desc_count(), 2);
        assert_eq!(se.rd_desc_count(), 1);
        assert_eq!(se.wr_desc_count(), 1);
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
        assert_eq!(recv.to_bytes().unwrap().as_ref(), b"hello world");

        let segments = recv.to_segments().unwrap();
        assert_eq!(segments.segment_count(), 2);
        assert_eq!(segments.as_slice()[0].as_ref(), b"hello");
        assert_eq!(segments.as_slice()[1].as_ref(), b" world");

        consumer.complete(recv, reply).unwrap();
        producer.reset().unwrap();
    }

    #[test]
    fn test_chain_independent_readables_preserve_pool_tiers() {
        let ring = make_ring(16);
        let layout = ring.layout();
        let mem = ring.mem();

        let lower = SlotLayout::new(
            mem.base_addr() + Layout::query_size(ring.len()) as u64 + 0x100,
            256,
            1,
        );

        let upper = SlotLayout::new(lower.end_addr().unwrap(), 4096, 1);
        let pool = SlotPool::new_tiered(lower, upper).unwrap();
        let notifier = TestNotifier::new();
        let producer = VirtqProducer::new(layout, mem, notifier, pool.clone());

        let send = producer
            .chain()
            .readable(128)
            .readable(4096)
            .build()
            .unwrap();

        let readables = send.owned.descriptors().collect::<Vec<_>>();

        assert_eq!(readables.len(), 2);
        assert_eq!(readables[0].addr, lower.base_addr);
        assert_eq!(readables[1].addr, upper.base_addr);
        assert_eq!(pool.num_free_lower(), 0);
        assert_eq!(pool.num_free_upper(), 0);

        drop(send);

        assert_eq!(pool.num_free_lower(), 1);
        assert_eq!(pool.num_free_upper(), 1);
    }

    #[test]
    fn chain_avail_uses_pool_availability_at_build() {
        for held_count in [0, 2, 3] {
            let builder = make_chain(2, 3, 4096, 3);
            let pool = builder.pool.clone();
            let builder = builder.writable_avail().readable(128);

            assert_eq!(pool.num_live(), 0);

            let held: Vec<_> = (0..held_count).map(|_| pool.alloc(4096).unwrap()).collect();

            let chain = builder.build().unwrap();

            let writable = (3 - held_count).min(2);
            assert_eq!(chain.rd_desc_count(), 1);
            assert_eq!(chain.wr_desc_count(), writable);
            assert_eq!(chain.desc_count(), 1 + writable);
            assert_eq!(chain.owned.buffers[0].capacity, 128);
            assert!(
                chain.owned.buffers[1..]
                    .iter()
                    .all(|buf| buf.capacity == 4096)
            );
            assert_eq!(pool.num_free_lower(), 1);
            assert_eq!(pool.num_free_upper(), 3 - held_count - writable);
            assert_eq!(pool.num_live(), held_count + chain.desc_count());

            drop(chain);

            assert_eq!(pool.num_live(), held_count);

            for allocation in held.into_iter().rev() {
                pool.dealloc(allocation.addr).unwrap();
            }

            assert_eq!(pool.num_live(), 0);
        }
    }

    #[test]
    fn chain_avail_respects_mandatory_descriptor_budget() {
        for max_descs in 0..3 {
            let builder = make_chain(2, 3, 4096, max_descs);
            let pool = builder.pool.clone();

            let result = builder
                .readable(4096)
                .readable(128)
                .writable_avail()
                .build();

            if max_descs == 2 {
                let chain = result.unwrap();

                assert_eq!(chain.rd_desc_count(), 2);
                assert_eq!(chain.wr_desc_count(), 0);

                drop(chain);
            } else {
                assert!(matches!(result, Err(VirtqError::Backpressure)));
            }

            assert_eq!(pool.num_live(), 0);

            let lower = pool.alloc(128).unwrap();
            let upper = pool.alloc(4096).unwrap();

            assert_eq!(lower.addr, pool.slot_addr(1).unwrap());
            assert_eq!(upper.addr, pool.slot_addr(4).unwrap());

            pool.dealloc(lower.addr).unwrap();
            pool.dealloc(upper.addr).unwrap();
        }
    }

    #[test]
    fn chain_avail_preserves_explicit_writable_capacity_when_full() {
        for (upper_count, max_descs) in [(2, 2), (1, 3)] {
            let builder = make_chain(1, upper_count, 4096, max_descs);
            let pool = builder.pool.clone();

            let chain = builder
                .writable_avail()
                .writable(128)
                .readable(128)
                .build()
                .unwrap();

            assert_eq!(chain.rd_desc_count(), 1);
            assert_eq!(chain.wr_desc_count(), 1);
            assert_eq!(chain.owned.buffers[0].capacity, 128);
            assert_eq!(chain.owned.buffers[1].capacity, 4096);
            assert!(chain.owned.buffers.iter().all(|buf| buf.written == 0));
            assert_eq!(pool.num_free_upper(), upper_count - 1);

            drop(chain);

            assert_eq!(pool.num_live(), 0);
        }
    }

    #[test]
    fn chain_avail_cannot_build_an_empty_chain() {
        for max_descs in [0, 2] {
            let builder = make_chain(1, 1, 4096, max_descs);
            let pool = builder.pool.clone();
            let held = (max_descs != 0).then(|| pool.alloc(4096).unwrap());

            assert!(matches!(
                builder.writable_avail().build(),
                Err(VirtqError::Backpressure)
            ));
            assert_eq!(pool.num_free_lower(), 1);
            assert_eq!(pool.num_live(), usize::from(held.is_some()));

            if let Some(allocation) = held {
                pool.dealloc(allocation.addr).unwrap();
            }
        }
    }

    #[test]
    fn chain_avail_only_uses_upper_slots() {
        let builder = make_chain(4, 2, 4096, 6);
        let pool = builder.pool.clone();

        let chain = builder.writable_avail().writable_avail().build().unwrap();

        assert_eq!(chain.rd_desc_count(), 0);
        assert_eq!(chain.wr_desc_count(), 2);
        assert_eq!(pool.num_free_lower(), 4);
        assert_eq!(pool.num_free_upper(), 0);

        drop(chain);

        assert_eq!(pool.num_live(), 0);
    }

    #[test]
    fn chain_preserves_region_order_with_odd_slot_sizes() {
        let builder = make_chain(1, 4, 3001, 5);
        let pool = builder.pool.clone();

        // The final short readable must fall back to an upper slot.
        let chain = builder
            .readable(128)
            .readable(6003)
            .writable_avail()
            .build()
            .unwrap();

        assert_eq!(chain.rd_desc_count(), 4);

        let actual_offsets = chain
            .owned
            .buffers
            .iter()
            .map(|buf| {
                (
                    buf.addr,
                    buf.capacity,
                    pool.allocation_len(buf.addr).unwrap(),
                )
            })
            .collect::<Vec<_>>();

        let expected_offsets = [
            (0, 128, 256),
            (4, 3001, 3001),
            (3, 3001, 3001),
            (2, 1, 3001),
            (1, 3001, 3001),
        ]
        .map(|(slot, capacity, allocated)| (pool.slot_addr(slot).unwrap(), capacity, allocated));

        assert_eq!(actual_offsets, expected_offsets);

        drop(chain);

        assert_eq!(pool.num_live(), 0);
    }

    #[test]
    fn chain_failure_releases_only_its_own_slots() {
        let builder = make_chain(2, 3, 4096, 4);
        let pool = builder.pool.clone();
        let held = pool.alloc(4096).unwrap();

        assert!(matches!(
            builder.readable(128).writable(4096 * 3).build(),
            Err(VirtqError::Backpressure)
        ));
        assert_eq!(pool.live_addrs(), [held.addr]);

        let lower = pool.alloc(128).unwrap();
        let upper = pool.alloc(4096).unwrap();
        let next_upper = pool.alloc(4096).unwrap();

        assert_eq!(lower.addr, pool.slot_addr(1).unwrap());
        assert_eq!(upper.addr, pool.slot_addr(3).unwrap());
        assert_eq!(next_upper.addr, pool.slot_addr(2).unwrap());

        pool.dealloc(next_upper.addr).unwrap();
        pool.dealloc(upper.addr).unwrap();
        pool.dealloc(lower.addr).unwrap();
        pool.dealloc(held.addr).unwrap();
    }

    #[test]
    fn chain_rejects_invalid_request_sequences() {
        for (readable, writable) in [(vec![128, 0], vec![]), (vec![128], vec![4096, 0])] {
            let mut builder = make_chain(1, 1, 4096, 4);
            let pool = builder.pool.clone();

            for cap in readable {
                builder = builder.readable(cap);
            }
            for cap in writable {
                builder = builder.writable(cap);
            }

            assert!(matches!(
                builder.build(),
                Err(VirtqError::Alloc(AllocError::InvalidArg))
            ));
            assert_eq!(pool.num_live(), 0);
        }

        let builder = make_chain(1, 1, 4096, 4);
        let pool = builder.pool.clone();

        assert!(matches!(
            builder.readable(usize::MAX).readable(1).build(),
            Err(VirtqError::Alloc(AllocError::Overflow))
        ));
        assert_eq!(pool.num_live(), 0);
    }

    #[test]
    fn chain_keeps_four_records_inline_and_one_pool_handle() {
        for count in [4, 5] {
            let builder = make_chain(0, count, 4096, count);
            let pool = builder.pool.clone();

            let chain = builder
                .readable((count - 1) * 4096)
                .writable_avail()
                .build()
                .unwrap();

            assert_eq!(chain.desc_count(), count);
            assert_eq!(chain.owned.buffers.spilled(), count > 4);
            assert_eq!(pool.strong_count(), 2);

            drop(chain);

            assert_eq!(pool.num_live(), 0);
        }
    }

    #[test]
    fn test_chain_multi_readable_appends_across_calls() {
        let ring = make_ring(16);
        let (mut producer, mut consumer) = make_virtq_pair(&ring, 4);

        let mut send = producer.chain().readable(8).build().unwrap();
        send.write_all(b"abc").unwrap();
        send.write_all(b"def").unwrap();
        assert_eq!(send.written(), 6);
        assert_eq!(send.remaining(), 2);

        producer.submit(send).unwrap();
        let (recv, reply) = poll_received(&mut consumer);
        let segments = recv.to_segments().unwrap();
        assert_eq!(segments.segment_count(), 2);
        assert_eq!(segments.as_slice()[0].as_ref(), b"abcd");
        assert_eq!(segments.as_slice()[1].as_ref(), b"ef");
        consumer.complete(recv, reply).unwrap();
        producer.reset().unwrap();
    }

    #[test]
    fn test_chain_readable_splits_logical_capacity() {
        let expected_lengths = [4, 4, 4];
        let ring = make_ring(16);
        let (mut producer, mut consumer, _) = make_test_producer_with_slot_size(&ring, 4);

        let mut se = producer.chain().readable(10).writable(32).build().unwrap();
        let readables = &se.owned.buffers[..se.rd_desc_count()];

        assert_eq!(se.rd_desc_count(), 3);
        assert_eq!(se.capacity(), 10);

        let caps = readables.iter().map(|buf| buf.capacity).collect::<Vec<_>>();
        assert_eq!(caps, [4, 4, 2]);

        let lengths = readables
            .iter()
            .map(|buf| producer.pool.allocation_len(buf.addr).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(lengths, expected_lengths);

        se.write_all(b"abcdefghij").unwrap();
        assert_eq!(se.written(), 10);

        let token = producer.submit(se).unwrap();
        let (recv, reply) = poll_received(&mut consumer);

        assert_eq!(recv.token(), token);
        assert_eq!(recv.to_bytes().unwrap().as_ref(), b"abcdefghij");

        let segments = recv.to_segments().unwrap();

        assert_eq!(segments.segment_count(), 3);
        assert_eq!(segments.as_slice()[0].as_ref(), b"abcd");
        assert_eq!(segments.as_slice()[1].as_ref(), b"efgh");
        assert_eq!(segments.as_slice()[2].as_ref(), b"ij");

        consumer.complete(recv, reply).unwrap();
        producer.reset().unwrap();

        assert_eq!(producer.pool.num_live(), 0);
    }

    #[test]
    fn test_chain_readable_splits_logical_capacity_tiered() {
        let expected_lengths = [4, 4, 2];
        let ring = make_ring(16);
        let (mut producer, mut consumer) = make_virtq_pair(&ring, 4);

        let mut se = producer.chain().readable(10).writable(32).build().unwrap();
        let readables = &se.owned.buffers[..se.rd_desc_count()];

        assert_eq!(se.rd_desc_count(), 3);
        assert_eq!(se.capacity(), 10);

        let caps = readables.iter().map(|buf| buf.capacity).collect::<Vec<_>>();
        assert_eq!(caps, [4, 4, 2]);

        let lengths = readables
            .iter()
            .map(|buf| producer.pool.allocation_len(buf.addr).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(lengths, expected_lengths);

        se.write_all(b"abcdefghij").unwrap();
        assert_eq!(se.written(), 10);

        let token = producer.submit(se).unwrap();
        let (recv, reply) = poll_received(&mut consumer);

        assert_eq!(recv.token(), token);
        assert_eq!(recv.to_bytes().unwrap().as_ref(), b"abcdefghij");

        let segments = recv.to_segments().unwrap();

        assert_eq!(segments.segment_count(), 3);
        assert_eq!(segments.as_slice()[0].as_ref(), b"abcd");
        assert_eq!(segments.as_slice()[1].as_ref(), b"efgh");
        assert_eq!(segments.as_slice()[2].as_ref(), b"ij");

        consumer.complete(recv, reply).unwrap();
        producer.reset().unwrap();

        assert_eq!(producer.pool.num_live(), 0);
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
        let (mut producer, mut consumer) = make_virtq_pair(&ring, 4);

        let se = producer.chain().writable(10).build().unwrap();
        let token = producer.submit(se).unwrap();

        let (recv, reply) = poll_received(&mut consumer);
        let ReplyChain::Writable(mut wc) = reply else {
            panic!("expected writable reply");
        };
        assert_eq!(wc.capacity(), 10);

        wc.write_all(b"abcdefghij").unwrap();
        consumer.complete(recv, wc).unwrap();

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
        assert_eq!(recv.to_bytes().unwrap().as_ref(), b"headbody");
        consumer.complete(recv, reply).unwrap();
        producer.reset().unwrap();
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
        let segments = recv.to_segments().unwrap();
        assert_eq!(segments.segment_count(), 2);
        assert_eq!(segments.to_bytes().as_ref(), b"headbody");
        consumer.complete(recv, reply).unwrap();
        producer.reset().unwrap();
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
        let segments = recv.to_segments().unwrap();
        assert_eq!(segments.segment_count(), 2);
        assert_eq!(segments.to_bytes().as_ref(), b"headbody");
        consumer.complete(recv, reply).unwrap();
        producer.reset().unwrap();
    }

    #[test]
    fn test_chain_multi_writable_used_returns_segments() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer_with_slot_size(&ring, 6);

        let se = producer.chain().writable(5).writable(6).build().unwrap();
        let token = producer.submit(se).unwrap();

        let (recv, reply) = poll_received(&mut consumer);
        let ReplyChain::Writable(mut wc) = reply else {
            panic!("expected writable reply");
        };
        assert_eq!(wc.capacity(), 12);

        wc.write_all(b"hello world").unwrap();
        consumer.complete(recv, wc).unwrap();

        let used = producer.poll().unwrap().unwrap();
        assert_eq!(used.token(), token);
        let segments = used.segments().unwrap();
        assert_eq!(segments.segment_count(), 2);
        assert_eq!(segments.as_slice()[0].as_ref(), b"hello ");
        assert_eq!(segments.as_slice()[1].as_ref(), b"world");
        assert_eq!(segments.to_bytes().as_ref(), b"hello world");
    }

    #[test]
    fn test_chain_multi_writable_short_used_truncates_last_segment() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer_with_slot_size(&ring, 6);

        let se = producer.chain().writable(5).writable(6).build().unwrap();
        producer.submit(se).unwrap();

        let (recv, reply) = poll_received(&mut consumer);
        let ReplyChain::Writable(mut wc) = reply else {
            panic!("expected writable reply");
        };

        wc.write_all(b"hello wo").unwrap();
        consumer.complete(recv, wc).unwrap();

        let used = producer.poll().unwrap().unwrap();
        let segments = used.segments().unwrap();
        assert_eq!(segments.segment_count(), 2);
        assert_eq!(segments.as_slice()[0].as_ref(), b"hello ");
        assert_eq!(segments.as_slice()[1].as_ref(), b"wo");
        assert_eq!(segments.to_bytes().as_ref(), b"hello wo");
    }

    #[test]
    fn test_chain_multi_writable_zero_used_returns_empty_segments() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().writable(5).writable(6).build().unwrap();
        producer.submit(se).unwrap();

        let (recv, reply) = poll_received(&mut consumer);
        consumer.complete(recv, reply).unwrap();

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
        assert_eq!(recv.to_bytes().unwrap().as_ref(), b"hello world");
        consumer.complete(recv, reply).unwrap();
        producer.reset().unwrap();
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
        assert_eq!(recv.to_bytes().unwrap().as_ref(), b"hello world");
        consumer.complete(recv, reply).unwrap();
        producer.reset().unwrap();
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
        assert_eq!(recv.to_bytes().unwrap().as_ref(), b"hello wo");
        consumer.complete(recv, reply).unwrap();
        producer.reset().unwrap();
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
        assert_eq!(recv.to_bytes().unwrap().as_ref(), b"hello");
        consumer.complete(recv, reply).unwrap();
        producer.reset().unwrap();
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
        assert_eq!(recv.to_bytes().unwrap().as_ref(), b"hello");
        consumer.complete(recv, reply).unwrap();
        producer.reset().unwrap();
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
        let (producer, _consumer) = make_virtq_pair(&ring, 4);

        let mut se = producer.chain().readable(8).build().unwrap();
        assert_eq!(se.rd_desc_count(), 2);
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
        producer.reset().unwrap();
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
        producer.reset().unwrap();
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
        producer.reset().unwrap();
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
        producer.reset().unwrap();
    }

    #[test]
    fn test_submit_write_only_notifies_by_default() {
        let ring = make_ring(16);
        let (mut producer, _consumer, notifier) = make_test_producer(&ring);

        let initial_count = notifier.notification_count();

        let se = producer.chain().writable(128).build().unwrap();
        producer.submit(se).unwrap();

        assert!(notifier.notification_count() > initial_count);
        producer.reset().unwrap();
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
        assert_eq!(recv.to_bytes().unwrap().as_ref(), b"first");
        consumer.complete(recv, reply).unwrap();

        let (recv, reply) = poll_received(&mut consumer);
        assert_eq!(recv.to_bytes().unwrap().as_ref(), b"second");
        consumer.complete(recv, reply).unwrap();
        producer.reset().unwrap();
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
        producer.reset().unwrap();
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
    fn test_batch_can_finish_without_notification() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, notifier) = make_test_producer(&ring);

        let mut batch = producer.batch();
        let mut chain = batch.chain().readable(4).build().unwrap();
        chain.write_all(b"data").unwrap();
        batch.submit(chain).unwrap();
        batch.finish_without_notify();

        assert_eq!(notifier.notification_count(), 0);

        let (recv, reply) = poll_received(&mut consumer);
        assert_eq!(recv.to_bytes().unwrap().as_ref(), b"data");

        consumer.complete(recv, reply).unwrap();
        producer.reset().unwrap();
    }

    #[test]
    fn test_write_only_round_trip() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().writable(32).build().unwrap();
        let token = producer.submit(se).unwrap();

        let (recv, reply) = poll_received(&mut consumer);
        assert_eq!(recv.token(), token);
        assert!(recv.to_bytes().unwrap().is_empty());

        if let ReplyChain::Writable(mut wc) = reply {
            wc.write_all(b"filled-by-consumer").unwrap();
            consumer.complete(recv, wc).unwrap();
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
        assert_eq!(recv.to_bytes().unwrap().as_ref(), b"fire-and-forget");
        assert!(matches!(reply, ReplyChain::Ack(_)));
        consumer.complete(recv, reply).unwrap();

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
        assert_eq!(recv.to_bytes().unwrap().as_ref(), b"request data");
        if let ReplyChain::Writable(mut wc) = reply {
            wc.write_all(b"response data").unwrap();
            consumer.complete(recv, wc).unwrap();
        } else {
            panic!("expected Writable");
        }

        let used = producer.poll().unwrap().unwrap();
        assert_eq!(used.token(), token);
        assert_eq!(used.to_bytes().unwrap().as_ref(), b"response data");
    }

    #[test]
    fn test_poll_used_requires_owned_mapping() {
        let ring = make_ring(16);
        let layout = ring.layout();
        let test_mem = ring.mem();
        let pool_base = test_mem.base_addr() + Layout::query_size(ring.len()) as u64 + 0x100;
        let pool = SlotPool::new(SlotLayout::new(pool_base, 128, 0x8000 / 128)).unwrap();
        let notifier = TestNotifier::new();
        let mem = FaultMem::new(test_mem);
        mem.deny_views();
        let mut producer = VirtqProducer::new(layout, mem.clone(), notifier.clone(), pool.clone());
        let mut consumer = VirtqConsumer::new(layout, mem, notifier);

        let mut se = producer.chain().readable(64).writable(128).build().unwrap();
        se.write_all(b"request data").unwrap();
        producer.submit(se).unwrap();

        let (recv, reply) = poll_received(&mut consumer);
        if let ReplyChain::Writable(mut wc) = reply {
            wc.write_all(b"response data").unwrap();
            consumer.complete(recv, wc).unwrap();
        } else {
            panic!("expected Writable");
        }

        assert!(matches!(producer.poll(), Err(VirtqError::MemoryReadError)));
        assert_eq!(pool.num_live(), 0);
    }

    #[test]
    fn test_villain_used_len_exceeding_writable_capacity_is_rejected_and_released() {
        let ring = make_ring(16);
        let (mut producer, _consumer, _notifier) = make_test_producer_with_slot_size(&ring, 4);
        let mut ring_consumer = make_consumer(&ring);

        let se = producer.chain().writable(4).build().unwrap();
        producer.submit(se).unwrap();

        let (id, _) = ring_consumer.poll_available().unwrap();
        ring_consumer.submit_used(id, 8).unwrap();

        assert!(matches!(producer.poll(), Err(VirtqError::InvalidState)));
        assert_eq!(producer.inner.num_inflight(), 0);

        let se = producer.chain().writable(4).build().unwrap();
        producer.submit(se).unwrap();
        assert_eq!(producer.inner.num_inflight(), 1);
        producer.reset().unwrap();
    }

    #[test]
    fn test_villain_used_descriptor_with_invalid_id_is_rejected() {
        let ring = make_ring(16);
        let (mut producer, _consumer, _notifier) = make_test_producer(&ring);

        let se = producer.chain().writable(4).build().unwrap();
        producer.submit(se).unwrap();

        let mut desc = Descriptor::new(0, 0, ring.len() as u16, DescFlags::empty());
        desc.mark_used(true);
        ring.write_desc(0, desc);

        assert!(matches!(
            producer.poll(),
            Err(VirtqError::RingError(RingError::InvalidState))
        ));
        assert_eq!(producer.inner.num_inflight(), 1);
        producer.reset().unwrap();
    }
}
