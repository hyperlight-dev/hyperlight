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
//!   request/response lifecycle, and notification decisions. This is the recommended API
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
//! ## Single Request/Response
//!
//! ```ignore
//! // Producer (driver) side - send request, get response
//! let token = producer.send(b"request data", response_capacity)?;
//! // ... wait for notification ...
//! if let Some(response) = producer.poll_once()? {
//!     process(response.data);
//! }
//!
//! // Consumer (device) side - receive request, send response
//! if let Some(request) = consumer.poll_once(max_request_size)? {
//!     let response = handle(request.data);
//!     consumer.complete(request.token, &response)?;
//! }
//! ```
//!
//! ## Batched Requests
//!
//! Use [`VirtqProducer::batch`] to submit multiple requests with a single notification:
//!
//! ```ignore
//! let mut batch = producer.batch();
//! batch.send(b"req1", 64)?;
//! batch.send(b"req2", 64)?;
//! batch.send(b"req3", 64)?;
//! let result = batch.commit()?;
//! // result.notified: whether device was signaled
//! // result.cursor_after: ring position after batch (for completion suppression)
//! ```
//!
//! ## Completion Batching with Event Suppression
//!
//! To receive a single notification when multiple requests complete:
//!
//! ```ignore
//! // Send batch of requests
//! let mut batch = producer.batch();
//! for req in requests {
//!     batch.send(req, 64)?;
//! }
//! let result = batch.commit()?;
//!
//! // Tell device: "notify me only after completing all requests"
//! producer.set_used_suppression(SuppressionKind::Descriptor(result.cursor_after))?;
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
mod desc;
mod event;
mod pool;
mod ring;

use alloc::vec;
use alloc::vec::Vec;
use smallvec::SmallVec;
use core::num::NonZeroU16;

pub use access::*;
use bytes::Bytes;
pub use desc::*;
pub use event::*;
pub use pool::*;
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
    #[error("Request too large for allocated buffer")]
    ReqTooLarge,
    #[error("Response too large for allocated buffer")]
    RespTooLarge,
    #[error("Internal state error")]
    InvalidState,
    #[error("Memory write error")]
    MemoryWriteError,
    #[error("Memory read error")]
    MemoryReadError,
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

/// An allocation of memory for use in the virtqueue.
#[derive(Debug, Clone)]
struct ProducerInflight {
    req: Allocation,
    resp: Allocation,
    resp_cap: usize,
}

/// A token representing a sent request in the virtqueue.
///
/// Tokens uniquely identify in-flight requests and are used to correlate
/// requests with their responses. The token value corresponds to the
/// descriptor ID in the underlying ring.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Token(pub u16);

/// An incoming request received by the consumer (device side).
///
/// Contains the request data and a token that must be passed to
/// [`VirtqConsumer::complete`] when sending the response.
#[derive(Debug)]
pub struct Request {
    /// Token identifying this request. Pass to [`VirtqConsumer::complete`].
    pub token: Token,
    /// Request data sent by the driver.
    pub data: Bytes,
}

/// A response received by the producer (driver side).
///
/// Contains the response data and metadata about the completed request.
#[derive(Debug)]
pub struct Response {
    /// Token identifying which request this response corresponds to.
    pub token: Token,
    /// Response data from the device.
    pub data: Bytes,
    /// Number of bytes actually written by the device (may be less than buffer capacity).
    pub written: usize,
}

/// A high-level virtqueue producer (driver side).
///
/// The producer sends requests to the consumer (device), and receives responses.
/// This is typically used on the driver/guest side.
///
/// # Example
///
/// ```ignore
/// let mut producer = VirtqProducer::new(layout, mem, notifier, pool);
///
/// // Send a request
/// let token = producer.send(b"hello", 64)?;
///
/// // Later, poll for response
/// if let Some(resp) = producer.poll_once()? {
///     assert_eq!(resp.token, token);
///     println!("Got response: {:?}", resp.data);
/// }
/// ```
pub struct VirtqProducer<M, N, P> {
    inner: RingProducer<M>,
    notifier: N,
    pool: P,
    inflight: Vec<Option<ProducerInflight>>,
}

impl<M, N, P> VirtqProducer<M, N, P>
where
    M: MemOps,
    N: Notifier,
    P: BufferProvider + Clone,
{
    /// Create a new virtqueue producer.
    ///
    /// # Arguments
    ///
    /// * `layout` - Ring memory layout (descriptor table and event suppression addresses)
    /// * `mem` - Memory operations implementation for reading/writing to shared memory
    /// * `notifier` - Callback for notifying the device (consumer) about new requests
    /// * `pool` - Buffer allocator for request/response data
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

    fn alloc(
        &self,
        size: usize,
    ) -> Result<AllocGuard<impl FnOnce(Allocation) + use<M, N, P>>, VirtqError> {
        let alloc = self.pool.alloc(size)?;
        let pool = self.pool.clone();

        Ok(AllocGuard::new(alloc, move |a| {
            let _ = pool.dealloc(a);
        }))
    }

    /// Poll for a single completed response from the device.
    ///
    /// Returns `Ok(Some(response))` if a response is available, `Ok(None)` if no
    /// responses are ready (would block), or an error if the device misbehaved.
    ///
    /// # Errors
    ///
    /// - [`VirtqError::InvalidState`] - Device returned invalid descriptor ID or
    ///   wrote more data than the response buffer capacity
    /// - [`VirtqError::MemoryReadError`] - Failed to read response data from shared memory
    pub fn poll_once(&mut self) -> Result<Option<Response>, VirtqError> {
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
        if written > inf.resp_cap {
            // free allocations; device misbehaved or protocol mismatch
            let _ = self.pool.dealloc(inf.req);
            let _ = self.pool.dealloc(inf.resp);
            return Err(VirtqError::InvalidState);
        }

        // TODO: use BufferOwner and Bytes::from_owner to avoid copy
        let mut buf = vec![0u8; written];
        self.inner
            .mem()
            .read(inf.resp.addr, &mut buf)
            .map_err(|_| VirtqError::MemoryReadError)?;

        let data = Bytes::from(buf);
        let token = Token(used.id);

        self.pool.dealloc(inf.req)?;
        self.pool.dealloc(inf.resp)?;

        Ok(Some(Response {
            token,
            data,
            written,
        }))
    }

    /// Drain all available responses, calling the provided closure for each.
    ///
    /// This is a convenience method that repeatedly calls [`poll_once`](Self::poll_once)
    /// until no more responses are available.
    ///
    /// # Arguments
    ///
    /// * `f` - Closure called for each response with its token and data
    ///
    /// # Example
    ///
    /// ```ignore
    /// producer.drain(|token, data| {
    ///     println!("Response for {:?}: {} bytes", token, data.len());
    /// })?;
    /// ```
    pub fn drain(&mut self, mut f: impl FnMut(Token, Bytes)) -> Result<(), VirtqError> {
        while let Some(resp) = self.poll_once()? {
            f(resp.token, resp.data);
        }

        Ok(())
    }

    /// Send a request and notify the device if event suppression allows.
    ///
    /// This is the simplest way to send a single request. For batching multiple
    /// requests with a single notification, use [`batch`](Self::batch) instead.
    ///
    /// # Arguments
    ///
    /// * `req` - Request data to send to the device
    /// * `resp_cap` - Maximum response size capacity (device may write up to this many bytes)
    ///
    /// # Returns
    ///
    /// A [`Token`] that uniquely identifies this request. Use it to correlate
    /// the response when it arrives via [`poll_once`](Self::poll_once) or [`drain`](Self::drain).
    ///
    /// # Errors
    ///
    /// - [`VirtqError::WouldBlock`] - Ring is full 
    /// - [`VirtqError::ReqTooLarge`] - Request data exceeds allocated buffer size
    /// - [`VirtqError::MemoryWriteError`] - Failed to write request to shared memory
    pub fn send(&mut self, req: &[u8], resp_cap: usize) -> Result<Token, VirtqError> {
        let cursor_before = self.inner.avail_cursor();
        let token = self.do_send(req, resp_cap)?;
        self.notify_since(cursor_before)?;
        Ok(token)
    }

    /// Start a batch transaction for sending multiple requests with a single notification.
    ///
    /// The returned [`BatchSender`] allows adding multiple requests before triggering
    /// a single event suppression check and potential notification. This is more efficient
    /// than calling `send()` multiple times when batching is desired.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut batch = producer.batch();
    /// let tok1 = batch.send(b"request1", 64)?;
    /// let tok2 = batch.send(b"request2", 64)?;
    /// let result = batch.commit()?;
    /// // result.tokens contains [tok1, tok2]
    /// // Single notification sent if event suppression allows
    /// ```
    pub fn batch(&mut self) -> BatchSender<'_, M, N, P> {
        BatchSender::new(self)
    }

    /// Get the current used cursor position.
    ///
    /// Useful for setting up descriptor-based event suppression.
    #[inline]
    pub fn used_cursor(&self) -> RingCursor {
        self.inner.used_cursor()
    }

    /// Internal: send without notification check.
    fn do_send(&mut self, req: &[u8], resp_cap: usize) -> Result<Token, VirtqError> {
        if self.inner.num_free() < 2 {
            return Err(RingError::WouldBlock.into());
        }

        let req_guard = self.alloc(req.len())?;
        let resp_guard = self.alloc(resp_cap)?;

        if req.len() > req_guard.len {
            return Err(VirtqError::ReqTooLarge);
        }

        self.inner
            .mem()
            .write(req_guard.addr, req)
            .map_err(|_| VirtqError::MemoryWriteError)?;

        let chain = BufferChainBuilder::new()
            .readable(req_guard.addr, req.len() as u32)
            .writable(resp_guard.addr, resp_guard.len as u32)
            .build()?;

        let id = self.inner.submit_available(&chain)?;

        let slot = self
            .inflight
            .get_mut(id as usize)
            .ok_or(VirtqError::InvalidState)?;

        if slot.is_some() {
            return Err(VirtqError::InvalidState);
        }

        let resp_cap = resp_guard.len;
        *slot = Some(ProducerInflight {
            req: req_guard.dismiss(),
            resp: resp_guard.dismiss(),
            resp_cap,
        });

        Ok(Token(id))
    }

    /// Internal: check event suppression and notify if needed.
    fn notify_since(&mut self, cursor_before: RingCursor) -> Result<bool, VirtqError> {
        let should_notify = self.inner.should_notify_since(cursor_before)?;

        if should_notify {
            self.notifier.notify(QueueStats {
                num_free: self.inner.num_free(),
                num_inflight: self.inner.num_inflight(),
            });
        }

        Ok(should_notify)
    }

    /// Configure event suppression for used buffer notifications.
    ///
    /// This controls when the device (consumer) signals us about completed buffers:
    ///
    /// - [`SuppressionKind::Enable`]: Always signal (default) - good for latency
    /// - [`SuppressionKind::Disable`]: Never signal - caller must poll
    /// - [`SuppressionKind::Descriptor`]: Signal only at specific cursor position - good for batching
    ///
    /// # Example: Polling Mode
    ///
    /// ```ignore
    /// producer.set_used_suppression(SuppressionKind::Disable)?;
    /// loop {
    ///     while let Some(resp) = producer.poll_once()? {
    ///         handle(resp);
    ///     }
    ///     // ... do other work ...
    /// }
    /// ```
    ///
    /// # Example: Completion Batching
    ///
    /// Receive a single notification when all requests in a batch complete:
    ///
    /// ```ignore
    /// // Send batch of requests
    /// let mut batch = producer.batch();
    /// batch.send(b"req1", 64)?;
    /// batch.send(b"req2", 64)?;
    /// batch.send(b"req3", 64)?;
    /// let result = batch.commit()?;
    ///
    /// // Tell device: notify only after completing all requests
    /// producer.set_used_suppression(SuppressionKind::Descriptor(result.cursor_after))?;
    ///
    /// // Wait for notification, then drain all responses
    /// // (notification will come only after all 3 requests complete)
    /// ```
    pub fn set_used_suppression(&mut self, kind: SuppressionKind) -> Result<(), VirtqError> {
        match kind {
            SuppressionKind::Enable => self.inner.enable_used_notifications()?,
            SuppressionKind::Disable => self.inner.disable_used_notifications()?,
            SuppressionKind::Descriptor(cursor) => {
                self.inner
                    .enable_used_notifications_desc(cursor.head(), cursor.wrap())?
            }
        }
        Ok(())
    }
}

/// Result of committing a batch of requests.
#[derive(Debug, Clone)]
pub struct BatchResult {
    /// Tokens for all successfully submitted requests in the batch.
    pub tokens: SmallVec<[Token; 8]>,
    /// Whether notification was sent to the device.
    pub notified: bool,
    /// Ring cursor position after the batch.
    pub cursor_after: RingCursor,
}

/// A batch sender for submitting multiple requests with a single notification.
///
/// Created via [`VirtqProducer::batch`]. Requests added via [`send`](Self::send)
/// are accumulated and only trigger a single event suppression check when
/// [`commit`](Self::commit) is called.
///
/// # Example
///
/// ```ignore
/// // Submit multiple requests with single notification
/// let mut batch = producer.batch();
/// batch.send(b"req1", 64)?;
/// batch.send(b"req2", 64)?;
/// let result = batch.commit()?;
///
/// // Optionally, set up completion batching
/// producer.set_used_suppression(SuppressionKind::Descriptor(result.cursor_after))?;
/// // Device will notify only after all requests complete
/// ```
///
/// If dropped without calling `commit` or `abort`, will automatically commit
/// any pending requests (conservative behavior to avoid silent descriptor leaks).
pub struct BatchSender<'a, M, N, P>
where
    M: MemOps,
    N: Notifier,
    P: BufferProvider + Clone,
{
    /// Inner virtqueue producer
    inner: &'a mut VirtqProducer<M, N, P>,
    /// Tokens for all requests in the batch
    tokens: SmallVec<[Token; 8]>,
    /// Cursor position before first send in the batch
    cursor_before: Option<RingCursor>,
    /// Whether commit/dismiss has been called
    committed: bool,
}

impl<'a, M, N, P> BatchSender<'a, M, N, P>
where
    M: MemOps,
    N: Notifier,
    P: BufferProvider + Clone,
{
    fn new(producer: &'a mut VirtqProducer<M, N, P>) -> Self {
        Self {
            inner: producer,
            tokens: SmallVec::new(),
            cursor_before: None,
            committed: false,
        }
    }

    /// Add a request to the batch.
    ///
    /// The request is submitted to the ring immediately, but no notification
    /// check is performed. Call [`commit`](Self::commit) to finalize the batch
    /// and trigger notification if needed.
    ///
    /// # Arguments
    ///
    /// * `req` - Request data to send
    /// * `resp_cap` - Maximum response size capacity
    pub fn send(&mut self, req: &[u8], resp_cap: usize) -> Result<Token, VirtqError> {
        // Record cursor before first send
        if self.cursor_before.is_none() {
            self.cursor_before = Some(self.inner.inner.avail_cursor());
        }

        let token = self.inner.do_send(req, resp_cap)?;
        self.tokens.push(token);
        Ok(token)
    }

    /// Get the number of requests in the batch so far.
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Check if the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// Finalize the batch and trigger notification if needed.
    ///
    /// Checks event suppression based on all requests submitted since the batch
    /// started and notifies the device if required.
    ///
    /// # Returns
    ///
    /// A [`BatchResult`] containing:
    /// - `tokens`: All tokens for submitted requests
    /// - `notified`: Whether the device was signaled
    /// - `cursor_after`: Ring position after batch (for completion suppression)
    pub fn commit(mut self) -> Result<BatchResult, VirtqError> {
        self.committed = true;

        // Capture cursor after all sends
        let cursor_after = self.inner.inner.avail_cursor();

        let notified = if let Some(cursor) = self.cursor_before {
            self.inner.notify_since(cursor)?
        } else {
            // Empty batch, no notification needed
            false
        };

        Ok(BatchResult {
            tokens: core::mem::take(&mut self.tokens),
            notified,
            cursor_after,
        })
    }

    /// Dismiss the batch without triggering notification.
    ///
    /// Note: Any requests already submitted remain in-flight and will still
    /// be processed by the device. This only skips the notification.
    pub fn dismiss(mut self) {
        self.committed = true;
        // Requests already submitted remain in-flight
    }
}

impl<M, N, P> Drop for BatchSender<'_, M, N, P>
where
    M: MemOps,
    N: Notifier,
    P: BufferProvider + Clone,
{
    fn drop(&mut self) {
        // If not committed/aborted and we have pending requests, notify conservatively
        if !self.committed && self.cursor_before.is_some() {
            // Best effort notification - ignore errors during drop
            let _ = self.inner.notify_since(self.cursor_before.unwrap());
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ConsumerInflight {
    resp: BufferElement,
    resp_cap: usize,
}

/// A high-level virtqueue consumer (device side).
///
/// The consumer receives requests from the producer (driver), processes them,
/// and sends back responses. This is typically used on the device/host side.
///
/// # Example
///
/// ```ignore
/// let mut consumer = VirtqConsumer::new(layout, mem, notifier);
///
/// // Process incoming requests
/// while let Some(req) = consumer.poll_once(MAX_REQ_SIZE)? {
///     let response = process_request(&req.data);
///     consumer.complete(req.token, &response)?;
/// }
/// ```
pub struct VirtqConsumer<M, N> {
    inner: RingConsumer<M>,
    notifier: N,
    inflight: Vec<Option<ConsumerInflight>>,
}

impl<M: MemOps, N: Notifier> VirtqConsumer<M, N> {
    /// Create a new virtqueue consumer.
    ///
    /// # Arguments
    ///
    /// * `layout` - Ring memory layout (descriptor table and event suppression addresses)
    /// * `mem` - Memory operations implementation for reading/writing to shared memory
    /// * `notifier` - Callback for notifying the driver (producer) about completed responses
    pub fn new(layout: Layout, mem: M, notifier: N) -> Self {
        let inner = RingConsumer::new(layout, mem);
        let inflight = vec![None; inner.len()];

        Self {
            inner,
            notifier,
            inflight,
        }
    }

    /// Poll for a single incoming request from the driver.
    ///
    /// Returns `Ok(Some(request))` if a request is available, `Ok(None)` if no
    /// requests are ready (would block), or an error if the request is malformed.
    ///
    /// Currently only accepts request chains with exactly one readable buffer
    /// (request data) and one writable buffer (response space).
    ///
    /// # Arguments
    ///
    /// * `max_req` - Maximum request size to accept. Requests larger than this
    ///   will return [`VirtqError::ReqTooLarge`].
    ///
    /// # Returns
    ///
    /// A [`Request`] containing the token (for use with [`complete`](Self::complete))
    /// and the request data.
    ///
    /// # Errors
    ///
    /// - [`VirtqError::ReqTooLarge`] - Request data exceeds `max_req` bytes
    /// - [`VirtqError::BadChain`] - Descriptor chain doesn't match expected format
    /// - [`VirtqError::InvalidState`] - Descriptor ID collision (driver bug)
    pub fn poll_once(&mut self, max_req: usize) -> Result<Option<Request>, VirtqError> {
        let (id, chain) = match self.inner.poll_available() {
            Ok(x) => x,
            Err(RingError::WouldBlock) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let (req_elem, resp_elem) = parse_single_req_resp(&chain)?;

        let req_len = req_elem.len as usize;
        if req_len > max_req {
            return Err(VirtqError::ReqTooLarge);
        }

        let mut buf = vec![0u8; req_len];
        self.inner
            .mem()
            .read(req_elem.addr, &mut buf)
            .map_err(|_| VirtqError::MemoryReadError)?;

        // Save response buffer for later completion
        let slot = self
            .inflight
            .get_mut(id as usize)
            .ok_or(VirtqError::InvalidState)?;

        if slot.is_some() {
            return Err(VirtqError::InvalidState);
        }

        *slot = Some(ConsumerInflight {
            resp: resp_elem,
            resp_cap: resp_elem.len as usize,
        });

        let req = Request {
            token: Token(id),
            data: Bytes::from(buf),
        };

        Ok(Some(req))
    }

    /// Complete a request by sending a response back to the driver.
    ///
    /// Writes the response data to the shared buffer provided by the driver,
    /// marks the descriptor as used, and notifies the driver if event suppression
    /// allows.
    ///
    /// # Arguments
    ///
    /// * `tok` - Token from the original [`Request`] returned by [`poll_once`](Self::poll_once)
    /// * `resp` - Response data to send back
    ///
    /// # Errors
    ///
    /// - [`VirtqError::BadToken`] - Token doesn't correspond to an in-flight request
    /// - [`VirtqError::RespTooLarge`] - Response exceeds the buffer capacity provided by driver
    /// - [`VirtqError::MemoryWriteError`] - Failed to write response to shared memory
    pub fn complete(&mut self, tok: Token, resp: &[u8]) -> Result<(), VirtqError> {
        let id = tok.0 as usize;

        let inf = self
            .inflight
            .get_mut(id)
            .ok_or(VirtqError::InvalidState)?
            .take()
            .ok_or(VirtqError::BadToken)?;

        if resp.len() > inf.resp_cap {
            // FIXME: this has to be handled on the protocol level:
            // for example we should communicate to the driver that the allocated buffer
            // cannot hold the entire response and send truncated data. For now, just error
            // out but this will certainly lead to a deadlock if the driver cannot handle it.
            return Err(VirtqError::RespTooLarge);
        }

        self.inner
            .mem()
            .write(inf.resp.addr, resp)
            .map_err(|_| VirtqError::MemoryWriteError)?;

        let notify = self
            .inner
            .submit_used_with_notify(tok.0, resp.len() as u32)?;

        if notify {
            let stats = QueueStats {
                num_free: self.inner.num_free(),
                num_inflight: self.inner.num_inflight(),
            };
            self.notifier.notify(stats);
        }

        Ok(())
    }

    /// Get the current available cursor position.
    ///
    /// Returns the position where the next available descriptor will be written.
    /// Useful for setting up descriptor-based event suppression.
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
    /// - [`SuppressionKind::Enable`]: Always signal (default) - good for latency
    /// - [`SuppressionKind::Disable`]: Never signal - caller must poll
    /// - [`SuppressionKind::Descriptor`]: Signal only at specific cursor position - good for batching
    ///
    /// # Example: Polling Mode
    /// ```ignore
    /// consumer.set_avail_suppression(SuppressionKind::Disable)?;
    /// loop {
    ///     while let Some(req) = consumer.poll_once(1024)? {
    ///         process(req);
    ///     }
    ///     // ... do other work ...
    /// }
    /// ```
    pub fn set_avail_suppression(&mut self, kind: SuppressionKind) -> Result<(), VirtqError> {
        match kind {
            SuppressionKind::Enable => self.inner.enable_avail_notifications()?,
            SuppressionKind::Disable => self.inner.disable_avail_notifications()?,
            SuppressionKind::Descriptor(cursor) => {
                self.inner
                    .enable_avail_notifications_desc(cursor.head(), cursor.wrap())?
            }
        }
        Ok(())
    }
}

#[inline]
fn parse_single_req_resp(
    chain: &BufferChain,
) -> Result<(BufferElement, BufferElement), VirtqError> {
    let r = chain.readables();
    let w = chain.writables();

    if r.len() != 1 || w.len() != 1 {
        return Err(VirtqError::BadChain);
    }

    Ok((r[0], w[0]))
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

#[cfg(test)]
mod tests {
    use alloc::rc::Rc;
    use core::cell::RefCell;

    use super::*;
    use crate::virtq::ring::tests::{make_ring, OwnedRing, TestMem};

    /// Simple notifier that tracks notification count
    #[derive(Debug, Clone)]
    struct TestNotifier {
        count: Rc<RefCell<usize>>,
    }

    impl TestNotifier {
        fn new() -> Self {
            Self {
                count: Rc::new(RefCell::new(0)),
            }
        }

        fn notification_count(&self) -> usize {
            *self.count.borrow()
        }
    }

    impl Notifier for TestNotifier {
        fn notify(&self, _stats: QueueStats) {
            *self.count.borrow_mut() += 1;
        }
    }

    /// Simple test buffer pool that allocates from a range
    #[derive(Clone)]
    struct TestPool {
        base: u64,
        next: Rc<RefCell<u64>>,
        size: usize,
    }

    impl TestPool {
        fn new(base: u64, size: usize) -> Self {
            Self {
                base,
                next: Rc::new(RefCell::new(base)),
                size,
            }
        }
    }

    impl BufferProvider for TestPool {
        fn alloc(&self, len: usize) -> Result<Allocation, AllocError> {
            let mut next = self.next.borrow_mut();
            let addr = *next;
            let end = addr + len as u64;
            if end > self.base + self.size as u64 {
                return Err(AllocError::OutOfMemory);
            }
            *next = end;
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

    /// Create test infrastructure for VirtqProducer tests
    fn make_test_producer(
        ring: &OwnedRing,
    ) -> (
        VirtqProducer<Rc<TestMem>, TestNotifier, TestPool>,
        VirtqConsumer<Rc<TestMem>, TestNotifier>,
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

    #[test]
    fn test_send_notifies() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, notifier) = make_test_producer(&ring);

        // send() should work and notify
        let token = producer.send(b"hello", 64).unwrap();
        assert!(notifier.notification_count() >= 1);

        // Consumer should see the request
        let req = consumer.poll_once(1024).unwrap().unwrap();
        assert_eq!(req.token, token);
    }

    #[test]
    fn test_batch_send_single() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, notifier) = make_test_producer(&ring);

        let initial_count = notifier.notification_count();

        let mut batch = producer.batch();
        let tok = batch.send(b"request", 64).unwrap();
        let result = batch.commit().unwrap();

        assert_eq!(result.tokens.len(), 1);
        assert_eq!(result.tokens[0], tok);
        assert!(result.notified);
        assert!(notifier.notification_count() > initial_count);

        // Consumer should see the request
        let req = consumer.poll_once(1024).unwrap().unwrap();
        assert_eq!(req.token, tok);
    }

    #[test]
    fn test_batch_send_multiple() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, notifier) = make_test_producer(&ring);

        let initial_count = notifier.notification_count();

        let mut batch = producer.batch();
        let tok1 = batch.send(b"request1", 64).unwrap();
        let tok2 = batch.send(b"request2", 64).unwrap();
        let tok3 = batch.send(b"request3", 64).unwrap();

        assert_eq!(batch.len(), 3);
        assert!(!batch.is_empty());

        let result = batch.commit().unwrap();

        assert_eq!(result.tokens.len(), 3);
        assert_eq!(result.tokens[0], tok1);
        assert_eq!(result.tokens[1], tok2);
        assert_eq!(result.tokens[2], tok3);

        // Only one notification for the entire batch
        let notification_delta = notifier.notification_count() - initial_count;
        assert_eq!(notification_delta, 1);

        // Consumer sees all requests
        for _ in 0..3 {
            consumer.poll_once(1024).unwrap().unwrap();
        }
    }

    #[test]
    fn test_batch_empty_commit() {
        let ring = make_ring(16);
        let (mut producer, _consumer, notifier) = make_test_producer(&ring);

        let initial_count = notifier.notification_count();

        let batch = producer.batch();
        assert!(batch.is_empty());

        let result = batch.commit().unwrap();

        assert!(result.tokens.is_empty());
        assert!(!result.notified);
        assert_eq!(notifier.notification_count(), initial_count);
    }

    #[test]
    fn test_batch_abort() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, notifier) = make_test_producer(&ring);

        let initial_count = notifier.notification_count();

        let mut batch = producer.batch();
        let _tok = batch.send(b"request", 64).unwrap();
        batch.dismiss();

        // No notification on abort
        assert_eq!(notifier.notification_count(), initial_count);

        // But the request is still in-flight and consumable
        let req = consumer.poll_once(1024).unwrap().unwrap();
        assert_eq!(&req.data[..], b"request");
    }

    #[test]
    fn test_batch_drop_notifies() {
        let ring = make_ring(16);
        let (mut producer, _consumer, notifier) = make_test_producer(&ring);

        let initial_count = notifier.notification_count();

        {
            let mut batch = producer.batch();
            let _tok = batch.send(b"request", 64).unwrap();
            // Drop without commit or abort
        }

        // Drop should trigger conservative notification
        assert!(notifier.notification_count() > initial_count);
    }

    #[test]
    fn test_set_used_suppression() {
        let ring = make_ring(16);
        let (mut producer, _consumer, _notifier) = make_test_producer(&ring);

        // Test Enable mode
        producer.set_used_suppression(SuppressionKind::Enable).unwrap();

        // Test Disable mode
        producer.set_used_suppression(SuppressionKind::Disable).unwrap();

        // Test Descriptor mode
        let cursor = producer.used_cursor();
        producer
            .set_used_suppression(SuppressionKind::Descriptor(cursor))
            .unwrap();
    }

    #[test]
    fn test_set_avail_suppression() {
        let ring = make_ring(16);
        let (_producer, mut consumer, _notifier) = make_test_producer(&ring);

        // Test Enable mode
        consumer.set_avail_suppression(SuppressionKind::Enable).unwrap();

        // Test Disable mode
        consumer.set_avail_suppression(SuppressionKind::Disable).unwrap();

        // Test Descriptor mode
        let cursor = consumer.avail_cursor();
        consumer
            .set_avail_suppression(SuppressionKind::Descriptor(cursor))
            .unwrap();
    }

    #[test]
    fn test_batch_result_cursor_after() {
        let ring = make_ring(16);
        let (mut producer, _consumer, _notifier) = make_test_producer(&ring);

        // Empty batch should have cursor at start
        let batch = producer.batch();
        let result = batch.commit().unwrap();
        let initial_cursor = result.cursor_after;

        // Batch with requests should advance cursor
        let mut batch = producer.batch();
        batch.send(b"req1", 64).unwrap();
        batch.send(b"req2", 64).unwrap();
        let result = batch.commit().unwrap();

        // Cursor should have advanced (each request uses 2 descriptors: req + resp)
        assert!(
            result.cursor_after.head() != initial_cursor.head()
                || result.cursor_after.wrap() != initial_cursor.wrap()
        );
    }

    #[test]
    fn test_completion_batching_pattern() {
        let ring = make_ring(16);
        let (mut producer, mut consumer, _notifier) = make_test_producer(&ring);

        // Send batch of requests
        let mut batch = producer.batch();
        let tok1 = batch.send(b"req1", 64).unwrap();
        let tok2 = batch.send(b"req2", 64).unwrap();
        let tok3 = batch.send(b"req3", 64).unwrap();
        let result = batch.commit().unwrap();

        // Set up completion batching - notify only after all 3 complete
        producer
            .set_used_suppression(SuppressionKind::Descriptor(result.cursor_after))
            .unwrap();

        // Consumer processes requests
        for _ in 0..3 {
            let req = consumer.poll_once(1024).unwrap().unwrap();
            consumer.complete(req.token, b"response").unwrap();
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
    //! - `Pool`: Buffer pool for request/response data

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
                let tok = prod.send(b"ping", 32).unwrap();
                loop {
                    if let Some(r) = prod.poll_once().unwrap() {
                        assert_eq!(r.token, tok);
                        assert_eq!(&r.data[..], b"pong");
                        break;
                    }
                    thread::yield_now();
                }
            });

            let t_cons = thread::spawn(move || {
                let req = loop {
                    if let Some(r) = cons.poll_once(1024).unwrap() {
                        break r;
                    }
                    thread::yield_now();
                };
                assert_eq!(&req.data[..], b"ping");
                cons.complete(req.token, b"pong").unwrap();
            });

            t_prod.join().unwrap();
            t_cons.join().unwrap();
        });
    }
}
