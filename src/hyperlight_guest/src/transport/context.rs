// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Guest virtqueue context.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::result;

use hyperlight_common::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
use hyperlight_common::flatbuffer_wrappers::function_types::{
    FunctionCallResult, ParameterValue, ReturnType, ReturnValue,
};
use hyperlight_common::flatbuffer_wrappers::guest_error::{ErrorCode, GuestError};
use hyperlight_common::layout::scratch_transport_end_gva;
use hyperlight_common::outb::OutBAction;
use hyperlight_common::stream::{DEFAULT_WINDOW, Mux, Side};
use hyperlight_common::transport::{
    EncodedMessage, ExternalValues, MailboxValue, MsgHeader, MsgKind, PendingMessage,
};
use hyperlight_common::virtq::{
    AllocError, BootstrapInfo, G2H_LOWER_SLOT_COUNT, G2H_LOWER_SLOT_SIZE, Layout, Notifier,
    QueueStats, Segments, SendChain, SlotLayout, SlotPool, Token, UsedChain, VirtqError,
    VirtqProducer, h2g_pool_layout,
};
use hyperlight_common::vmem::PAGE_SIZE;

use super::{GuestMemOps, codec};
use crate::error::{GuestErrorContext, Result};
use crate::exit::out32;
use crate::{bail, ensure, layout, task};

/// Exits to the host to process available virtqueue work.
#[derive(Clone, Copy)]
pub struct OutbNotifier;

impl Notifier for OutbNotifier {
    fn notify(&self, _stats: QueueStats) {
        unsafe {
            out32(OutBAction::VirtqNotify as u16, 0);
        }
    }
}

#[derive(Clone, Copy)]
pub struct NoopNotifier;

impl Notifier for NoopNotifier {
    fn notify(&self, _stats: QueueStats) {}
}

/// Type alias for the guest-side G2H producer.
type G2hProducer = VirtqProducer<GuestMemOps, OutbNotifier>;

/// Type alias for the guest-side H2G producer.
type H2gProducer = VirtqProducer<GuestMemOps, NoopNotifier>;

/// Work selected by one H2G dispatch entry.
pub enum DispatchAction {
    /// Invoke one guest function and return its correlation ID.
    Call(u32, FunctionCall),
    /// Run ready tasks and flush stream records.
    Progress,
}

/// Configuration for one queue passed to [`GuestContext::new`].
#[derive(Debug)]
pub struct QueueConfig {
    /// Ring descriptor layout in shared memory.
    pub layout: Layout,
    /// Base GVA of the buffer pool region.
    pub pool_gva: u64,
    /// Number of pages in the buffer pool.
    pub pool_pages: usize,
    /// Size of each upper-tier buffer.
    pub buffer_size: usize,
}

/// Writable capacity reserved on a G2H request chain.
#[derive(Clone, Copy)]
enum ReplyCapacity {
    /// The chain carries no reply.
    None,
    /// Reserve at least this many reply bytes.
    Bounded(usize),
    /// Reserve at least one preferred allocation, then all remaining capacity.
    Available,
}

impl ReplyCapacity {
    /// Select reply capacity for one host function return type.
    fn for_return_type(return_type: ReturnType) -> Self {
        match return_type {
            // TODO: Bound tuples without byte elements by their largest encoding.
            ReturnType::String
            | ReturnType::VecBytes
            | ReturnType::ByteChunks
            | ReturnType::Tuple => Self::Available,
            _ => Self::Bounded(G2H_LOWER_SLOT_SIZE),
        }
    }
}

/// Virtqueue runtime state for guest-host communication.
pub struct GuestContext {
    /// Guest-to-host driver.
    g2h_producer: G2hProducer,
    /// Host-to-guest driver.
    h2g_producer: H2gProducer,
    /// Snapshot lineage whose scratch slots belong to the current pools.
    generation: u64,
    /// Size of each prefilled H2G buffer.
    h2g_slot_size: usize,
    /// Transport mailbox GVA.
    mbx_gva: u64,
    /// Correlation ID assigned to the next host-function request.
    next_cid: u32,
    /// Stream state of the session. Function calls and results move readers through it.
    mux: Mux,
    /// Reusable control storage for outgoing messages.
    encode_buffer: Vec<u8>,
}

impl GuestContext {
    /// Initialize G2H and H2G queues and post receive buffers.
    ///
    /// # Safety
    ///
    /// The caller must run in an initialized single-vCPU Hyperlight guest and
    /// exclusively own both queues, their pools, and the writable `u64` mailbox
    /// at `mbx_gva`. The mailbox must lie in scratch, disjoint from both queues
    /// and pools. Both rings and pools must lie in the transport arena, which
    /// starts at the G2H ring and ends below the reserved scratch-top pages,
    /// with the pools after the rings. Host consumers must be at their initial
    /// cursors. Scratch must remain mapped while the context or any returned
    /// buffer views exist.
    pub unsafe fn new(g2h: QueueConfig, h2g: QueueConfig, mbx_gva: u64) -> Result<Self> {
        // SAFETY: Generation has been initialized by host.
        let generation = unsafe { layout::snapshot_generation_gva().read_volatile() };

        let g2h_pool = g2h_pool(g2h.pool_gva, g2h.pool_pages, g2h.buffer_size)
            .with_context(|| "failed to create G2H pool")?;
        // The G2H ring starts the transport arena.
        let arena_gva = g2h.layout.desc_table_addr();
        let scratch_gva = layout::scratch_base_gva();
        // SAFETY: The caller owns the pool's scratch pages.
        let mem = unsafe { pool_mem(&g2h_pool, arena_gva, scratch_gva) }
            .with_context(|| "failed to initialize G2H pool access")?;
        g2h.layout
            .initialize(&mem)
            .with_context(|| "failed to initialize G2H ring")?;
        let g2h_producer = VirtqProducer::new(g2h.layout, mem, OutbNotifier, g2h_pool);

        let h2g_layout = h2g_pool_layout(h2g.pool_gva, h2g.pool_pages, h2g.buffer_size)
            .with_context(|| "invalid H2G pool geometry")?;
        let h2g_pool =
            SlotPool::from_layout(h2g_layout).with_context(|| "failed to create H2G slot pool")?;
        // SAFETY: The caller owns this disjoint pool.
        let mem = unsafe { pool_mem(&h2g_pool, arena_gva, scratch_gva) }
            .with_context(|| "failed to initialize H2G pool access")?;
        h2g.layout
            .initialize(&mem)
            .with_context(|| "failed to initialize H2G ring")?;
        // H2G prefill supplies writable buffers for host-initiated messages.
        let h2g_producer = VirtqProducer::new(h2g.layout, mem, NoopNotifier, h2g_pool);

        let mut ctx = Self {
            g2h_producer,
            h2g_producer,
            generation,
            h2g_slot_size: h2g.buffer_size,
            mbx_gva,
            next_cid: 1,
            mux: Mux::new(Side::Guest, DEFAULT_WINDOW),
            encode_buffer: Vec::new(),
        };

        ctx.prefill_h2g()?;
        Ok(ctx)
    }

    /// Call a host function via the G2H virtqueue.
    ///
    /// Slot-aligned external values use a separate readable region. The same
    /// chain carries bounded writable buffers for the response.
    ///
    /// # Errors
    ///
    /// Returns an error when encoding, queue submission, host dispatch,
    /// or response validation fails.
    pub fn call_host_function(
        &mut self,
        function_name: &str,
        parameters: Option<Vec<ParameterValue>>,
        return_type: ReturnType,
    ) -> Result<ReturnValue> {
        let fc = FunctionCall::new(
            function_name.into(),
            parameters,
            FunctionCallType::Host,
            return_type,
        );

        let cid = self.allocate_cid();
        let pending = PendingMessage::new_call(fc, cid, &mut self.mux)
            .with_context(|| "failed to prepare host function call")?;
        let message = pending
            .encode(&mut self.encode_buffer)
            .with_context(|| "failed to encode host function call")?;

        let reply_cap = ReplyCapacity::for_return_type(return_type);

        // Submit once more after forcing the host to drain on backpressure.
        let mut res = Self::try_send(&mut self.g2h_producer, &message, reply_cap);
        let retried = matches!(&res, Err(error) if error.is_transient());

        if retried {
            self.g2h_producer.notify_backpressure();

            if let Err(error) = self.g2h_producer.reclaim() {
                bail!("G2H reclaim: {error}");
            }

            res = Self::try_send(&mut self.g2h_producer, &message, reply_cap);
        }

        drop(message);

        let token = match pending.settle(res) {
            Ok(token) => token,
            Err(error) if retried => bail!("G2H call retry: {error}"),
            Err(error) => bail!("G2H call: {error}"),
        };

        // Poll completions, skipping earlier one-way acknowledgements until
        // the request reply is available.
        let reply = loop {
            let Some(reply) = self.g2h_producer.poll()? else {
                bail!("G2H: no reply received");
            };
            if reply.token() == token {
                break reply;
            }
            if matches!(&reply, UsedChain::Data(..)) {
                bail!("G2H: unexpected reply token {:?}", reply.token());
            }
        };

        let segments = match reply {
            UsedChain::Data(_, segments) => segments,
            UsedChain::Ack(_) => bail!("G2H: response was ack-only"),
        };

        // Decode external ByteChunks without flattening their transport-backed
        // segments.
        let fcr = codec::decode_response(segments, cid, &mut self.mux)?;
        Ok(fcr.into_inner()?)
    }

    /// Receive one host-to-guest dispatch action.
    ///
    /// External `ByteChunks` retain their owner-backed H2G slots. Contiguous
    /// `VecBytes` values copy directly into their final `Vec<u8>`.
    pub fn recv_h2g_dispatch(&mut self) -> Result<DispatchAction> {
        self.g2h_producer
            .reclaim()
            .with_context(|| "G2H completion reclaim failed")?;

        let Some((header, payload)) = self.recv_h2g_message()? else {
            return Ok(DispatchAction::Progress);
        };

        let action = match header.kind {
            MsgKind::Request => {
                ensure!(header.cid != 0, "Invalid request framing");
                let call = codec::decode_request(header.control_len, payload, &mut self.mux)?;
                DispatchAction::Call(header.cid, call)
            }
            MsgKind::Stream => {
                // ensure cid downstream
                self.recv_stream(header, payload)?;
                DispatchAction::Progress
            }
            _ => bail!("H2G buffer has invalid request framing"),
        };

        // Apply the Stream messages that follow.
        while let Some((header, payload)) = self.recv_h2g_message()? {
            self.recv_stream(header, payload)?;
        }

        Ok(action)
    }

    /// Apply one H2G `Stream` message.
    fn recv_stream(&mut self, header: MsgHeader, payload: Segments) -> Result<()> {
        ensure!(
            header.kind == MsgKind::Stream && header.cid == 0,
            "Invalid stream record"
        );
        codec::recv_stream(header.control_len, payload, &mut self.mux)
    }

    /// Receive the next H2G message header and payload, or `None` when no buffer is used.
    ///
    /// A message fills its first buffer and the continuation buffers its payload length needs.
    fn recv_h2g_message(&mut self) -> Result<Option<(MsgHeader, Segments)>> {
        let Some(used) = self.h2g_producer.poll()? else {
            return Ok(None);
        };

        let mut payload = match used {
            UsedChain::Data(_, segments) => segments,
            UsedChain::Ack(_) => bail!("H2G buffer was ack-only"),
        };

        let header = payload
            .split_to(MsgHeader::SIZE)
            .context("H2G buffer is missing its message header")?
            .into_bytes();

        let Some(header) = MsgHeader::from_bytes(&header) else {
            bail!("H2G buffer has an invalid message header");
        };

        let payload_len =
            usize::try_from(header.payload_len).context("H2G payload length overflow")?;

        let mut received = payload.len();
        if received > payload_len {
            bail!("H2G first buffer exceeds the declared payload length");
        }

        while received < payload_len {
            let Some(used) = self.h2g_producer.poll()? else {
                bail!("H2G: expected a continuation buffer");
            };

            let segments = match used {
                UsedChain::Data(_, segments) => segments,
                UsedChain::Ack(_) => bail!("H2G continuation buffer was ack-only"),
            };

            if segments.is_empty() {
                bail!("H2G continuation buffer is empty");
            }

            received = received
                .checked_add(segments.len())
                .context("H2G payload length overflow")?;

            if received > payload_len {
                bail!("H2G buffers exceed the declared payload length");
            }
            payload.append(segments);
        }

        Ok(Some((header, payload)))
    }

    /// Return a guest-function result, flush stream records and STATUS, and replenish H2G receive
    /// buffers.
    pub fn send_h2g_result(&mut self, cid: u32, result: FunctionCallResult) -> Result<()> {
        self.g2h_producer.reclaim()?;

        if let Some(message) = self.send_result(cid, result)? {
            let error =
                FunctionCallResult::new(Err(GuestError::new(ErrorCode::GuestError, message)));

            if let Some(reason) = self.send_result(cid, error)? {
                bail!("G2H error response submission failed: {reason}");
            }
        }

        self.flush_streams(1)?;
        self.publish_status(false)?;
        self.prefill_h2g()
    }

    /// Publish a result, or return the admission error to send to the host.
    fn send_result(&mut self, cid: u32, result: FunctionCallResult) -> Result<Option<String>> {
        // Committing a reader transfer can change STATUS.
        let moves_reader = result.readers().next().is_some();

        let pending = match PendingMessage::new_result(result, cid, &mut self.mux) {
            Ok(pending) => pending,
            Err(error) => return Ok(Some(error.to_string())),
        };

        let encoded = pending
            .encode(&mut self.encode_buffer)
            .with_context(|| "failed to encode guest function result")?;

        let prod = &mut self.g2h_producer;
        let reserved = usize::from(moves_reader);

        let chain = Self::build_g2h_chain(prod, &encoded, reserved, ReplyCapacity::None);
        drop(encoded);

        let res = match chain {
            Ok(chain) if moves_reader => pending.settle(Self::submit_deferred(prod, chain)),
            Ok(chain) => {
                // There are no transfers to commit. Dropping the byte owners can free slots
                // or wake a guest task, so check room and STATUS after they drop.
                drop(pending);

                let full = chain.desc_count() == prod.num_free() || prod.pool().num_free() == 0;
                let maybe_status = PendingMessage::new_status(&mut self.mux, task::status());

                if full && maybe_status.is_some() {
                    Err(VirtqError::Backpressure)
                } else {
                    Self::submit_deferred(prod, chain)
                }
            }
            Err(error) => Err(error),
        };

        match res {
            Ok(_) => Ok(None),
            Err(error) if error.is_transient() => Ok(Some(
                "Guest response exceeds virtqueue capacity".to_string(),
            )),
            Err(error) => {
                self.mux.fail();
                bail!("G2H response submission failed: {error}");
            }
        }
    }

    /// Publish successful guest initialization at the startup halt.
    ///
    /// Fails while guest tasks or streams are live, since initialization publishes no STATUS for
    /// the host's snapshot gate.
    pub fn complete_initialization(&mut self) -> Result<()> {
        ensure!(
            task::status().is_empty() && !self.mux.has_live_streams(),
            "Initialization left live tasks or streams"
        );

        let status = MailboxValue::InitComplete.raw();
        // SAFETY: Construction requires an exclusively owned, mapped mailbox.
        unsafe { (self.mbx_gva as *mut u64).write_volatile(status) };

        Ok(())
    }

    /// End a progress turn: flush stream records, publish STATUS, and replenish H2G receive
    /// buffers.
    ///
    /// The flush may fill G2H. STATUS then notifies the host to drain it and retries once.
    pub fn finish_progress_turn(&mut self) -> Result<()> {
        self.g2h_producer.reclaim()?;
        self.flush_streams(0)?;
        self.publish_status(true)?;
        self.prefill_h2g()
    }

    /// Publish pending stream records for the host to apply after the final halt.
    ///
    /// Each message fits the largest G2H slot free when the flush starts, and leaves `reserve`
    /// descriptors and slots free. Retained host replies can hold every upper slot, and lower
    /// slots then carry the records. A full queue or pool stops the flush and leaves the remaining
    /// records pending for the next turn. Any other error is fatal.
    fn flush_streams(&mut self, reserve: usize) -> Result<()> {
        // Once per flush, so DATA splits into lower-slot messages only when no upper slot is free.
        let Some(max_len) = self.g2h_producer.pool().max_free_slot_size() else {
            return Ok(());
        };

        let prod = &mut self.g2h_producer;

        while let Some(pending) = PendingMessage::next_stream(&mut self.mux, max_len) {
            let encoded = pending
                .encode(&mut self.encode_buffer)
                .with_context(|| "failed to encode G2H stream message")?;

            let res = Self::try_send_deferred(prod, &encoded, reserve, ReplyCapacity::None);
            drop(encoded);

            match pending.settle(res) {
                Ok(_) => {}
                Err(error) if error.is_transient() => break,
                Err(error) => bail!("G2H stream message: {error}"),
            }
        }

        Ok(())
    }

    /// Publish STATUS when the guest's activity changed.
    ///
    /// Call it after the flush, so READY covers the records left pending. A call turn publishes
    /// into the room its flush left and cannot retry, since nothing after the Response notifies
    /// the host. A progress turn retries once after the host drains G2H.
    fn publish_status(&mut self, retry: bool) -> Result<()> {
        let status = task::status();

        let Some(pending) = PendingMessage::new_status(&mut self.mux, status) else {
            return Ok(());
        };

        let encoded = pending
            .encode(&mut self.encode_buffer)
            .with_context(|| "failed to encode G2H status")?;

        let producer = &mut self.g2h_producer;
        let mut res = Self::try_send_deferred(producer, &encoded, 0, ReplyCapacity::None);

        // Retry once on backpressure
        if retry && matches!(&res, Err(err) if err.is_transient()) {
            producer.notify_backpressure();

            if let Err(err) = producer.reclaim() {
                bail!("G2H status reclaim: {err}");
            }

            res = Self::try_send_deferred(producer, &encoded, 0, ReplyCapacity::None);
        }

        drop(encoded);

        if let Err(error) = pending.settle(res) {
            bail!("G2H status: {error}");
        }

        Ok(())
    }

    /// Reconstruct transport ownership for the host's current generation.
    ///
    /// Retained owners keep captured aliases and old pool leases. Private storage
    /// is reused without touching requests written by the host before guest entry.
    pub fn maybe_refresh(&mut self) {
        // SAFETY: Construction requires initialized guest scratch metadata.
        let generation = unsafe { layout::snapshot_generation_gva().read_volatile() };

        if self.generation == generation {
            return;
        }

        let g2h = &self.g2h_producer;
        let g2h_info =
            BootstrapInfo::empty(g2h.layout(), g2h.pool().layout()).expect("invalid G2H bootstrap");

        let h2g = &self.h2g_producer;
        let h2g_info = BootstrapInfo::prefilled(h2g.layout(), h2g.pool().layout())
            .expect("invalid H2G bootstrap");

        // SAFETY: The host discarded the old queues and installed the matching
        // bootstrap with no live chain handles or builders. No producer has run.
        // Retained views have captured backing and old pool handles only release leases.
        unsafe {
            self.g2h_producer
                .refresh(g2h_info)
                .expect("G2H ownership reconstruction failed");
            self.h2g_producer
                .refresh(h2g_info)
                .expect("H2G ownership reconstruction failed");
        }

        self.generation = generation;
    }

    /// Send a log message via the G2H queue.
    ///
    /// Current notification policy exits to the host for every log.
    ///
    /// # Errors
    ///
    /// Returns an error when the message cannot be framed or submitted.
    pub fn emit_log(&mut self, log_data: &[u8]) -> Result<()> {
        let message = EncodedMessage::new(MsgKind::Log, 0, log_data, ExternalValues::new())
            .context("G2H message length overflow")?;
        self.send_g2h_oneshot(&message)
    }

    /// Publish one writable H2G chain for each currently free slot.
    fn prefill_h2g(&mut self) -> Result<()> {
        let mut batch = self.h2g_producer.batch();

        loop {
            let chain = match batch.chain().writable(self.h2g_slot_size).build() {
                Ok(chain) => chain,
                Err(error) if error.is_transient() => {
                    batch.finish_without_notify();
                    return Ok(());
                }
                Err(error) => bail!("H2G prefill build: {error}"),
            };

            match batch.submit(chain) {
                Ok(_) => {}
                Err(error) if error.is_transient() => {
                    batch.finish_without_notify();
                    return Ok(());
                }
                Err(error) => bail!("H2G prefill submit: {error}"),
            }
        }
    }

    /// Submit a one-way G2H message without polling its acknowledgement.
    ///
    /// Completed acknowledgements remain available for normal polling or
    /// reclamation when later submissions encounter backpressure.
    fn send_g2h_oneshot(&mut self, message: &EncodedMessage<'_>) -> Result<()> {
        match Self::try_send(&mut self.g2h_producer, message, ReplyCapacity::None) {
            Ok(_) => Ok(()),
            Err(error) if error.is_transient() => {
                // VM exit so host drains and completes G2H entries.
                self.g2h_producer.notify_backpressure();

                if let Err(error) = self.g2h_producer.reclaim() {
                    bail!("G2H one-way reclaim: {error}");
                }

                match Self::try_send(&mut self.g2h_producer, message, ReplyCapacity::None) {
                    Ok(_) => Ok(()),
                    Err(error) => bail!("G2H one-way retry: {error}"),
                }
            }
            Err(error) => bail!("G2H one-way message: {error}"),
        }
    }

    /// Build and submit one G2H descriptor chain.
    ///
    /// `reply_cap` defines optional host-function reply space. The helpers
    /// borrow only the producer, so they run while an outgoing call borrows
    /// the Mux.
    fn try_send(
        producer: &mut G2hProducer,
        message: &EncodedMessage<'_>,
        reply_cap: ReplyCapacity,
    ) -> result::Result<Token, VirtqError> {
        let chain = Self::build_g2h_chain(producer, message, 0, reply_cap)?;
        producer.submit(chain)
    }

    /// Submit one G2H message for polling after the existing final halt leaving `reserve`
    /// ring descriptors and pool slots free, or reports backpressure.
    fn try_send_deferred(
        producer: &mut G2hProducer,
        message: &EncodedMessage<'_>,
        reserve: usize,
        reply_cap: ReplyCapacity,
    ) -> result::Result<Token, VirtqError> {
        let chain = Self::build_g2h_chain(producer, message, reserve, reply_cap)?;
        Self::submit_deferred(producer, chain)
    }

    /// Leave notification of this chain to the turn's halt.
    fn submit_deferred(
        producer: &mut G2hProducer,
        chain: SendChain<GuestMemOps>,
    ) -> result::Result<Token, VirtqError> {
        let mut batch = producer.batch();
        let token = batch.submit(chain)?;

        batch.finish_without_notify();
        Ok(token)
    }

    /// Build and initialize one G2H message chain, leaving `reserve` descriptors and slots free.
    fn build_g2h_chain(
        producer: &G2hProducer,
        message: &EncodedMessage<'_>,
        reserve: usize,
        reply_cap: ReplyCapacity,
    ) -> result::Result<SendChain<GuestMemOps>, VirtqError> {
        let segment_len = producer.preferred_segment_len();
        let mut builder = producer.chain().keep_free(reserve);

        for len in message_region_lengths(message, segment_len) {
            builder = builder.readable(len);
        }

        let builder = match reply_cap {
            ReplyCapacity::None => builder,
            ReplyCapacity::Bounded(cap) => builder.writable(cap),
            ReplyCapacity::Available => builder.writable(segment_len).writable_avail(),
        };

        let mut chain = builder.build()?;
        for chunk in message.chunks() {
            chain.write_all(chunk)?;
        }

        Ok(chain)
    }

    /// Allocate a new correlation ID for a host function request.
    fn allocate_cid(&mut self) -> u32 {
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);

        if self.next_cid == 0 {
            self.next_cid = 1;
        }
        cid
    }
}

/// Group message bytes into logical readable region lengths.
fn message_region_lengths(
    message: &EncodedMessage<'_>,
    segment_len: usize,
) -> impl Iterator<Item = usize> {
    let external_len = message.external_len();
    let split_external = external_len != 0 && external_len.is_multiple_of(segment_len);

    let first_len = if split_external {
        message.prefix_len()
    } else {
        message.total_len()
    };

    core::iter::once(first_len).chain(split_external.then_some(external_len))
}

fn pool_len(pages: usize) -> result::Result<usize, AllocError> {
    pages
        .checked_mul(hyperlight_common::vmem::PAGE_SIZE)
        .ok_or(AllocError::Overflow)
}

/// Validate pool placement and bind access to the arena up to the pool's end.
///
/// The bounds start at the arena, whose address does not depend on the
/// scratch size. The pools follow the rings, so a producer's rings and pool
/// lie in [arena, end of its pool). That range must start in scratch above
/// `scratch_gva`, where the copied page tables sit, and end below the guard
/// page under the reserved scratch-top pages.
///
/// # Safety
///
/// Run on the initialized guest vCPU and own the pool's scratch.
unsafe fn pool_mem(
    pool: &SlotPool,
    arena_gva: u64,
    scratch_gva: u64,
) -> result::Result<GuestMemOps, AllocError> {
    let limit = scratch_transport_end_gva();

    let base = pool.base_addr();
    let end = base + pool.byte_len() as u64;

    if !arena_gva.is_multiple_of(PAGE_SIZE as u64)
        || arena_gva <= scratch_gva
        || !base.is_multiple_of(PAGE_SIZE as u64)
        || base < arena_gva
        || end > limit
    {
        return Err(AllocError::InvalidArg);
    }

    // SAFETY: The validated pool lies in the arena on the serialized guest vCPU.
    unsafe { Ok(GuestMemOps::new(arena_gva, end)) }
}

/// Build the tiered G2H pool.
///
/// One page of 256-byte slots serves small control and log messages without
/// consuming configured-size slots. Complete slots in the remaining pages form
/// the upper tier.
fn g2h_pool(base: u64, pages: usize, upper_size: usize) -> result::Result<SlotPool, AllocError> {
    if upper_size == 0 {
        return Err(AllocError::InvalidArg);
    }
    let pool_len = pool_len(pages)?;
    let lower_len = G2H_LOWER_SLOT_COUNT
        .checked_mul(G2H_LOWER_SLOT_SIZE)
        .ok_or(AllocError::Overflow)?;

    let upper_len = pool_len
        .checked_sub(lower_len)
        .ok_or(AllocError::EmptyRegion)?;

    let upper_count = upper_len / upper_size;

    let lower = SlotLayout::new(base, G2H_LOWER_SLOT_SIZE, G2H_LOWER_SLOT_COUNT)?;
    let upper = SlotLayout::new(lower.end_addr(), upper_size, upper_count)?;
    SlotPool::new_tiered(lower, upper)
}

#[cfg(test)]
mod tests {
    use hyperlight_common::flatbuffer_wrappers::ExternalValueSink;

    use super::*;

    #[test]
    fn pool_mem_binds_the_arena_below_the_reserved_top() {
        let limit = scratch_transport_end_gva();
        let page = PAGE_SIZE as u64;
        let arena = limit - 8 * page;
        let scratch = arena - 16 * page;
        let pool = |base, pages| {
            SlotPool::from_layout(h2g_pool_layout(base, pages, 256).unwrap()).unwrap()
        };
        // SAFETY: only bounds are computed. No memory is touched.
        unsafe {
            assert!(pool_mem(&pool(arena + 4 * page, 4), arena, scratch).is_ok());
            // Into the guard page or the reserved pages.
            assert!(pool_mem(&pool(arena + 4 * page, 5), arena, scratch).is_err());
            // Below the arena.
            assert!(pool_mem(&pool(arena - page, 1), arena, scratch).is_err());
            // An arena below scratch, at its base, or not page aligned.
            assert!(pool_mem(&pool(arena + 4 * page, 4), 0, scratch).is_err());
            assert!(pool_mem(&pool(arena + 4 * page, 4), scratch, scratch).is_err());
            assert!(pool_mem(&pool(arena + 4 * page, 4), arena + 8, scratch).is_err());
        }
    }

    fn encoded_message(external: &[u8]) -> EncodedMessage<'_> {
        let mut values = ExternalValues::new();
        values.push_bytes(external).unwrap();
        EncodedMessage::new(MsgKind::Request, 1, b"control", values).unwrap()
    }

    #[test]
    fn message_regions_split_only_aligned_external_values() {
        let aligned = [0; 4096];
        let message = encoded_message(&aligned);
        let regions = message_region_lengths(&message, 4096).collect::<Vec<_>>();
        assert_eq!(regions, [message.prefix_len(), aligned.len()]);

        let unaligned = [0; 4095];
        let message = encoded_message(&unaligned);
        let regions = message_region_lengths(&message, 4096).collect::<Vec<_>>();
        assert_eq!(regions, [message.total_len()]);
    }
}
