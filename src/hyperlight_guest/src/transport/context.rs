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

//! Guest virtqueue context.

use alloc::vec::Vec;
use core::result;

use flatbuffers::FlatBufferBuilder;
use hyperlight_common::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
use hyperlight_common::flatbuffer_wrappers::function_types::{
    FunctionCallResult, ParameterValue, ReturnType, ReturnValue,
};
use hyperlight_common::flatbuffer_wrappers::guest_error::GuestError;
use hyperlight_common::flatbuffer_wrappers::util::estimate_flatbuffer_capacity;
use hyperlight_common::outb::OutBAction;
use hyperlight_common::transport::{EncodedMessage, ExternalValueRefs, MsgHeader, MsgKind};
use hyperlight_common::virtq::{
    AllocError, BufferProvider, G2H_LOWER_SLOT_COUNT, G2H_LOWER_SLOT_SIZE, Layout, Notifier,
    QueueStats, Segments, SendChain, SlotLayout, SlotPool, Token, UsedChain, VirtqError,
    VirtqProducer,
};

use super::{GuestMemOps, codec};
use crate::bail;
use crate::error::{GuestErrorContext, Result};
use crate::exit::out32;

/// G2H notifier that exits to the host to process available work.
#[derive(Clone, Copy)]
pub struct G2hNotifier;

impl Notifier for G2hNotifier {
    fn notify(&self, _stats: QueueStats) {
        unsafe {
            out32(OutBAction::VirtqNotify as u16, 0);
        }
    }
}

/// H2G prefill does not notify before the host consumer is attached.
#[derive(Clone, Copy)]
pub struct H2gNotifier;

impl Notifier for H2gNotifier {
    fn notify(&self, _stats: QueueStats) {}
}

/// Type alias for the guest-side G2H producer.
pub type G2hProducer = VirtqProducer<GuestMemOps, G2hNotifier, SlotPool>;

/// Type alias for the guest-side H2G producer.
pub type H2gProducer = VirtqProducer<GuestMemOps, H2gNotifier, SlotPool>;

/// Configuration for one queue passed to [`GuestContext::new`].
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

/// Virtqueue runtime state for guest-host communication.
pub struct GuestContext {
    /// Guest-to-host driver.
    g2h_producer: G2hProducer,
    /// G2H pool state used to size writable replies.
    g2h_pool: SlotPool,
    /// Host-to-guest driver.
    h2g_producer: H2gProducer,
    /// Size of each prefilled H2G buffer.
    h2g_slot_size: usize,
    /// Correlation ID assigned to the next host-function request.
    next_cid: u32,
    /// Used by the C API.
    last_host_result: Option<Result<ReturnValue>>,
    /// Error set by a C guest function.
    last_guest_error: Option<GuestError>,
}

impl GuestContext {
    /// Create a new context with G2H and H2G queues.
    pub fn new(g2h: QueueConfig, h2g: QueueConfig) -> Result<Self> {
        let g2h_pool = g2h_pool(g2h.pool_gva, g2h.pool_pages, g2h.buffer_size)
            .with_context(|| "failed to create G2H pool")?;
        let mem = GuestMemOps::for_scratch();
        let g2h_producer = VirtqProducer::new(g2h.layout, mem, G2hNotifier, g2h_pool.clone());

        let h2g_pool = h2g_pool(h2g.pool_gva, h2g.pool_pages, h2g.buffer_size)
            .with_context(|| "failed to create H2G slot pool")?;
        let h2g_producer = VirtqProducer::new(h2g.layout, mem, H2gNotifier, h2g_pool.clone());

        let mut ctx = Self {
            g2h_producer,
            g2h_pool,
            h2g_producer,
            h2g_slot_size: h2g.buffer_size,
            next_cid: 1,
            last_host_result: None,
            last_guest_error: None,
        };

        ctx.prefill_h2g()?;
        Ok(ctx)
    }

    /// Record an error raised through the C guest API.
    pub fn set_guest_error(&mut self, error: GuestError) {
        self.last_guest_error = Some(error);
    }

    /// Take an error raised through the C guest API.
    pub fn take_guest_error(&mut self) -> Option<GuestError> {
        self.last_guest_error.take()
    }

    /// Call a host function via the G2H virtqueue.
    ///
    /// Control data and borrowed external values form one readable request.
    /// The same chain carries bounded writable buffers for the response.
    ///
    /// # Errors
    ///
    /// Returns an error when encoding, queue submission, host dispatch,
    /// response validation, or return-value conversion fails.
    pub fn call_host_function<T: TryFrom<ReturnValue>>(
        &mut self,
        function_name: &str,
        parameters: Option<Vec<ParameterValue>>,
        return_type: ReturnType,
    ) -> Result<T> {
        // Encode control data separately from borrowed external byte values.
        let params = parameters.as_deref().unwrap_or_default();
        let estimated_capacity = estimate_flatbuffer_capacity(function_name, params);

        let fc = FunctionCall::new(
            function_name.into(),
            parameters,
            FunctionCallType::Host,
            return_type,
        );

        let mut builder = FlatBufferBuilder::with_capacity(estimated_capacity);
        let mut externals = ExternalValueRefs::new();

        let control = fc
            .encode(&mut builder, &mut externals)
            .with_context(|| "failed to encode host function call")?;

        // Frame the request and include external values in its total length.
        let cid = self.allocate_cid();
        let msg = EncodedMessage::new(MsgKind::Request, cid, control, externals)
            .context("G2H message length overflow")?;

        // Reserve response capacity from the ring and pool state that remains
        // after this request.
        let reply_cap = self.reply_capacity(msg.total_len(), return_type)?;

        // Submit once more after forcing the host to drain on backpressure.
        let token = match self.try_send(&msg, Some(reply_cap)) {
            Ok(token) => token,
            Err(error) if error.is_transient() => {
                self.g2h_producer.notify_backpressure();

                if let Err(error) = self.g2h_producer.reclaim() {
                    bail!("G2H reclaim: {error}");
                }

                match self.try_send(&msg, Some(reply_cap)) {
                    Ok(token) => token,
                    Err(error) => bail!("G2H call retry: {error}"),
                }
            }
            Err(error) => {
                bail!("G2H call: {error}");
            }
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
        let fcr = codec::decode_response(segments, cid)?;
        let ret = fcr.into_inner()?;

        let Ok(ret) = T::try_from(ret) else {
            bail!("G2H: host return value type mismatch");
        };

        Ok(ret)
    }

    /// Receive one host-to-guest function call.
    ///
    /// External `ByteChunks` retain their owner-backed H2G slots. Contiguous
    /// `VecBytes` values copy directly into their final `Vec<u8>`.
    pub fn recv_h2g_call(&mut self) -> Result<(u32, FunctionCall)> {
        self.g2h_producer
            .reclaim()
            .with_context(|| "G2H completion reclaim failed")?;

        let Some(used) = self.h2g_producer.poll()? else {
            bail!("H2G: expected a guest function call buffer");
        };

        let mut first = match used {
            UsedChain::Data(_, segments) => segments,
            UsedChain::Ack(_) => bail!("H2G: guest function call buffer was ack-only"),
        };

        let header = first
            .split_to(MsgHeader::SIZE)
            .context("H2G buffer is missing its message header")?
            .into_bytes();

        let Some(header) = MsgHeader::from_bytes(&header) else {
            bail!("H2G buffer has an invalid message header");
        };
        if header.msg_kind() != Ok(MsgKind::Request) || header.cid == 0 {
            bail!("H2G buffer has invalid request framing");
        }

        let payload_len =
            usize::try_from(header.payload_len).context("H2G payload length overflow")?;

        if first.len() > payload_len {
            bail!("H2G first buffer exceeds the declared payload length");
        }

        let mut received = first.len();
        let mut payload = first.into_chunks();

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
            payload.extend(segments.into_chunks());
        }

        codec::decode_request(header.cid, Segments::new(payload))
    }

    /// Return a guest-function result and replenish H2G receive buffers.
    pub fn send_h2g_result(&mut self, cid: u32, result: FunctionCallResult) -> Result<()> {
        self.g2h_producer
            .reclaim()
            .with_context(|| "G2H response reclaim failed")?;

        {
            let mut builder = FlatBufferBuilder::new();
            let mut external_values = ExternalValueRefs::new();

            let control = result
                .encode(&mut builder, &mut external_values)
                .with_context(|| "failed to encode guest function result")?;

            let msg = EncodedMessage::new(MsgKind::Response, cid, control, external_values)
                .context("G2H response length overflow")?;

            self.try_send_deferred(&msg, None)
                .with_context(|| "G2H response submission failed")?;
        }

        drop(result);
        self.prefill_h2g()
    }

    /// Send a log message via the G2H queue.
    ///
    /// Current notification policy exits to the host for every log.
    ///
    /// # Errors
    ///
    /// Returns an error when the message cannot be framed or submitted.
    pub fn emit_log(&mut self, log_data: &[u8]) -> Result<()> {
        let message = EncodedMessage::new(MsgKind::Log, 0, log_data, ExternalValueRefs::new())
            .context("G2H message length overflow")?;
        self.send_g2h_oneshot(&message)
    }

    /// Stash a host function result for later retrieval.
    ///
    /// Used by the C API's two-step calling convention where
    /// `hl_call_host_function` and `hl_get_host_return_value_as_*`
    /// are separate calls.
    pub fn stash_host_result(&mut self, result: Result<ReturnValue>) {
        self.last_host_result = Some(result);
    }

    /// Take the stashed host return value.
    ///
    /// Panics if no value was stashed or if the type conversion fails.
    /// If the stashed result was an error, panics with the error message.
    pub fn take_host_return<T: TryFrom<ReturnValue>>(&mut self) -> T {
        let value = self
            .last_host_result
            .take()
            .expect("No host return value available")
            .expect("Host function returned an error");

        match T::try_from(value) {
            Ok(value) => value,
            Err(_) => panic!("Host return value type mismatch"),
        }
    }

    /// Publish one writable H2G chain for each currently free slot.
    ///
    /// Retained external values reduce the number of available receive buffers
    /// until their final owner drops.
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

    /// Size writable reply buffers after accounting for the request.
    ///
    /// Variable returns use every remaining upper-tier slot allowed by ring
    /// descriptor headroom. Fixed returns reserve one lower-sized allocation,
    /// with the pool's normal upper-tier fallback.
    fn reply_capacity(&mut self, req_len: usize, return_type: ReturnType) -> Result<usize> {
        if let Some(cap) = self.try_reply_capacity(req_len, return_type)? {
            return Ok(cap);
        }

        // A deferred batch can own all available slots or descriptors. Force
        // one host drain and reclaim before reporting insufficient capacity.
        if self.g2h_producer.num_inflight() != 0 {
            self.g2h_producer.notify_backpressure();

            if let Err(error) = self.g2h_producer.reclaim() {
                bail!("G2H reclaim: {error}");
            }

            if let Some(capacity) = self.try_reply_capacity(req_len, return_type)? {
                return Ok(capacity);
            }
        }

        bail!("No virtqueue capacity remains for a host function response");
    }

    /// Calculate reply capacity without allocating request buffers.
    ///
    /// `None` means current ring or pool occupancy leaves no response capacity.
    fn try_reply_capacity(&self, req_len: usize, return_type: ReturnType) -> Result<Option<usize>> {
        let plan = match self.g2h_pool.plan_alloc(req_len) {
            Ok(request) => request,
            Err(AllocError::NoSpace) => return Ok(None),
            Err(error) => bail!("G2H request allocation plan: {error}"),
        };

        let free_descs = self
            .g2h_producer
            .num_free()
            .saturating_sub(plan.num_slots());

        let (free_slots, slot_size) = match return_type {
            ReturnType::String | ReturnType::VecBytes | ReturnType::ByteChunks => (
                self.g2h_pool.num_free_upper() - plan.upper_slots(),
                self.g2h_pool.max_alloc_len(),
            ),
            _ => (
                usize::from(self.g2h_pool.num_free() > plan.num_slots()),
                self.g2h_pool
                    .lower_slot_size()
                    .unwrap_or_else(|| self.g2h_pool.max_alloc_len()),
            ),
        };

        let capacity = free_slots.min(free_descs) * slot_size;
        Ok((capacity != 0).then_some(capacity))
    }

    /// Submit a one-way G2H message without polling its acknowledgement.
    ///
    /// Completed acknowledgements remain available for normal polling or
    /// reclamation when later submissions encounter backpressure.
    fn send_g2h_oneshot(&mut self, message: &EncodedMessage<'_>) -> Result<()> {
        match self.try_send(message, None) {
            Ok(_) => Ok(()),
            Err(error) if error.is_transient() => {
                // VM exit so host drains and completes G2H entries.
                self.g2h_producer.notify_backpressure();

                if let Err(error) = self.g2h_producer.reclaim() {
                    bail!("G2H one-way reclaim: {error}");
                }

                match self.try_send(message, None) {
                    Ok(_) => Ok(()),
                    Err(error) => bail!("G2H one-way retry: {error}"),
                }
            }
            Err(error) => bail!("G2H one-way message: {error}"),
        }
    }

    /// Build and submit one G2H descriptor chain.
    ///
    /// The readable region contains the header, control message, and external
    /// values. `reply_cap` adds a writable region for a host function reply.
    fn try_send(
        &mut self,
        message: &EncodedMessage<'_>,
        reply_cap: Option<usize>,
    ) -> result::Result<Token, VirtqError> {
        let chain = self.build_g2h_chain(message, reply_cap)?;
        self.g2h_producer.submit(chain)
    }

    /// Submit one G2H message for polling after the existing final halt.
    fn try_send_deferred(
        &mut self,
        message: &EncodedMessage<'_>,
        reply_cap: Option<usize>,
    ) -> result::Result<Token, VirtqError> {
        let chain = self.build_g2h_chain(message, reply_cap)?;
        let mut batch = self.g2h_producer.batch();

        let token = batch.submit(chain)?;
        batch.finish_without_notify();

        Ok(token)
    }

    /// Build and initialize one G2H message chain.
    fn build_g2h_chain(
        &self,
        message: &EncodedMessage<'_>,
        reply_cap: Option<usize>,
    ) -> result::Result<SendChain<GuestMemOps, SlotPool>, VirtqError> {
        // Allocate the readable request and optional writable reply together.
        let chain = self.g2h_producer.chain().readable(message.total_len());

        let mut chain = match reply_cap {
            Some(reply_cap) => chain.writable(reply_cap),
            None => chain,
        }
        .build()?;

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

fn pool_len(pages: usize) -> result::Result<usize, AllocError> {
    pages
        .checked_mul(hyperlight_common::vmem::PAGE_SIZE)
        .ok_or(AllocError::Overflow)
}

/// Build the uniform H2G pool.
///
/// Each slot becomes one independent preposted receive buffer.
fn h2g_pool(base: u64, pages: usize, buffer_size: usize) -> result::Result<SlotPool, AllocError> {
    let count = pool_len(pages)? / buffer_size;
    SlotPool::new(SlotLayout::new(base, buffer_size, count))
}

/// Build the tiered G2H pool.
///
/// One page of 256-byte slots serves small control and log messages without
/// consuming configured-size slots. Complete slots in the remaining pages form
/// the upper tier.
fn g2h_pool(base: u64, pages: usize, upper_size: usize) -> result::Result<SlotPool, AllocError> {
    let pool_len = pool_len(pages)?;
    let lower_len = G2H_LOWER_SLOT_COUNT
        .checked_mul(G2H_LOWER_SLOT_SIZE)
        .ok_or(AllocError::Overflow)?;

    let upper_len = pool_len
        .checked_sub(lower_len)
        .ok_or(AllocError::EmptyRegion)?;

    let upper_count = upper_len / upper_size;

    let lower = SlotLayout::new(base, G2H_LOWER_SLOT_SIZE, G2H_LOWER_SLOT_COUNT);
    let upper = SlotLayout::new(lower.end_addr()?, upper_size, upper_count);
    SlotPool::new_tiered(lower, upper)
}
