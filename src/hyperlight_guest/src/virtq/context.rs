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
use core::sync::atomic::AtomicU16;
use core::sync::atomic::Ordering::Relaxed;

use flatbuffers::FlatBufferBuilder;
use hyperlight_common::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
use hyperlight_common::flatbuffer_wrappers::function_types::{
    FunctionCallResult, ParameterValue, ReturnType, ReturnValue,
};
use hyperlight_common::flatbuffer_wrappers::util::estimate_flatbuffer_capacity;
use hyperlight_common::mem::PAGE_SIZE_USIZE;
use hyperlight_common::outb::OutBAction;
use hyperlight_common::virtq::msg::{MsgKind, VirtqMsgHeader};
use hyperlight_common::virtq::{
    self, BufferPool, Layout, Notifier, QueueStats, RecyclePool, Token, VirtqProducer,
};
use tracing::instrument;

use super::GuestMemOps;
use crate::bail;
use crate::error::Result;

static REQUEST_ID: AtomicU16 = AtomicU16::new(0);

/// Guest-side notifier that triggers a VM exit via outb.
#[derive(Clone, Copy)]
pub struct GuestNotifier;

impl Notifier for GuestNotifier {
    fn notify(&self, _stats: QueueStats) {
        unsafe { crate::exit::out32(OutBAction::VirtqNotify as u16, 0) };
    }
}

/// Type alias for the guest-side G2H producer.
pub type G2hProducer = VirtqProducer<GuestMemOps, GuestNotifier, BufferPool>;

/// Type alias for the guest-side H2G producer (uses fixed-size RecyclePool slots).
pub type H2gProducer = VirtqProducer<GuestMemOps, GuestNotifier, RecyclePool>;

/// Configuration for one queue passed to [`GuestContext::new`].
pub struct QueueConfig {
    /// Ring descriptor layout in shared memory.
    pub layout: Layout,
    /// Base GVA of the buffer pool region.
    pub pool_gva: u64,
    /// Number of pages in the buffer pool.
    pub pool_pages: usize,
}

/// Virtqueue runtime state for guest-host communication.
pub struct GuestContext {
    /// guest-to-host driver
    g2h_producer: G2hProducer,
    /// host-to-guest driver
    h2g_producer: H2gProducer,
    /// Max writable bytes the host can write into a G2H completion.
    /// Derived from the G2H pool upper slab slot size.
    g2h_response_cap: usize,
    /// H2G slot size in bytes (each prefilled writable descriptor).
    h2g_slot_size: usize,
    /// snapshot generation counter
    generation: u64,
    /// Number of H2G requests received that still need a G2H response.
    pending_replies: u32,
    /// used by cabi
    last_host_result: Option<Result<ReturnValue>>,
}

impl GuestContext {
    /// Create a new context with G2H and H2G queues.
    pub fn new(g2h: QueueConfig, h2g: QueueConfig, generation: u64) -> Self {
        let size = g2h.pool_pages * PAGE_SIZE_USIZE;
        let g2h_pool =
            BufferPool::new(g2h.pool_gva, size).expect("failed to create G2H buffer pool");
        let g2h_response_cap = BufferPool::<256, 4096>::upper_slot_size();
        let g2h_producer =
            VirtqProducer::new(g2h.layout, GuestMemOps, GuestNotifier, g2h_pool.clone());

        let size = h2g.pool_pages * PAGE_SIZE_USIZE;
        let h2g_slot_size = PAGE_SIZE_USIZE;
        let h2g_pool = RecyclePool::new(h2g.pool_gva, size, h2g_slot_size)
            .expect("failed to create H2G recycle pool");
        let h2g_producer =
            VirtqProducer::new(h2g.layout, GuestMemOps, GuestNotifier, h2g_pool.clone());

        let mut ctx = Self {
            g2h_producer,
            h2g_producer,
            g2h_response_cap,
            h2g_slot_size,
            generation,
            pending_replies: 0,
            last_host_result: None,
        };

        ctx.prefill_h2g().expect("H2G initial prefill failed");
        ctx
    }

    /// Call a host function via the G2H virtqueue.
    ///
    /// The reply guard is checked before submitting the readwrite chain
    /// to ensure G2H capacity is reserved for pending responses.
    #[instrument(skip_all, level = "Info")]
    pub fn call_host_function<T: TryFrom<ReturnValue>>(
        &mut self,
        function_name: &str,
        parameters: Option<Vec<ParameterValue>>,
        return_type: ReturnType,
    ) -> Result<T> {
        let params = parameters.as_deref().unwrap_or_default();
        let estimated_capacity = estimate_flatbuffer_capacity(function_name, params);

        let fc = FunctionCall::new(
            function_name.into(),
            parameters,
            FunctionCallType::Host,
            return_type,
        );

        let mut builder = FlatBufferBuilder::with_capacity(estimated_capacity);
        let payload = fc.encode(&mut builder);

        let reqid = REQUEST_ID.fetch_add(1, Relaxed);
        let hdr = VirtqMsgHeader::new(MsgKind::Request, reqid, payload.len() as u32);
        let hdr_bytes = bytemuck::bytes_of(&hdr);

        let entry_len = VirtqMsgHeader::SIZE + payload.len();

        // Reply guard: readwrite chains use 2 descriptors, leave room for pending replies.
        self.ensure_reply_capacity(2)?;

        let token = match self.try_send_readwrite(hdr_bytes, payload, entry_len) {
            Ok(tok) => tok,
            Err(e) if e.is_transient() => {
                self.g2h_producer.notify_backpressure();

                if let Err(err) = self.g2h_producer.reclaim() {
                    bail!("G2H reclaim: {err}");
                }

                let Ok(tok) = self.try_send_readwrite(hdr_bytes, payload, entry_len) else {
                    bail!("G2H call retry");
                };

                tok
            }
            Err(e) => bail!("G2H call: {e}"),
        };

        // Poll completions, skipping earlier entries like log acks
        // until we find the completion matching our request token.
        let completion = loop {
            let Some(cqe) = self.g2h_producer.poll()? else {
                bail!("G2H: no completion received");
            };
            if cqe.token == token {
                break cqe;
            }
        };

        let result_bytes = &completion.data;
        if result_bytes.len() < VirtqMsgHeader::SIZE {
            bail!("G2H: response too short for header");
        }

        let payload_bytes = &result_bytes[VirtqMsgHeader::SIZE..];
        let Ok(fcr) = FunctionCallResult::try_from(payload_bytes) else {
            bail!("G2H: malformed response");
        };

        let ret = fcr.into_inner()?;
        let Ok(ret) = T::try_from(ret) else {
            bail!("G2H: host return value type mismatch");
        };

        Ok(ret)
    }

    /// Receive a host-to-guest function call from the H2G queue.
    ///
    /// Each descriptor carries a [`VirtqMsgHeader`] with `payload_len` for
    /// that chunk. If [`MsgFlags::MORE`](hyperlight_common::virtq::msg::MsgFlags::MORE)
    /// is set, more descriptors follow.
    ///
    /// Increments the reply guard counter so that subsequent G2H sends
    /// reserve capacity for the response.
    pub fn recv_h2g_call(&mut self) -> Result<FunctionCall> {
        let Some(first) = self.h2g_producer.poll()? else {
            bail!("H2G: no pending call");
        };

        let data = &first.data;
        if data.len() < VirtqMsgHeader::SIZE {
            bail!("H2G: completion too short for header");
        }

        let hdr: &VirtqMsgHeader = bytemuck::from_bytes(&data[..VirtqMsgHeader::SIZE]);

        if hdr.msg_kind() != Ok(MsgKind::Request) {
            bail!("H2G: unexpected message kind: 0x{:02x}", hdr.kind);
        }

        let chunk_len = hdr.payload_len as usize;

        // Track that we owe a response on G2H.
        self.pending_replies = self.pending_replies.saturating_add(1);

        if !hdr.has_more() {
            // Single-descriptor fast path
            let payload = &data[VirtqMsgHeader::SIZE..VirtqMsgHeader::SIZE + chunk_len];
            let fc = FunctionCall::try_from(payload)?;
            return Ok(fc);
        }

        // Multi-descriptor: accumulate payload until MsgFlags::MORE is cleared
        let mut assembled = Vec::with_capacity(chunk_len * 2);
        assembled.extend_from_slice(&data[VirtqMsgHeader::SIZE..VirtqMsgHeader::SIZE + chunk_len]);

        loop {
            let Some(next) = self.h2g_producer.poll()? else {
                bail!("H2G: expected continuation descriptor, none available");
            };

            let next_data = &next.data;
            if next_data.len() < VirtqMsgHeader::SIZE {
                bail!("H2G: continuation too short for header");
            }

            let next_hdr: &VirtqMsgHeader =
                bytemuck::from_bytes(&next_data[..VirtqMsgHeader::SIZE]);

            let next_chunk = next_hdr.payload_len as usize;

            assembled.extend_from_slice(
                &next_data[VirtqMsgHeader::SIZE..VirtqMsgHeader::SIZE + next_chunk],
            );

            if !next_hdr.has_more() {
                break;
            }
        }

        let fc = FunctionCall::try_from(assembled.as_slice())?;
        Ok(fc)
    }

    /// Send the result of a host-to-guest call back to the host via the
    /// G2H queue, then refill H2G descriptor slots until the ring is full.
    ///
    /// Decrements the reply guard counter after a successful send.
    pub fn send_h2g_result(&mut self, payload: &[u8]) -> Result<()> {
        self.send_g2h_oneshot(MsgKind::Response, payload)?;
        self.pending_replies = self.pending_replies.saturating_sub(1);
        self.prefill_h2g()
    }

    /// Restore the H2G producer after snapshot restore.
    ///
    /// Creates a new [`RecyclePool`] at `pool_gva` and calls
    /// [`restore_from_ring`] to reconstruct inflight state
    /// from the host's prefilled descriptors.
    pub fn restore_h2g(&mut self, pool_gva: u64, pool_size: usize) {
        let pool = RecyclePool::new(pool_gva, pool_size, self.h2g_slot_size)
            .expect("H2G RecyclePool creation failed");

        self.h2g_producer
            .restore_from_ring(pool)
            .expect("H2G restore_from_ring failed");
    }

    /// Reset the G2H producer with a fresh pool.
    ///
    /// Creates a new [`BufferPool`] at `pool_gva` and resets the
    /// producer to its initial state.
    pub fn reset_g2h(&mut self, pool_gva: u64, pool_size: usize) {
        let pool = BufferPool::new(pool_gva, pool_size).expect("G2H BufferPool creation failed");
        self.g2h_producer.reset_with_pool(pool);
        self.last_host_result = None;
    }

    /// Send a log message via the G2H queue. Fire-and-forget.
    pub fn emit_log(&mut self, log_data: &[u8]) -> Result<()> {
        self.send_g2h_oneshot(MsgKind::Log, log_data)
    }

    /// Get the current generation counter.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Set the generation counter after snapshot restore.
    pub fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
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
        let val = self
            .last_host_result
            .take()
            .expect("No host return value available")
            .expect("Host function returned an error");

        match T::try_from(val) {
            Ok(v) => v,
            Err(_) => panic!("Host return value type mismatch"),
        }
    }

    /// Pre-fill the H2G queue with completion-only descriptors so the host
    /// can write incoming call payloads into them.
    fn prefill_h2g(&mut self) -> Result<()> {
        loop {
            let entry = match self
                .h2g_producer
                .chain()
                .completion(self.h2g_slot_size)
                .build()
            {
                Ok(e) => e,
                Err(e) if e.is_transient() => return Ok(()),
                Err(e) => bail!("H2G prefill build: {e}"),
            };

            match self.h2g_producer.submit(entry) {
                Ok(_) => {}
                Err(e) if e.is_transient() => return Ok(()),
                Err(e) => bail!("H2G prefill submit: {e}"),
            }
        }
    }

    /// Ensure the G2H ring has enough free descriptors to accommodate
    /// both the requested send (`need_descs`) and all pending replies.
    fn ensure_reply_capacity(&mut self, need_descs: usize) -> Result<()> {
        let reserved = self.pending_replies as usize;
        loop {
            let free = self.g2h_producer.num_free();
            if free >= need_descs + reserved {
                return Ok(());
            }

            self.g2h_producer.notify_backpressure();
            let reclaimed = self.g2h_producer.reclaim()?;
            if reclaimed == 0 {
                // No progress - host hasn't completed any entries yet.
                // Fall through and let the send path handle backpressure
                // via its own retry logic.
                return Ok(());
            }
        }
    }

    /// Send a one-way message on the G2H queue ReadOnly and no completion.
    ///
    /// For non-response sends, the reply guard is checked first to
    /// ensure enough G2H capacity is reserved for pending replies.
    fn send_g2h_oneshot(&mut self, kind: MsgKind, payload: &[u8]) -> Result<()> {
        let reqid = REQUEST_ID.fetch_add(1, Relaxed);
        let hdr = VirtqMsgHeader::new(kind, reqid, payload.len() as u32);
        let hdr_bytes = bytemuck::bytes_of(&hdr);
        let entry_len = VirtqMsgHeader::SIZE + payload.len();

        // Reply guard: non-response sends must leave room for pending replies.
        if kind != MsgKind::Response {
            self.ensure_reply_capacity(1)?;
        }

        // First attempt
        match self.try_send_readonly(hdr_bytes, payload, entry_len) {
            Ok(_) => return Ok(()),
            Err(virtq::VirtqError::Backpressure) => {
                // VM exit so host drains and completes G2H entries.
                self.g2h_producer.notify_backpressure();
            }
            Err(e) => bail!("G2H oneshot: {e}"),
        }

        // Reclaim ring/pool resources from completed entries.
        if let Err(e) = self.g2h_producer.reclaim() {
            bail!("G2H oneshot retry: {e}");
        }
        // Retry after backpressure
        match self.try_send_readonly(hdr_bytes, payload, entry_len) {
            Ok(_) => Ok(()),
            Err(e) => bail!("G2H oneshot retry: {e}"),
        }
    }

    fn try_send_readonly(
        &mut self,
        header: &[u8],
        payload: &[u8],
        entry_len: usize,
    ) -> result::Result<Token, virtq::VirtqError> {
        let mut entry = self.g2h_producer.chain().entry(entry_len).build()?;

        entry.write_all(header)?;
        entry.write_all(payload)?;
        self.g2h_producer.submit(entry)
    }

    fn try_send_readwrite(
        &mut self,
        header: &[u8],
        payload: &[u8],
        entry_len: usize,
    ) -> result::Result<Token, virtq::VirtqError> {
        let mut entry = self
            .g2h_producer
            .chain()
            .entry(entry_len)
            .completion(self.g2h_response_cap)
            .build()?;

        entry.write_all(header)?;
        entry.write_all(payload)?;
        self.g2h_producer.submit(entry)
    }
}
