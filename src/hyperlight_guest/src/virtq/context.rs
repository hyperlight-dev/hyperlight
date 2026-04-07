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

use super::GuestMemOps;
use crate::bail;
use crate::error::Result;

static REQUEST_ID: AtomicU16 = AtomicU16::new(0);
const MAX_RESPONSE_CAP: usize = 4096;

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
    g2h_producer: G2hProducer,
    h2g_producer: H2gProducer,
    generation: u64,
    last_host_return: Option<ReturnValue>,
}

impl GuestContext {
    /// Create a new context with G2H and H2G queues.
    pub fn new(g2h: QueueConfig, h2g: QueueConfig, generation: u64) -> Self {
        let size = g2h.pool_pages * PAGE_SIZE_USIZE;
        let g2h_pool =
            BufferPool::new(g2h.pool_gva, size).expect("failed to create G2H buffer pool");
        let g2h_producer =
            VirtqProducer::new(g2h.layout, GuestMemOps, GuestNotifier, g2h_pool.clone());

        // Each H2G prefill entry is a single descriptor with one contiguous buffer: one
        // fixed-size buffer per descriptor, large payloads split across multiple independent
        // completions.
        //
        // TODO(virtq): consider smaller slot_size (e.g. pool_size / desc_count) to maximize
        // prefilled entries for host-side call batching.
        let size = h2g.pool_pages * PAGE_SIZE_USIZE;
        let slot = PAGE_SIZE_USIZE;
        let h2g_pool =
            RecyclePool::new(h2g.pool_gva, size, slot).expect("failed to create H2G recycle pool");
        let h2g_producer =
            VirtqProducer::new(h2g.layout, GuestMemOps, GuestNotifier, h2g_pool.clone());

        let mut ctx = Self {
            g2h_producer,
            h2g_producer,
            generation,
            last_host_return: None,
        };

        ctx.prefill_h2g();
        ctx
    }

    /// Call a host function via the G2H virtqueue.
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
        if result_bytes.len() > MAX_RESPONSE_CAP {
            bail!("G2H: response is too large");
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
    pub fn recv_h2g_call(&mut self) -> Result<FunctionCall> {
        let Some(completion) = self.h2g_producer.poll()? else {
            bail!("H2G: no pending call");
        };

        let data = &completion.data;
        if data.len() < VirtqMsgHeader::SIZE {
            bail!("H2G: completion too short for header");
        }

        let hdr: &VirtqMsgHeader = bytemuck::from_bytes(&data[..VirtqMsgHeader::SIZE]);

        if hdr.msg_kind() != Ok(MsgKind::Request) {
            bail!("H2G: unexpected message kind: 0x{:02x}", hdr.kind);
        }

        let payload_end = VirtqMsgHeader::SIZE + hdr.payload_len as usize;
        if payload_end > data.len() {
            bail!("H2G: payload length exceeds completion data");
        }

        let payload = &data[VirtqMsgHeader::SIZE..payload_end];
        let fc = FunctionCall::try_from(payload)?;
        Ok(fc)
    }

    /// Send the result of a host-to-guest call back to the host via the
    /// G2H queue, then refill one H2G descriptor slot.
    pub fn send_h2g_result(&mut self, payload: &[u8]) -> Result<()> {
        self.send_g2h_oneshot(MsgKind::Response, payload)?;

        // Best-effort refill of one H2G slot. Backpressure is expected
        // (pool/ring may be full), other errors are propagated.
        match self
            .h2g_producer
            .chain()
            .completion(PAGE_SIZE_USIZE)
            .build()
        {
            Ok(e) => match self.h2g_producer.submit(e) {
                Ok(_) => {}
                Err(virtq::VirtqError::Backpressure) => {}
                Err(e) => bail!("H2G refill submit: {e}"),
            },
            Err(virtq::VirtqError::Backpressure) => {}
            Err(e) => bail!("H2G refill build: {e}"),
        }

        Ok(())
    }

    /// Pre-fill the H2G queue with completion-only descriptors so the host
    /// can write incoming call payloads into them.
    fn prefill_h2g(&mut self) {
        loop {
            let entry = match self
                .h2g_producer
                .chain()
                .completion(PAGE_SIZE_USIZE)
                .build()
            {
                Ok(e) => e,
                Err(virtq::VirtqError::Backpressure) => break,
                Err(e) => panic!("H2G prefill build: {e}"),
            };

            match self.h2g_producer.submit(entry) {
                Ok(_) => {}
                Err(virtq::VirtqError::Backpressure) => break,
                Err(e) => panic!("H2G prefill submit: {e}"),
            }
        }
    }

    /// Send a one-way message on the G2H queue ReadOnly and no completion.
    ///
    /// If the pool or ring is full, triggers backpressure, VM exit so
    /// the host can drain, then retries once.
    fn send_g2h_oneshot(&mut self, kind: MsgKind, payload: &[u8]) -> Result<()> {
        let reqid = REQUEST_ID.fetch_add(1, Relaxed);
        let hdr = VirtqMsgHeader::new(kind, reqid, payload.len() as u32);
        let hdr_bytes = bytemuck::bytes_of(&hdr);
        let entry_len = VirtqMsgHeader::SIZE + payload.len();

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

    /// Drain any pending G2H completions.
    ///
    /// This is called before checking for H2G calls so that the host
    /// can reclaim G2H response buffers.
    pub fn drain_g2h_completions(&mut self) {
        while let Ok(Some(_)) = self.g2h_producer.poll() {}
    }

    /// Send a log message via the G2H queue. Fire-and-forget.
    pub fn emit_log(&mut self, log_data: &[u8]) -> Result<()> {
        self.send_g2h_oneshot(MsgKind::Log, log_data)
    }

    /// Reset ring and pool state after snapshot restore.
    pub(super) fn reset(&mut self, new_generation: u64) {
        self.g2h_producer.reset();
        // H2G state is NOT reset. The guest's inflight and cursors
        // survived via CoW and are already correct. The host's
        // restore_h2g_prefill() wrote matching descriptors to the
        // zeroed ring memory. Both sides are in sync.
        self.generation = new_generation;
    }

    pub(super) fn generation(&self) -> u64 {
        self.generation
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
            .completion(MAX_RESPONSE_CAP)
            .build()?;

        entry.write_all(header)?;
        entry.write_all(payload)?;
        self.g2h_producer.submit(entry)
    }

    /// Stash a host function return value for later retrieval.
    ///
    /// Used by the C API's two-step calling convention where
    /// `hl_call_host_function` and `hl_get_host_return_value_as_*`
    /// are separate calls.
    pub fn stash_host_return(&mut self, value: ReturnValue) {
        self.last_host_return = Some(value);
    }

    /// Take the stashed host return value.
    ///
    /// Panics if no value was stashed or if the type conversion fails.
    pub fn take_host_return<T: TryFrom<ReturnValue>>(&mut self) -> T {
        let rv = self
            .last_host_return
            .take()
            .expect("No host return value available");
        match T::try_from(rv) {
            Ok(v) => v,
            Err(_) => panic!("Host return value type mismatch"),
        }
    }
}
