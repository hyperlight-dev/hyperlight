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
use core::num::NonZeroU16;
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
use hyperlight_common::virtq::recycle_pool::RecyclePool;
use hyperlight_common::virtq::{BufferPool, Layout, Notifier, QueueStats, VirtqProducer};

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

        let mut entry = self
            .g2h_producer
            .chain()
            .entry(entry_len)
            .completion(MAX_RESPONSE_CAP)
            .build()?;

        entry.write_all(hdr_bytes)?;
        entry.write_all(payload)?;
        self.g2h_producer.submit(entry)?;

        let Some(completion) = self.g2h_producer.poll()? else {
            bail!("G2H: no completion received");
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
                Err(_) => break,
            };
            if self.h2g_producer.submit(entry).is_err() {
                break;
            }
        }
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

        if hdr.kind != MsgKind::Request as u8 {
            bail!("H2G: unexpected message kind");
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
        // Build a Response message on the G2H queue
        let reqid = REQUEST_ID.fetch_add(1, Relaxed);
        let hdr = VirtqMsgHeader::new(MsgKind::Response, reqid, payload.len() as u32);
        let hdr_bytes = bytemuck::bytes_of(&hdr);

        let entry_len = VirtqMsgHeader::SIZE + payload.len();
        let mut entry = self.g2h_producer.chain().entry(entry_len).build()?;

        entry.write_all(hdr_bytes)?;
        entry.write_all(payload)?;
        self.g2h_producer.submit(entry)?;

        // Refill one H2G completion slot
        if let Ok(e) = self
            .h2g_producer
            .chain()
            .completion(PAGE_SIZE_USIZE)
            .build()
        {
            let _ = self.h2g_producer.submit(e);
        }

        Ok(())
    }

    /// Drain any pending G2H completions (discard them).
    ///
    /// This is called before checking for H2G calls so that the host
    /// can reclaim G2H response buffers.
    pub fn drain_g2h_completions(&mut self) {
        while let Ok(Some(_)) = self.g2h_producer.poll() {}
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
}
