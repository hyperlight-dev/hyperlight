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

use alloc::sync::Arc;
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
use hyperlight_common::outb::OutBAction;
use hyperlight_common::virtq::msg::{MsgKind, VirtqMsgHeader};
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
pub type G2hProducer = VirtqProducer<GuestMemOps, GuestNotifier, Arc<BufferPool>>;

/// Virtqueue runtime state for guest-host communication.
pub struct GuestContext {
    g2h_pool: Arc<BufferPool>,
    g2h_producer: G2hProducer,
    generation: u64,
}

impl GuestContext {
    /// Create a new context with a G2H queue.
    ///
    /// # Safety
    ///
    /// `ring_gva` must point to valid, zeroed ring memory.
    /// `pool_gva` must point to valid, zeroed memory.
    pub unsafe fn new(
        ring_gva: u64,
        num_descs: u16,
        pool_gva: u64,
        pool_size: usize,
        generation: u64,
    ) -> Self {
        let pool = Arc::new(
            BufferPool::new(pool_gva, pool_size).expect("failed to create G2H buffer pool"),
        );
        let nz = NonZeroU16::new(num_descs).expect("G2H queue depth must be non-zero");
        let layout = unsafe { Layout::from_base(ring_gva, nz) }.expect("invalid G2H ring layout");
        let producer = VirtqProducer::new(layout, GuestMemOps, GuestNotifier, pool.clone());

        Self {
            g2h_pool: pool,
            g2h_producer: producer,
            generation,
        }
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

    /// Reset ring and pool state after snapshot restore.
    pub(super) fn reset(&mut self, new_generation: u64) {
        self.g2h_producer.reset();
        self.g2h_pool.reset();
        self.generation = new_generation;
    }

    pub(super) fn generation(&self) -> u64 {
        self.generation
    }
}
