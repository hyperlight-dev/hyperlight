// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Host virtqueue consumers, G2H I/O, and snapshot restoration.
//!
//! Rings occupy fixed arena storage. Payload accesses are bounded copies
//! within mapped scratch. Consumers validate descriptors when they are used.
//!
//! G2H codec helpers copy untrusted request data into host-owned values before
//! dispatch. Shared wire framing lives in `hyperlight_common::transport`.
//!
//! Snapshots require canonical rings with empty G2H and the initial H2G prefill.
//! H2G chains contain one writable descriptor of the configured buffer size.

use anyhow::{Context, bail};
use flatbuffers::FlatBufferBuilder;
use hyperlight_common::flatbuffer_wrappers::ExternalValueSource;
use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::{Bytes, FunctionCallResult};
use hyperlight_common::flatbuffer_wrappers::guest_error::{ErrorCode, GuestError};
use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
use hyperlight_common::transport::{
    EncodedMessage, ExternalValues, MsgKind, SIZE_PREFIX_LEN, size_prefix_payload_len,
    size_prefixed_len,
};
use hyperlight_common::virtq::canonical::validate_canon_image;
use hyperlight_common::virtq::{
    Layout as VirtqLayout, Notifier, QueueStats, RecvChain, VirtqConsumer, WritableChain,
};

use super::layout::SandboxMemoryLayout;
use super::shared_mem::{HostSharedMemory, SharedMemory};
use super::virtq_mem::{HostMemOps, ImageMem};
use crate::{Result, new_error};

/// Host-side G2H virtqueue consumer.
pub(crate) type G2hConsumer = VirtqConsumer<HostMemOps, HostNotifier>;
/// Host-side H2G virtqueue consumer.
pub(crate) type H2gConsumer = VirtqConsumer<HostMemOps, HostNotifier>;

/// No-op notifier because the host completes work during the current VM exit.
#[derive(Clone, Copy)]
pub(crate) struct HostNotifier;

impl Notifier for HostNotifier {
    fn notify(&self, _stats: QueueStats) {}
}

/// Create both host consumers before the first guest entry.
///
/// Ring contents are not inspected because the guest has not initialized them
/// yet. Consumer cursors start at zero and observe descriptors published later.
pub(crate) fn create_consumers(
    layout: &SandboxMemoryLayout,
    scratch_mem: &HostSharedMemory,
) -> Result<(G2hConsumer, H2gConsumer)> {
    let (g2h_layout, h2g_layout) = ring_layouts(layout)?;
    let mem = HostMemOps::new(scratch_mem);

    let g2h = VirtqConsumer::new(g2h_layout, mem.clone(), HostNotifier);
    let h2g = VirtqConsumer::new(h2g_layout, mem, HostNotifier);

    Ok((g2h, h2g))
}

/// Decode one complete host function call from a G2H request.
///
/// Control data and external values are copied out of guest-writable scratch.
/// Unconsumed trailing bytes are rejected.
pub(crate) fn get_host_function_call(
    chain: &mut RecvChain<HostMemOps>,
) -> anyhow::Result<FunctionCall> {
    let control = read_control(chain)?;
    let mut external_values = ChainExternalValues::new(chain);
    FunctionCall::decode_external(&control, &mut external_values)
}

/// Encode a host function result into a G2H reply.
///
/// A result that exceeds the writable capacity is replaced with a bounded
/// transport error. An error is returned if that fallback also cannot fit.
pub(crate) fn write_response_from_host_function_call(
    chain: &mut WritableChain<HostMemOps>,
    cid: u32,
    result: &FunctionCallResult,
) -> anyhow::Result<()> {
    if try_write_response_from_host_function_call(chain, cid, result)? {
        return Ok(());
    }

    let error = FunctionCallResult::new(Err(GuestError::new(
        ErrorCode::HostFunctionError,
        "Host response exceeds virtqueue capacity".into(),
    )));

    if !try_write_response_from_host_function_call(chain, cid, &error)? {
        bail!(
            "Writable response capacity {} cannot hold a transport error",
            chain.capacity()
        );
    }
    Ok(())
}

/// Decode guest log data and reject trailing external bytes.
pub(crate) fn read_guest_log_data(
    chain: &mut RecvChain<HostMemOps>,
) -> anyhow::Result<GuestLogData> {
    let control = read_control(chain)?;
    if chain.remaining() != 0 {
        bail!("G2H log has {} trailing external bytes", chain.remaining());
    }
    GuestLogData::try_from(control.as_slice())
}

/// Validated ring images excluded from ordinary snapshot pages.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct VirtqSnapshot {
    /// Scratch size used to derive transport GVAs.
    scratch_size: usize,
    /// Canonical guest-to-host ring image.
    g2h_ring: Vec<u8>,
    /// Canonical host-to-guest ring image.
    h2g_ring: Vec<u8>,
}

impl VirtqSnapshot {
    /// Capture and validate rings against the final transport geometry.
    ///
    /// The guest must stay stopped through memory capture.
    pub(crate) fn capture(
        layout: &SandboxMemoryLayout,
        scratch_mem: &HostSharedMemory,
    ) -> Result<Self> {
        let (g2h_offset, h2g_offset) = ring_offsets(layout);

        let g2h_ring = read_ring(
            scratch_mem,
            g2h_offset,
            layout.get_g2h_queue_dims().ring_len(),
        )?;

        let h2g_ring = read_ring(
            scratch_mem,
            h2g_offset,
            layout.get_h2g_queue_dims().ring_len(),
        )?;

        let snapshot = Self {
            scratch_size: layout.get_scratch_size(),
            g2h_ring,
            h2g_ring,
        };

        snapshot.validate(layout)?;
        Ok(snapshot)
    }

    /// Restore these rings using the owning snapshot's transport layout.
    pub(crate) fn restore(
        &self,
        layout: &SandboxMemoryLayout,
        scratch_mem: &HostSharedMemory,
    ) -> Result<(G2hConsumer, H2gConsumer)> {
        let (g2h_offset, h2g_offset) = ring_offsets(layout);

        write_published_arena_gpa(scratch_mem, layout.get_transport_arena().base_addr())?;

        scratch_mem.copy_from_slice(&self.g2h_ring, g2h_offset)?;
        scratch_mem.copy_from_slice(&self.h2g_ring, h2g_offset)?;
        create_consumers(layout, scratch_mem)
    }

    /// Check geometry, canonical state, and H2G receive-buffer shape at admission.
    fn validate(&self, layout: &SandboxMemoryLayout) -> Result<()> {
        if self.scratch_size != layout.get_scratch_size() {
            return Err(new_error!(
                "virtqueue snapshot scratch size {} does not match layout size {}",
                self.scratch_size,
                layout.get_scratch_size()
            ));
        }

        if self.g2h_ring.len() != layout.get_g2h_queue_dims().ring_len()
            || self.h2g_ring.len() != layout.get_h2g_queue_dims().ring_len()
        {
            return Err(new_error!(
                "virtqueue snapshot ring lengths do not match layout"
            ));
        }

        let (g2h, h2g) = ring_layouts(layout)?;
        let g2h_mem = ImageMem::new(g2h.desc_table_addr(), &self.g2h_ring);

        validate_canon_image(&g2h_mem, g2h, 0, |_, _| false)
            .map_err(|error| new_error!("invalid canonical G2H image: {error}"))?;

        let buffer_size = layout.get_h2g_buffer_size();
        let h2g_dims = layout.get_h2g_queue_dims();

        let h2g_prefill = usize::from(h2g_dims.size().get()).min(h2g_dims.pool_len() / buffer_size);
        let h2g_mem = ImageMem::new(h2g.desc_table_addr(), &self.h2g_ring);

        let chains = validate_canon_image(&h2g_mem, h2g, h2g_prefill, |_, elem| {
            elem.writable && usize::try_from(elem.len).ok() == Some(buffer_size)
        })
        .map_err(|error| new_error!("invalid canonical H2G image: {error}"))?;

        if chains.len() != h2g_prefill {
            return Err(new_error!(
                "H2G snapshot chains must contain one descriptor"
            ));
        }

        Ok(())
    }
}

fn ring_layouts(layout: &SandboxMemoryLayout) -> Result<(VirtqLayout, VirtqLayout)> {
    let base = hyperlight_common::layout::scratch_base_gva(layout.get_scratch_size());
    let (g2h_offset, h2g_offset) = ring_offsets(layout);
    let g2h = layout.get_g2h_queue_dims();
    let h2g = layout.get_h2g_queue_dims();

    // SAFETY: The arena reserves aligned rings of these lengths. Callers back
    // them with scratch or exact-length immutable images.
    let g2h_layout = unsafe { VirtqLayout::from_base(base + g2h_offset as u64, g2h.size()) }
        .map_err(|error| new_error!("invalid G2H ring layout: {error}"))?;

    // SAFETY: H2G has the same backing guarantees in a disjoint, aligned arena range.
    let h2g_layout = unsafe { VirtqLayout::from_base(base + h2g_offset as u64, h2g.size()) }
        .map_err(|error| new_error!("invalid H2G ring layout: {error}"))?;
    Ok((g2h_layout, h2g_layout))
}

/// Copies external values from guest-writable scratch into host-owned storage.
///
/// Chunked values become one owned chunk because host calls cannot retain
/// references into untrusted guest memory.
struct ChainExternalValues<'a> {
    request: &'a mut RecvChain<HostMemOps>,
}

impl<'a> ChainExternalValues<'a> {
    fn new(request: &'a mut RecvChain<HostMemOps>) -> Self {
        Self { request }
    }
}

impl ExternalValueSource for ChainExternalValues<'_> {
    fn take_bytes(&mut self, length: usize) -> anyhow::Result<Vec<u8>> {
        validate_external_length("VecBytes", length, self.request.remaining())?;
        let mut value = zeroed_vec(length, "external VecBytes")?;

        self.request.read_exact(&mut value)?;
        Ok(value)
    }

    fn take_chunks(&mut self, length: usize) -> anyhow::Result<Vec<Bytes>> {
        if length == 0 {
            return Ok(Vec::new());
        }

        validate_external_length("ByteChunks", length, self.request.remaining())?;
        let mut value = zeroed_vec(length, "external ByteChunks")?;
        self.request.read_exact(&mut value)?;

        Ok(vec![Bytes::from(value)])
    }

    fn finish(&mut self) -> anyhow::Result<()> {
        if self.request.remaining() != 0 {
            bail!(
                "G2H message has {} trailing external bytes",
                self.request.remaining()
            );
        }
        Ok(())
    }
}

/// Publish the fixed transport arena GPA in scratch-top metadata.
fn write_published_arena_gpa(scratch_mem: &HostSharedMemory, arena_gpa: u64) -> Result<()> {
    let offset = hyperlight_common::layout::SCRATCH_TOP_TRANSPORT_ARENA_GPA_OFFSET as usize;
    Ok(scratch_mem.write::<u64>(scratch_mem.mem_size() - offset, arena_gpa)?)
}

fn read_ring(scratch_mem: &HostSharedMemory, offset: usize, len: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0; len];
    scratch_mem.copy_to_slice(&mut bytes, offset)?;
    Ok(bytes)
}

fn ring_offsets(layout: &SandboxMemoryLayout) -> (usize, usize) {
    let arena = layout.get_transport_arena();
    let scratch_base = hyperlight_common::layout::scratch_base_gpa(layout.get_scratch_size());
    let g2h_offset = (arena.base_addr() - scratch_base) as usize;
    let (h2g_offset, ..) = arena.to_offsets();
    (g2h_offset, g2h_offset + h2g_offset)
}

/// Write a response only when the complete wire message fits.
///
/// `false` means no bytes were written, allowing the caller to try a bounded
/// transport error. Encoding and chain write failures are returned as errors.
fn try_write_response_from_host_function_call(
    reply: &mut WritableChain<HostMemOps>,
    cid: u32,
    result: &FunctionCallResult,
) -> anyhow::Result<bool> {
    let mut builder = FlatBufferBuilder::new();
    let mut external_values = ExternalValues::new();

    let control = result.encode_external(&mut builder, &mut external_values)?;
    let message = EncodedMessage::new(MsgKind::Response, cid, control, external_values)
        .context("Host function response length overflow")?;

    if message.total_len() > reply.capacity() {
        return Ok(false);
    }

    for chunk in message.chunks() {
        reply.write_all(chunk)?;
    }

    Ok(true)
}

/// Copy size-prefixed control data and leave external values unread.
fn read_control(request: &mut RecvChain<HostMemOps>) -> anyhow::Result<Vec<u8>> {
    let mut prefix = [0u8; SIZE_PREFIX_LEN];
    request.read_exact(&mut prefix)?;

    let payload_len = size_prefix_payload_len(&prefix).context("invalid G2H size prefix")?;
    if payload_len > request.remaining() {
        bail!(
            "G2H control data declares {payload_len} bytes, only {} remain",
            request.remaining()
        );
    }

    let control_len = size_prefixed_len(payload_len).context("G2H control length overflow")?;
    // Do not trust control_len to be small enough to allocate.
    let mut control = zeroed_vec(control_len, "G2H control data")?;

    control[..SIZE_PREFIX_LEN].copy_from_slice(&prefix);
    request.read_exact(&mut control[SIZE_PREFIX_LEN..])?;
    Ok(control)
}

/// Allocate zeroed host-owned storage without panicking on reserve failure.
fn zeroed_vec(length: usize, what: &str) -> anyhow::Result<Vec<u8>> {
    let mut value = Vec::new();
    value
        .try_reserve_exact(length)
        .with_context(|| format!("Failed to allocate {length} bytes for {what}"))?;

    value.resize(length, 0);
    Ok(value)
}

/// Validate a declared external length before allocating its storage.
fn validate_external_length(kind: &str, length: usize, remaining: usize) -> anyhow::Result<()> {
    if length > remaining {
        bail!("External {kind} requires {length} bytes, only {remaining} remain");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU16;

    use hyperlight_common::virtq::{
        DescFlags, Descriptor, MemOps, RingError, SlotLayout, SlotPool, VirtqError, VirtqProducer,
    };
    use hyperlight_common::vmem;

    use super::*;
    use crate::mem::shared_mem::ExclusiveSharedMemory;
    use crate::sandbox::SandboxConfiguration;

    const SCRATCH_SIZE: usize = 0x20_000;
    const G2H_DEPTH: u16 = 16;
    const H2G_DEPTH: u16 = 8;
    const G2H_POOL_PAGES: usize = 3;
    const H2G_POOL_PAGES: usize = 2;
    const H2G_BUFFER_SIZE: usize = 3000;

    #[test]
    fn external_length_is_bounded_before_allocation() {
        assert!(validate_external_length("VecBytes", usize::MAX, 16).is_err());
        assert!(validate_external_length("ByteChunks", 17, 16).is_err());
        assert!(validate_external_length("VecBytes", 16, 16).is_ok());
    }

    #[test]
    fn oversized_allocation_fails_without_panicking() {
        assert!(zeroed_vec(usize::MAX, "test buffer").is_err());
    }

    fn memory_layout() -> SandboxMemoryLayout {
        let mut config = SandboxConfiguration::default();
        config.set_scratch_size(SCRATCH_SIZE);
        config.set_g2h_queue_size(G2H_DEPTH as usize);
        config.set_h2g_queue_size(H2G_DEPTH as usize);
        config.set_h2g_buffer_size(H2G_BUFFER_SIZE);
        config.set_g2h_pool_pages(G2H_POOL_PAGES);
        config.set_h2g_pool_pages(H2G_POOL_PAGES);

        SandboxMemoryLayout::new(config, 4096, 0, None).unwrap()
    }

    fn host_scratch() -> HostSharedMemory {
        let scratch = ExclusiveSharedMemory::new(SCRATCH_SIZE).unwrap();
        scratch.build().0
    }

    struct TestCase {
        scratch: HostSharedMemory,
        mem: HostMemOps,
        h2g_pool_base: u64,
        g2h_layout: VirtqLayout,
        h2g_layout: VirtqLayout,
    }

    fn test_case() -> TestCase {
        let scratch = host_scratch();

        let layout = memory_layout();
        let arena = layout.get_transport_arena();
        let scratch_base_gpa = hyperlight_common::layout::scratch_base_gpa(SCRATCH_SIZE);
        let scratch_base_gva = hyperlight_common::layout::scratch_base_gva(SCRATCH_SIZE);
        let to_gva = |gpa| scratch_base_gva + (gpa - scratch_base_gpa);

        let ring_base = to_gva(arena.g2h_ring_addr());
        let h2g_base = to_gva(arena.h2g_ring_addr());
        let h2g_pool_base = to_gva(arena.h2g_pool_addr());

        // SAFETY: The scratch mapping covers both ring layouts.
        let g2h_layout = unsafe {
            VirtqLayout::from_base(ring_base, NonZeroU16::new(G2H_DEPTH).unwrap()).unwrap()
        };
        // SAFETY: The scratch mapping covers both ring layouts.
        let h2g_layout = unsafe {
            VirtqLayout::from_base(h2g_base, NonZeroU16::new(H2G_DEPTH).unwrap()).unwrap()
        };

        let mem = HostMemOps::new(&scratch);
        let h2g_prefill_chains = (H2G_POOL_PAGES * vmem::PAGE_SIZE) / H2G_BUFFER_SIZE;

        let layout = SlotLayout::new(h2g_pool_base, H2G_BUFFER_SIZE, h2g_prefill_chains).unwrap();
        let h2g_pool = SlotPool::new(layout).unwrap();

        let mut h2g = VirtqProducer::new(h2g_layout, mem.clone(), HostNotifier, h2g_pool.clone());
        let mut batch = h2g.batch();

        for _ in 0..h2g_pool.num_free() {
            let chain = batch.chain().writable(H2G_BUFFER_SIZE).build().unwrap();
            batch.submit(chain).unwrap();
        }

        batch.finish().unwrap();
        write_published_arena_gpa(&scratch, arena.base_addr()).unwrap();

        TestCase {
            scratch,
            mem,
            h2g_pool_base,
            g2h_layout,
            h2g_layout,
        }
    }

    fn read_desc(mem: &HostMemOps, layout: VirtqLayout, index: u16) -> Descriptor {
        mem.read_val(layout.desc_table_addr() + u64::from(index) * Descriptor::SIZE as u64)
            .unwrap()
    }

    fn write_desc(mem: &HostMemOps, layout: VirtqLayout, index: u16, desc: Descriptor) {
        mem.write_val(
            layout.desc_table_addr() + u64::from(index) * Descriptor::SIZE as u64,
            desc,
        )
        .unwrap();
    }

    #[test]
    fn snapshots_and_restores_rings() {
        let case = test_case();
        let layout = memory_layout();
        let stale_pool = [0xa5; 16];
        case.mem.write(case.h2g_pool_base, &stale_pool).unwrap();
        case.scratch.copy_from_slice(&[0x5a; 16], 0).unwrap();

        let captured = VirtqSnapshot::capture(&layout, &case.scratch).unwrap();
        let restored = host_scratch();
        let allocator = layout.get_first_free_scratch_gpa();
        let allocator_offset =
            restored.mem_size() - hyperlight_common::layout::SCRATCH_TOP_ALLOCATOR_OFFSET as usize;
        restored.write::<u64>(allocator_offset, allocator).unwrap();

        let (mut g2h, mut h2g) = captured.restore(&layout, &restored).unwrap();
        let restored_snapshot = VirtqSnapshot::capture(&layout, &restored).unwrap();
        let restored_mem = HostMemOps::new(&restored);
        let mut pool_bytes = [0; 16];
        restored_mem
            .read(case.h2g_pool_base, &mut pool_bytes)
            .unwrap();

        assert_eq!(restored_snapshot, captured);
        assert_eq!(restored.read::<u64>(allocator_offset).unwrap(), allocator);
        assert_eq!(restored.read::<[u8; 16]>(0).unwrap(), [0; 16]);
        assert_eq!(pool_bytes, [0; 16]);
        assert!(g2h.poll(0).unwrap().is_none());
        let (recv, reply) = h2g.poll(0).unwrap().unwrap();
        h2g.complete(recv, reply).unwrap();

        drop((g2h, h2g));
        captured.restore(&layout, &restored).unwrap();
        assert_eq!(
            VirtqSnapshot::capture(&layout, &restored).unwrap(),
            captured
        );
    }

    #[test]
    fn rejects_snapshot_geometry_mismatches() {
        let case = test_case();
        let layout = memory_layout();
        let mut captured = VirtqSnapshot::capture(&layout, &case.scratch).unwrap();

        captured.scratch_size -= vmem::PAGE_SIZE;
        assert!(captured.validate(&layout).is_err());
        captured.scratch_size = layout.get_scratch_size();
        captured.g2h_ring.pop();
        assert!(captured.validate(&layout).is_err());
        captured.g2h_ring.push(0);
        captured.h2g_ring.pop();
        assert!(captured.validate(&layout).is_err());
    }

    #[test]
    fn rejects_noncanonical_snapshot_images() {
        let case = test_case();
        let layout = memory_layout();

        case.mem
            .write(case.g2h_layout.desc_table_addr(), &[1])
            .unwrap();
        let error = VirtqSnapshot::capture(&layout, &case.scratch).unwrap_err();
        assert!(error.to_string().contains("invalid canonical G2H image"));

        case.mem
            .write(case.g2h_layout.desc_table_addr(), &[0])
            .unwrap();
        case.mem
            .write(case.h2g_layout.drv_evt_addr(), &[1])
            .unwrap();
        let error = VirtqSnapshot::capture(&layout, &case.scratch).unwrap_err();
        assert!(error.to_string().contains("invalid canonical H2G image"));
    }

    #[test]
    fn rejects_h2g_snapshot_buffer_attributes() {
        let case = test_case();
        let layout = memory_layout();
        let original = read_desc(&case.mem, case.h2g_layout, 0);

        for (len, flags) in [
            (original.len, original.flags & !DescFlags::WRITE.bits()),
            (original.len - 1, original.flags),
            (original.len + 1, original.flags),
        ] {
            let desc = Descriptor {
                len,
                flags,
                ..original
            };
            write_desc(&case.mem, case.h2g_layout, 0, desc);
            assert!(VirtqSnapshot::capture(&layout, &case.scratch).is_err());
        }
    }

    #[test]
    fn rejects_h2g_snapshot_chain_shape() {
        let case = test_case();
        let layout = memory_layout();
        let mut head = read_desc(&case.mem, case.h2g_layout, 0);
        let mut tail = read_desc(&case.mem, case.h2g_layout, 1);
        head.flags |= DescFlags::NEXT.bits();
        tail.id = head.id;
        write_desc(&case.mem, case.h2g_layout, 0, head);
        write_desc(&case.mem, case.h2g_layout, 1, tail);

        assert!(VirtqSnapshot::capture(&layout, &case.scratch).is_err());
    }

    #[test]
    fn restores_with_finalized_layout() {
        let case = test_case();
        let layout = memory_layout();
        let snapshot = VirtqSnapshot::capture(&layout, &case.scratch).unwrap();

        let mut grown_layout = layout;
        grown_layout
            .set_pt_size(layout.get_pt_size() + vmem::PAGE_SIZE)
            .unwrap();
        grown_layout.set_snapshot_size(layout.snapshot_size() + page_size::get());
        let restored = host_scratch();

        snapshot.restore(&grown_layout, &restored).unwrap();
        assert_eq!(
            VirtqSnapshot::capture(&grown_layout, &restored).unwrap(),
            snapshot
        );
        let arena_gpa_offset = restored.mem_size()
            - hyperlight_common::layout::SCRATCH_TOP_TRANSPORT_ARENA_GPA_OFFSET as usize;
        assert_eq!(
            restored.read::<u64>(arena_gpa_offset).unwrap(),
            grown_layout.get_transport_arena().base_addr()
        );
    }

    #[test]
    fn uses_scratch_payloads_outside_pools() {
        let case = test_case();
        let addr = hyperlight_common::layout::scratch_base_gva(SCRATCH_SIZE) + 1;
        case.mem.write(addr, &[1, 2, 3]).unwrap();

        let mut g2h_desc = Descriptor::new(addr, 3, 0, DescFlags::empty());
        g2h_desc.mark_avail(true);
        write_desc(&case.mem, case.g2h_layout, 0, g2h_desc);
        let mut h2g_desc = read_desc(&case.mem, case.h2g_layout, 0);
        h2g_desc.addr = addr;
        h2g_desc.len = 3;
        write_desc(&case.mem, case.h2g_layout, 0, h2g_desc);

        let (mut g2h, mut h2g) = create_consumers(&memory_layout(), &case.scratch).unwrap();
        let (mut recv, reply) = g2h.poll(3).unwrap().unwrap();
        let mut bytes = [0; 3];
        recv.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes, [1, 2, 3]);
        g2h.complete(recv, reply).unwrap();

        let (recv, reply) = h2g.poll(0).unwrap().unwrap();
        let Ok(mut reply) = reply.into_writable() else {
            panic!("expected a writable H2G chain");
        };
        reply.write_all(&[4, 5, 6]).unwrap();
        h2g.complete(recv, reply).unwrap();
        case.mem.read(addr, &mut bytes).unwrap();
        assert_eq!(bytes, [4, 5, 6]);
    }

    #[test]
    fn payload_bounds_are_checked_on_use() {
        let case = test_case();
        let layout = memory_layout();
        let end = hyperlight_common::layout::scratch_base_gva(SCRATCH_SIZE) + SCRATCH_SIZE as u64;
        let mut h2g_desc = read_desc(&case.mem, case.h2g_layout, 0);
        h2g_desc.addr = end - 1;
        write_desc(&case.mem, case.h2g_layout, 0, h2g_desc);

        let captured = VirtqSnapshot::capture(&layout, &case.scratch).unwrap();
        let restored = host_scratch();
        let (mut g2h, mut h2g) = captured.restore(&layout, &restored).unwrap();

        let mut g2h_desc = Descriptor::new(end, 1, 0, DescFlags::empty());
        g2h_desc.mark_avail(true);
        write_desc(&HostMemOps::new(&restored), case.g2h_layout, 0, g2h_desc);
        let (mut recv, reply) = g2h.poll(1).unwrap().unwrap();
        assert!(matches!(
            recv.read_exact(&mut [0]),
            Err(VirtqError::MemoryReadError)
        ));
        g2h.complete(recv, reply).unwrap();

        let (recv, reply) = h2g.poll(0).unwrap().unwrap();
        let Ok(mut reply) = reply.into_writable() else {
            panic!("expected a writable H2G chain");
        };
        reply.write_all(&[1]).unwrap();
        assert!(matches!(
            reply.write_all(&[2]),
            Err(VirtqError::MemoryWriteError)
        ));
        h2g.complete(recv, reply).unwrap();
    }

    #[test]
    fn malformed_descriptors_fail_when_polled() {
        let case = test_case();
        let mut desc = read_desc(&case.mem, case.h2g_layout, 0);
        desc.flags |= DescFlags::INDIRECT.bits();
        write_desc(&case.mem, case.h2g_layout, 0, desc);
        let (_, mut h2g) = create_consumers(&memory_layout(), &case.scratch).unwrap();
        assert!(matches!(
            h2g.poll(0),
            Err(VirtqError::RingError(RingError::BadChain))
        ));
    }
}
