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

//! Host virtqueue construction, I/O, and canonical snapshot validation.
//!
//! Runtime consumers bind bounded ring and pool views to the host-owned fixed
//! transport arena. They start at cursor zero before the first guest entry and
//! observe descriptors published by the guest later.
//!
//! G2H codec helpers copy untrusted request data into host-owned values before
//! dispatch. Shared wire framing lives in `hyperlight_common::virtq::msg`.
//!
//! Snapshot capture and restore validate canonical ring images against the
//! configured arena before exposing consumers.

use core::ops::Range;

use anyhow::{Context, bail};
use flatbuffers::FlatBufferBuilder;
use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::{Bytes, FunctionCallResult};
use hyperlight_common::flatbuffer_wrappers::guest_error::{ErrorCode, GuestError};
use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
use hyperlight_common::flatbuffer_wrappers::{ExternalValueRefs, ExternalValueSource};
use hyperlight_common::layout::{QueueDims, TransportArena};
use hyperlight_common::virtq::canonical::validate_canon_image;
use hyperlight_common::virtq::msg::{
    EncodedMessage, MsgKind, SIZE_PREFIX_LEN, size_prefix_payload_len, size_prefixed_len,
};
use hyperlight_common::virtq::{
    Layout as VirtqLayout, MemOps, Notifier, QueueStats, RecvChain, VirtqConsumer, VirtqError,
    WritableChain,
};

use super::layout::{BaseGpaRegion, SandboxMemoryLayout};
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
    let validator = Validator::new(layout)?;
    let regions = validator.resolve_gva_regions()?;
    let g2h_layout = validator.config.g2h.layout(&regions.g2h_ring, "G2H")?;
    let h2g_layout = validator.config.h2g.layout(&regions.h2g_ring, "H2G")?;

    build_consumers(scratch_mem, regions, g2h_layout, h2g_layout)
}

/// Validate a materialized canonical image before attaching consumers.
fn attach_canonical(
    layout: &SandboxMemoryLayout,
    scratch_mem: &HostSharedMemory,
) -> Result<(G2hConsumer, H2gConsumer)> {
    let validator = Validator::new(layout)?;
    let arena_gpa = read_published_arena_gpa(scratch_mem)?;
    let regions = validator.validate_published_arena(arena_gpa)?;

    let g2h_ring_mem = HostMemOps::new(scratch_mem, regions.g2h_ring.clone())?;
    let g2h_layout = validator.validate_g2h(&g2h_ring_mem, regions.g2h_ring.clone())?;

    let h2g_ring_mem = HostMemOps::new(scratch_mem, regions.h2g_ring.clone())?;
    let h2g_layout = validator.validate_h2g(
        &h2g_ring_mem,
        regions.h2g_ring.clone(),
        regions.h2g_pool.clone(),
    )?;

    build_consumers(scratch_mem, regions, g2h_layout, h2g_layout)
}

/// Bind consumers to separately bounded ring and pool mappings.
fn build_consumers(
    scratch_mem: &HostSharedMemory,
    regions: GvaRegions,
    g2h_layout: VirtqLayout,
    h2g_layout: VirtqLayout,
) -> Result<(G2hConsumer, H2gConsumer)> {
    let g2h_ring_mem = HostMemOps::new(scratch_mem, regions.g2h_ring)?;
    let g2h_pool_mem = HostMemOps::new(scratch_mem, regions.g2h_pool)?;
    let h2g_ring_mem = HostMemOps::new(scratch_mem, regions.h2g_ring)?;
    let h2g_pool_mem = HostMemOps::new(scratch_mem, regions.h2g_pool)?;

    Ok((
        VirtqConsumer::new_split(g2h_layout, g2h_ring_mem, g2h_pool_mem, HostNotifier),
        VirtqConsumer::new_split(h2g_layout, h2g_ring_mem, h2g_pool_mem, HostNotifier),
    ))
}

/// Capture the canonical ring state omitted from the main memory snapshot.
///
/// Pool contents are transient and are not included.
pub(crate) fn snapshot(
    layout: &SandboxMemoryLayout,
    scratch_mem: &HostSharedMemory,
) -> Result<VirtqSnapshot> {
    let validator = Validator::new(layout)?;

    let arena_gpa = read_published_arena_gpa(scratch_mem)?;
    let regions = validator.validate_published_arena(arena_gpa)?;

    let g2h_mem = HostMemOps::new(scratch_mem, regions.g2h_ring.clone())?;
    validator.validate_g2h(&g2h_mem, regions.g2h_ring.clone())?;

    let h2g_mem = HostMemOps::new(scratch_mem, regions.h2g_ring.clone())?;
    validator.validate_h2g(&h2g_mem, regions.h2g_ring.clone(), regions.h2g_pool.clone())?;

    // The vCPU is stopped, so the ring images and snapshotted guest producer
    // bookkeeping describe the same instant.
    Ok(VirtqSnapshot {
        scratch_size: layout.get_scratch_size(),
        g2h_ring: read_ring(scratch_mem, regions.g2h_ring)?,
        h2g_ring: read_ring(scratch_mem, regions.h2g_ring)?,
    })
}

/// Validate and restore one canonical transport image.
///
/// Validation completes before restored scratch is mutated. Fresh consumers
/// start from the canonical cursor state encoded in the rings.
pub(crate) fn restore(
    layout: &SandboxMemoryLayout,
    scratch_mem: &HostSharedMemory,
    snapshot: &VirtqSnapshot,
) -> Result<(G2hConsumer, H2gConsumer)> {
    let regions = Validator::new(layout)?.validate_snapshot(snapshot)?;

    write_published_arena_gpa(scratch_mem, layout.get_transport_arena().base_addr())?;
    write_ring(scratch_mem, regions.g2h_ring, &snapshot.g2h_ring)?;
    write_ring(scratch_mem, regions.h2g_ring, &snapshot.h2g_ring)?;
    attach_canonical(layout, scratch_mem)
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

/// Bounded GVA regions derived from validated transport GPAs.
struct GvaRegions {
    /// Guest-to-host packed ring image.
    g2h_ring: Range<u64>,
    /// Host-to-guest packed ring image.
    h2g_ring: Range<u64>,
    /// Guest-to-host descriptor buffer pool.
    g2h_pool: Range<u64>,
    /// Host-to-guest descriptor buffer pool.
    h2g_pool: Range<u64>,
}

#[derive(Clone, Copy)]
struct QueueConfig {
    /// Address-independent queue dimensions.
    dims: QueueDims,
    /// Size of each buffer in the pool in bytes.
    buffer_size: usize,
}

impl QueueConfig {
    fn new(dims: QueueDims, buffer_size: usize) -> Result<Self> {
        if buffer_size == 0 {
            return Err(new_error!("buffer size is zero"));
        }

        Ok(Self { dims, buffer_size })
    }

    fn layout(&self, ring: &Range<u64>, direction: &str) -> Result<VirtqLayout> {
        // SAFETY: `ring` is derived from the validated fixed transport arena.
        unsafe { VirtqLayout::from_base(ring.start, self.dims.depth()) }
            .map_err(|error| new_error!("invalid {direction} ring layout: {error}"))
    }
}

/// Host-owned transport dimensions.
#[derive(Clone, Copy)]
struct Config {
    /// Host-requested G2H configuration.
    g2h: QueueConfig,
    /// Host-requested H2G configuration.
    h2g: QueueConfig,
    /// Fixed host-assigned transport arena.
    arena: TransportArena,
    /// Number of one-descriptor chains posted before the H2G ring or pool fills.
    h2g_prefill_chains: usize,
}

impl Config {
    /// Compute the host transport configuration from the memory layout.
    fn from_layout(layout: &SandboxMemoryLayout) -> Result<Self> {
        let g2h = QueueConfig::new(layout.get_g2h_queue_dims(), layout.get_g2h_buffer_size())?;
        let h2g = QueueConfig::new(layout.get_h2g_queue_dims(), layout.get_h2g_buffer_size())?;

        let h2g_prefill_chains =
            usize::from(h2g.dims.depth().get()).min(h2g.dims.pool_len() / h2g.buffer_size);

        let arena = layout.get_transport_arena();

        Ok(Self {
            g2h,
            h2g,
            arena,
            h2g_prefill_chains,
        })
    }
}

/// Canonical in-memory transport state excluded from ordinary snapshot pages.
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
    /// Validate every captured field before mutating restored scratch.
    pub(crate) fn preflight(&self, layout: &SandboxMemoryLayout) -> Result<()> {
        Validator::new(layout)?.validate_snapshot(self).map(|_| ())
    }
}

/// Validates live and captured transport images against one host layout.
struct Validator<'a> {
    config: Config,
    layout: &'a SandboxMemoryLayout,
}

impl<'a> Validator<'a> {
    fn new(layout: &'a SandboxMemoryLayout) -> Result<Self> {
        Ok(Self {
            config: Config::from_layout(layout)?,
            layout,
        })
    }

    /// Validate a canonical G2H image and return its layout.
    fn validate_g2h<M: MemOps>(&self, mem: &M, ring: Range<u64>) -> Result<VirtqLayout> {
        let layout = self.config.g2h.layout(&ring, "G2H")?;

        validate_canon_image(mem, layout, 0, |_, _| false)
            .map_err(|error| new_error!("invalid canonical G2H image: {error}"))?;

        Ok(layout)
    }

    /// Validate a canonical H2G image and return its layout.
    ///
    /// Every available chain contains one configured size writable descriptor.
    /// Descriptors must name distinct, slot-aligned ranges inside the H2G pool.
    fn validate_h2g<M: MemOps>(
        &self,
        mem: &M,
        ring: Range<u64>,
        pool: Range<u64>,
    ) -> Result<VirtqLayout> {
        let layout = self.config.h2g.layout(&ring, "H2G")?;

        let bufsz = self.config.h2g.buffer_size;
        let prefill = self.config.h2g_prefill_chains;

        if prefill == 0 {
            return Err(new_error!("H2G pool has no complete buffers"));
        }

        // Record the accepted descriptor ranges to detect overlaps.
        let mut accepted: Vec<Range<u64>> = Vec::with_capacity(prefill);

        let image = validate_canon_image(mem, layout, prefill, |_, elem| {
            let Ok(bufsz_u64) = u64::try_from(bufsz) else {
                return false;
            };

            // all descriptors must be writable and match the configured buffer size
            if !elem.writable || usize::try_from(elem.len).ok() != Some(bufsz) {
                return false;
            }

            let Some(offset) = elem.addr.checked_sub(pool.start) else {
                return false;
            };
            let Some(end) = elem.addr.checked_add(u64::from(elem.len)) else {
                return false;
            };

            // all descriptors must be slot-aligned and remain inside the pool
            if !offset.is_multiple_of(bufsz_u64) || end > pool.end {
                return false;
            }

            let buf = elem.addr..end;

            // all descriptors must name distinct ranges
            if accepted
                .iter()
                .any(|other| buf.start < other.end && other.start < buf.end)
            {
                return false;
            }

            accepted.push(buf);
            true
        })
        .map_err(|error| new_error!("invalid canonical H2G image: {error}"))?;

        // compare the number of accepted chains to the expected prefill count
        if image.len() != prefill {
            return Err(new_error!("invalid initial H2G chains"));
        }

        Ok(layout)
    }

    /// Validate the published arena and return its GVA regions.
    fn validate_published_arena(&self, arena_gpa: u64) -> Result<GvaRegions> {
        if arena_gpa != self.config.arena.base_addr() {
            return Err(new_error!("published transport arena is invalid"));
        }

        self.resolve_gva_regions()
    }

    fn validate_snapshot(&self, snapshot: &VirtqSnapshot) -> Result<GvaRegions> {
        if snapshot.scratch_size != self.layout.get_scratch_size() {
            return Err(new_error!(
                "virtqueue snapshot scratch size {} does not match layout size {}",
                snapshot.scratch_size,
                self.layout.get_scratch_size()
            ));
        }

        let regions = self.resolve_gva_regions()?;
        validate_ring_len("G2H", &snapshot.g2h_ring, self.config.g2h.dims.ring_len())?;
        validate_ring_len("H2G", &snapshot.h2g_ring, self.config.h2g.dims.ring_len())?;

        let g2h_mem = ImageMem::new(regions.g2h_ring.start, &snapshot.g2h_ring);
        self.validate_g2h(&g2h_mem, regions.g2h_ring.clone())?;

        let h2g_mem = ImageMem::new(regions.h2g_ring.start, &snapshot.h2g_ring);
        self.validate_h2g(&h2g_mem, regions.h2g_ring.clone(), regions.h2g_pool.clone())?;

        Ok(regions)
    }

    /// Translate validated transport GPAs into the GVA ranges used by descriptors.
    fn resolve_gva_regions(&self) -> Result<GvaRegions> {
        let to_gva = |gpa| {
            let resolved = self
                .layout
                .resolve_gpa(gpa, &[])
                .ok_or_else(|| new_error!("GPA {gpa:#x} is outside scratch"))?;

            if !matches!(resolved.base, BaseGpaRegion::Scratch(())) {
                return Err(new_error!("GPA {gpa:#x} is outside scratch"));
            }

            hyperlight_common::layout::scratch_base_gva(self.layout.get_scratch_size())
                .checked_add(u64::try_from(resolved.offset)?)
                .ok_or_else(|| new_error!("GPA {gpa:#x} to GVA translation overflow"))
        };

        let (
            g2h_ring_addr,
            h2g_ring_addr,
            g2h_pool_addr,
            h2g_pool_addr,
            g2h_ring_len,
            h2g_ring_len,
            g2h_pool_len,
            h2g_pool_len,
        ) = (
            self.config.arena.g2h_ring_addr(),
            self.config.arena.h2g_ring_addr(),
            self.config.arena.g2h_pool_addr(),
            self.config.arena.h2g_pool_addr(),
            self.config.g2h.dims.ring_len(),
            self.config.h2g.dims.ring_len(),
            self.config.g2h.dims.pool_len(),
            self.config.h2g.dims.pool_len(),
        );

        Ok(GvaRegions {
            g2h_ring: checked_region(to_gva(g2h_ring_addr)?, g2h_ring_len, "G2H ring")?,
            h2g_ring: checked_region(to_gva(h2g_ring_addr)?, h2g_ring_len, "H2G ring")?,
            g2h_pool: checked_region(to_gva(g2h_pool_addr)?, g2h_pool_len, "G2H pool")?,
            h2g_pool: checked_region(to_gva(h2g_pool_addr)?, h2g_pool_len, "H2G pool")?,
        })
    }
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

/// Read the transport arena GPA from scratch-top metadata.
fn read_published_arena_gpa(scratch_mem: &HostSharedMemory) -> Result<u64> {
    let offset = hyperlight_common::layout::SCRATCH_TOP_TRANSPORT_ARENA_GPA_OFFSET as usize;
    scratch_mem.read::<u64>(scratch_mem.mem_size() - offset)
}

/// Publish the fixed transport arena GPA in scratch-top metadata.
fn write_published_arena_gpa(scratch_mem: &HostSharedMemory, arena_gpa: u64) -> Result<()> {
    let offset = hyperlight_common::layout::SCRATCH_TOP_TRANSPORT_ARENA_GPA_OFFSET as usize;
    scratch_mem.write::<u64>(scratch_mem.mem_size() - offset, arena_gpa)
}

/// Copy one ring image from its bounded scratch mapping.
fn read_ring(scratch_mem: &HostSharedMemory, ring: Range<u64>) -> Result<Vec<u8>> {
    let len = usize::try_from(
        ring.end
            .checked_sub(ring.start)
            .ok_or_else(|| new_error!("invalid ring range"))?,
    )?;

    let mem = HostMemOps::new(scratch_mem, ring.clone())?;
    let mut bytes = vec![0; len];
    mem.read(ring.start, &mut bytes)?;

    Ok(bytes)
}

/// Copy one validated ring image into its bounded scratch mapping.
fn write_ring(scratch_mem: &HostSharedMemory, ring: Range<u64>, bytes: &[u8]) -> Result<()> {
    validate_ring_len("restored", bytes, usize::try_from(ring.end - ring.start)?)?;
    let mem = HostMemOps::new(scratch_mem, ring.clone())?;
    mem.write(ring.start, bytes)
}

/// Require a captured ring image to match its configured region exactly.
fn validate_ring_len(direction: &str, bytes: &[u8], expected: usize) -> Result<()> {
    if bytes.len() != expected {
        return Err(new_error!(
            "{direction} snapshot ring length {} and expected length {expected}",
            bytes.len()
        ));
    }
    Ok(())
}

/// Build a GVA range while checking address arithmetic.
fn checked_region(start: u64, len: usize, tag: &str) -> Result<Range<u64>> {
    let end = start
        .checked_add(u64::try_from(len)?)
        .ok_or_else(|| new_error!("{tag} GVA range overflow"))?;

    Ok(start..end)
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
    let mut external_values = ExternalValueRefs::new();

    let control = result.encode_external(&mut builder, &mut external_values)?;
    let message = EncodedMessage::new(MsgKind::Response, cid, control, external_values)
        .context("Host function response length overflow")?;

    if message.wire_len() > reply.capacity() {
        return Ok(false);
    }

    message.try_for_each_chunk(|chunk| {
        reply.write_all(chunk)?;
        Ok::<(), VirtqError>(())
    })?;

    Ok(true)
}

/// Copy size-prefixed control data and leave external values unread.
fn read_control(request: &mut RecvChain<HostMemOps>) -> anyhow::Result<Vec<u8>> {
    let mut prefix = [0u8; SIZE_PREFIX_LEN];
    request.read_exact(&mut prefix)?;

    let payload_len = size_prefix_payload_len(&prefix).expect("size prefix length is fixed");
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
        DescFlags, Descriptor, MemOps, SlotLayout, SlotPool, VirtqProducer,
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
        config.set_g2h_queue_depth(G2H_DEPTH as usize);
        config.set_h2g_queue_depth(H2G_DEPTH as usize);
        config.set_h2g_buffer_size(H2G_BUFFER_SIZE);
        config.set_g2h_pool_pages(G2H_POOL_PAGES);
        config.set_h2g_pool_pages(H2G_POOL_PAGES);
        SandboxMemoryLayout::new(config, 4096, 0, None).unwrap()
    }

    fn attach_config() -> Config {
        Config::from_layout(&memory_layout()).unwrap()
    }

    fn host_scratch() -> HostSharedMemory {
        let scratch = ExclusiveSharedMemory::new(SCRATCH_SIZE).unwrap();
        scratch.build().0
    }

    fn validate_published(arena_gpa: u64, config: Config) -> Result<GvaRegions> {
        let layout = memory_layout();
        Validator {
            config,
            layout: &layout,
        }
        .validate_published_arena(arena_gpa)
    }

    struct PreparedVirtq {
        scratch: HostSharedMemory,
        g2h_mem: HostMemOps,
        h2g_mem: HostMemOps,
        g2h_ring: Range<u64>,
        h2g_ring: Range<u64>,
        g2h_pool: Range<u64>,
        h2g_pool: Range<u64>,
        g2h_layout: VirtqLayout,
        h2g_layout: VirtqLayout,
    }

    fn prepared_virtq() -> PreparedVirtq {
        let scratch = ExclusiveSharedMemory::new(SCRATCH_SIZE).unwrap();
        let (scratch, _) = scratch.build();

        let layout = memory_layout();
        let config = Config::from_layout(&layout).unwrap();
        let scratch_base_gpa = hyperlight_common::layout::scratch_base_gpa(SCRATCH_SIZE);
        let scratch_base_gva = hyperlight_common::layout::scratch_base_gva(SCRATCH_SIZE);
        let to_gva = |gpa| scratch_base_gva + (gpa - scratch_base_gpa);

        let ring_base = to_gva(config.arena.g2h_ring_addr());
        let h2g_base = to_gva(config.arena.h2g_ring_addr());
        let g2h_pool_base = to_gva(config.arena.g2h_pool_addr());
        let g2h_pool_end = g2h_pool_base + (G2H_POOL_PAGES * vmem::PAGE_SIZE) as u64;
        let h2g_pool_base = to_gva(config.arena.h2g_pool_addr());
        let h2g_pool_end = h2g_pool_base + (H2G_POOL_PAGES * vmem::PAGE_SIZE) as u64;

        // SAFETY: The scratch mapping covers both ring layouts.
        let g2h_layout = unsafe {
            VirtqLayout::from_base(ring_base, NonZeroU16::new(G2H_DEPTH).unwrap()).unwrap()
        };
        // SAFETY: The scratch mapping covers both ring layouts.
        let h2g_layout = unsafe {
            VirtqLayout::from_base(h2g_base, NonZeroU16::new(H2G_DEPTH).unwrap()).unwrap()
        };

        let mem = HostMemOps::new(&scratch, ring_base..h2g_pool_end).unwrap();
        let h2g_prefill_chains = (H2G_POOL_PAGES * vmem::PAGE_SIZE) / H2G_BUFFER_SIZE;

        let h2g_pool = SlotPool::new(SlotLayout::new(
            h2g_pool_base,
            H2G_BUFFER_SIZE,
            h2g_prefill_chains,
        ))
        .unwrap();

        let mut h2g = VirtqProducer::new(h2g_layout, mem, HostNotifier, h2g_pool.clone());
        let mut batch = h2g.batch();

        for _ in 0..h2g_pool.num_free() {
            let chain = batch.chain().writable(H2G_BUFFER_SIZE).build().unwrap();
            batch.submit(chain).unwrap();
        }

        batch.finish().unwrap();
        write_published_arena_gpa(&scratch, config.arena.base_addr()).unwrap();

        let g2h_ring = ring_base..ring_base + VirtqLayout::query_size(G2H_DEPTH as usize) as u64;
        let h2g_ring = h2g_base..h2g_base + VirtqLayout::query_size(H2G_DEPTH as usize) as u64;
        let g2h_pool = g2h_pool_base..g2h_pool_end;
        let h2g_pool = h2g_pool_base..h2g_pool_end;
        let g2h_mem = HostMemOps::new(&scratch, g2h_ring.clone()).unwrap();
        let h2g_mem = HostMemOps::new(&scratch, h2g_ring.clone()).unwrap();

        PreparedVirtq {
            scratch,
            g2h_mem,
            h2g_mem,
            g2h_ring,
            h2g_ring,
            g2h_pool,
            h2g_pool,
            g2h_layout,
            h2g_layout,
        }
    }

    fn validate(prepared: &PreparedVirtq) -> Result<()> {
        let layout = memory_layout();
        let validator = Validator::new(&layout)?;

        validator.validate_g2h(&prepared.g2h_mem, prepared.g2h_ring.clone())?;
        validator.validate_h2g(
            &prepared.h2g_mem,
            prepared.h2g_ring.clone(),
            prepared.h2g_pool.clone(),
        )?;
        Ok(())
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
    fn validates_host_placed_regions() {
        let config = attach_config();
        let regions = validate_published(config.arena.base_addr(), config).unwrap();

        assert_eq!(
            regions.g2h_ring.end - regions.g2h_ring.start,
            config.g2h.dims.ring_len() as u64
        );
        assert_eq!(
            regions.h2g_ring.end - regions.h2g_ring.start,
            config.h2g.dims.ring_len() as u64
        );
        assert_eq!(
            regions.g2h_pool.end - regions.g2h_pool.start,
            config.g2h.dims.pool_len() as u64
        );
        assert_eq!(
            regions.h2g_pool.end - regions.h2g_pool.start,
            config.h2g.dims.pool_len() as u64
        );
    }

    #[test]
    fn rejects_invalid_published_regions() {
        let config = attach_config();
        let arena_gpa = config.arena.base_addr() + 1;
        assert!(validate_published(arena_gpa, config).is_err());
    }

    #[test]
    fn rejects_published_region_overflow() {
        let config = attach_config();
        assert!(validate_published(u64::MAX, config).is_err());
    }

    #[test]
    fn rejects_untranslatable_gva_regions() {
        let config = attach_config();
        let invalid = hyperlight_common::layout::scratch_base_gpa(SCRATCH_SIZE) - 1;
        assert!(validate_published(invalid, config).is_err());
    }

    #[test]
    fn validates_initial_virtq_images() {
        validate(&prepared_virtq()).unwrap();
    }

    #[test]
    fn snapshots_and_restores_canonical_image() {
        let prepared = prepared_virtq();
        let layout = memory_layout();
        let stale_pool = [0xa5; 16];
        let pool_mem = HostMemOps::new(&prepared.scratch, prepared.h2g_pool.clone()).unwrap();
        pool_mem
            .write(prepared.h2g_pool.start, &stale_pool)
            .unwrap();

        let captured = snapshot(&layout, &prepared.scratch).unwrap();
        let restored = host_scratch();
        let allocator = layout.get_first_free_scratch_gpa();
        let allocator_offset =
            restored.mem_size() - hyperlight_common::layout::SCRATCH_TOP_ALLOCATOR_OFFSET as usize;
        restored.write::<u64>(allocator_offset, allocator).unwrap();

        restore(&layout, &restored, &captured).unwrap();
        let restored_snapshot = snapshot(&layout, &restored).unwrap();
        let restored_pool = HostMemOps::new(&restored, prepared.h2g_pool.clone()).unwrap();
        let mut pool_bytes = [0; 16];
        restored_pool
            .read(prepared.h2g_pool.start, &mut pool_bytes)
            .unwrap();

        assert_eq!(restored_snapshot, captured);
        assert_eq!(restored.read::<u64>(allocator_offset).unwrap(), allocator);
        assert_eq!(pool_bytes, [0; 16]);
    }

    #[test]
    fn rejects_corrupt_snapshot_ring_before_restore() {
        let prepared = prepared_virtq();
        let layout = memory_layout();
        let mut snapshot = snapshot(&layout, &prepared.scratch).unwrap();
        snapshot.h2g_ring.fill(0);
        let restored = host_scratch();

        assert!(restore(&layout, &restored, &snapshot).is_err());
        assert_eq!(read_published_arena_gpa(&restored).unwrap(), 0);
    }

    #[test]
    fn restores_with_grown_page_tables() {
        let prepared = prepared_virtq();
        let layout = memory_layout();
        let snapshot = snapshot(&layout, &prepared.scratch).unwrap();
        let mut grown_layout = layout;
        grown_layout
            .set_pt_size(layout.get_pt_size() + vmem::PAGE_SIZE)
            .unwrap();
        let restored = host_scratch();

        restore(&grown_layout, &restored, &snapshot).unwrap();
        assert_eq!(
            read_published_arena_gpa(&restored).unwrap(),
            grown_layout.get_transport_arena().base_addr()
        );
    }

    #[test]
    fn rejects_h2g_descriptors_outside_pool() {
        let prepared = prepared_virtq();
        let mut desc = read_desc(&prepared.h2g_mem, prepared.h2g_layout, 0);
        desc.addr = prepared.g2h_pool.start;
        write_desc(&prepared.h2g_mem, prepared.h2g_layout, 0, desc);
        assert!(validate(&prepared).is_err());
    }

    #[test]
    fn rejects_nonzero_g2h_descriptors() {
        let prepared = prepared_virtq();
        let mut desc = read_desc(&prepared.g2h_mem, prepared.g2h_layout, 0);
        desc.addr = prepared.g2h_pool.start;
        write_desc(&prepared.g2h_mem, prepared.g2h_layout, 0, desc);
        assert!(validate(&prepared).is_err());
    }

    #[test]
    fn rejects_readable_h2g_descriptor() {
        let prepared = prepared_virtq();
        let mut desc = read_desc(&prepared.h2g_mem, prepared.h2g_layout, 0);
        desc.flags &= !DescFlags::WRITE.bits();
        write_desc(&prepared.h2g_mem, prepared.h2g_layout, 0, desc);
        assert!(validate(&prepared).is_err());
    }

    #[test]
    fn rejects_invalid_h2g_size() {
        let prepared = prepared_virtq();
        let mut desc = read_desc(&prepared.h2g_mem, prepared.h2g_layout, 0);
        desc.len -= 1;
        write_desc(&prepared.h2g_mem, prepared.h2g_layout, 0, desc);
        assert!(validate(&prepared).is_err());
    }

    #[test]
    fn rejects_misaligned_h2g_descriptor() {
        let prepared = prepared_virtq();
        let mut desc = read_desc(&prepared.h2g_mem, prepared.h2g_layout, 0);
        desc.addr += 1;
        write_desc(&prepared.h2g_mem, prepared.h2g_layout, 0, desc);
        assert!(validate(&prepared).is_err());
    }

    #[test]
    fn rejects_overlapping_h2g_descriptors() {
        let prepared = prepared_virtq();
        let first = read_desc(&prepared.h2g_mem, prepared.h2g_layout, 0);
        let mut second = read_desc(&prepared.h2g_mem, prepared.h2g_layout, 1);
        second.addr = first.addr;
        write_desc(&prepared.h2g_mem, prepared.h2g_layout, 1, second);
        assert!(validate(&prepared).is_err());
    }
}
