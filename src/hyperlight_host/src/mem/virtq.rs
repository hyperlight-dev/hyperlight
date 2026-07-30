// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Host virtqueue attachment.
//!
//! The host publishes one transport arena address in scratch-top metadata. Guest
//! initialization builds both queues in those fixed regions. This module
//! validates the complete initial image before returning either consumer.

use core::ops::Range;

use hyperlight_common::layout::{QueueDims, TransportArena};
use hyperlight_common::virtq::canonical::validate_canon_image;
use hyperlight_common::virtq::{
    Layout as VirtqLayout, MemOps, Notifier, QueueStats, VirtqConsumer,
};

use super::layout::{BaseGpaRegion, SandboxMemoryLayout};
use super::shared_mem::{HostSharedMemory, SharedMemory};
use super::virtq_mem::HostMemOps;
use crate::{Result, new_error};

/// Host-side G2H virtqueue consumer.
pub(crate) type G2hConsumer = VirtqConsumer<HostMemOps, HostNotifier>;
/// Host-side H2G virtqueue consumer.
pub(crate) type H2gConsumer = VirtqConsumer<HostMemOps, HostNotifier>;

/// No-op notifier for polled host transport.
#[derive(Clone, Copy)]
pub(crate) struct HostNotifier;

impl Notifier for HostNotifier {
    fn notify(&self, _stats: QueueStats) {}
}

/// Build both host consumers from a guest-produced initial transport image.
///
/// The consumers are returned only after the host-assigned arena and both
/// directional ring images have passed validation.
pub(crate) fn attach(
    layout: &SandboxMemoryLayout,
    scratch_mem: &HostSharedMemory,
) -> Result<(G2hConsumer, H2gConsumer)> {
    let validator = Validator::new(layout)?;
    let arena_gpa = read_published_arena_gpa(scratch_mem)?;
    let regions = validator.validate_published_arena(arena_gpa)?;

    let g2h_ring_mem = HostMemOps::new(scratch_mem, regions.g2h_ring.clone())?;
    let g2h_pool_mem = HostMemOps::new(scratch_mem, regions.g2h_pool)?;
    let g2h_layout = validator.validate_g2h(&g2h_ring_mem, regions.g2h_ring)?;

    let h2g_ring_mem = HostMemOps::new(scratch_mem, regions.h2g_ring.clone())?;
    let h2g_pool_mem = HostMemOps::new(scratch_mem, regions.h2g_pool.clone())?;
    let h2g_layout = validator.validate_h2g(&h2g_ring_mem, regions.h2g_ring, regions.h2g_pool)?;

    Ok((
        VirtqConsumer::new_split(g2h_layout, g2h_ring_mem, g2h_pool_mem, HostNotifier),
        VirtqConsumer::new_split(h2g_layout, h2g_ring_mem, h2g_pool_mem, HostNotifier),
    ))
}

/// Bounded GVA regions derived from validated transport GPAs.
struct GvaRegions {
    g2h_ring: Range<u64>,
    h2g_ring: Range<u64>,
    g2h_pool: Range<u64>,
    h2g_pool: Range<u64>,
}

#[derive(Clone, Copy)]
struct QueueConfig {
    /// Address-independent queue dimensions.
    dims: QueueDims,
    /// Size of the ring image in bytes including event suppressions.
    ring_len: usize,
    /// Size of the buffer pool in bytes.
    pool_len: usize,
    /// Size of each buffer in the pool in bytes.
    buffer_size: usize,
}

impl QueueConfig {
    fn new(dims: QueueDims, buffer_size: usize) -> Result<Self> {
        let ring_len = dims
            .checked_ring_len()
            .ok_or_else(|| new_error!("ring size overflow"))?;
        let pool_len = dims
            .checked_pool_len()
            .ok_or_else(|| new_error!("pool size overflow"))?;

        if buffer_size == 0 {
            return Err(new_error!("buffer size is zero"));
        }

        Ok(Self {
            dims,
            ring_len,
            pool_len,
            buffer_size,
        })
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
            usize::from(h2g.dims.depth().get()).min(h2g.pool_len / h2g.buffer_size);
        let arena = layout.get_transport_arena();

        Ok(Self {
            g2h,
            h2g,
            arena,
            h2g_prefill_chains,
        })
    }
}

/// Validates one initial transport image against one host layout.
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

    /// Validate the initial G2H queue and return its layout.
    fn validate_g2h<M: MemOps>(&self, mem: &M, ring: Range<u64>) -> Result<VirtqLayout> {
        // SAFETY: `ring` spans the configured image and `mem` keeps that image
        // valid for the duration of validation.
        let layout = unsafe { VirtqLayout::from_base(ring.start, self.config.g2h.dims.depth()) }
            .map_err(|error| new_error!("invalid G2H ring layout: {error}"))?;

        validate_canon_image(mem, layout, 0, |_, _| false)
            .map_err(|error| new_error!("invalid canonical G2H image: {error}"))?;

        Ok(layout)
    }

    /// Validate the initial H2G queue and return its layout.
    ///
    /// Every available chain contains one configured size writable descriptor.
    /// Descriptors must name distinct, slot-aligned ranges inside the H2G pool.
    fn validate_h2g<M: MemOps>(
        &self,
        mem: &M,
        ring: Range<u64>,
        pool: Range<u64>,
    ) -> Result<VirtqLayout> {
        // SAFETY: `ring` spans the configured image and `mem` keeps that image
        // valid for the duration of validation.
        let layout = unsafe { VirtqLayout::from_base(ring.start, self.config.h2g.dims.depth()) }
            .map_err(|error| new_error!("invalid H2G ring layout: {error}"))?;

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
            self.config.g2h.ring_len,
            self.config.h2g.ring_len,
            self.config.g2h.pool_len,
            self.config.h2g.pool_len,
        );

        Ok(GvaRegions {
            g2h_ring: checked_region(to_gva(g2h_ring_addr)?, g2h_ring_len, "G2H ring")?,
            h2g_ring: checked_region(to_gva(h2g_ring_addr)?, h2g_ring_len, "H2G ring")?,
            g2h_pool: checked_region(to_gva(g2h_pool_addr)?, g2h_pool_len, "G2H pool")?,
            h2g_pool: checked_region(to_gva(h2g_pool_addr)?, h2g_pool_len, "H2G pool")?,
        })
    }
}

/// Read the transport arena GPA from scratch-top metadata.
fn read_published_arena_gpa(scratch_mem: &HostSharedMemory) -> Result<u64> {
    let offset = hyperlight_common::layout::SCRATCH_TOP_TRANSPORT_ARENA_GPA_OFFSET as usize;
    Ok(scratch_mem.read::<u64>(scratch_mem.mem_size() - offset)?)
}

#[cfg(test)]
fn write_published_arena_gpa(scratch_mem: &HostSharedMemory, arena_gpa: u64) -> Result<()> {
    let offset = hyperlight_common::layout::SCRATCH_TOP_TRANSPORT_ARENA_GPA_OFFSET as usize;
    Ok(scratch_mem.write::<u64>(scratch_mem.mem_size() - offset, arena_gpa)?)
}

fn checked_region(start: u64, len: usize, tag: &str) -> Result<Range<u64>> {
    let end = start
        .checked_add(u64::try_from(len)?)
        .ok_or_else(|| new_error!("{tag} GVA range overflow"))?;

    Ok(start..end)
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
            config.g2h.ring_len as u64
        );
        assert_eq!(
            regions.h2g_ring.end - regions.h2g_ring.start,
            config.h2g.ring_len as u64
        );
        assert_eq!(
            regions.g2h_pool.end - regions.g2h_pool.start,
            config.g2h.pool_len as u64
        );
        assert_eq!(
            regions.h2g_pool.end - regions.h2g_pool.start,
            config.h2g.pool_len as u64
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
    fn rejects_untranslatable_or_overflowing_gva_regions() {
        let config = attach_config();
        let arena_gpa = config.arena.base_addr();
        let invalid = hyperlight_common::layout::scratch_base_gpa(SCRATCH_SIZE) - 1;
        assert!(validate_published(invalid, config).is_err());

        let mut config = config;
        config.g2h.ring_len = usize::MAX;
        assert!(validate_published(arena_gpa, config).is_err());
    }

    #[test]
    fn validates_initial_virtq_images() {
        validate(&prepared_virtq()).unwrap();
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
