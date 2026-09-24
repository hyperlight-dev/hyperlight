// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Host virtqueue consumers, I/O, and snapshot restoration.
//!
//! Rings occupy fixed arena storage. Payload accesses are bounded copies
//! within mapped scratch. Consumers validate descriptors when they are used.
//!
//! H2G requests are written into guest-prefilled chains. G2H codec helpers copy
//! untrusted guest requests and results into host-owned values before use.
//! Shared wire framing lives in `hyperlight_common::transport`.
//!
//! Snapshots require canonical rings with empty G2H and the initial H2G prefill.
//! Each H2G chain contains one writable descriptor naming a distinct,
//! configured-size slot aligned relative to the H2G pool start.

mod codec;
mod mem;
#[cfg(test)]
pub(crate) mod tests;

use std::collections::HashSet;

pub(crate) use codec::{
    get_host_function_call, read_guest_function_call_result, read_guest_log_data,
    read_message_header, try_write_response,
};
use hyperlight_common::virtq::canonical::validate_canon_image;
use hyperlight_common::virtq::{Layout as VirtqLayout, Notifier, QueueStats, VirtqConsumer};
use mem::{HostMemOps, ImageMem};

use super::layout::SandboxMemoryLayout;
use super::shared_mem::{HostSharedMemory, SharedMemory};
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

/// Bind both host consumers at canonical cursor zero.
///
/// Rings must be uninitialized or contain a validated canonical image.
/// Their contents are not inspected here.
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

/// Validated ring images excluded from ordinary snapshot pages.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct VirtqSnapshot {
    /// Scratch size used to derive transport GVAs.
    scratch_size: usize,
    /// Guest-to-host ring bytes.
    g2h_ring: Vec<u8>,
    /// Host-to-guest ring bytes.
    h2g_ring: Vec<u8>,
}

impl VirtqSnapshot {
    /// Validate captured or decoded rings against the final transport geometry.
    pub(crate) fn new(
        layout: &SandboxMemoryLayout,
        scratch_size: usize,
        g2h_ring: Vec<u8>,
        h2g_ring: Vec<u8>,
    ) -> Result<Self> {
        let snapshot = Self {
            scratch_size,
            g2h_ring,
            h2g_ring,
        };

        snapshot.validate(layout)?;
        Ok(snapshot)
    }

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

        Self::new(layout, layout.get_scratch_size(), g2h_ring, h2g_ring)
    }

    /// Scratch size used to interpret the saved ring addresses.
    pub(crate) fn scratch_size(&self) -> usize {
        self.scratch_size
    }

    /// Canonical guest-to-host ring bytes.
    pub(crate) fn g2h_ring(&self) -> &[u8] {
        &self.g2h_ring
    }

    /// Canonical host-to-guest ring bytes.
    pub(crate) fn h2g_ring(&self) -> &[u8] {
        &self.h2g_ring
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

    /// Check geometry, canonical rings, and distinct, aligned H2G pool slots.
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

        let (_, _, _, pool_offset, _) = layout.get_transport_arena().to_offsets();
        let pool_start = g2h.desc_table_addr() + pool_offset as u64;
        let pool_end = pool_start + h2g_dims.pool_len() as u64;
        let mut seen_slots = HashSet::with_capacity(h2g_prefill);

        let chains = validate_canon_image(&h2g_mem, h2g, h2g_prefill, |_, elem| {
            if !elem.writable || usize::try_from(elem.len).ok() != Some(buffer_size) {
                return false;
            }

            let Some(offset) = elem.addr.checked_sub(pool_start) else {
                return false;
            };

            let Some(end) = elem.addr.checked_add(u64::from(elem.len)) else {
                return false;
            };

            if !offset.is_multiple_of(buffer_size as u64) || end > pool_end {
                return false;
            }

            seen_slots.insert(offset)
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
