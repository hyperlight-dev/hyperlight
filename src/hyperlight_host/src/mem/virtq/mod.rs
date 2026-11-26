// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Host virtqueue consumers, I/O, and snapshot restoration.
//!
//! Rings occupy fixed arena storage. Payload accesses are bounded copies
//! within mapped scratch. Consumers validate descriptors when they are used.
//!
//! H2G requests are written into guest-prefilled chains. G2H codec helpers copy
//! untrusted guest messages into host-owned values before use.
//! Shared wire framing lives in `hyperlight_common::transport`.
//!
//! Snapshots contain deterministic bootstrap images with empty G2H and full
//! H2G prefill. Guest entry reconstructs their producer ownership.

mod codec;
mod mem;
#[cfg(test)]
pub(crate) mod tests;

pub(crate) use codec::{RecvMessage, recv_one_way, try_write_response};
use hyperlight_common::transport::MailboxValue;
use hyperlight_common::virtq::{
    BootstrapInfo, Layout as VirtqLayout, Notifier, QueueStats, VirtqConsumer, h2g_pool_layout,
};
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

/// Bootstrap ring images cached outside ordinary snapshot pages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VirtqSnapshot {
    /// Guest-to-host ring bytes.
    g2h_ring: Vec<u8>,
    /// Host-to-guest ring bytes.
    h2g_ring: Vec<u8>,
}

impl VirtqSnapshot {
    /// Build bootstrap images without accessing live guest memory.
    pub(crate) fn bootstrap(layout: &SandboxMemoryLayout) -> Result<Self> {
        let (g2h, h2g) = ring_layouts(layout)?;
        let h2g_dims = layout.get_h2g_queue_dims();
        let buffer_size = layout.get_h2g_buffer_size();

        let (_, _, _, pool_offset, _) = layout.get_transport_arena().to_offsets();
        let pool = h2g_pool_layout(
            g2h.desc_table_addr() + pool_offset as u64,
            h2g_dims.pool_pages().get(),
            buffer_size,
        )
        .map_err(|error| new_error!("invalid H2G bootstrap pool: {error}"))?;

        let info = BootstrapInfo::prefilled(h2g, pool)
            .map_err(|error| new_error!("invalid H2G bootstrap: {error}"))?;

        let mut g2h_ring = vec![0; layout.get_g2h_queue_dims().ring_len()];
        let mut h2g_ring = vec![0; h2g_dims.ring_len()];

        g2h.initialize(&ImageMem::new(g2h.desc_table_addr(), &mut g2h_ring))
            .map_err(|error| new_error!("G2H bootstrap initialization failed: {error}"))?;

        info.initialize(&ImageMem::new(h2g.desc_table_addr(), &mut h2g_ring))
            .map_err(|error| new_error!("H2G bootstrap initialization failed: {error}"))?;

        Ok(Self { g2h_ring, h2g_ring })
    }

    /// Restore these rings using the owning snapshot's transport layout.
    pub(crate) fn restore(
        &self,
        layout: &SandboxMemoryLayout,
        scratch_mem: &HostSharedMemory,
    ) -> Result<(G2hConsumer, H2gConsumer)> {
        let (g2h_offset, h2g_offset) = ring_offsets(layout);
        let mbx_offset = layout.mbx_scratch_offset();
        let status = MailboxValue::InitComplete.as_bytes();

        write_published_arena_gpa(scratch_mem, layout.get_transport_arena().base_addr())?;

        scratch_mem.copy_from_slice(&self.g2h_ring, g2h_offset)?;
        scratch_mem.copy_from_slice(&self.h2g_ring, h2g_offset)?;
        scratch_mem.copy_from_slice(status, mbx_offset)?;
        create_consumers(layout, scratch_mem)
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

fn ring_offsets(layout: &SandboxMemoryLayout) -> (usize, usize) {
    let g2h_offset = layout.arena_scratch_offset();
    let (h2g_offset, ..) = layout.get_transport_arena().to_offsets();
    (g2h_offset, g2h_offset + h2g_offset)
}
