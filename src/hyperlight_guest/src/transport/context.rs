// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Guest virtqueue context.

use core::result;

use hyperlight_common::virtq::{
    AllocError, G2H_LOWER_SLOT_COUNT, G2H_LOWER_SLOT_SIZE, Layout, Notifier, QueueStats,
    SlotLayout, SlotPool, VirtqProducer,
};

use super::GuestMemOps;
use crate::error::{GuestErrorContext, Result};

/// Guest-side notifier for polled transport operation.
#[derive(Clone, Copy)]
pub struct GuestNotifier;

impl Notifier for GuestNotifier {
    fn notify(&self, _stats: QueueStats) {}
}

/// Type alias for the guest-side G2H producer.
pub type G2hProducer = VirtqProducer<GuestMemOps, GuestNotifier, SlotPool>;

/// Type alias for the guest-side H2G producer.
pub type H2gProducer = VirtqProducer<GuestMemOps, GuestNotifier, SlotPool>;

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
    _g2h_producer: G2hProducer,
    /// Host-to-guest driver.
    h2g_producer: H2gProducer,
    /// Size of each prefilled H2G buffer.
    h2g_slot_size: usize,
}

impl GuestContext {
    /// Create a new context with G2H and H2G queues.
    pub fn new(g2h: QueueConfig, h2g: QueueConfig) -> Result<Self> {
        Self::with_mem(g2h, h2g, GuestMemOps::for_scratch())
    }

    /// Create a new context with memory access provided.
    fn with_mem(g2h: QueueConfig, h2g: QueueConfig, mem: GuestMemOps) -> Result<Self> {
        let g2h_pool = g2h_pool(g2h.pool_gva, g2h.pool_pages, g2h.buffer_size)
            .with_context(|| "failed to create G2H pool")?;
        let g2h_producer = VirtqProducer::new(g2h.layout, mem, GuestNotifier, g2h_pool);

        let h2g_pool = h2g_pool(h2g.pool_gva, h2g.pool_pages, h2g.buffer_size)
            .with_context(|| "failed to create H2G slot pool")?;
        let h2g_producer = VirtqProducer::new(h2g.layout, mem, GuestNotifier, h2g_pool);

        let mut ctx = Self {
            _g2h_producer: g2h_producer,
            h2g_producer,
            h2g_slot_size: h2g.buffer_size,
        };

        ctx.prefill_h2g().expect("H2G initial prefill failed");
        Ok(ctx)
    }

    /// Pre-fill H2G with writable buffers until its ring or pool is full.
    fn prefill_h2g(&mut self) -> Result<()> {
        let mut batch = self.h2g_producer.batch();

        loop {
            let chain = match batch.chain().writable(self.h2g_slot_size).build() {
                Ok(chain) => chain,
                Err(error) if error.is_transient() => {
                    batch.finish()?;
                    return Ok(());
                }
                Err(error) => return Err(error.into()),
            };

            match batch.submit(chain) {
                Ok(_) => {}
                Err(error) if error.is_transient() => {
                    batch.finish()?;
                    return Ok(());
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

fn pool_len(pages: usize) -> result::Result<usize, AllocError> {
    pages
        .checked_mul(hyperlight_common::vmem::PAGE_SIZE)
        .ok_or(AllocError::Overflow)
}

/// Build the uniform H2G pool.
///
/// Every preposted receive buffer has the configured size so the host sees one
/// predictable capacity for guest calls.
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
