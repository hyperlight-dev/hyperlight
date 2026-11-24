// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Deterministic queue initialization shared by both peers.

use bytemuck::Zeroable;

use super::{
    AllocError, DescFlags, Descriptor, Layout, MemOps, PoolLayout, RingError, SlotLayout, SlotPool,
    ring,
};

/// Ring and pool geometry for empty or prefilled producer reconstruction.
#[derive(Clone, Copy, Debug)]
pub struct BootstrapInfo {
    /// Descriptor table and event-suppression geometry.
    layout: Layout,
    /// Payload pool geometry.
    pool: PoolLayout,
    /// Initial prefix of writable single-buffer chains.
    posted: u16,
}

impl BootstrapInfo {
    /// Describe an empty ring with all slots in its one- or two-tier pool free.
    pub fn empty(layout: Layout, pool: PoolLayout) -> Result<Self, RingError> {
        Self::new(layout, pool, 0)
    }

    /// Describe a ring filled with as many slots as its descriptor count permits.
    ///
    /// Prefill follows lower-first, per-tier allocation order.
    pub fn prefilled(layout: Layout, pool: PoolLayout) -> Result<Self, RingError> {
        let posted = pool.slot_count().min(usize::from(layout.desc_table_len())) as u16;
        Self::new(layout, pool, posted)
    }

    /// Require every pool tier to be disjoint from the ring and its events.
    fn new(layout: Layout, pool: PoolLayout, posted: u16) -> Result<Self, RingError> {
        for slots in pool.tiers() {
            if slots.base_addr() < layout.end_addr() && layout.desc_table_addr() < slots.end_addr()
            {
                return Err(RingError::InvalidLayout);
            }
        }

        Ok(Self {
            layout,
            pool,
            posted,
        })
    }

    /// Write descriptors and enable both peers' notifications without touching payloads.
    ///
    /// Both peers must stay stopped until initialization succeeds. An error can
    /// leave a partial image, which must be reinitialized or discarded.
    pub fn initialize<M: MemOps>(&self, mem: &M) -> Result<(), RingError> {
        self.layout
            .initialize_with(mem, |index| self.desc_at(index))
    }

    /// Number of buffers initially owned by the queue.
    pub(crate) const fn avail(&self) -> u16 {
        self.posted
    }

    /// Original capacity and identity, independent of consumer-written used lengths.
    pub(crate) fn desc_at(&self, index: u16) -> Descriptor {
        if index >= self.posted {
            return Descriptor::zeroed();
        }

        let Some(alloc) = SlotPool::alloc_for(self.pool, index as usize) else {
            return Descriptor::zeroed();
        };

        let desc_cnt = self.layout.desc_table_len();
        let Some(id) = ring::id_for(desc_cnt, index) else {
            return Descriptor::zeroed();
        };

        Descriptor::new(
            alloc.addr,
            alloc.len,
            id,
            DescFlags::WRITE | DescFlags::AVAIL,
        )
    }

    /// Ring geometry used for initialization.
    pub(crate) const fn layout(&self) -> Layout {
        self.layout
    }

    /// Normalized slot geometry for recreating the initial buffer pool.
    pub(crate) const fn pool_layout(&self) -> PoolLayout {
        self.pool
    }
}

/// Uniform H2G receive slots in the host-assigned pool.
pub fn h2g_pool_layout(
    base: u64,
    pages: usize,
    buffer_size: usize,
) -> Result<PoolLayout, AllocError> {
    if buffer_size == 0 {
        return Err(AllocError::InvalidArg);
    }

    let len = pages
        .checked_mul(crate::vmem::PAGE_SIZE)
        .ok_or(AllocError::Overflow)?;

    let slots = SlotLayout::new(base, buffer_size, len / buffer_size)?;
    Ok(PoolLayout::single(slots))
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use super::*;
    use crate::virtq::canonical::validate_canon_image;
    use crate::virtq::ring::tests::{FaultMem, make_consumer, make_producer, make_ring};
    use crate::virtq::{MemOp, RingProducer, SlotLayout};

    #[test]
    fn h2g_pool_uses_only_complete_slots() {
        let layout = h2g_pool_layout(0x1000, 3, 3000).unwrap();
        let pool = SlotPool::from_layout(layout).unwrap();

        assert_eq!(pool.num_free(), 4);
        assert_eq!(pool.byte_len(), 12_000);
        assert_eq!(pool.alloc(3000).unwrap().addr, 0x1000 + 9000);
    }

    #[test]
    fn h2g_pool_rejects_zero_buffer_size() {
        assert_matches!(h2g_pool_layout(0x1000, 1, 0), Err(AllocError::InvalidArg));
    }

    #[test]
    fn h2g_pool_rejects_undersized_backing() {
        assert_matches!(
            h2g_pool_layout(0x1000, 1, crate::vmem::PAGE_SIZE + 1),
            Err(AllocError::EmptyRegion)
        );
    }

    #[test]
    fn h2g_pool_rejects_size_overflow() {
        assert_matches!(
            h2g_pool_layout(0, usize::MAX, 64),
            Err(AllocError::Overflow)
        );
    }

    #[test]
    fn bootstrap_matches_fresh_pool_submissions() {
        let ring = make_ring(8);
        let mem = ring.mem();
        let base = ring.layout().end_addr();
        let slots = SlotLayout::new(base, 64, 3).unwrap();
        let pool = SlotPool::new(slots).unwrap();

        let mut producer = make_producer(&ring);
        let mut consumer = make_consumer(&ring);
        let mut expected = alloc::vec::Vec::new();

        for index in 0..3 {
            let alloc = pool.alloc(64).unwrap();
            producer.submit_one(alloc.addr, alloc.len, true).unwrap();

            expected.push(ring.read_desc(index));
        }

        producer.disable_used_notifications().unwrap();
        consumer.disable_avail_notifications().unwrap();

        mem.write(base, &[0xa5; 192]).unwrap();

        BootstrapInfo::prefilled(ring.layout(), pool.layout())
            .unwrap()
            .initialize(&mem)
            .unwrap();

        let chains = validate_canon_image(&mem, ring.layout(), 3, |_, elem| {
            elem.writable && elem.len == 64
        })
        .unwrap();

        assert_eq!(chains.len(), 3);

        for (index, desc) in expected.into_iter().enumerate() {
            assert_eq!(ring.read_desc(index as u16), desc);
        }

        let mut payloads = [0; 192];
        mem.read(base, &mut payloads).unwrap();
        assert_eq!(payloads, [0xa5; 192]);
    }

    #[test]
    fn empty_bootstrap_clears_descriptors_and_events() {
        let ring = make_ring(4);
        let slots = SlotLayout::new(ring.layout().end_addr(), 64, 2).unwrap();
        let info = BootstrapInfo::empty(ring.layout(), PoolLayout::single(slots)).unwrap();
        let mut producer = make_producer(&ring);
        let mut consumer = make_consumer(&ring);

        producer.submit_one(0x1000, 64, true).unwrap();
        producer.enable_used_notifications_desc(2, false).unwrap();
        consumer.disable_avail_notifications().unwrap();

        info.initialize(&ring.mem()).unwrap();

        assert!(
            validate_canon_image(&ring.mem(), ring.layout(), 0, |_, _| false)
                .unwrap()
                .is_empty()
        );

        let mut fresh = make_consumer(&ring);
        assert_matches!(fresh.poll_available(), Err(RingError::WouldBlock));

        let mut restored = RingProducer::new(ring.layout(), ring.mem());
        restored.refresh(info.avail());

        let id = restored.submit_one(0x1000, 64, false).unwrap();
        let (received_id, _) = fresh.poll_available().unwrap();

        assert_eq!(received_id, id);
    }

    #[test]
    fn bootstrap_rejects_pool_overlapping_event_storage() {
        let ring = make_ring(4);
        let slots = SlotLayout::new(ring.layout().dev_evt_addr(), 64, 1).unwrap();

        assert_matches!(
            BootstrapInfo::prefilled(ring.layout(), PoolLayout::single(slots)),
            Err(RingError::InvalidLayout)
        );
    }

    #[test]
    fn empty_bootstrap_rejects_lower_tier_overlapping_events() {
        let ring = make_ring(4);
        let lower = SlotLayout::new(ring.layout().dev_evt_addr(), 64, 1).unwrap();
        let upper = SlotLayout::new(lower.end_addr(), 128, 1).unwrap();
        let pool = PoolLayout::tiered(lower, upper).unwrap();

        assert_matches!(
            BootstrapInfo::empty(ring.layout(), pool),
            Err(RingError::InvalidLayout)
        );
    }

    #[test]
    fn empty_bootstrap_rejects_upper_tier_overlapping_events() {
        let ring = make_ring(4);
        let upper = SlotLayout::new(ring.layout().dev_evt_addr(), 64, 1).unwrap();

        assert_matches!(
            BootstrapInfo::empty(ring.layout(), PoolLayout::single(upper)),
            Err(RingError::InvalidLayout)
        );
    }

    #[test]
    fn bootstrap_can_retry_a_failed_write() {
        let ring = make_ring(4);
        let mem = FaultMem::new(ring.mem());
        let slots = SlotLayout::new(ring.layout().dev_evt_addr() + 0x100, 64, 2).unwrap();
        let info = BootstrapInfo::prefilled(ring.layout(), PoolLayout::single(slots)).unwrap();

        mem.fail_write_at(5);

        assert_matches!(
            info.initialize(&mem),
            Err(RingError::MemError {
                op: MemOp::WriteDesc,
                ..
            })
        );

        mem.allow_writes();
        info.initialize(&mem).unwrap();

        let len = validate_canon_image(&mem, ring.layout(), 2, |_, _| true)
            .unwrap()
            .len();

        assert_eq!(len, 2);
    }
}
