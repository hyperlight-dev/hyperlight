// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use hyperlight_common::layout::SCRATCH_TOP_ALLOCATOR_OFFSET;
use hyperlight_common::virtq::{
    DescFlags, Descriptor, MemOps, RingError, RingProducer, SlotLayout, SlotPool, VirtqError,
};

use super::mem::HostMemOps;
use super::*;
use crate::mem::shared_mem::{ExclusiveSharedMemory, HostSharedMemory};
use crate::sandbox::SandboxConfiguration;

pub(crate) const SCRATCH_SIZE: usize = 0x20_000;
pub(crate) const H2G_BUFFER_SIZE: usize = 3000;

/// Empty G2H and prefilled H2G rings in host-backed scratch.
pub(crate) struct TestCase {
    pub(crate) scratch: HostSharedMemory,
    pub(crate) mem: HostMemOps,
    pub(crate) g2h_pool_base: u64,
    h2g_pool_base: u64,
    pub(crate) g2h_layout: VirtqLayout,
    h2g_layout: VirtqLayout,
}

impl TestCase {
    /// Allocate canonical rings with the configured H2G receive capacity.
    pub(crate) fn new() -> Self {
        let scratch = host_scratch();
        let layout = memory_layout();
        let arena = layout.get_transport_arena();
        let (g2h_layout, h2g_layout) = ring_layouts(&layout).unwrap();
        let g2h_pool_base = scratch_gva(arena.g2h_pool_addr());
        let h2g_pool_base = scratch_gva(arena.h2g_pool_addr());
        let h2g = layout.get_h2g_queue_dims();
        let mem = HostMemOps::new(&scratch);
        let buffer_size = layout.get_h2g_buffer_size();
        let h2g_prefill_descs = usize::from(h2g.size().get()).min(h2g.pool_len() / buffer_size);
        let h2g_pool_layout =
            SlotLayout::new(h2g_pool_base, buffer_size, h2g_prefill_descs).unwrap();
        let h2g_pool = SlotPool::new(h2g_pool_layout).unwrap();

        let mut producer = RingProducer::new(h2g_layout, mem.clone());

        for _ in 0..h2g_prefill_descs {
            let allocation = h2g_pool.alloc(buffer_size).unwrap();
            producer
                .submit_one(allocation.addr, allocation.len, true)
                .unwrap();
        }

        write_published_arena_gpa(&scratch, arena.base_addr()).unwrap();

        Self {
            scratch,
            mem,
            g2h_pool_base,
            h2g_pool_base,
            g2h_layout,
            h2g_layout,
        }
    }

    pub(crate) fn h2g_consumer(&self) -> H2gConsumer {
        create_consumers(&memory_layout(), &self.scratch).unwrap().1
    }

    pub(crate) fn g2h_consumer(&self) -> G2hConsumer {
        create_consumers(&memory_layout(), &self.scratch).unwrap().0
    }

    pub(crate) fn h2g_desc(&self, index: u16) -> Descriptor {
        read_desc(&self.mem, self.h2g_layout, index)
    }

    pub(crate) fn set_h2g_desc(&self, index: u16, desc: Descriptor) {
        write_desc(&self.mem, self.h2g_layout, index, desc);
    }

    pub(crate) fn h2g_buffer(&self, index: u16, addr: u64) -> Vec<u8> {
        let desc = self.h2g_desc(index);
        let mut bytes = vec![0; desc.len as usize];
        self.mem.read(addr, &mut bytes).unwrap();
        bytes
    }
}

/// The test scratch's GVA for `gpa`.
fn scratch_gva(gpa: u64) -> u64 {
    hyperlight_common::layout::scratch_base_gva(SCRATCH_SIZE)
        + (gpa - hyperlight_common::layout::scratch_base_gpa(SCRATCH_SIZE))
}

pub(crate) fn memory_layout() -> SandboxMemoryLayout {
    let mut config = SandboxConfiguration::default();
    config.set_scratch_size(SCRATCH_SIZE);
    config.set_g2h_queue_size(16);
    config.set_h2g_queue_size(8);
    config.set_h2g_buffer_size(H2G_BUFFER_SIZE);
    config.set_g2h_pool_pages(3);
    config.set_h2g_pool_pages(3);

    SandboxMemoryLayout::new(config, 4096).unwrap()
}

fn host_scratch() -> HostSharedMemory {
    ExclusiveSharedMemory::new(SCRATCH_SIZE).unwrap().build().0
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

/// Read live rings for comparison with bootstrap images.
fn read_snapshot(
    layout: &SandboxMemoryLayout,
    scratch: &HostSharedMemory,
) -> Result<VirtqSnapshot> {
    let (g2h_offset, h2g_offset) = ring_offsets(layout);
    let mut g2h = vec![0; layout.get_g2h_queue_dims().ring_len()];
    let mut h2g = vec![0; layout.get_h2g_queue_dims().ring_len()];
    scratch.copy_to_slice(&mut g2h, g2h_offset)?;
    scratch.copy_to_slice(&mut h2g, h2g_offset)?;

    Ok(VirtqSnapshot {
        g2h_ring: g2h,
        h2g_ring: h2g,
    })
}

#[test]
fn snapshots_and_restores_rings() {
    let case = TestCase::new();
    let layout = memory_layout();
    let stale_pool = [0xa5; 16];
    case.mem.write(case.h2g_pool_base, &stale_pool).unwrap();
    let spare_offset =
        (case.h2g_pool_base - hyperlight_common::layout::scratch_base_gva(SCRATCH_SIZE)) as usize
            + layout.get_h2g_queue_dims().pool_len();
    case.scratch
        .copy_from_slice(&[0x5a; 16], spare_offset)
        .unwrap();

    let captured = VirtqSnapshot::bootstrap(&layout).unwrap();
    assert_eq!(read_snapshot(&layout, &case.scratch).unwrap(), captured);
    let restored = host_scratch();
    let allocator = layout.get_pt_base_gpa();
    let allocator_offset = restored.mem_size() - SCRATCH_TOP_ALLOCATOR_OFFSET as usize;

    let mbx_offset = layout.mbx_scratch_offset();
    let status = MailboxValue::InitPending.as_bytes();

    restored.write::<u64>(allocator_offset, allocator).unwrap();
    restored.copy_from_slice(status, mbx_offset).unwrap();

    let (mut g2h, mut h2g) = captured.restore(&layout, &restored).unwrap();
    let restored_snapshot = read_snapshot(&layout, &restored).unwrap();
    let restored_mem = HostMemOps::new(&restored);
    let mut pool_bytes = [0; 16];
    restored_mem
        .read(case.h2g_pool_base, &mut pool_bytes)
        .unwrap();

    assert_eq!(restored_snapshot, captured);
    assert_eq!(restored.read::<u64>(allocator_offset).unwrap(), allocator);
    let arena_gpa_offset = restored.mem_size()
        - hyperlight_common::layout::SCRATCH_TOP_TRANSPORT_ARENA_GPA_OFFSET as usize;
    assert_eq!(
        restored.read::<u64>(arena_gpa_offset).unwrap(),
        layout.get_transport_arena().base_addr()
    );
    assert_eq!(restored.read::<[u8; 16]>(spare_offset).unwrap(), [0; 16]);
    assert_eq!(pool_bytes, [0; 16]);

    let mbx = restored.read::<u64>(mbx_offset).unwrap();
    assert_eq!(
        MailboxValue::try_from(mbx).unwrap(),
        MailboxValue::InitComplete
    );

    assert!(g2h.poll(0).unwrap().is_none());
    let (recv, reply) = h2g.poll(0).unwrap().unwrap();
    h2g.complete(recv, reply).unwrap();

    drop((g2h, h2g));
    captured.restore(&layout, &restored).unwrap();
    assert_eq!(read_snapshot(&layout, &restored).unwrap(), captured);
}

#[test]
fn uses_scratch_payloads_outside_pools() {
    let case = TestCase::new();
    // General scratch, below the arena: the allocator's first free page.
    let addr = scratch_gva(memory_layout().get_pt_base_gpa());
    case.mem.write(addr, &[1, 2, 3]).unwrap();

    let mut g2h_desc = Descriptor::new(addr, 3, 0, DescFlags::empty());
    g2h_desc.mark_avail(true);
    write_desc(&case.mem, case.g2h_layout, 0, g2h_desc);
    let mut h2g_desc = case.h2g_desc(0);
    h2g_desc.addr = addr;
    h2g_desc.len = 3;
    case.set_h2g_desc(0, h2g_desc);

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

/// Guest-written descriptors are checked on use after restore.
#[test]
fn payload_bounds_are_checked_on_use() {
    let case = TestCase::new();
    let layout = memory_layout();
    let end = hyperlight_common::layout::scratch_base_gva(SCRATCH_SIZE) + SCRATCH_SIZE as u64;
    let captured = VirtqSnapshot::bootstrap(&layout).unwrap();
    let restored = host_scratch();
    let (mut g2h, mut h2g) = captured.restore(&layout, &restored).unwrap();
    let mem = HostMemOps::new(&restored);

    let mut h2g_desc = case.h2g_desc(0);
    h2g_desc.addr = end - 1;
    write_desc(&mem, case.h2g_layout, 0, h2g_desc);

    let mut g2h_desc = Descriptor::new(end, 1, 0, DescFlags::empty());
    g2h_desc.mark_avail(true);
    write_desc(&mem, case.g2h_layout, 0, g2h_desc);
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
    let case = TestCase::new();
    let mut desc = case.h2g_desc(0);
    desc.flags |= DescFlags::INDIRECT.bits();
    case.set_h2g_desc(0, desc);
    let (_, mut h2g) = create_consumers(&memory_layout(), &case.scratch).unwrap();
    assert!(matches!(
        h2g.poll(0),
        Err(VirtqError::RingError(RingError::BadChain))
    ));
}
