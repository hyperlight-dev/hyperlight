// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use hyperlight_common::layout::SCRATCH_TOP_ALLOCATOR_OFFSET;
use hyperlight_common::virtq::{
    DescFlags, Descriptor, MemOps, RingError, SlotLayout, SlotPool, VirtqError, VirtqProducer,
};
use hyperlight_common::vmem;

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
        let to_gva = |gpa| {
            hyperlight_common::layout::scratch_base_gva(SCRATCH_SIZE)
                + (gpa - hyperlight_common::layout::scratch_base_gpa(SCRATCH_SIZE))
        };
        let g2h_pool_base = to_gva(arena.g2h_pool_addr());
        let h2g_pool_base = to_gva(arena.h2g_pool_addr());
        let h2g = layout.get_h2g_queue_dims();
        let mem = HostMemOps::new(&scratch);
        let buffer_size = layout.get_h2g_buffer_size();
        let h2g_prefill_descs = usize::from(h2g.size().get()).min(h2g.pool_len() / buffer_size);
        let h2g_pool_layout =
            SlotLayout::new(h2g_pool_base, buffer_size, h2g_prefill_descs).unwrap();
        let h2g_pool = SlotPool::new(h2g_pool_layout).unwrap();

        let mut producer = VirtqProducer::new(h2g_layout, mem.clone(), HostNotifier, h2g_pool);
        let mut batch = producer.batch();

        for _ in 0..h2g_prefill_descs {
            let chain = batch.chain().writable(buffer_size).build().unwrap();
            batch.submit(chain).unwrap();
        }

        batch.finish_without_notify();
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

pub(crate) fn memory_layout() -> SandboxMemoryLayout {
    let mut config = SandboxConfiguration::default();
    config.set_scratch_size(SCRATCH_SIZE);
    config.set_g2h_queue_size(16);
    config.set_h2g_queue_size(8);
    config.set_h2g_buffer_size(H2G_BUFFER_SIZE);
    config.set_g2h_pool_pages(3);
    config.set_h2g_pool_pages(3);

    SandboxMemoryLayout::new(config, 4096, 0, None).unwrap()
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

    let captured = VirtqSnapshot::capture(&layout, &case.scratch).unwrap();
    let restored = host_scratch();
    let allocator = layout.get_first_free_scratch_gpa();
    let allocator_offset = restored.mem_size() - SCRATCH_TOP_ALLOCATOR_OFFSET as usize;

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
    assert_eq!(restored.read::<[u8; 16]>(spare_offset).unwrap(), [0; 16]);
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
    let case = TestCase::new();
    let layout = memory_layout();
    let captured = VirtqSnapshot::capture(&layout, &case.scratch).unwrap();
    let scratch_size = layout.get_scratch_size();
    let g2h = captured.g2h_ring();
    let h2g = captured.h2g_ring();

    for (size, g2h_len, h2g_len) in [
        (scratch_size - vmem::PAGE_SIZE, g2h.len(), h2g.len()),
        (scratch_size, g2h.len() - 1, h2g.len()),
        (scratch_size, g2h.len(), h2g.len() - 1),
    ] {
        assert!(
            VirtqSnapshot::new(
                &layout,
                size,
                g2h[..g2h_len].to_vec(),
                h2g[..h2g_len].to_vec(),
            )
            .is_err()
        );
    }
}

#[test]
fn rejects_noncanonical_snapshot_images() {
    let case = TestCase::new();
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
    let case = TestCase::new();
    let layout = memory_layout();
    let original = case.h2g_desc(0);

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
        case.set_h2g_desc(0, desc);
        assert!(VirtqSnapshot::capture(&layout, &case.scratch).is_err());
    }
}

/// Distinct descriptor IDs do not imply distinct receive slots.
#[test]
fn rejects_h2g_snapshot_duplicate_slots() {
    let case = TestCase::new();
    let first = case.h2g_desc(0);
    let mut second = case.h2g_desc(1);

    assert_ne!(first.id, second.id);

    second.addr = first.addr;
    case.set_h2g_desc(1, second);

    let error = VirtqSnapshot::capture(&memory_layout(), &case.scratch).unwrap_err();
    assert!(error.to_string().contains("descriptor 1 buffer"), "{error}");
}

/// Slot alignment is relative to the pool, and free-list order may vary.
#[test]
fn accepts_h2g_snapshot_slot_permutations() {
    let case = TestCase::new();
    let mut first = case.h2g_desc(0);
    let mut second = case.h2g_desc(1);

    assert!(!case.h2g_pool_base.is_multiple_of(H2G_BUFFER_SIZE as u64));

    std::mem::swap(&mut first.addr, &mut second.addr);
    case.set_h2g_desc(0, first);
    case.set_h2g_desc(1, second);

    VirtqSnapshot::capture(&memory_layout(), &case.scratch).unwrap();
}

#[test]
fn rejects_h2g_snapshot_chain_shape() {
    let case = TestCase::new();
    let layout = memory_layout();
    let mut head = case.h2g_desc(0);
    let mut tail = case.h2g_desc(1);
    head.flags |= DescFlags::NEXT.bits();
    tail.id = head.id;
    case.set_h2g_desc(0, head);
    case.set_h2g_desc(1, tail);

    let error = VirtqSnapshot::capture(&layout, &case.scratch).unwrap_err();
    assert!(
        error.to_string().contains("must contain one descriptor"),
        "{error}"
    );
}

#[test]
fn restores_with_finalized_layout() {
    let case = TestCase::new();
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
    let case = TestCase::new();
    let addr = case.h2g_pool_base + memory_layout().get_h2g_queue_dims().pool_len() as u64;
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

/// Snapshot admission does not replace checks after the guest resumes.
#[test]
fn payload_bounds_are_checked_on_use() {
    let case = TestCase::new();
    let layout = memory_layout();
    let end = hyperlight_common::layout::scratch_base_gva(SCRATCH_SIZE) + SCRATCH_SIZE as u64;
    let captured = VirtqSnapshot::capture(&layout, &case.scratch).unwrap();
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
