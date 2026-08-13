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

use core::ops::Range;

use hyperlight_common::layout::SCRATCH_TOP_ALLOCATOR_OFFSET;
use hyperlight_common::virtq::{
    DescFlags, Descriptor, MemOps, SlotLayout, SlotPool, VirtqProducer,
};
use hyperlight_common::vmem;

use super::mem::HostMemOps;
use super::*;
use crate::mem::shared_mem::{ExclusiveSharedMemory, HostSharedMemory};
use crate::sandbox::SandboxConfiguration;

pub(crate) const SCRATCH_SIZE: usize = 0x20_000;
pub(crate) const H2G_BUFFER_SIZE: usize = 3000;

pub(crate) struct TestVirtq {
    pub(crate) scratch: HostSharedMemory,
    pub(crate) g2h_mem: HostMemOps,
    pub(crate) h2g_mem: HostMemOps,
    pub(crate) g2h_ring: Range<u64>,
    pub(crate) h2g_ring: Range<u64>,
    pub(crate) g2h_pool: Range<u64>,
    pub(crate) h2g_pool: Range<u64>,
    pub(crate) g2h_layout: VirtqLayout,
    pub(crate) h2g_layout: VirtqLayout,
}

impl TestVirtq {
    pub(crate) fn new() -> Self {
        let scratch = host_scratch();
        let layout = memory_layout();

        let validator = Validator::new(&layout).unwrap();
        let config = validator.config;
        let regions = validator.resolve_gva_regions().unwrap();

        let g2h_layout = config.g2h.layout(&regions.g2h_ring).unwrap();
        let h2g_layout = config.h2g.layout(&regions.h2g_ring).unwrap();
        let arena = regions.g2h_ring.start..regions.h2g_pool.end;

        let mem = HostMemOps::new(&scratch, arena).unwrap();

        let h2g_pool = SlotPool::new(SlotLayout::new(
            regions.h2g_pool.start,
            config.h2g.buffer_size,
            config.h2g_prefill_descs,
        ))
        .unwrap();

        let mut producer = VirtqProducer::new(h2g_layout, mem, HostNotifier, h2g_pool.clone());
        let mut batch = producer.batch();

        for _ in 0..config.h2g_prefill_descs {
            let chain = batch
                .chain()
                .writable(config.h2g.buffer_size)
                .build()
                .unwrap();
            batch.submit(chain).unwrap();
        }

        batch.finish_without_notify();

        write_published_arena_gpa(&scratch, config.arena.base_addr()).unwrap();

        Self {
            g2h_mem: HostMemOps::new(&scratch, regions.g2h_ring.clone()).unwrap(),
            h2g_mem: HostMemOps::new(&scratch, regions.h2g_ring.clone()).unwrap(),
            scratch,
            g2h_ring: regions.g2h_ring,
            h2g_ring: regions.h2g_ring,
            g2h_pool: regions.g2h_pool,
            h2g_pool: regions.h2g_pool,
            g2h_layout,
            h2g_layout,
        }
    }

    pub(crate) fn h2g_consumer(&self) -> H2gConsumer {
        attach_canonical(&memory_layout(), &self.scratch).unwrap().1
    }

    pub(crate) fn g2h_consumer(&self) -> G2hConsumer {
        attach_canonical(&memory_layout(), &self.scratch).unwrap().0
    }

    fn validate(&self) -> Result<()> {
        let layout = memory_layout();
        let validator = Validator::new(&layout)?;
        validator.validate_g2h(&self.g2h_mem, self.g2h_ring.clone())?;
        validator.validate_h2g(&self.h2g_mem, self.h2g_ring.clone(), self.h2g_pool.clone())?;
        Ok(())
    }

    fn g2h_desc(&self, index: u16) -> Descriptor {
        read_desc(&self.g2h_mem, self.g2h_layout, index)
    }

    pub(crate) fn h2g_desc(&self, index: u16) -> Descriptor {
        read_desc(&self.h2g_mem, self.h2g_layout, index)
    }

    fn set_g2h_desc(&self, index: u16, desc: Descriptor) {
        write_desc(&self.g2h_mem, self.g2h_layout, index, desc);
    }

    pub(crate) fn set_h2g_desc(&self, index: u16, desc: Descriptor) {
        write_desc(&self.h2g_mem, self.h2g_layout, index, desc);
    }

    pub(crate) fn h2g_buffer(&self, index: u16, addr: u64) -> Vec<u8> {
        let desc = self.h2g_desc(index);
        let mut bytes = vec![0; desc.len as usize];
        let pool = HostMemOps::new(&self.scratch, self.h2g_pool.clone()).unwrap();
        pool.read(addr, &mut bytes).unwrap();
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
fn validates_host_placed_regions() {
    let layout = memory_layout();
    let validator = Validator::new(&layout).unwrap();
    let config = validator.config;
    let regions = validator.resolve_gva_regions().unwrap();

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
fn rejects_incorrect_published_arena() {
    let layout = memory_layout();
    let validator = Validator::new(&layout).unwrap();
    let arena_gpa = validator.config.arena.base_addr() + 1;
    assert!(validator.validate_published_arena(arena_gpa).is_err());
}

#[test]
fn validates_initial_virtq_images() {
    TestVirtq::new().validate().unwrap();
}

#[test]
fn snapshots_and_restores_canonical_image() {
    let queue = TestVirtq::new();
    let layout = memory_layout();
    let stale_pool = [0xa5; 16];
    let pool_mem = HostMemOps::new(&queue.scratch, queue.h2g_pool.clone()).unwrap();

    pool_mem.write(queue.h2g_pool.start, &stale_pool).unwrap();

    let captured = snapshot(&layout, &queue.scratch).unwrap();
    let restored = host_scratch();
    let allocator = layout.get_first_free_scratch_gpa();
    let allocator_offset = restored.mem_size() - SCRATCH_TOP_ALLOCATOR_OFFSET as usize;

    restored.write::<u64>(allocator_offset, allocator).unwrap();

    restore(&layout, &restored, &captured).unwrap();
    let restored_snapshot = snapshot(&layout, &restored).unwrap();
    let restored_pool = HostMemOps::new(&restored, queue.h2g_pool.clone()).unwrap();
    let mut pool_bytes = [0; 16];

    restored_pool
        .read(queue.h2g_pool.start, &mut pool_bytes)
        .unwrap();

    assert_eq!(restored_snapshot, captured);
    assert_eq!(restored.read::<u64>(allocator_offset).unwrap(), allocator);
    assert_eq!(pool_bytes, [0; 16]);
}

#[test]
fn rejects_corrupt_snapshot_ring_before_restore() {
    let queue = TestVirtq::new();
    let layout = memory_layout();
    let mut captured = snapshot(&layout, &queue.scratch).unwrap();

    captured.h2g_ring.fill(0);
    let restored = host_scratch();

    assert!(restore(&layout, &restored, &captured).is_err());
    assert_eq!(read_published_arena_gpa(&restored).unwrap(), 0);
}

#[test]
fn restores_with_grown_page_tables() {
    let queue = TestVirtq::new();
    let layout = memory_layout();
    let captured = snapshot(&layout, &queue.scratch).unwrap();

    let mut grown_layout = layout;

    grown_layout
        .set_pt_size(layout.get_pt_size() + vmem::PAGE_SIZE)
        .unwrap();

    let restored = host_scratch();

    restore(&grown_layout, &restored, &captured).unwrap();
    assert_eq!(
        read_published_arena_gpa(&restored).unwrap(),
        grown_layout.get_transport_arena().base_addr()
    );
}

#[test]
fn rejects_nonzero_g2h_descriptors() {
    let queue = TestVirtq::new();
    let mut desc = queue.g2h_desc(0);
    desc.addr = queue.g2h_pool.start;
    queue.set_g2h_desc(0, desc);
    assert!(queue.validate().is_err());
}

#[test]
fn rejects_invalid_h2g_descriptors() {
    #[derive(Debug)]
    enum Corruption {
        OutsidePool,
        Readable,
        WrongSize,
        Misaligned,
        Overlapping,
    }

    for corruption in [
        Corruption::OutsidePool,
        Corruption::Readable,
        Corruption::WrongSize,
        Corruption::Misaligned,
        Corruption::Overlapping,
    ] {
        let queue = TestVirtq::new();
        let mut desc = queue.h2g_desc(0);

        let index = match corruption {
            Corruption::OutsidePool => {
                desc.addr = queue.g2h_pool.start;
                0
            }
            Corruption::Readable => {
                desc.flags &= !DescFlags::WRITE.bits();
                0
            }
            Corruption::WrongSize => {
                desc.len -= 1;
                0
            }
            Corruption::Misaligned => {
                desc.addr += 1;
                0
            }
            Corruption::Overlapping => {
                let first_addr = desc.addr;
                desc = queue.h2g_desc(1);
                desc.addr = first_addr;
                1
            }
        };

        queue.set_h2g_desc(index, desc);
        assert!(queue.validate().is_err(), "{corruption:?}");
    }
}
