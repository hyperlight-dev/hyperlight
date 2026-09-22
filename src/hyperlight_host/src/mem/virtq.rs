// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Host virtqueue attachment and snapshot restoration.
//!
//! Rings occupy fixed arena storage. Payload accesses are bounded copies
//! within mapped scratch. Consumers validate descriptors when they are used.
//! Snapshots require canonical rings with empty G2H and the initial H2G prefill.
//! H2G chains contain one writable descriptor of the configured buffer size.

use hyperlight_common::virtq::canonical::validate_canon_image;
use hyperlight_common::virtq::{Layout as VirtqLayout, Notifier, QueueStats, VirtqConsumer};

use super::layout::SandboxMemoryLayout;
use super::shared_mem::{HostSharedMemory, SharedMemory};
use super::virtq_mem::{HostMemOps, ImageMem};
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

/// Bind both host consumers at the guest's initial cursor zero.
///
/// Ring addresses come from the host layout. Entries are checked when consumed.
pub(crate) fn attach(
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
    scratch_size: usize,
    g2h_ring: Vec<u8>,
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
        attach(layout, scratch_mem)
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

        let (mut g2h, mut h2g) = attach(&memory_layout(), &case.scratch).unwrap();
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
        let (_, mut h2g) = attach(&memory_layout(), &case.scratch).unwrap();
        assert!(matches!(
            h2g.poll(0),
            Err(VirtqError::RingError(RingError::BadChain))
        ));
    }
}
