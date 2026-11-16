// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.
//! This module describes the virtual and physical addresses of a
//! number of special regions in the hyperlight VM, although we hope
//! to reduce the number of these over time.
//!
//! A snapshot freshly created from an empty VM will result in roughly
//! the following physical layout:
//!
//! +-------------------------------------------+
//! |             Guest Page Tables             |
//! +-------------------------------------------+
//! |               Guest Code                  |
//! +-------------------------------------------+ 0x1_000
//! |              NULL guard page              |
//! +-------------------------------------------+ 0x0_000
//!
//! Everything except for the guest page tables is currently
//! identity-mapped; the guest page tables themselves are mapped at
//! [`hyperlight_common::layout::SNAPSHOT_PT_GVA`] =
//! 0xffff_8000_0000_0000.
//!
//! The guest heap is outside this layout. The guest maps heap pages
//! from scratch on first touch.
//!
//! There is also a scratch region at the top of physical memory,
//! which is mostly laid out as a large undifferentiated blob of
//! memory. The copied page tables start at the scratch base, which moves
//! with the scratch size. The transport arena's address does not depend
//! on the scratch size:
//!
//! +-------------------------------------------+ (top of physical memory)
//! |         Exception Stack, Metadata         |
//! +-------------------------------------------+ (reserved pages below)
//! | Guard page (not in the guest page tables) |
//! +-------------------------------------------+ (SCRATCH_TRANSPORT_GAP_PAGES)
//! |              Transport Arena              |
//! +-------------------------------------------+
//! |              Scratch Memory               |
//! +-------------------------------------------+
//! |             Guest Page Tables             |
//! +-------------------------------------------+ (scratch size)

use std::fmt::Debug;

use hyperlight_common::layout::{QueueDims, TransportArena};
use hyperlight_common::vmem::PAGE_SIZE;
use tracing::{Span, instrument};

use super::memory_region::MemoryRegionType::Code;
use super::memory_region::{
    GuestMemoryRegion, MemoryRegion_, MemoryRegionFlags, MemoryRegionVecBuilder,
};
use crate::error::HyperlightError::{MemoryRequestTooBig, MemoryRequestTooSmall};
use crate::sandbox::SandboxConfiguration;
use crate::{Result, new_error};

#[derive(Copy, Clone)]
pub(crate) struct SandboxMemoryLayout {
    /// The size of the guest code section.
    code_size: usize,
    /// Guest virtual address of the code section.
    code_gva: usize,
    /// The size of the scratch region in physical memory.
    scratch_size: usize,
    /// G2H ring and buffer pool dimensions.
    g2h_dims: QueueDims,
    /// H2G ring and buffer pool dimensions.
    h2g_dims: QueueDims,
    /// Capacity of each G2H upper-tier buffer.
    g2h_buffer_size: usize,
    /// Capacity of each H2G buffer.
    h2g_buffer_size: usize,
    /// Fixed ring and pool placement within scratch.
    transport_arena: TransportArena,
}

impl Debug for SandboxMemoryLayout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut ff = f.debug_struct("SandboxMemoryLayout");
        ff.field(
            "Total Memory Size",
            &format_args!("{:#x}", self.get_memory_size().unwrap_or(0)),
        )
        .field("Code Size", &format_args!("{:#x}", self.code_size))
        .field("Code GVA", &format_args!("{:#x}", self.code_gva))
        .field("Scratch Size", &format_args!("{:#x}", self.scratch_size))
        .field("G2H Queue Size", &self.get_g2h_queue_size())
        .field("H2G Queue Size", &self.get_h2g_queue_size())
        .field("G2H Buffer Size", &self.g2h_buffer_size)
        .field("H2G Buffer Size", &self.h2g_buffer_size)
        .field("G2H Pool Pages", &self.get_g2h_pool_pages())
        .field("H2G Pool Pages", &self.get_h2g_pool_pages())
        .field(
            "Guest Code Offset",
            &format_args!("{:#x}", self.guest_code_offset()),
        )
        .finish()
    }
}

impl SandboxMemoryLayout {
    /// The maximum amount of memory a single sandbox will be allowed.
    ///
    /// Both the scratch region and the snapshot region are bounded by
    /// this size. The value is arbitrary but chosen to be large enough
    /// for most workloads while preventing accidental resource exhaustion.
    pub(crate) const MAX_MEMORY_SIZE: usize = (16 * 1024 * 1024 * 1024) - Self::BASE_ADDRESS; // 16 GiB - BASE_ADDRESS

    /// The base address of the sandbox's memory.
    pub(crate) const BASE_ADDRESS: usize = 0x4000;

    /// Create a new `SandboxMemoryLayout` with the given
    /// `SandboxConfiguration` and code size.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn new(cfg: SandboxConfiguration, code_size: usize) -> Result<Self> {
        let scratch_size = cfg.get_scratch_size();
        if scratch_size > Self::MAX_MEMORY_SIZE {
            return Err(MemoryRequestTooBig(scratch_size, Self::MAX_MEMORY_SIZE));
        }
        if !scratch_size.is_multiple_of(PAGE_SIZE) {
            return Err(new_error!(
                "scratch size {scratch_size} must be a multiple of {PAGE_SIZE}"
            ));
        }
        let g2h_queue_size = cfg.get_g2h_queue_size();
        let h2g_queue_size = cfg.get_h2g_queue_size();
        let g2h_buffer_size = cfg.get_g2h_buffer_size();
        let h2g_buffer_size = cfg.get_h2g_buffer_size();
        let g2h_pool_pages = cfg.get_g2h_pool_pages();
        let h2g_pool_pages = cfg.get_h2g_pool_pages();

        let g2h_dims = QueueDims::new(g2h_queue_size, g2h_pool_pages)
            .ok_or(MemoryRequestTooSmall(scratch_size, usize::MAX))?;
        let h2g_dims = QueueDims::new(h2g_queue_size, h2g_pool_pages)
            .ok_or(MemoryRequestTooSmall(scratch_size, usize::MAX))?;
        let transport_arena = Self::transport_arena_for(g2h_dims, h2g_dims)
            .ok_or(MemoryRequestTooSmall(scratch_size, usize::MAX))?;
        let min_scratch_size = Self::min_scratch_for(&transport_arena);
        if scratch_size < min_scratch_size {
            return Err(MemoryRequestTooSmall(
                scratch_size,
                min_scratch_size.next_multiple_of(Self::host_page_size()),
            ));
        }

        let ret = Self {
            code_size,
            code_gva: Self::BASE_ADDRESS,
            scratch_size,
            g2h_dims,
            h2g_dims,
            g2h_buffer_size,
            h2g_buffer_size,
            transport_arena,
        };
        ret.get_memory_size()?;
        Ok(ret)
    }

    /// Granularity the host maps scratch in: host pages, which can be
    /// larger than the guest's.
    pub(crate) fn host_page_size() -> usize {
        PAGE_SIZE.max(page_size::get())
    }

    /// Fixed scratch overhead: the arena and the guard page above it count
    /// as transport memory.
    fn min_scratch_for(arena: &TransportArena) -> usize {
        hyperlight_common::layout::min_scratch_size(
            arena
                .size()
                .saturating_add(hyperlight_common::layout::SCRATCH_TRANSPORT_GAP_PAGES * PAGE_SIZE),
        )
    }

    /// Smallest scratch for this layout before page tables.
    pub(crate) fn min_scratch(&self) -> usize {
        Self::min_scratch_for(&self.transport_arena)
    }

    /// The transport arena sits below the reserved top pages, at an
    /// address that does not depend on the scratch size.
    fn transport_arena_for(g2h: QueueDims, h2g: QueueDims) -> Option<TransportArena> {
        let len = TransportArena::new(0, g2h, h2g)?.size() as u64;
        let base = hyperlight_common::layout::scratch_transport_end_gpa().checked_sub(len)?;
        TransportArena::new(base, g2h, h2g)
    }

    /// This layout with another scratch size. Room for the page tables is
    /// checked when they are built (`ensure_page_tables_fit`), since their
    /// size depends on the guest's mappings.
    pub(crate) fn with_scratch_size(&self, scratch_size: usize) -> Result<Self> {
        if scratch_size > Self::MAX_MEMORY_SIZE {
            return Err(MemoryRequestTooBig(scratch_size, Self::MAX_MEMORY_SIZE));
        }
        // The host maps scratch in host pages, which can be larger than
        // the guest's. A size checked here is one a restore can map.
        let page = Self::host_page_size();
        let min = self.min_scratch().next_multiple_of(page);
        if scratch_size < min {
            return Err(MemoryRequestTooSmall(scratch_size, min));
        }
        if !scratch_size.is_multiple_of(page) {
            return Err(new_error!(
                "scratch size {scratch_size} must be a multiple of {page}"
            ));
        }
        let mut ret = *self;
        ret.scratch_size = scratch_size;
        Ok(ret)
    }

    /// Scratch offset of the transport arena.
    pub(crate) fn arena_scratch_offset(&self) -> usize {
        debug_assert!(
            self.transport_arena.base_addr()
                > hyperlight_common::layout::scratch_base_gpa(self.scratch_size),
            "the minimum scratch size keeps the arena above the scratch base"
        );
        (self.transport_arena.base_addr()
            - hyperlight_common::layout::scratch_base_gpa(self.scratch_size)) as usize
    }

    /// Scratch offset of the checkpoint mailbox.
    pub(crate) fn mbx_scratch_offset(&self) -> usize {
        self.arena_scratch_offset() + self.transport_arena.mbx_offset()
    }

    pub(crate) fn code_size(&self) -> usize {
        self.code_size
    }

    pub(crate) fn get_scratch_size(&self) -> usize {
        self.scratch_size
    }

    pub(crate) fn get_g2h_queue_size(&self) -> usize {
        usize::from(self.g2h_dims.size().get())
    }

    pub(crate) fn get_h2g_queue_size(&self) -> usize {
        usize::from(self.h2g_dims.size().get())
    }

    pub(crate) fn get_g2h_buffer_size(&self) -> usize {
        self.g2h_buffer_size
    }

    pub(crate) fn get_h2g_buffer_size(&self) -> usize {
        self.h2g_buffer_size
    }

    pub(crate) fn get_g2h_pool_pages(&self) -> usize {
        self.g2h_dims.pool_pages().get()
    }

    pub(crate) fn get_h2g_pool_pages(&self) -> usize {
        self.h2g_dims.pool_pages().get()
    }

    pub(crate) fn get_g2h_queue_dims(&self) -> QueueDims {
        self.g2h_dims
    }

    pub(crate) fn get_h2g_queue_dims(&self) -> QueueDims {
        self.h2g_dims
    }

    pub(crate) fn ensure_page_tables_fit(&self, page_table_len: usize) -> Result<()> {
        let min_scratch = self.min_scratch().saturating_add(page_table_len);
        if self.scratch_size < min_scratch {
            // Report a size the host can map.
            let page = Self::host_page_size();
            return Err(MemoryRequestTooSmall(
                self.scratch_size,
                min_scratch.next_multiple_of(page),
            ));
        }
        Ok(())
    }

    /// Returns the memory regions associated with this memory layout,
    /// suitable for passing to a hypervisor for mapping into memory
    pub(crate) fn get_memory_regions(&self) -> Result<Vec<MemoryRegion_<GuestMemoryRegion>>> {
        let mut builder = MemoryRegionVecBuilder::new(Self::BASE_ADDRESS, Self::BASE_ADDRESS);

        // code
        let final_offset = builder.push_page_aligned(
            self.code_size,
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE | MemoryRegionFlags::EXECUTE,
            Code,
        );

        let expected_final_offset = TryInto::<usize>::try_into(self.get_memory_size()?)?;

        // This function is primarily used to construct
        // GuestMemoryRegions used to populate initial guest page
        // tables. Therefore, the regions above are aligned based on
        // the guest page size. However, the total final size of the
        // region mapped into the guest needs to be aligned based on
        // the host page size. Therefore, align both of these values
        // to both page sizes before comparing them.
        let final_offset = final_offset.next_multiple_of(page_size::get());
        let expected_final_offset =
            expected_final_offset.next_multiple_of(hyperlight_common::vmem::PAGE_SIZE);

        if final_offset != expected_final_offset {
            return Err(new_error!(
                "Final offset does not match expected Final offset expected:  {}, actual:  {}",
                expected_final_offset,
                final_offset
            ));
        }

        let mut regions = builder.build();

        for region in &mut regions {
            if region.region_type == Code {
                let end = self
                    .code_gva
                    .checked_add(region.guest_region.len())
                    .ok_or_else(|| {
                        new_error!(
                            "code mapping overflow: base {:#x} + size {:#x}",
                            self.code_gva,
                            region.guest_region.len()
                        )
                    })?;
                region.guest_region = self.code_gva..end;
            }
        }
        Ok(regions)
    }

    /// Set the code GVA after checking that its address range fits.
    pub(crate) fn set_code_gva(&mut self, code_gva: u64) -> Result<()> {
        let code_gva = usize::try_from(code_gva)?;
        code_gva
            .checked_add(self.code_size.next_multiple_of(PAGE_SIZE))
            .ok_or_else(|| {
                new_error!(
                    "code mapping overflow: base {:#x} + size {:#x}",
                    code_gva,
                    self.code_size
                )
            })?;

        self.code_gva = code_gva;
        Ok(())
    }
}

/// Changes to the below methods is part of Snapshot ABI, and
/// changing any output shifts where the loader
/// reads captured bytes and breaks existing snapshots. Any change here
/// is a snapshot ABI break: see the `layout_offsets_are_pinned` test
/// and docs/snapshot-versioning.md.
impl SandboxMemoryLayout {
    /// The code offset is always 0.
    pub(crate) fn guest_code_offset(&self) -> usize {
        0
    }

    /// Guest physical address of the code section.
    pub(crate) fn get_guest_code_gpa(&self) -> usize {
        Self::BASE_ADDRESS + self.guest_code_offset()
    }

    /// Guest virtual address of the code section.
    pub(crate) fn get_guest_code_gva(&self) -> usize {
        self.code_gva
    }

    /// Offset from the beginning of the scratch region to the location
    /// where page tables are eagerly copied on restore.
    pub(crate) fn get_pt_base_scratch_offset(&self) -> usize {
        0
    }

    /// Base GPA to which the page tables are eagerly copied on restore.
    pub(crate) fn get_pt_base_gpa(&self) -> u64 {
        hyperlight_common::layout::scratch_base_gpa(self.scratch_size)
    }

    /// Exact transport placement below the reserved scratch-top pages.
    pub(crate) fn get_transport_arena(&self) -> TransportArena {
        self.transport_arena
    }

    /// Total size of guest memory in `self`'s memory layout, aligned
    /// to page size boundaries.
    pub(crate) fn get_memory_size(&self) -> Result<usize> {
        let total_memory = self.code_size.next_multiple_of(PAGE_SIZE);

        // Size should be a multiple of host page size.
        let remainder = total_memory % page_size::get();
        let multiples = total_memory / page_size::get();
        let size = match remainder {
            0 => total_memory,
            _ => (multiples + 1) * page_size::get(),
        };

        if size > Self::MAX_MEMORY_SIZE {
            Err(MemoryRequestTooBig(size, Self::MAX_MEMORY_SIZE))
        } else {
            Ok(size)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only guest code occupies the initial snapshot data region.
    #[test]
    fn initial_memory_contains_only_code() {
        for code_size in [1, PAGE_SIZE, PAGE_SIZE + 1] {
            let layout =
                SandboxMemoryLayout::new(SandboxConfiguration::default(), code_size).unwrap();
            let regions = layout.get_memory_regions().unwrap();

            assert_eq!(regions.len(), 1);
            assert_eq!(regions[0].region_type, Code);
            assert_eq!(
                regions[0].guest_region.len(),
                code_size.next_multiple_of(PAGE_SIZE)
            );
            assert_eq!(
                layout.get_memory_size().unwrap(),
                code_size.next_multiple_of(SandboxMemoryLayout::host_page_size())
            );
        }
    }

    #[test]
    fn transport_arena_sits_below_the_reserved_top() {
        let cfg = SandboxConfiguration::default();
        let layout = SandboxMemoryLayout::new(cfg, 4096).unwrap();
        let arena = layout.get_transport_arena();
        let scratch_base = hyperlight_common::layout::scratch_base_gpa(layout.get_scratch_size());

        assert_eq!(
            arena.end_addr()
                + (hyperlight_common::layout::SCRATCH_TRANSPORT_GAP_PAGES * PAGE_SIZE) as u64,
            hyperlight_common::layout::scratch_reserved_top_gpa()
        );
        assert_eq!(layout.get_pt_base_gpa(), scratch_base);
        assert_eq!(layout.get_pt_base_scratch_offset(), 0);

        layout.ensure_page_tables_fit(PAGE_SIZE).unwrap();

        assert_eq!(layout.get_transport_arena(), arena);
    }

    /// A different scratch size keeps the arena where it is, so a guest's
    /// cached ring addresses stay valid in a resized snapshot.
    #[test]
    fn resizing_scratch_keeps_the_transport_arena() {
        let mut cfg = SandboxConfiguration::default();
        cfg.set_scratch_size(4 << 20);
        let layout = SandboxMemoryLayout::new(cfg, 4096).unwrap();
        // Sizes in host pages, which can be larger than the guest's.
        let page = SandboxMemoryLayout::host_page_size();
        let half = (layout.get_scratch_size() / 2).next_multiple_of(page);
        let smaller = layout.with_scratch_size(half).unwrap();

        assert_eq!(smaller.get_transport_arena(), layout.get_transport_arena());
        assert_eq!(
            smaller.get_pt_base_gpa(),
            hyperlight_common::layout::scratch_base_gpa(half)
        );
        assert_eq!(
            smaller.mbx_scratch_offset() + (layout.get_scratch_size() - half),
            layout.mbx_scratch_offset()
        );
        assert!(matches!(
            layout.with_scratch_size(layout.min_scratch() - 1),
            Err(MemoryRequestTooSmall(..))
        ));
        assert!(layout.with_scratch_size(half + 1).is_err());
        assert!(matches!(
            layout.with_scratch_size(
                SandboxMemoryLayout::MAX_MEMORY_SIZE.next_multiple_of(page) + page
            ),
            Err(MemoryRequestTooBig(..))
        ));

        let larger = layout
            .with_scratch_size(layout.get_scratch_size() * 2)
            .unwrap();
        assert_eq!(larger.get_transport_arena(), layout.get_transport_arena());
        assert_eq!(
            larger.mbx_scratch_offset(),
            layout.mbx_scratch_offset() + layout.get_scratch_size()
        );
    }

    #[test]
    fn transport_memory_is_part_of_minimum_scratch_size() {
        let mut cfg = SandboxConfiguration::default();
        let layout = SandboxMemoryLayout::new(cfg, 4096).unwrap();
        let minimum = layout.min_scratch();
        cfg.set_scratch_size(minimum);
        let layout = SandboxMemoryLayout::new(cfg, 4096).unwrap();

        assert!(matches!(
            layout.ensure_page_tables_fit(PAGE_SIZE),
            Err(MemoryRequestTooSmall(..))
        ));
    }

    #[test]
    fn transport_minimum_rejects_capacity_overflow() {
        for (g2h_pages, h2g_pages) in [
            (usize::MAX, 4),
            (8, usize::MAX),
            (usize::MAX / PAGE_SIZE, 1),
        ] {
            let mut cfg = SandboxConfiguration::default();
            cfg.set_g2h_pool_pages(g2h_pages);
            cfg.set_h2g_pool_pages(h2g_pages);

            let layout = SandboxMemoryLayout::new(cfg, 4096);
            assert!(matches!(layout, Err(MemoryRequestTooSmall(_, usize::MAX))));
        }
    }

    #[test]
    fn rejects_unaligned_scratch_size() {
        let mut cfg = SandboxConfiguration::default();
        cfg.set_scratch_size(SandboxConfiguration::DEFAULT_SCRATCH_SIZE + 1);

        let error = SandboxMemoryLayout::new(cfg, 4096).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "scratch size {} must be a multiple of {PAGE_SIZE}",
                SandboxConfiguration::DEFAULT_SCRATCH_SIZE + 1
            )
        );
    }

    #[test]
    fn code_gva_updates_code_region() {
        let mut layout =
            SandboxMemoryLayout::new(SandboxConfiguration::default(), PAGE_SIZE).unwrap();
        let code_gva = 0x100_0000;
        layout.set_code_gva(code_gva).unwrap();

        assert_eq!(
            layout.get_guest_code_gpa(),
            SandboxMemoryLayout::BASE_ADDRESS
        );
        assert_eq!(layout.get_guest_code_gva(), code_gva as usize);
        let code = layout
            .get_memory_regions()
            .unwrap()
            .into_iter()
            .find(|region| region.region_type == Code)
            .unwrap();
        assert_eq!(code.host_region.start, SandboxMemoryLayout::BASE_ADDRESS);
        assert_eq!(code.guest_region.start, code_gva as usize);
    }

    #[test]
    fn code_gva_rejects_overflow() {
        let mut layout =
            SandboxMemoryLayout::new(SandboxConfiguration::default(), PAGE_SIZE).unwrap();
        assert!(layout.set_code_gva(u64::MAX).is_err());
    }

    #[test]
    fn test_max_memory_sandbox() {
        let mut cfg = SandboxConfiguration::default();
        // scratch_size exceeds 16 GiB limit
        cfg.set_scratch_size(17 * 1024 * 1024 * 1024);
        let layout = SandboxMemoryLayout::new(cfg, 4096);
        assert!(matches!(layout.unwrap_err(), MemoryRequestTooBig(..)));
    }

    /// Pinned region offsets. These methods place every region that a
    /// restored snapshot is interpreted against, so a change shifts
    /// where the loader reads captured bytes and breaks existing
    /// snapshots. Treat a failure as an ABI change: follow
    /// docs/snapshot-versioning.md rather than editing the constants.
    #[test]
    fn layout_offsets_are_pinned() {
        /// `assert_eq!` carrying the shared snapshot-ABI failure
        /// message, mirroring `abi_assert!` in the snapshot tripwires.
        macro_rules! pin_eq {
            ($left:expr, $right:expr) => {
                assert_eq!(
                    $left, $right,
                    "snapshot ABI changed: this breaks loading of existing snapshots. \
                     Do not just update the expected value to make this compile. \
                     See docs/snapshot-versioning.md."
                );
            };
        }

        // The scratch region's top GVA and GPA are baked into snapshot
        // page tables by `map_specials`, so they are part of the
        // snapshot ABI. The pins below fix offsets from this base.
        #[cfg(target_arch = "x86_64")]
        {
            pin_eq!(
                hyperlight_common::layout::SCRATCH_TOP_GVA,
                0xffff_ffff_ffff_efff
            );
            pin_eq!(
                hyperlight_common::layout::SCRATCH_TOP_GPA,
                0x0000_000f_ffff_ffff
            );
        }
        #[cfg(target_arch = "aarch64")]
        {
            pin_eq!(
                hyperlight_common::layout::SCRATCH_TOP_GVA,
                0x0000_ffff_ffff_dfff
            );
            pin_eq!(
                hyperlight_common::layout::SCRATCH_TOP_GPA,
                0x0000_000f_ffff_bfff
            );
        }

        // `map_specials` bakes the IO page mapping into snapshot page
        // tables, so its address is part of the snapshot ABI. amd64 has
        // no IO page. aarch64 maps one fixed GPA to one fixed GVA.
        #[cfg(target_arch = "x86_64")]
        pin_eq!(hyperlight_common::layout::io_page(), None);
        #[cfg(target_arch = "aarch64")]
        pin_eq!(
            hyperlight_common::layout::io_page(),
            Some((0x0000_000f_ffff_f000, 0x0000_ffff_ffff_e000))
        );

        let mut cfg = SandboxConfiguration::default();
        cfg.set_scratch_size(0x30000);
        let layout = SandboxMemoryLayout::new(cfg, 0x1000).unwrap();

        pin_eq!(layout.guest_code_offset(), 0);
        pin_eq!(
            layout.get_memory_size().unwrap(),
            0x1000_usize.next_multiple_of(page_size::get())
        );

        pin_eq!(layout.get_scratch_size(), 0x30000);
        pin_eq!(layout.get_pt_base_scratch_offset(), 0);

        // The transport arena sits below the reserved top pages, at an
        // address that does not depend on the scratch size. The page
        // tables start at the scratch base. With the `SCRATCH_TOP` pins
        // above, these fix the absolute addresses.
        let arena = layout.get_transport_arena();
        let scratch_top = hyperlight_common::layout::SCRATCH_TOP_GPA as u64 + 1;
        pin_eq!(scratch_top - arena.g2h_ring_addr(), 0x22000);
        pin_eq!(arena.h2g_ring_addr() - arena.g2h_ring_addr(), 0x410);
        pin_eq!(arena.mbx_addr() - arena.g2h_ring_addr(), 0x618);
        pin_eq!(arena.g2h_pool_addr() - arena.g2h_ring_addr(), 0x1000);
        pin_eq!(arena.h2g_pool_addr() - arena.g2h_ring_addr(), 0xd000);
        pin_eq!(scratch_top - arena.end_addr(), 0xd000);
        pin_eq!(
            layout.get_pt_base_gpa(),
            hyperlight_common::layout::scratch_base_gpa(0x30000)
        );
        // A second snapshot layout, with a different scratch size, keeps
        // the transport arena at the same address.
        let mut cfg = SandboxConfiguration::default();
        cfg.set_scratch_size(0x40000);
        let layout = SandboxMemoryLayout::new(cfg, 0x3000).unwrap();

        pin_eq!(layout.guest_code_offset(), 0);
        pin_eq!(
            layout.get_memory_size().unwrap(),
            0x3000_usize.next_multiple_of(page_size::get())
        );

        pin_eq!(layout.get_scratch_size(), 0x40000);
        pin_eq!(layout.get_pt_base_scratch_offset(), 0);

        let arena = layout.get_transport_arena();
        let scratch_top = hyperlight_common::layout::SCRATCH_TOP_GPA as u64 + 1;
        pin_eq!(scratch_top - arena.g2h_ring_addr(), 0x22000);
        pin_eq!(arena.h2g_ring_addr() - arena.g2h_ring_addr(), 0x410);
        pin_eq!(arena.mbx_addr() - arena.g2h_ring_addr(), 0x618);
        pin_eq!(arena.g2h_pool_addr() - arena.g2h_ring_addr(), 0x1000);
        pin_eq!(arena.h2g_pool_addr() - arena.g2h_ring_addr(), 0xd000);
        pin_eq!(scratch_top - arena.end_addr(), 0xd000);

        pin_eq!(
            layout.get_pt_base_gpa(),
            hyperlight_common::layout::scratch_base_gpa(0x40000)
        );
    }
}
