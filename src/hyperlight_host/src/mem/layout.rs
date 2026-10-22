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
//! |              Init Data                    | (GuestBlob size)
//! +-------------------------------------------+
//! |             Guest Heap                    |
//! +-------------------------------------------+
//! |                PEB Struct                 | (HyperlightPEB size)
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
//! - `InitData` - some extra data that can be loaded onto the sandbox during
//!   initialization.
//!
//! - `GuestHeap` - this is a buffer that is used for heap data in the guest. the length
//!   of this field is returned by the `heap_size()` method of this struct
//!
//! There is also a scratch region at the top of physical memory,
//! which is mostly laid out as a large undifferentiated blob of
//! memory, although the transport arena and copied page tables have
//! fixed positions:
//!
//! +-------------------------------------------+ (top of physical memory)
//! |         Exception Stack, Metadata         |
//! +-------------------------------------------+ (1 page below)
//! |              Scratch Memory               |
//! +-------------------------------------------+
//! |             Guest Page Tables             |
//! +-------------------------------------------+
//! |              Transport Arena              |
//! +-------------------------------------------+ (scratch size)

use std::fmt::Debug;
use std::mem::size_of;

use hyperlight_common::layout::{QueueDims, TransportArena};
use hyperlight_common::mem::HyperlightPEB;
use hyperlight_common::vmem::PAGE_SIZE;
use tracing::{Span, instrument};

use super::memory_region::MemoryRegionType::{Code, Heap, InitData, Peb};
use super::memory_region::{
    DEFAULT_GUEST_BLOB_MEM_FLAGS, GuestMemoryRegion, MemoryRegion_, MemoryRegionFlags,
    MemoryRegionVecBuilder,
};
use crate::error::HyperlightError::{MemoryRequestTooBig, MemoryRequestTooSmall};
use crate::sandbox::SandboxConfiguration;
use crate::{Result, new_error};

#[derive(Copy, Clone)]
pub(crate) struct SandboxMemoryLayout {
    /// The heap size of this sandbox.
    heap_size: usize,
    /// The size of the guest code section.
    code_size: usize,
    /// Guest virtual address of the code section.
    code_gva: usize,
    /// The size of the init data section (guest blob).
    init_data_size: usize,
    /// Permission flags for the init data region.
    init_data_permissions: Option<MemoryRegionFlags>,
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
        .field("Heap Size", &format_args!("{:#x}", self.heap_size))
        .field(
            "Init Data Size",
            &format_args!("{:#x}", self.init_data_size),
        )
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
        .field("PEB Offset", &format_args!("{:#x}", self.peb_offset()))
        .field("PEB Address", &format_args!("{:#x}", self.peb_address()));
        ff.field(
            "Guest Heap Buffer Offset",
            &format_args!("{:#x}", self.guest_heap_buffer_offset()),
        )
        .field(
            "Init Data Offset",
            &format_args!("{:#x}", self.init_data_offset()),
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
    /// `SandboxConfiguration`, code size and stack/heap size.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn new(
        cfg: SandboxConfiguration,
        code_size: usize,
        init_data_size: usize,
        init_data_permissions: Option<MemoryRegionFlags>,
    ) -> Result<Self> {
        let heap_size = usize::try_from(cfg.get_heap_size())?;
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
        let arena_base_gpa = hyperlight_common::layout::scratch_base_gpa(scratch_size);
        let transport_arena = TransportArena::new(arena_base_gpa, g2h_dims, h2g_dims)
            .ok_or(MemoryRequestTooSmall(scratch_size, usize::MAX))?;
        let min_scratch_size = hyperlight_common::layout::min_scratch_size(transport_arena.size());
        if scratch_size < min_scratch_size {
            return Err(MemoryRequestTooSmall(scratch_size, min_scratch_size));
        }

        let ret = Self {
            heap_size,
            code_size,
            code_gva: Self::BASE_ADDRESS,
            init_data_size,
            init_data_permissions,
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

    pub(crate) fn heap_size(&self) -> usize {
        self.heap_size
    }

    pub(crate) fn code_size(&self) -> usize {
        self.code_size
    }

    pub(crate) fn init_data_size(&self) -> usize {
        self.init_data_size
    }

    pub(crate) fn init_data_permissions(&self) -> Option<MemoryRegionFlags> {
        self.init_data_permissions
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
        let min_fixed_scratch =
            hyperlight_common::layout::min_scratch_size(self.transport_arena.size());
        let min_scratch = min_fixed_scratch.saturating_add(page_table_len);
        if self.scratch_size < min_scratch {
            return Err(MemoryRequestTooSmall(self.scratch_size, min_scratch));
        }
        Ok(())
    }

    /// Returns the memory regions associated with this memory layout,
    /// suitable for passing to a hypervisor for mapping into memory
    pub(crate) fn get_memory_regions(&self) -> Result<Vec<MemoryRegion_<GuestMemoryRegion>>> {
        let mut builder = MemoryRegionVecBuilder::new(Self::BASE_ADDRESS, Self::BASE_ADDRESS);

        // code
        let peb_offset = builder.push_page_aligned(
            self.code_size,
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE | MemoryRegionFlags::EXECUTE,
            Code,
        );

        let expected_peb_offset = TryInto::<usize>::try_into(self.peb_offset())?;

        if peb_offset != expected_peb_offset {
            return Err(new_error!(
                "PEB offset does not match expected PEB offset expected:  {}, actual:  {}",
                expected_peb_offset,
                peb_offset
            ));
        }

        // PEB
        let heap_offset =
            builder.push_page_aligned(size_of::<HyperlightPEB>(), MemoryRegionFlags::READ, Peb);

        let expected_heap_offset = TryInto::<usize>::try_into(self.guest_heap_buffer_offset())?;

        if heap_offset != expected_heap_offset {
            return Err(new_error!(
                "Guest Heap offset does not match expected Guest Heap offset expected:  {}, actual:  {}",
                expected_heap_offset,
                heap_offset
            ));
        }

        // heap
        #[cfg(feature = "executable_heap")]
        let init_data_offset = builder.push_page_aligned(
            self.heap_size,
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE | MemoryRegionFlags::EXECUTE,
            Heap,
        );
        #[cfg(not(feature = "executable_heap"))]
        let init_data_offset = builder.push_page_aligned(
            self.heap_size,
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
            Heap,
        );

        let expected_init_data_offset = TryInto::<usize>::try_into(self.init_data_offset())?;

        if init_data_offset != expected_init_data_offset {
            return Err(new_error!(
                "Init Data offset does not match expected Init Data offset expected:  {}, actual:  {}",
                expected_init_data_offset,
                init_data_offset
            ));
        }

        // init data
        let after_init_offset = if self.init_data_size > 0 {
            let mem_flags = self
                .init_data_permissions
                .unwrap_or(DEFAULT_GUEST_BLOB_MEM_FLAGS);
            builder.push_page_aligned(self.init_data_size, mem_flags, InitData)
        } else {
            init_data_offset
        };

        let final_offset = after_init_offset;

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

    /// Set the code GVA after checking that it does not overlap another region.
    pub(crate) fn set_code_gva(&mut self, code_gva: u64) -> Result<()> {
        let code_gva = usize::try_from(code_gva)?;
        let code_end = code_gva
            .checked_add(self.code_size.next_multiple_of(PAGE_SIZE))
            .ok_or_else(|| {
                new_error!(
                    "code mapping overflow: base {:#x} + size {:#x}",
                    code_gva,
                    self.code_size
                )
            })?;
        for region in self.get_memory_regions()? {
            if region.region_type == Code {
                continue;
            }
            if code_gva < region.guest_region.end && region.guest_region.start < code_end {
                return Err(new_error!(
                    "code mapping [{:#x}, {:#x}) conflicts with {:?} region [{:#x}, {:#x})",
                    code_gva,
                    code_end,
                    region.region_type,
                    region.guest_region.start,
                    region.guest_region.end,
                ));
            }
        }
        self.code_gva = code_gva;
        Ok(())
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn write_init_data(&self, out: &mut [u8], bytes: &[u8]) -> Result<()> {
        out[self.init_data_offset()..self.init_data_offset() + self.init_data_size]
            .copy_from_slice(bytes);
        Ok(())
    }

    /// Write the finished memory layout to `mem` and return `Ok` if
    /// successful.
    ///
    /// Note: `mem` may have been modified, even if `Err` was returned
    /// from this function.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn write_peb(&self, mem: &mut [u8]) -> Result<()> {
        use hyperlight_common::mem::GuestMemoryRegion;

        let guest_base = Self::BASE_ADDRESS as u64;

        let peb = HyperlightPEB {
            init_data: GuestMemoryRegion {
                size: (self.get_unaligned_memory_size() - self.init_data_offset()) as u64,
                ptr: guest_base + self.init_data_offset() as u64,
            },
            guest_heap: GuestMemoryRegion {
                size: self.heap_size as u64,
                ptr: guest_base + self.guest_heap_buffer_offset() as u64,
            },
        };

        let offset = self.peb_offset();
        let bytes = bytemuck::bytes_of(&peb);
        let end = offset + bytes.len();
        let mem_len = mem.len();
        let dst = mem.get_mut(offset..end).ok_or_else(|| {
            new_error!(
                "memory too small to write PEB: need {} bytes at offset {:#x}, have {} bytes",
                bytes.len(),
                offset,
                mem_len
            )
        })?;
        dst.copy_from_slice(bytes);

        Ok(())
    }
}

/// Changes to the below methods is part of Snapshot ABI, and
/// changing any output shifts where the loader
/// reads captured bytes and breaks existing snapshots. Any change here
/// is a snapshot ABI break: see the `layout_offsets_are_pinned` test
/// and docs/snapshot-versioning.md.
impl SandboxMemoryLayout {
    /// Offset of the PEB struct within the snapshot region.
    pub(crate) fn peb_offset(&self) -> usize {
        self.code_size.next_multiple_of(PAGE_SIZE)
    }

    /// Guest physical address of the PEB.
    pub(crate) fn peb_address(&self) -> usize {
        Self::BASE_ADDRESS + self.peb_offset()
    }

    /// Offset of the guest heap buffer within the snapshot region.
    pub(crate) fn guest_heap_buffer_offset(&self) -> usize {
        (self.peb_offset() + size_of::<HyperlightPEB>()).next_multiple_of(PAGE_SIZE)
    }

    /// Offset of the init data section within the snapshot region.
    pub(crate) fn init_data_offset(&self) -> usize {
        (self.guest_heap_buffer_offset() + self.heap_size).next_multiple_of(PAGE_SIZE)
    }

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
        self.transport_arena.size()
    }

    /// Base GPA to which the page tables are eagerly copied on restore.
    pub(crate) fn get_pt_base_gpa(&self) -> u64 {
        self.transport_arena.end_addr()
    }

    /// Exact transport placement in the fixed scratch prefix.
    pub(crate) fn get_transport_arena(&self) -> TransportArena {
        self.transport_arena
    }

    /// Total size of guest memory in `self`'s memory layout.
    fn get_unaligned_memory_size(&self) -> usize {
        self.init_data_offset() + self.init_data_size
    }

    /// Total size of guest memory in `self`'s memory layout, aligned
    /// to page size boundaries.
    pub(crate) fn get_memory_size(&self) -> Result<usize> {
        let total_memory = self.get_unaligned_memory_size();

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

    // helper func for testing
    fn get_expected_memory_size(layout: &SandboxMemoryLayout) -> usize {
        let mut expected_size = 0;
        // in order of layout
        expected_size += layout.code_size;

        // PEB
        let peb_and_array = size_of::<HyperlightPEB>();
        expected_size += peb_and_array.next_multiple_of(PAGE_SIZE);

        expected_size += layout.heap_size.next_multiple_of(PAGE_SIZE);

        expected_size.next_multiple_of(page_size::get())
    }

    #[test]
    fn test_get_memory_size() {
        let sbox_cfg = SandboxConfiguration::default();
        let sbox_mem_layout = SandboxMemoryLayout::new(sbox_cfg, 4096, 0, None).unwrap();
        assert_eq!(
            sbox_mem_layout.get_memory_size().unwrap(),
            get_expected_memory_size(&sbox_mem_layout)
        );
    }

    #[test]
    fn transport_arena_starts_at_scratch_base() {
        let cfg = SandboxConfiguration::default();
        let layout = SandboxMemoryLayout::new(cfg, 4096, 0, None).unwrap();
        let arena = layout.get_transport_arena();
        let scratch_base = hyperlight_common::layout::scratch_base_gpa(layout.get_scratch_size());

        assert_eq!(arena.base_addr(), scratch_base);
        assert_eq!(layout.get_pt_base_gpa(), arena.end_addr());
        assert_eq!(layout.get_pt_base_scratch_offset(), arena.size());

        layout.ensure_page_tables_fit(PAGE_SIZE).unwrap();

        assert_eq!(layout.get_transport_arena(), arena);
    }

    #[test]
    fn transport_memory_is_part_of_minimum_scratch_size() {
        let mut cfg = SandboxConfiguration::default();
        let layout = SandboxMemoryLayout::new(cfg, 4096, 0, None).unwrap();
        let minimum =
            hyperlight_common::layout::min_scratch_size(layout.get_transport_arena().size());
        cfg.set_scratch_size(minimum);
        let layout = SandboxMemoryLayout::new(cfg, 4096, 0, None).unwrap();

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

            let layout = SandboxMemoryLayout::new(cfg, 4096, 0, None);
            assert!(matches!(layout, Err(MemoryRequestTooSmall(_, usize::MAX))));
        }
    }

    #[test]
    fn rejects_unaligned_scratch_size() {
        let mut cfg = SandboxConfiguration::default();
        cfg.set_scratch_size(SandboxConfiguration::DEFAULT_SCRATCH_SIZE + 1);

        let error = SandboxMemoryLayout::new(cfg, 4096, 0, None).unwrap_err();
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
            SandboxMemoryLayout::new(SandboxConfiguration::default(), PAGE_SIZE, 0, None).unwrap();
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
    fn code_gva_rejects_overlap() {
        let mut layout =
            SandboxMemoryLayout::new(SandboxConfiguration::default(), PAGE_SIZE, 0, None).unwrap();
        assert!(layout.set_code_gva(layout.peb_address() as u64).is_err());
    }

    #[test]
    fn test_max_memory_sandbox() {
        let mut cfg = SandboxConfiguration::default();
        // scratch_size exceeds 16 GiB limit
        cfg.set_scratch_size(17 * 1024 * 1024 * 1024);
        let layout = SandboxMemoryLayout::new(cfg, 4096, 4096, None);
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
        cfg.set_heap_size(0x2000);
        cfg.set_scratch_size(0x30000);
        let layout = SandboxMemoryLayout::new(cfg, 0x1000, 0, None).unwrap();

        pin_eq!(layout.guest_code_offset(), 0);
        pin_eq!(layout.peb_offset(), 0x1000);
        pin_eq!(layout.peb_address(), 0x5000);
        pin_eq!(layout.guest_heap_buffer_offset(), 0x2000);
        pin_eq!(layout.init_data_offset(), 0x4000);
        pin_eq!(layout.get_memory_size().unwrap(), 0x4000);

        pin_eq!(layout.get_scratch_size(), 0x30000);
        pin_eq!(layout.get_pt_base_scratch_offset(), 0x15000);

        let arena = layout.get_transport_arena();
        let scratch_base_gpa = hyperlight_common::layout::scratch_base_gpa(0x30000);
        pin_eq!(arena.g2h_ring_addr() - scratch_base_gpa, 0);
        pin_eq!(arena.h2g_ring_addr() - scratch_base_gpa, 0x410);
        pin_eq!(arena.mbx_addr() - scratch_base_gpa, 0x618);
        pin_eq!(arena.g2h_pool_addr() - scratch_base_gpa, 0x1000);
        pin_eq!(arena.h2g_pool_addr() - scratch_base_gpa, 0xd000);
        pin_eq!(arena.end_addr() - scratch_base_gpa, 0x15000);

        // The transport arena sits at the scratch base. The page tables
        // follow it. With the `SCRATCH_TOP` pins above, these fix the
        // absolute addresses.
        pin_eq!(
            layout.get_pt_base_gpa() - hyperlight_common::layout::scratch_base_gpa(0x30000),
            0x15000
        );
        // A second snapshot layout keeps the transport prefix fixed
        // relative to its scratch base.
        let mut cfg = SandboxConfiguration::default();
        cfg.set_heap_size(0x5000);
        cfg.set_scratch_size(0x40000);
        let layout = SandboxMemoryLayout::new(cfg, 0x3000, 0, None).unwrap();

        pin_eq!(layout.guest_code_offset(), 0);
        pin_eq!(layout.peb_offset(), 0x3000);
        pin_eq!(layout.peb_address(), 0x7000);
        pin_eq!(layout.guest_heap_buffer_offset(), 0x4000);
        pin_eq!(layout.init_data_offset(), 0x9000);
        pin_eq!(
            layout.get_memory_size().unwrap(),
            0x9000_usize.next_multiple_of(page_size::get())
        );

        pin_eq!(layout.get_scratch_size(), 0x40000);
        pin_eq!(layout.get_pt_base_scratch_offset(), 0x15000);

        let arena = layout.get_transport_arena();
        let scratch_base_gpa = hyperlight_common::layout::scratch_base_gpa(0x40000);
        pin_eq!(arena.g2h_ring_addr() - scratch_base_gpa, 0);
        pin_eq!(arena.h2g_ring_addr() - scratch_base_gpa, 0x410);
        pin_eq!(arena.mbx_addr() - scratch_base_gpa, 0x618);
        pin_eq!(arena.g2h_pool_addr() - scratch_base_gpa, 0x1000);
        pin_eq!(arena.h2g_pool_addr() - scratch_base_gpa, 0xd000);
        pin_eq!(arena.end_addr() - scratch_base_gpa, 0x15000);

        pin_eq!(
            layout.get_pt_base_gpa() - hyperlight_common::layout::scratch_base_gpa(0x40000),
            0x15000
        );
    }
}
