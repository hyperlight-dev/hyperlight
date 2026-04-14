/*
Copyright 2025  The Hyperlight Authors.

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
//! memory, although at present the snapshot process specially
//! privileges the statically allocated input and output data regions:
//!
//! +-------------------------------------------+ (top of physical memory)
//! |         Exception Stack, Metadata         |
//! +-------------------------------------------+ (1 page below)
//! |              Scratch Memory               |
//! +-------------------------------------------+
//! |                Output Data                |
//! +-------------------------------------------+
//! |                Input Data                 |
//! +-------------------------------------------+ (scratch size)

use std::fmt::Debug;
use std::mem::{offset_of, size_of};

use hyperlight_common::mem::{HyperlightPEB, PAGE_SIZE_USIZE};
use tracing::{Span, instrument};

use super::memory_region::MemoryRegionType::{Code, Heap, InitData, Peb};
use super::memory_region::{
    DEFAULT_GUEST_BLOB_MEM_FLAGS, MemoryRegion, MemoryRegion_, MemoryRegionFlags, MemoryRegionKind,
    MemoryRegionVecBuilder,
};
#[cfg(any(gdb, feature = "mem_profile"))]
use super::shared_mem::HostSharedMemory;
use super::shared_mem::{ExclusiveSharedMemory, ReadonlySharedMemory};
use crate::error::HyperlightError::{MemoryRequestTooBig, MemoryRequestTooSmall};
use crate::sandbox::SandboxConfiguration;
use crate::{Result, new_error};

pub(crate) enum BaseGpaRegion<Sn, Sc> {
    Snapshot(Sn),
    Scratch(Sc),
    Mmap(MemoryRegion),
}

// It's an invariant of this type, checked on creation, that the
// offset is in bounds for the base region.
pub(crate) struct ResolvedGpa<Sn, Sc> {
    pub(crate) offset: usize,
    pub(crate) base: BaseGpaRegion<Sn, Sc>,
}

impl AsRef<[u8]> for ExclusiveSharedMemory {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}
impl AsRef<[u8]> for ReadonlySharedMemory {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<Sn, Sc> ResolvedGpa<Sn, Sc> {
    pub(crate) fn with_memories<Sn2, Sc2>(self, sn: Sn2, sc: Sc2) -> ResolvedGpa<Sn2, Sc2> {
        ResolvedGpa {
            offset: self.offset,
            base: match self.base {
                BaseGpaRegion::Snapshot(_) => BaseGpaRegion::Snapshot(sn),
                BaseGpaRegion::Scratch(_) => BaseGpaRegion::Scratch(sc),
                BaseGpaRegion::Mmap(r) => BaseGpaRegion::Mmap(r),
            },
        }
    }
}
impl<'a> BaseGpaRegion<&'a [u8], &'a [u8]> {
    pub(crate) fn as_ref<'b>(&'b self) -> &'a [u8] {
        match self {
            BaseGpaRegion::Snapshot(sn) => sn,
            BaseGpaRegion::Scratch(sc) => sc,
            BaseGpaRegion::Mmap(r) => unsafe {
                #[allow(clippy::useless_conversion)]
                let host_region_base: usize = r.host_region.start.into();
                #[allow(clippy::useless_conversion)]
                let host_region_end: usize = r.host_region.end.into();
                let len = host_region_end - host_region_base;
                std::slice::from_raw_parts(host_region_base as *const u8, len)
            },
        }
    }
}
impl<'a> ResolvedGpa<&'a [u8], &'a [u8]> {
    pub(crate) fn as_ref<'b>(&'b self) -> &'a [u8] {
        let base = self.base.as_ref();
        if self.offset > base.len() {
            return &[];
        }
        &self.base.as_ref()[self.offset..]
    }
}
#[cfg(any(gdb, feature = "mem_profile"))]
#[allow(unused)] // may be unused when i686-guest is also enabled
pub(crate) trait ReadableSharedMemory {
    fn copy_to_slice(&self, slice: &mut [u8], offset: usize) -> Result<()>;
}
#[cfg(any(gdb, feature = "mem_profile"))]
impl ReadableSharedMemory for &HostSharedMemory {
    fn copy_to_slice(&self, slice: &mut [u8], offset: usize) -> Result<()> {
        HostSharedMemory::copy_to_slice(self, slice, offset)
    }
}
#[cfg(any(gdb, feature = "mem_profile"))]
mod coherence_hack {
    use super::{ExclusiveSharedMemory, ReadonlySharedMemory};
    #[allow(unused)] // it actually is; see the impl below
    pub(super) trait SharedMemoryAsRefMarker: AsRef<[u8]> {}
    impl SharedMemoryAsRefMarker for ExclusiveSharedMemory {}
    impl SharedMemoryAsRefMarker for &ExclusiveSharedMemory {}
    impl SharedMemoryAsRefMarker for ReadonlySharedMemory {}
    impl SharedMemoryAsRefMarker for &ReadonlySharedMemory {}
}
#[cfg(any(gdb, feature = "mem_profile"))]
impl<T: coherence_hack::SharedMemoryAsRefMarker> ReadableSharedMemory for T {
    fn copy_to_slice(&self, slice: &mut [u8], offset: usize) -> Result<()> {
        let ss: &[u8] = self.as_ref();
        let end = offset + slice.len();
        if end > ss.len() {
            return Err(new_error!(
                "Attempt to read up to {} in memory of size {}",
                offset + slice.len(),
                self.as_ref().len()
            ));
        }
        slice.copy_from_slice(&ss[offset..end]);
        Ok(())
    }
}
#[cfg(any(gdb, feature = "mem_profile"))]
impl<Sn: ReadableSharedMemory, Sc: ReadableSharedMemory> ResolvedGpa<Sn, Sc> {
    #[allow(unused)] // may be unused when i686-guest is also enabled
    pub(crate) fn copy_to_slice(&self, slice: &mut [u8]) -> Result<()> {
        match &self.base {
            BaseGpaRegion::Snapshot(sn) => sn.copy_to_slice(slice, self.offset),
            BaseGpaRegion::Scratch(sc) => sc.copy_to_slice(slice, self.offset),
            BaseGpaRegion::Mmap(r) => unsafe {
                #[allow(clippy::useless_conversion)]
                let host_region_base: usize = r.host_region.start.into();
                #[allow(clippy::useless_conversion)]
                let host_region_end: usize = r.host_region.end.into();
                let len = host_region_end - host_region_base;
                // Safety: it's a documented invariant of MemoryRegion
                // that the memory must remain alive as long as the
                // sandbox is alive, and the way this code is used,
                // the lifetimes of the snapshot and scratch memories
                // ensure that the sandbox is still alive. This could
                // perhaps be cleaned up/improved/made harder to
                // misuse significantly, but it would require a much
                // larger rework.
                let ss = std::slice::from_raw_parts(host_region_base as *const u8, len);
                let end = self.offset + slice.len();
                if end > ss.len() {
                    return Err(new_error!(
                        "Attempt to read up to {} in memory of size {}",
                        self.offset + slice.len(),
                        ss.len()
                    ));
                }
                slice.copy_from_slice(&ss[self.offset..end]);
                Ok(())
            },
        }
    }
}

#[derive(Copy, Clone)]
pub(crate) struct SandboxMemoryLayout {
    pub(super) sandbox_memory_config: SandboxConfiguration,
    /// The heap size of this sandbox.
    pub(super) heap_size: usize,
    init_data_size: usize,

    /// The following fields are offsets to the actual PEB struct fields.
    /// They are used when writing the PEB struct itself
    peb_offset: usize,
    peb_input_data_offset: usize,
    peb_output_data_offset: usize,
    peb_init_data_offset: usize,
    peb_heap_data_offset: usize,
    #[cfg(feature = "nanvix-unstable")]
    peb_file_mappings_offset: usize,

    guest_heap_buffer_offset: usize,
    init_data_offset: usize,
    pt_size: Option<usize>,

    // other
    pub(crate) peb_address: usize,
    code_size: usize,
    // The offset in the sandbox memory where the code starts
    guest_code_offset: usize,
    #[cfg_attr(feature = "i686-guest", allow(unused))]
    pub(crate) init_data_permissions: Option<MemoryRegionFlags>,

    // The size of the scratch region in physical memory; note that
    // this will appear under the top of physical memory.
    scratch_size: usize,
    // The size of the snapshot region in physical memory; note that
    // this will appear somewhere near the base of physical memory.
    snapshot_size: usize,
}

impl Debug for SandboxMemoryLayout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut ff = f.debug_struct("SandboxMemoryLayout");
        ff.field(
            "Total Memory Size",
            &format_args!("{:#x}", self.get_memory_size().unwrap_or(0)),
        )
        .field("Heap Size", &format_args!("{:#x}", self.heap_size))
        .field(
            "Init Data Size",
            &format_args!("{:#x}", self.init_data_size),
        )
        .field("PEB Address", &format_args!("{:#x}", self.peb_address))
        .field("PEB Offset", &format_args!("{:#x}", self.peb_offset))
        .field("Code Size", &format_args!("{:#x}", self.code_size))
        .field(
            "Input Data Offset",
            &format_args!("{:#x}", self.peb_input_data_offset),
        )
        .field(
            "Output Data Offset",
            &format_args!("{:#x}", self.peb_output_data_offset),
        )
        .field(
            "Init Data Offset",
            &format_args!("{:#x}", self.peb_init_data_offset),
        )
        .field(
            "Guest Heap Offset",
            &format_args!("{:#x}", self.peb_heap_data_offset),
        );
        #[cfg(feature = "nanvix-unstable")]
        ff.field(
            "File Mappings Offset",
            &format_args!("{:#x}", self.peb_file_mappings_offset),
        );
        ff.field(
            "Guest Heap Buffer Offset",
            &format_args!("{:#x}", self.guest_heap_buffer_offset),
        )
        .field(
            "Init Data Offset",
            &format_args!("{:#x}", self.init_data_offset),
        )
        .field("PT Size", &format_args!("{:#x}", self.pt_size.unwrap_or(0)))
        .field(
            "Guest Code Offset",
            &format_args!("{:#x}", self.guest_code_offset),
        )
        .field(
            "Scratch region size",
            &format_args!("{:#x}", self.scratch_size),
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
    const MAX_MEMORY_SIZE: usize = (16 * 1024 * 1024 * 1024) - Self::BASE_ADDRESS; // 16 GiB - BASE_ADDRESS

    /// The base address of the sandbox's memory.
    pub(crate) const BASE_ADDRESS: usize = 0x1000;

    // the offset into a sandbox's input/output buffer where the stack starts
    pub(crate) const STACK_POINTER_SIZE_BYTES: u64 = 8;

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
        let min_scratch_size = hyperlight_common::layout::min_scratch_size(
            cfg.get_input_data_size(),
            cfg.get_output_data_size(),
        );
        if scratch_size < min_scratch_size {
            return Err(MemoryRequestTooSmall(scratch_size, min_scratch_size));
        }

        let guest_code_offset = 0;
        // The following offsets are to the fields of the PEB struct itself!
        let peb_offset = code_size.next_multiple_of(PAGE_SIZE_USIZE);
        let peb_input_data_offset = peb_offset + offset_of!(HyperlightPEB, input_stack);
        let peb_output_data_offset = peb_offset + offset_of!(HyperlightPEB, output_stack);
        let peb_init_data_offset = peb_offset + offset_of!(HyperlightPEB, init_data);
        let peb_heap_data_offset = peb_offset + offset_of!(HyperlightPEB, guest_heap);
        #[cfg(feature = "nanvix-unstable")]
        let peb_file_mappings_offset = peb_offset + offset_of!(HyperlightPEB, file_mappings);

        // The following offsets are the actual values that relate to memory layout,
        // which are written to PEB struct
        let peb_address = Self::BASE_ADDRESS + peb_offset;
        // make sure heap buffer starts at 4K boundary.
        // The FileMappingInfo array is stored immediately after the PEB struct.
        // We statically reserve space for MAX_FILE_MAPPINGS entries so that
        // the heap never overlaps the array, even when all slots are used.
        // The host writes file mapping metadata here via write_file_mapping_entry;
        // the guest only reads the entries. We don't know at layout time how
        // many file mappings the host will register, so we reserve space for
        // the maximum number.
        // The heap starts at the next page boundary after this reserved area.
        #[cfg(feature = "nanvix-unstable")]
        let file_mappings_array_end = peb_offset
            + size_of::<HyperlightPEB>()
            + hyperlight_common::mem::MAX_FILE_MAPPINGS
                * size_of::<hyperlight_common::mem::FileMappingInfo>();
        #[cfg(feature = "nanvix-unstable")]
        let guest_heap_buffer_offset = file_mappings_array_end.next_multiple_of(PAGE_SIZE_USIZE);
        #[cfg(not(feature = "nanvix-unstable"))]
        let guest_heap_buffer_offset =
            (peb_offset + size_of::<HyperlightPEB>()).next_multiple_of(PAGE_SIZE_USIZE);

        // make sure init data starts at 4K boundary
        let init_data_offset =
            (guest_heap_buffer_offset + heap_size).next_multiple_of(PAGE_SIZE_USIZE);
        let mut ret = Self {
            peb_offset,
            heap_size,
            peb_input_data_offset,
            peb_output_data_offset,
            peb_init_data_offset,
            peb_heap_data_offset,
            #[cfg(feature = "nanvix-unstable")]
            peb_file_mappings_offset,
            sandbox_memory_config: cfg,
            code_size,
            guest_heap_buffer_offset,
            peb_address,
            guest_code_offset,
            init_data_offset,
            init_data_size,
            init_data_permissions,
            pt_size: None,
            scratch_size,
            snapshot_size: 0,
        };
        ret.set_snapshot_size(ret.get_memory_size()?);
        Ok(ret)
    }

    /// Get the offset in guest memory to the output data size
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_output_data_size_offset(&self) -> usize {
        // The size field is the first field in the `OutputData` struct
        self.peb_output_data_offset
    }

    /// Get the offset in guest memory to the init data size
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_init_data_size_offset(&self) -> usize {
        // The init data size is the first field in the `GuestMemoryRegion` struct
        self.peb_init_data_offset
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_scratch_size(&self) -> usize {
        self.scratch_size
    }

    /// Get the offset in guest memory to the output data pointer.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_output_data_pointer_offset(&self) -> usize {
        // This field is immediately after the output data size field,
        // which is a `u64`.
        self.get_output_data_size_offset() + size_of::<u64>()
    }

    /// Get the offset in guest memory to the init data pointer.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_init_data_pointer_offset(&self) -> usize {
        // The init data pointer is immediately after the init data size field,
        // which is a `u64`.
        self.get_init_data_size_offset() + size_of::<u64>()
    }

    /// Get the guest virtual address of the start of output data.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_output_data_buffer_gva(&self) -> u64 {
        hyperlight_common::layout::scratch_base_gva(self.scratch_size)
            + self.sandbox_memory_config.get_input_data_size() as u64
    }

    /// Get the offset into the host scratch buffer of the start of
    /// the output data.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_output_data_buffer_scratch_host_offset(&self) -> usize {
        self.sandbox_memory_config.get_input_data_size()
    }

    /// Get the offset in guest memory to the input data size.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_input_data_size_offset(&self) -> usize {
        // The input data size is the first field in the input stack's `GuestMemoryRegion` struct
        self.peb_input_data_offset
    }

    /// Get the offset in guest memory to the input data pointer.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_input_data_pointer_offset(&self) -> usize {
        // The input data pointer is immediately after the input
        // data size field in the input data `GuestMemoryRegion` struct which is a `u64`.
        self.get_input_data_size_offset() + size_of::<u64>()
    }

    /// Get the guest virtual address of the start of input data
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_input_data_buffer_gva(&self) -> u64 {
        hyperlight_common::layout::scratch_base_gva(self.scratch_size)
    }

    /// Get the offset into the host scratch buffer of the start of
    /// the input data
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_input_data_buffer_scratch_host_offset(&self) -> usize {
        0
    }

    /// Get the offset from the beginning of the scratch region to the
    /// location where page tables will be eagerly copied on restore
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_pt_base_scratch_offset(&self) -> usize {
        (self.sandbox_memory_config.get_input_data_size()
            + self.sandbox_memory_config.get_output_data_size())
        .next_multiple_of(hyperlight_common::vmem::PAGE_SIZE)
    }

    /// Get the base GPA to which the page tables will be eagerly
    /// copied on restore
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_pt_base_gpa(&self) -> u64 {
        hyperlight_common::layout::scratch_base_gpa(self.scratch_size)
            + self.get_pt_base_scratch_offset() as u64
    }

    /// Get the first GPA of the scratch region that the host hasn't
    /// used for something else
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_first_free_scratch_gpa(&self) -> u64 {
        self.get_pt_base_gpa() + self.pt_size.unwrap_or(0) as u64
    }

    /// Get the offset in guest memory to the heap size
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_heap_size_offset(&self) -> usize {
        self.peb_heap_data_offset
    }

    /// Get the offset in guest memory to the file_mappings count field
    /// (the `size` field of the `GuestMemoryRegion` in the PEB).
    #[cfg(feature = "nanvix-unstable")]
    pub(crate) fn get_file_mappings_size_offset(&self) -> usize {
        self.peb_file_mappings_offset
    }

    /// Get the offset in guest memory to the file_mappings pointer field.
    #[cfg(feature = "nanvix-unstable")]
    fn get_file_mappings_pointer_offset(&self) -> usize {
        self.get_file_mappings_size_offset() + size_of::<u64>()
    }

    /// Get the offset in snapshot memory where the FileMappingInfo array starts
    /// (immediately after the PEB struct, within the same page).
    #[cfg(feature = "nanvix-unstable")]
    pub(crate) fn get_file_mappings_array_offset(&self) -> usize {
        self.peb_offset + size_of::<HyperlightPEB>()
    }

    /// Get the guest address of the FileMappingInfo array.
    #[cfg(feature = "nanvix-unstable")]
    fn get_file_mappings_array_gva(&self) -> u64 {
        (Self::BASE_ADDRESS + self.get_file_mappings_array_offset()) as u64
    }

    /// Get the offset of the heap pointer in guest memory,
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_heap_pointer_offset(&self) -> usize {
        // The heap pointer is immediately after the
        // heap size field in the guest heap's `GuestMemoryRegion` struct which is a `u64`.
        self.get_heap_size_offset() + size_of::<u64>()
    }

    /// Get the total size of guest memory in `self`'s memory
    /// layout.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_unaligned_memory_size(&self) -> usize {
        self.init_data_offset + self.init_data_size
    }

    /// get the code offset
    /// This is the offset in the sandbox memory where the code starts
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_guest_code_offset(&self) -> usize {
        self.guest_code_offset
    }

    /// Get the guest address of the code section in the sandbox
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_guest_code_address(&self) -> usize {
        Self::BASE_ADDRESS + self.guest_code_offset
    }

    /// Get the total size of guest memory in `self`'s memory
    /// layout aligned to page size boundaries.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_memory_size(&self) -> Result<usize> {
        let total_memory = self.get_unaligned_memory_size();

        // Size should be a multiple of page size.
        let remainder = total_memory % PAGE_SIZE_USIZE;
        let multiples = total_memory / PAGE_SIZE_USIZE;
        let size = match remainder {
            0 => total_memory,
            _ => (multiples + 1) * PAGE_SIZE_USIZE,
        };

        if size > Self::MAX_MEMORY_SIZE {
            Err(MemoryRequestTooBig(size, Self::MAX_MEMORY_SIZE))
        } else {
            Ok(size)
        }
    }

    /// Sets the size of the memory region used for page tables
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn set_pt_size(&mut self, size: usize) -> Result<()> {
        let min_fixed_scratch = hyperlight_common::layout::min_scratch_size(
            self.sandbox_memory_config.get_input_data_size(),
            self.sandbox_memory_config.get_output_data_size(),
        );
        let min_scratch = min_fixed_scratch + size;
        if self.scratch_size < min_scratch {
            return Err(MemoryRequestTooSmall(self.scratch_size, min_scratch));
        }
        let old_pt_size = self.pt_size.unwrap_or(0);
        self.snapshot_size = self.snapshot_size - old_pt_size + size;
        self.pt_size = Some(size);
        Ok(())
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn set_snapshot_size(&mut self, new_size: usize) {
        self.snapshot_size = new_size;
    }

    /// Get the size of the memory region used for page tables
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_pt_size(&self) -> usize {
        self.pt_size.unwrap_or(0)
    }

    /// Returns the memory regions associated with this memory layout,
    /// suitable for passing to a hypervisor for mapping into memory
    #[cfg_attr(feature = "i686-guest", allow(unused))]
    pub(crate) fn get_memory_regions_<K: MemoryRegionKind>(
        &self,
        host_base: K::HostBaseType,
    ) -> Result<Vec<MemoryRegion_<K>>> {
        let mut builder = MemoryRegionVecBuilder::new(Self::BASE_ADDRESS, host_base);

        // code
        let peb_offset = builder.push_page_aligned(
            self.code_size,
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE | MemoryRegionFlags::EXECUTE,
            Code,
        );

        let expected_peb_offset = TryInto::<usize>::try_into(self.peb_offset)?;

        if peb_offset != expected_peb_offset {
            return Err(new_error!(
                "PEB offset does not match expected PEB offset expected:  {}, actual:  {}",
                expected_peb_offset,
                peb_offset
            ));
        }

        // PEB + preallocated FileMappingInfo array
        #[cfg(feature = "nanvix-unstable")]
        let heap_offset = {
            let peb_and_array_size = size_of::<HyperlightPEB>()
                + hyperlight_common::mem::MAX_FILE_MAPPINGS
                    * size_of::<hyperlight_common::mem::FileMappingInfo>();
            builder.push_page_aligned(
                peb_and_array_size,
                MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
                Peb,
            )
        };
        #[cfg(not(feature = "nanvix-unstable"))]
        let heap_offset =
            builder.push_page_aligned(size_of::<HyperlightPEB>(), MemoryRegionFlags::READ, Peb);

        let expected_heap_offset = TryInto::<usize>::try_into(self.guest_heap_buffer_offset)?;

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

        let expected_init_data_offset = TryInto::<usize>::try_into(self.init_data_offset)?;

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

        if final_offset != expected_final_offset {
            return Err(new_error!(
                "Final offset does not match expected Final offset expected:  {}, actual:  {}",
                expected_final_offset,
                final_offset
            ));
        }

        Ok(builder.build())
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn write_init_data(&self, out: &mut [u8], bytes: &[u8]) -> Result<()> {
        out[self.init_data_offset..self.init_data_offset + self.init_data_size]
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
        let guest_offset = SandboxMemoryLayout::BASE_ADDRESS;

        fn write_u64(mem: &mut [u8], offset: usize, value: u64) -> Result<()> {
            if offset + 8 > mem.len() {
                return Err(new_error!(
                    "Cannot write to offset {} in slice of len {}",
                    offset,
                    mem.len()
                ));
            }
            mem[offset..offset + 8].copy_from_slice(&u64::to_ne_bytes(value));
            Ok(())
        }

        macro_rules! get_address {
            ($something:ident) => {
                u64::try_from(guest_offset + self.$something)?
            };
        }

        // Start of setting up the PEB. The following are in the order of the PEB fields

        // Set up input buffer pointer
        write_u64(
            mem,
            self.get_input_data_size_offset(),
            self.sandbox_memory_config
                .get_input_data_size()
                .try_into()?,
        )?;
        write_u64(
            mem,
            self.get_input_data_pointer_offset(),
            self.get_input_data_buffer_gva(),
        )?;

        // Set up output buffer pointer
        write_u64(
            mem,
            self.get_output_data_size_offset(),
            self.sandbox_memory_config
                .get_output_data_size()
                .try_into()?,
        )?;
        write_u64(
            mem,
            self.get_output_data_pointer_offset(),
            self.get_output_data_buffer_gva(),
        )?;

        // Set up init data pointer
        write_u64(
            mem,
            self.get_init_data_size_offset(),
            (self.get_unaligned_memory_size() - self.init_data_offset).try_into()?,
        )?;
        let addr = get_address!(init_data_offset);
        write_u64(mem, self.get_init_data_pointer_offset(), addr)?;

        // Set up heap buffer pointer
        let addr = get_address!(guest_heap_buffer_offset);
        write_u64(mem, self.get_heap_size_offset(), self.heap_size.try_into()?)?;
        write_u64(mem, self.get_heap_pointer_offset(), addr)?;

        // Set up the file_mappings descriptor in the PEB.
        // - The `size` field holds the number of valid FileMappingInfo
        //   entries currently written (initially 0 — entries are added
        //   later by map_file_cow / evolve).
        // - The `ptr` field holds the guest address of the preallocated
        //   FileMappingInfo array
        #[cfg(feature = "nanvix-unstable")]
        write_u64(mem, self.get_file_mappings_size_offset(), 0)?;
        #[cfg(feature = "nanvix-unstable")]
        write_u64(
            mem,
            self.get_file_mappings_pointer_offset(),
            self.get_file_mappings_array_gva(),
        )?;

        // End of setting up the PEB

        // The input and output data regions do not have their layout
        // initialised here, because they are in the scratch
        // region---they are instead set in
        // [`SandboxMemoryManager::update_scratch_bookkeeping`].

        Ok(())
    }

    /// Determine what region this gpa is in, and its offset into that region
    pub(crate) fn resolve_gpa(
        &self,
        gpa: u64,
        mmap_regions: &[MemoryRegion],
    ) -> Option<ResolvedGpa<(), ()>> {
        let scratch_base = hyperlight_common::layout::scratch_base_gpa(self.scratch_size);
        if gpa >= scratch_base && gpa < scratch_base + self.scratch_size as u64 {
            return Some(ResolvedGpa {
                offset: (gpa - scratch_base) as usize,
                base: BaseGpaRegion::Scratch(()),
            });
        } else if gpa >= SandboxMemoryLayout::BASE_ADDRESS as u64
            && gpa < SandboxMemoryLayout::BASE_ADDRESS as u64 + self.snapshot_size as u64
        {
            return Some(ResolvedGpa {
                offset: gpa as usize - SandboxMemoryLayout::BASE_ADDRESS,
                base: BaseGpaRegion::Snapshot(()),
            });
        }
        for rgn in mmap_regions {
            if gpa >= rgn.guest_region.start as u64 && gpa < rgn.guest_region.end as u64 {
                return Some(ResolvedGpa {
                    offset: gpa as usize - rgn.guest_region.start,
                    base: BaseGpaRegion::Mmap(rgn.clone()),
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use hyperlight_common::mem::PAGE_SIZE_USIZE;

    use super::*;

    // helper func for testing
    fn get_expected_memory_size(layout: &SandboxMemoryLayout) -> usize {
        let mut expected_size = 0;
        // in order of layout
        expected_size += layout.code_size;

        // PEB + preallocated FileMappingInfo array
        #[cfg(feature = "nanvix-unstable")]
        let peb_and_array = size_of::<HyperlightPEB>()
            + hyperlight_common::mem::MAX_FILE_MAPPINGS
                * size_of::<hyperlight_common::mem::FileMappingInfo>();
        #[cfg(not(feature = "nanvix-unstable"))]
        let peb_and_array = size_of::<HyperlightPEB>();
        expected_size += peb_and_array.next_multiple_of(PAGE_SIZE_USIZE);

        expected_size += layout.heap_size.next_multiple_of(PAGE_SIZE_USIZE);

        expected_size
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
    fn test_max_memory_sandbox() {
        let mut cfg = SandboxConfiguration::default();
        // scratch_size exceeds 16 GiB limit
        cfg.set_scratch_size(17 * 1024 * 1024 * 1024);
        cfg.set_input_data_size(16 * 1024 * 1024 * 1024);
        let layout = SandboxMemoryLayout::new(cfg, 4096, 4096, None);
        assert!(matches!(layout.unwrap_err(), MemoryRequestTooBig(..)));
    }
}
