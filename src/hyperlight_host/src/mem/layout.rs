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
//! 0xffff_ff00_0000_0000.
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

use hyperlight_common::mem::{GuestMemoryRegion, HyperlightPEB, PAGE_SIZE_USIZE};
use hyperlight_common::util::round_up_to;
use rand::{RngCore, rng};
use tracing::{Span, instrument};

#[cfg(feature = "init-paging")]
use super::memory_region::MemoryRegionType::PageTables;
use super::memory_region::MemoryRegionType::{
    Code, GuardPage, Heap, InitData, InputData, OutputData, Peb, Stack,
};
use super::memory_region::{
    DEFAULT_GUEST_BLOB_MEM_FLAGS, MemoryRegion, MemoryRegion_, MemoryRegionFlags, MemoryRegionKind, MemoryRegionVecBuilder,
};
#[cfg(feature = "init-paging")]
use super::mgr::AMOUNT_OF_MEMORY_PER_PT;
use super::shared_mem::{ExclusiveSharedMemory, GuestSharedMemory, SharedMemory};
use crate::error::HyperlightError::{GuestOffsetIsInvalid, MemoryRequestTooBig, MemoryRequestTooSmall};
use crate::sandbox::SandboxConfiguration;
use crate::{Result, new_error};

/// - `InitData` - some extra data that can be loaded onto the sandbox during
///   initialization.
///
/// - `HostDefinitions` - the length of this is the `HostFunctionDefinitionSize`
///   field from `SandboxConfiguration`
///
/// - `InputData` -  this is a buffer that is used for input data to the host program.
///   the length of this field is `InputDataSize` from `SandboxConfiguration`
///
/// - `OutputData` - this is a buffer that is used for output data from host program.
///   the length of this field is `OutputDataSize` from `SandboxConfiguration`
///
/// - `GuestHeap` - this is a buffer that is used for heap data in the guest. the length
///   of this field is returned by the `heap_size()` method of this struct
///

#[derive(Copy, Clone)]
pub(crate) struct SandboxMemoryLayout {
    pub(super) sandbox_memory_config: SandboxConfiguration,
    /// The heap size of this sandbox.
    pub(super) heap_size: usize,
    init_data_size: usize,

    /// The following fields are offsets to the actual PEB struct fields.
    /// They are used when writing the PEB struct itself
    peb_offset: usize,
    peb_guest_dispatch_function_ptr_offset: usize, // set by guest in guest entrypoint
    peb_input_data_offset: usize,
    peb_output_data_offset: usize,
    peb_init_data_offset: usize,
    peb_heap_data_offset: usize,

    guest_heap_buffer_offset: usize,
    init_data_offset: usize,
    pt_offset: usize,
    pt_size: Option<usize>,

    // other
    pub(crate) peb_address: usize,
    code_size: usize,
    // The offset in the sandbox memory where the code starts
    guest_code_offset: usize,
    pub(crate) init_data_permissions: Option<MemoryRegionFlags>,

    // The size of the scratch region in physical memory; note that
    // this will appear under the top of physical memory.
    scratch_size: usize,

    // The stack pointer that the guest has set up, if it has been set up
    rsp_gva: Option<u64>,
}

impl Debug for SandboxMemoryLayout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxMemoryLayout")
            .field(
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
                "Guest Dispatch Function Pointer Offset",
                &format_args!("{:#x}", self.peb_guest_dispatch_function_ptr_offset),
            )
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
            )
            .field(
                "Guest Heap Buffer Offset",
                &format_args!("{:#x}", self.guest_heap_buffer_offset),
            )
            .field(
                "Init Data Offset",
                &format_args!("{:#x}", self.init_data_offset),
            )
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
    /// Currently, both the scratch region and the snapshot region are
    /// bounded by this size. The current value is essentially
    /// arbitrary and chosen for historical reasons; the modern
    /// sandbox virtual memory layout can support much more, so this
    /// could be increased should use cases for larger sandboxes
    /// arise.
    const MAX_MEMORY_SIZE: usize = 0x4000_0000 - Self::BASE_ADDRESS;

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
        heap_size: usize,
        scratch_size: usize,
        init_data_size: usize,
        init_data_permissions: Option<MemoryRegionFlags>,
    ) -> Result<Self> {
        if scratch_size > Self::MAX_MEMORY_SIZE {
            return Err(MemoryRequestTooBig(scratch_size, Self::MAX_MEMORY_SIZE))
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
        let peb_offset = round_up_to(code_size, PAGE_SIZE_USIZE);
        let peb_guest_dispatch_function_ptr_offset =
            peb_offset + offset_of!(HyperlightPEB, guest_function_dispatch_ptr);
        let peb_input_data_offset = peb_offset + offset_of!(HyperlightPEB, input_stack);
        let peb_output_data_offset = peb_offset + offset_of!(HyperlightPEB, output_stack);
        let peb_init_data_offset = peb_offset + offset_of!(HyperlightPEB, init_data);
        let peb_heap_data_offset = peb_offset + offset_of!(HyperlightPEB, guest_heap);

        // The following offsets are the actual values that relate to memory layout,
        // which are written to PEB struct
        let peb_address = Self::BASE_ADDRESS + peb_offset;
        // make sure heap buffer starts at 4K boundary
        let guest_heap_buffer_offset = round_up_to(
            peb_heap_data_offset + size_of::<GuestMemoryRegion>(),
            PAGE_SIZE_USIZE,
        );
        // make sure init data starts at 4K boundary
        let init_data_offset = round_up_to(guest_heap_buffer_offset + heap_size, PAGE_SIZE_USIZE);
        let pt_offset = round_up_to(
            init_data_offset + init_data_size,
            PAGE_SIZE_USIZE
        );

        Ok(Self {
            peb_offset,
            heap_size,
            peb_guest_dispatch_function_ptr_offset,
            peb_input_data_offset,
            peb_output_data_offset,
            peb_init_data_offset,
            peb_heap_data_offset,
            sandbox_memory_config: cfg,
            code_size,
            guest_heap_buffer_offset,
            peb_address,
            guest_code_offset,
            init_data_offset,
            init_data_size,
            init_data_permissions,
            pt_offset,
            pt_size: None,
            scratch_size,
            rsp_gva: None,
        })
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
        hyperlight_common::layout::scratch_base_gva(self.scratch_size) +
            self.sandbox_memory_config.get_input_data_size() as u64
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

    /// Get the offset into the host scratch buffer of the start of
    /// the input data
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_first_free_scratch_gpa(&self) -> u64 {
        round_up_to(
            hyperlight_common::layout::scratch_base_gpa(self.scratch_size as usize) as usize +
                self.sandbox_memory_config.get_input_data_size() +
                self.sandbox_memory_config.get_output_data_size(),
            hyperlight_common::vm::PAGE_SIZE,
        ) as u64
    }

    /// Get the offset in guest memory to where the guest dispatch function
    /// pointer is written
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_dispatch_function_pointer_offset(&self) -> usize {
        self.peb_guest_dispatch_function_ptr_offset
    }

    /// Get the offset in guest memory to the heap size
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_heap_size_offset(&self) -> usize {
        self.peb_heap_data_offset
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
        self.pt_offset + self.pt_size.unwrap_or(0)
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

    /// Get the offset into the snapshot region of the page tables
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_pt_offset(&self) -> usize {
        self.pt_offset
    }

    /// Get the offset into the snapshot region of the page tables
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn set_pt_size(&mut self, size: usize) {
        self.pt_size = Some(size);
    }

    /// Get the offset into the snapshot region of the guest user stack
    /// pointer, to be used when entering the guest
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn set_rsp_gva(&mut self, rsp: u64) {
        self.rsp_gva = Some(rsp);
    }

    /// Get the offset into the snapshot region of the guest user stack
    /// pointer, to be used when entering the guest.
    ///
    /// This is the raw aligned stack address, and should be adjusted
    /// (see [`get_rsp_gva_for_entry`] when jumping to the guest
    /// without pushing a return address.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_rsp_gva(&self) -> u64 {
        if let Some(rsp) = self.rsp_gva {
            rsp
        } else {
            (hyperlight_common::layout::MAX_GVA - hyperlight_common::layout::SCRATCH_TOP_EXN_STACK_OFFSET as usize + 1) as u64
        }
    }
    /// Get the aligned rsp to use when entering a guest
    ///
    /// This should be ≡ 8 % 16, since when we jump into the guest the
    /// machine does not push a return address as it would on a normal
    /// call.  For simplicity's sake, we mostly write as constants /
    /// store the aligned versions, and do the adjustment here.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_rsp_gva_for_entry(&self) -> u64 {
        self.get_rsp_gva() as u64 - 8
    }

    pub fn get_memory_regions(&self, shared_mem: &GuestSharedMemory) -> Result<Vec<MemoryRegion>> {
        self.get_memory_regions_(shared_mem.base_addr())
    }

    /// Returns the memory regions associated with this memory layout,
    /// suitable for passing to a hypervisor for mapping into memory
    pub(crate) fn get_memory_regions_<K: MemoryRegionKind>(&self, host_base: K::HostBaseType) -> Result<Vec<MemoryRegion_<K>>> {
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

        // PEB
        let heap_offset = builder.push_page_aligned(
            size_of::<HyperlightPEB>(),
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
            Peb,
        );

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
        let pt_offset = if self.init_data_size > 0 {
            let mem_flags = self
                .init_data_permissions
                .unwrap_or(DEFAULT_GUEST_BLOB_MEM_FLAGS);
            builder.push_page_aligned(self.init_data_size, mem_flags, InitData)
        } else {
            init_data_offset
        };

        let expected_pt_offset = TryInto::<usize>::try_into(self.pt_offset)?;

        if pt_offset != expected_pt_offset {
            return Err(new_error!(
                "Page table offset does not match expected:  {}, actual:  {}",
                expected_init_data_offset,
                init_data_offset
            ));
        }

        // page tables
        let final_offset = if let Some(pt_size) = self.pt_size {
            builder.push_page_aligned(pt_size, MemoryRegionFlags::READ | MemoryRegionFlags::WRITE, PageTables)
        } else {
            pt_offset
        };

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
    pub(crate) fn write_init_data(
        &self,
        out: &mut [u8],
        bytes: &[u8],
    ) -> Result<()> {
        Ok(out[self.init_data_offset..self.init_data_offset + self.init_data_size].copy_from_slice(bytes))
    }

    /// Write the finished memory layout to `shared_mem` and return
    /// `Ok` if successful.
    ///
    /// Note: `shared_mem` may have been modified, even if `Err` was returned
    /// from this function.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn write(
        &self,
        shared_mem: &mut ExclusiveSharedMemory,
        guest_offset: usize,
        size: usize,
    ) -> Result<()> {
        macro_rules! get_address {
            ($something:ident) => {
                u64::try_from(guest_offset + self.$something)?
            };
        }

        if guest_offset != SandboxMemoryLayout::BASE_ADDRESS
            && guest_offset != shared_mem.base_addr()
        {
            return Err(GuestOffsetIsInvalid(guest_offset));
        }

        // Start of setting up the PEB. The following are in the order of the PEB fields

        // Skip guest_dispatch_function_ptr_offset because it is set by the guest

        // Skip code, is set when loading binary
        // skip outb and outb context, is set when running in_proc

        // Set up input buffer pointer
        shared_mem.write_u64(
            self.get_input_data_size_offset(),
            self.sandbox_memory_config
                .get_input_data_size()
                .try_into()?,
        )?;
        let addr = self.get_input_data_buffer_gva();
        shared_mem.write_u64(
            self.get_input_data_pointer_offset(),
            self.get_input_data_buffer_gva(),
        )?;

        // Set up output buffer pointer
        shared_mem.write_u64(
            self.get_output_data_size_offset(),
            self.sandbox_memory_config
                .get_output_data_size()
                .try_into()?,
        )?;
        shared_mem.write_u64(
            self.get_output_data_pointer_offset(),
            self.get_output_data_buffer_gva(),
        )?;

        // Set up init data pointer
        shared_mem.write_u64(
            self.get_init_data_size_offset(),
            (self.get_unaligned_memory_size() - self.init_data_offset).try_into()?,
        )?;
        let addr = get_address!(init_data_offset);
        shared_mem.write_u64(self.get_init_data_pointer_offset(), addr)?;

        // Set up heap buffer pointer
        let addr = get_address!(guest_heap_buffer_offset);
        shared_mem.write_u64(self.get_heap_size_offset(), self.heap_size.try_into()?)?;
        shared_mem.write_u64(self.get_heap_pointer_offset(), addr)?;
        // End of setting up the PEB

        // The input and output data regions do not have their layout
        // initialised here, because they are in the scratch
        // region---they are instead set in
        // [`SandboxMemoryManager::update_scratch_bookkeeping`].

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use hyperlight_common::mem::PAGE_SIZE_USIZE;

    use super::*;

    #[test]
    fn test_round_up() {
        assert_eq!(0, round_up_to(0, 4));
        assert_eq!(4, round_up_to(1, 4));
        assert_eq!(4, round_up_to(2, 4));
        assert_eq!(4, round_up_to(3, 4));
        assert_eq!(4, round_up_to(4, 4));
        assert_eq!(8, round_up_to(5, 4));
        assert_eq!(8, round_up_to(6, 4));
        assert_eq!(8, round_up_to(7, 4));
        assert_eq!(8, round_up_to(8, 4));
        assert_eq!(PAGE_SIZE_USIZE, round_up_to(44, PAGE_SIZE_USIZE));
        assert_eq!(PAGE_SIZE_USIZE, round_up_to(4095, PAGE_SIZE_USIZE));
        assert_eq!(PAGE_SIZE_USIZE, round_up_to(4096, PAGE_SIZE_USIZE));
        assert_eq!(PAGE_SIZE_USIZE * 2, round_up_to(4097, PAGE_SIZE_USIZE));
        assert_eq!(PAGE_SIZE_USIZE * 2, round_up_to(8191, PAGE_SIZE_USIZE));
    }

    // helper func for testing
    fn get_expected_memory_size(layout: &SandboxMemoryLayout) -> usize {
        let cfg = layout.sandbox_memory_config;
        let mut expected_size = 0;
        // in order of layout
        expected_size += layout.code_size;

        expected_size += round_up_to(size_of::<HyperlightPEB>(), PAGE_SIZE_USIZE);

        expected_size += round_up_to(layout.heap_size, PAGE_SIZE_USIZE);

        expected_size
    }

    #[test]
    fn test_get_memory_size() {
        let sbox_cfg = SandboxConfiguration::default();
        let sbox_mem_layout =
            SandboxMemoryLayout::new(sbox_cfg, 4096, 4096, 0x12000, 0, None).unwrap();
        assert_eq!(
            sbox_mem_layout.get_memory_size().unwrap(),
            get_expected_memory_size(&sbox_mem_layout)
        );
    }
}
