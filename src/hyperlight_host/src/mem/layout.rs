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
//! |             Guest (User) Stack            |
//! +-------------------------------------------+
//! |             Guard Page (4KiB)             |
//! +-------------------------------------------+
//! |             Guest Heap                    |
//! +-------------------------------------------+
//! |             Output Data                   |
//! +-------------------------------------------+
//! |              Input Data                   |
//! +-------------------------------------------+
//! |        Host Function Definitions          |
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
//! 0xffff_0000_0000_0000.
//!
//! - `InitData` - some extra data that can be loaded onto the sandbox during
//!   initialization.
//!
//! - `HostDefinitions` - the length of this is the `HostFunctionDefinitionSize`
//!   field from `SandboxConfiguration`
//!
//! - `InputData` -  this is a buffer that is used for input data to the host program.
//!   the length of this field is `InputDataSize` from `SandboxConfiguration`
//!
//! - `OutputData` - this is a buffer that is used for output data from host program.
//!   the length of this field is `OutputDataSize` from `SandboxConfiguration`
//!
//! - `GuestHeap` - this is a buffer that is used for heap data in the guest. the length
//!   of this field is returned by the `heap_size()` method of this struct
//!
//! - `GuestStack` - this is a buffer that is used for stack data in the guest. the length
//!   of this field is returned by the `stack_size()` method of this struct. in reality,
//!   the stack might be slightly bigger or smaller than this value since total memory
//!   size is rounded up to the nearest 4K, and there is a 16-byte stack guard written
//!   to the top of the stack. (see below for more details

use std::fmt::Debug;
use std::mem::{offset_of, size_of};

use hyperlight_common::mem::{GuestMemoryRegion, HyperlightPEB, PAGE_SIZE_USIZE};
use hyperlight_common::time::GuestClockRegion;
use rand::{RngCore, rng};
use tracing::{Span, instrument};

#[cfg(feature = "init-paging")]
use super::memory_region::MemoryRegionType::PageTables;
use super::memory_region::MemoryRegionType::{
    ClockPage, Code, GuardPage, Heap, HostFunctionDefinitions, InitData, InputData, OutputData,
    Peb, Stack,
};
use super::memory_region::{
    DEFAULT_GUEST_BLOB_MEM_FLAGS, MemoryRegion, MemoryRegion_, MemoryRegionFlags, MemoryRegionKind,
    MemoryRegionVecBuilder,
};
use super::shared_mem::{ExclusiveSharedMemory, GuestSharedMemory, SharedMemory};
use crate::error::HyperlightError::{GuestOffsetIsInvalid, MemoryRequestTooBig};
use crate::sandbox::SandboxConfiguration;
use crate::{Result, new_error};

#[derive(Copy, Clone)]
pub(crate) struct SandboxMemoryLayout {
    pub(super) sandbox_memory_config: SandboxConfiguration,
    /// The total stack size of this sandbox.
    pub(super) stack_size: usize,
    /// The heap size of this sandbox.
    pub(super) heap_size: usize,
    init_data_size: usize,

    /// The following fields are offsets to the actual PEB struct fields.
    /// They are used when writing the PEB struct itself
    peb_offset: usize,
    peb_security_cookie_seed_offset: usize,
    peb_guest_dispatch_function_ptr_offset: usize, // set by guest in guest entrypoint
    pub(super) peb_host_function_definitions_offset: usize,
    peb_input_data_offset: usize,
    peb_output_data_offset: usize,
    peb_init_data_offset: usize,
    peb_heap_data_offset: usize,
    peb_guest_stack_data_offset: usize,
    peb_guest_clock_offset: usize,

    // The following are the actual values
    // that are written to the PEB struct
    pub(crate) host_function_definitions_buffer_offset: usize,
    pub(super) input_data_buffer_offset: usize,
    pub(super) output_data_buffer_offset: usize,
    /// Offset to the clock page (4KB page for pvclock/Reference TSC)
    pub(crate) clock_page_offset: usize,
    guest_heap_buffer_offset: usize,
    guard_page_offset: usize,
    guest_user_stack_buffer_offset: usize, // the lowest address of the user stack
    init_data_offset: usize,
    pt_offset: usize,
    pt_size: Option<usize>,

    // other
    pub(crate) peb_address: usize,
    code_size: usize,
    // The offset in the sandbox memory where the code starts
    guest_code_offset: usize,
    pub(crate) init_data_permissions: Option<MemoryRegionFlags>,
}

impl Debug for SandboxMemoryLayout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxMemoryLayout")
            .field(
                "Total Memory Size",
                &format_args!("{:#x}", self.get_memory_size().unwrap_or(0)),
            )
            .field("Stack Size", &format_args!("{:#x}", self.stack_size))
            .field("Heap Size", &format_args!("{:#x}", self.heap_size))
            .field(
                "Init Data Size",
                &format_args!("{:#x}", self.init_data_size),
            )
            .field("PEB Address", &format_args!("{:#x}", self.peb_address))
            .field("PEB Offset", &format_args!("{:#x}", self.peb_offset))
            .field("Code Size", &format_args!("{:#x}", self.code_size))
            .field(
                "Security Cookie Seed Offset",
                &format_args!("{:#x}", self.peb_security_cookie_seed_offset),
            )
            .field(
                "Guest Dispatch Function Pointer Offset",
                &format_args!("{:#x}", self.peb_guest_dispatch_function_ptr_offset),
            )
            .field(
                "Host Function Definitions Offset",
                &format_args!("{:#x}", self.peb_host_function_definitions_offset),
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
                "Guest Stack Offset",
                &format_args!("{:#x}", self.peb_guest_stack_data_offset),
            )
            .field(
                "Guest Clock Offset",
                &format_args!("{:#x}", self.peb_guest_clock_offset),
            )
            .field(
                "Host Function Definitions Buffer Offset",
                &format_args!("{:#x}", self.host_function_definitions_buffer_offset),
            )
            .field(
                "Input Data Buffer Offset",
                &format_args!("{:#x}", self.input_data_buffer_offset),
            )
            .field(
                "Output Data Buffer Offset",
                &format_args!("{:#x}", self.output_data_buffer_offset),
            )
            .field(
                "Clock Page Offset",
                &format_args!("{:#x}", self.clock_page_offset),
            )
            .field(
                "Guest Heap Buffer Offset",
                &format_args!("{:#x}", self.guest_heap_buffer_offset),
            )
            .field(
                "Guard Page Offset",
                &format_args!("{:#x}", self.guard_page_offset),
            )
            .field(
                "Guest User Stack Buffer Offset",
                &format_args!("{:#x}", self.guest_user_stack_buffer_offset),
            )
            .field(
                "Init Data Offset",
                &format_args!("{:#x}", self.init_data_offset),
            )
            .field("PT Offset", &format_args!("{:#x}", self.pt_offset))
            .field("PT Size", &format_args!("{:#x}", self.pt_size.unwrap_or(0)))
            .field(
                "Guest Code Offset",
                &format_args!("{:#x}", self.guest_code_offset),
            )
            .finish()
    }
}

impl SandboxMemoryLayout {
    /// The maximum amount of memory a single sandbox will be allowed.
    /// The addressable virtual memory with current paging setup is virtual address 0x0 - 0x40000000 (excl.),
    /// However, the memory up to Self::BASE_ADDRESS is not used.
    const MAX_MEMORY_SIZE: usize = 0x40000000 - Self::BASE_ADDRESS;

    /// The base address of the sandbox's memory.
    #[cfg(feature = "init-paging")]
    pub(crate) const BASE_ADDRESS: usize = 0x1000;
    #[cfg(not(feature = "init-paging"))]
    pub(crate) const BASE_ADDRESS: usize = 0x0;

    // the offset into a sandbox's input/output buffer where the stack starts
    const STACK_POINTER_SIZE_BYTES: u64 = 8;

    /// Create a new `SandboxMemoryLayout` with the given
    /// `SandboxConfiguration`, code size and stack/heap size.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn new(
        cfg: SandboxConfiguration,
        code_size: usize,
        stack_size: usize,
        heap_size: usize,
        init_data_size: usize,
        init_data_permissions: Option<MemoryRegionFlags>,
    ) -> Result<Self> {
        let guest_code_offset = 0;
        // The following offsets are to the fields of the PEB struct itself!
        let peb_offset = round_up_to(code_size, PAGE_SIZE_USIZE);
        let peb_security_cookie_seed_offset =
            peb_offset + offset_of!(HyperlightPEB, security_cookie_seed);
        let peb_guest_dispatch_function_ptr_offset =
            peb_offset + offset_of!(HyperlightPEB, guest_function_dispatch_ptr);
        let peb_input_data_offset = peb_offset + offset_of!(HyperlightPEB, input_stack);
        let peb_output_data_offset = peb_offset + offset_of!(HyperlightPEB, output_stack);
        let peb_init_data_offset = peb_offset + offset_of!(HyperlightPEB, init_data);
        let peb_heap_data_offset = peb_offset + offset_of!(HyperlightPEB, guest_heap);
        let peb_guest_stack_data_offset = peb_offset + offset_of!(HyperlightPEB, guest_stack);
        let peb_guest_clock_offset = peb_offset + offset_of!(HyperlightPEB, guest_clock);
        let peb_host_function_definitions_offset =
            peb_offset + offset_of!(HyperlightPEB, host_function_definitions);

        // The following offsets are the actual values that relate to memory layout,
        // which are written to PEB struct
        let peb_address = Self::BASE_ADDRESS + peb_offset;
        // make sure host function definitions buffer starts at 4K boundary
        let host_function_definitions_buffer_offset = round_up_to(
            peb_host_function_definitions_offset + size_of::<GuestMemoryRegion>(),
            PAGE_SIZE_USIZE,
        );
        let input_data_buffer_offset = round_up_to(
            host_function_definitions_buffer_offset + cfg.get_host_function_definition_size(),
            PAGE_SIZE_USIZE,
        );
        let output_data_buffer_offset = round_up_to(
            input_data_buffer_offset + cfg.get_input_data_size(),
            PAGE_SIZE_USIZE,
        );
        // Clock page for pvclock/Reference TSC - needs to be page-aligned
        let clock_page_offset = round_up_to(
            output_data_buffer_offset + cfg.get_output_data_size(),
            PAGE_SIZE_USIZE,
        );
        // make sure heap buffer starts at 4K boundary (after clock page)
        let guest_heap_buffer_offset = clock_page_offset + PAGE_SIZE_USIZE;
        // make sure guard page starts at 4K boundary
        let guard_page_offset = round_up_to(guest_heap_buffer_offset + heap_size, PAGE_SIZE_USIZE);
        let guest_user_stack_buffer_offset = guard_page_offset + PAGE_SIZE_USIZE;
        // round up stack size to page size. This is needed for MemoryRegion
        let stack_size_rounded = round_up_to(stack_size, PAGE_SIZE_USIZE);
        let init_data_offset = guest_user_stack_buffer_offset + stack_size_rounded;
        let pt_offset = round_up_to(init_data_offset + init_data_size, PAGE_SIZE_USIZE);

        Ok(Self {
            peb_offset,
            stack_size: stack_size_rounded,
            heap_size,
            peb_security_cookie_seed_offset,
            peb_guest_dispatch_function_ptr_offset,
            peb_host_function_definitions_offset,
            peb_input_data_offset,
            peb_output_data_offset,
            peb_init_data_offset,
            peb_heap_data_offset,
            peb_guest_stack_data_offset,
            peb_guest_clock_offset,
            sandbox_memory_config: cfg,
            code_size,
            host_function_definitions_buffer_offset,
            input_data_buffer_offset,
            output_data_buffer_offset,
            clock_page_offset,
            guest_heap_buffer_offset,
            guest_user_stack_buffer_offset,
            peb_address,
            guard_page_offset,
            guest_code_offset,
            init_data_offset,
            init_data_size,
            init_data_permissions,
            pt_offset,
            pt_size: None,
        })
    }

    /// Get the offset in guest memory to the output data size
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_output_data_size_offset(&self) -> usize {
        // The size field is the first field in the `OutputData` struct
        self.peb_output_data_offset
    }

    /// Get the offset in guest memory to the host function definitions
    /// size
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_host_function_definitions_size_offset(&self) -> usize {
        // The size field is the first field in the `HostFunctions` struct
        self.peb_host_function_definitions_offset
    }

    /// Get the offset in guest memory to the host function definitions
    /// pointer.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_host_function_definitions_pointer_offset(&self) -> usize {
        // The size field is the field after the size field in the `HostFunctions` struct which is a u64
        self.peb_host_function_definitions_offset + size_of::<u64>()
    }

    /// Get the offset in guest memory to the init data size
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_init_data_size_offset(&self) -> usize {
        // The init data size is the first field in the `GuestMemoryRegion` struct
        self.peb_init_data_offset
    }

    /// Get the offset in guest memory to the minimum guest stack address.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_min_guest_stack_address_offset(&self) -> usize {
        // The minimum guest user stack address is the start of the guest stack
        self.peb_guest_stack_data_offset
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_guest_stack_size(&self) -> usize {
        self.stack_size
    }

    /// Get the offset in guest memory to the guest clock region.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_guest_clock_offset(&self) -> usize {
        self.peb_guest_clock_offset
    }

    /// Get the offset in guest memory to the clock page.
    /// This is a 4KB page used for pvclock/Reference TSC data.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_clock_page_offset(&self) -> usize {
        self.clock_page_offset
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

    /// Get the offset in guest memory to the start of output data.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    #[cfg(test)]
    pub(crate) fn get_output_data_offset(&self) -> usize {
        self.output_data_buffer_offset
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

    /// Get the offset to the top of the stack in guest memory
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    #[cfg(feature = "init-paging")]
    pub(crate) fn get_top_of_user_stack_offset(&self) -> usize {
        self.guest_user_stack_buffer_offset
    }

    /// Get the offset of the user stack pointer in guest memory,
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_user_stack_pointer_offset(&self) -> usize {
        // The userStackAddress is immediately after the
        // minUserStackAddress (top of user stack) field in the `GuestStackData` struct which is a `u64`.
        self.get_min_guest_stack_address_offset() + size_of::<u64>()
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

    /// Sets the size of the memory region used for page tables
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    #[cfg(feature = "init-paging")]
    pub(crate) fn set_pt_size(&mut self, size: usize) {
        self.pt_size = Some(size);
    }

    /// Get the offset into the snapshot region of the guest user stack
    /// pointer, to be used when entering the guest
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    #[cfg(feature = "init-paging")]
    pub(crate) fn get_rsp_offset(&self) -> usize {
        self.get_top_of_user_stack_offset() + self.stack_size - 0x28
    }

    pub fn get_memory_regions(&self, shared_mem: &GuestSharedMemory) -> Result<Vec<MemoryRegion>> {
        self.get_memory_regions_(shared_mem.base_addr())
    }

    /// Returns the memory regions associated with this memory layout,
    /// suitable for passing to a hypervisor for mapping into memory
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

        // PEB
        let host_functions_definitions_offset = builder.push_page_aligned(
            size_of::<HyperlightPEB>(),
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
            Peb,
        );

        let expected_host_functions_definitions_offset =
            TryInto::<usize>::try_into(self.host_function_definitions_buffer_offset)?;

        if host_functions_definitions_offset != expected_host_functions_definitions_offset {
            return Err(new_error!(
                "Host Function Definitions offset does not match expected Host Function Definitions offset expected:  {}, actual:  {}",
                expected_host_functions_definitions_offset,
                host_functions_definitions_offset
            ));
        }

        // host function definitions
        let input_data_offset = builder.push_page_aligned(
            self.sandbox_memory_config
                .get_host_function_definition_size(),
            MemoryRegionFlags::READ,
            HostFunctionDefinitions,
        );

        let expected_input_data_offset = TryInto::<usize>::try_into(self.input_data_buffer_offset)?;

        if input_data_offset != expected_input_data_offset {
            return Err(new_error!(
                "Input Data offset does not match expected Input Data offset expected:  {}, actual:  {}",
                expected_input_data_offset,
                input_data_offset
            ));
        }

        // guest input data
        let output_data_offset = builder.push_page_aligned(
            self.sandbox_memory_config.get_input_data_size(),
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
            InputData,
        );

        let expected_output_data_offset =
            TryInto::<usize>::try_into(self.output_data_buffer_offset)?;

        if output_data_offset != expected_output_data_offset {
            return Err(new_error!(
                "Output Data offset does not match expected Output Data offset expected:  {}, actual:  {}",
                expected_output_data_offset,
                output_data_offset
            ));
        }

        // guest output data
        let clock_page_offset = builder.push_page_aligned(
            self.sandbox_memory_config.get_output_data_size(),
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
            OutputData,
        );

        let expected_clock_page_offset = TryInto::<usize>::try_into(self.clock_page_offset)?;

        if clock_page_offset != expected_clock_page_offset {
            return Err(new_error!(
                "Clock Page offset does not match expected Clock Page offset expected:  {}, actual:  {}",
                expected_clock_page_offset,
                clock_page_offset
            ));
        }

        // clock page for pvclock/Reference TSC
        let heap_offset = builder.push_page_aligned(
            PAGE_SIZE_USIZE,
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
            ClockPage,
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
        let guard_page_offset = builder.push_page_aligned(
            self.heap_size,
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE | MemoryRegionFlags::EXECUTE,
            Heap,
        );
        #[cfg(not(feature = "executable_heap"))]
        let guard_page_offset = builder.push_page_aligned(
            self.heap_size,
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
            Heap,
        );

        let expected_guard_page_offset = TryInto::<usize>::try_into(self.guard_page_offset)?;

        if guard_page_offset != expected_guard_page_offset {
            return Err(new_error!(
                "Guard Page offset does not match expected Guard Page offset expected:  {}, actual:  {}",
                expected_guard_page_offset,
                guard_page_offset
            ));
        }

        // guard page
        let stack_offset = builder.push_page_aligned(
            PAGE_SIZE_USIZE,
            MemoryRegionFlags::READ | MemoryRegionFlags::STACK_GUARD,
            GuardPage,
        );

        let expected_stack_offset =
            TryInto::<usize>::try_into(self.guest_user_stack_buffer_offset)?;

        if stack_offset != expected_stack_offset {
            return Err(new_error!(
                "Stack offset does not match expected Stack offset expected:  {}, actual:  {}",
                expected_stack_offset,
                stack_offset
            ));
        }

        // stack
        let init_data_offset = builder.push_page_aligned(
            self.get_guest_stack_size(),
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
            Stack,
        );

        let expected_init_data_offset = TryInto::<usize>::try_into(self.init_data_offset)?;

        if init_data_offset != expected_init_data_offset {
            return Err(new_error!(
                "Init Data offset does not match expected Init Data offset expected:  {}, actual:  {}",
                expected_init_data_offset,
                init_data_offset
            ));
        }

        let after_init_offset = if self.init_data_size > 0 {
            let mem_flags = self
                .init_data_permissions
                .unwrap_or(DEFAULT_GUEST_BLOB_MEM_FLAGS);
            builder.push_page_aligned(self.init_data_size, mem_flags, InitData)
        } else {
            init_data_offset
        };

        #[cfg(feature = "init-paging")]
        let final_offset = {
            let expected_pt_offset = TryInto::<usize>::try_into(self.pt_offset)?;

            if after_init_offset != expected_pt_offset {
                return Err(new_error!(
                    "Page table offset does not match expected:  {}, actual:  {}",
                    expected_pt_offset,
                    after_init_offset
                ));
            }

            if let Some(pt_size) = self.pt_size {
                builder.push_page_aligned(
                    pt_size,
                    MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
                    PageTables,
                )
            } else {
                after_init_offset
            }
        };

        #[cfg(not(feature = "init-paging"))]
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
        //TODO: Unused remove
        _size: usize,
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

        // Set up the security cookie seed
        let mut security_cookie_seed = [0u8; 8];
        rng().fill_bytes(&mut security_cookie_seed);
        shared_mem.copy_from_slice(&security_cookie_seed, self.peb_security_cookie_seed_offset)?;

        // Skip guest_dispatch_function_ptr_offset because it is set by the guest

        // Set up Host Function Definition
        shared_mem.write_u64(
            self.get_host_function_definitions_size_offset(),
            self.sandbox_memory_config
                .get_host_function_definition_size()
                .try_into()?,
        )?;
        let addr = get_address!(host_function_definitions_buffer_offset);
        shared_mem.write_u64(self.get_host_function_definitions_pointer_offset(), addr)?;

        // Skip code, is set when loading binary
        // skip outb and outb context, is set when running in_proc

        // Set up input buffer pointer
        shared_mem.write_u64(
            self.get_input_data_size_offset(),
            self.sandbox_memory_config
                .get_input_data_size()
                .try_into()?,
        )?;
        let addr = get_address!(input_data_buffer_offset);
        shared_mem.write_u64(self.get_input_data_pointer_offset(), addr)?;

        // Set up output buffer pointer
        shared_mem.write_u64(
            self.get_output_data_size_offset(),
            self.sandbox_memory_config
                .get_output_data_size()
                .try_into()?,
        )?;
        let addr = get_address!(output_data_buffer_offset);
        shared_mem.write_u64(self.get_output_data_pointer_offset(), addr)?;

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

        // Set up user stack pointers

        // Bottom of user stack

        shared_mem.write_u64(
            self.get_min_guest_stack_address_offset(),
            get_address!(guest_user_stack_buffer_offset),
        )?;

        // Start of user stack

        let start_of_user_stack: u64 =
            get_address!(guest_user_stack_buffer_offset) + self.stack_size as u64;

        shared_mem.write_u64(self.get_user_stack_pointer_offset(), start_of_user_stack)?;

        // Initialize guest clock region with default values (no clock configured yet)
        // GuestClockRegion is 32 bytes: clock_page_ptr (8) + clock_type (8) + boot_time_ns (8) + utc_offset_seconds (4) + padding (4)
        // The actual clock configuration is done by the hypervisor-specific code
        let guest_clock_bytes = [0u8; size_of::<GuestClockRegion>()];
        shared_mem.copy_from_slice(&guest_clock_bytes, self.get_guest_clock_offset())?;

        // End of setting up the PEB

        // Initialize the stack pointers of input data and output data
        // to point to the ninth (index 8) byte, which is the first free address
        // of the each respective stack. The first 8 bytes are the stack pointer itself.
        shared_mem.write_u64(
            self.input_data_buffer_offset,
            Self::STACK_POINTER_SIZE_BYTES,
        )?;
        shared_mem.write_u64(
            self.output_data_buffer_offset,
            Self::STACK_POINTER_SIZE_BYTES,
        )?;

        Ok(())
    }
}

fn round_up_to(value: usize, multiple: usize) -> usize {
    (value + multiple - 1) & !(multiple - 1)
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

        expected_size += round_up_to(cfg.get_host_function_definition_size(), PAGE_SIZE_USIZE);

        expected_size += round_up_to(cfg.get_input_data_size(), PAGE_SIZE_USIZE);

        expected_size += round_up_to(cfg.get_output_data_size(), PAGE_SIZE_USIZE);

        expected_size += PAGE_SIZE_USIZE; // clock page

        expected_size += round_up_to(layout.heap_size, PAGE_SIZE_USIZE);

        expected_size += PAGE_SIZE_USIZE; // guard page

        expected_size += round_up_to(layout.stack_size, PAGE_SIZE_USIZE);

        expected_size
    }

    #[test]
    fn test_get_memory_size() {
        let sbox_cfg = SandboxConfiguration::default();
        let sbox_mem_layout =
            SandboxMemoryLayout::new(sbox_cfg, 4096, 2048, 4096, 0, None).unwrap();
        assert_eq!(
            sbox_mem_layout.get_memory_size().unwrap(),
            get_expected_memory_size(&sbox_mem_layout)
        );
    }
}
