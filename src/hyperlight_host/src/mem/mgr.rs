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

use std::cmp::Ordering;

use hyperlight_common::flatbuffer_wrappers::function_call::{
    FunctionCall, validate_guest_function_call_buffer,
};
use hyperlight_common::flatbuffer_wrappers::function_types::ReturnValue;
use hyperlight_common::flatbuffer_wrappers::guest_error::GuestError;
use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
use hyperlight_common::flatbuffer_wrappers::host_function_details::HostFunctionDetails;
use tracing::{Span, instrument};

use super::exe::ExeInfo;
use super::layout::SandboxMemoryLayout;
use super::memory_region::MemoryRegion;
#[cfg(feature = "init-paging")]
use super::memory_region::{DEFAULT_GUEST_BLOB_MEM_FLAGS, MemoryRegionType};
use super::ptr::{GuestPtr, RawPtr};
use super::ptr_offset::Offset;
use super::shared_mem::{ExclusiveSharedMemory, GuestSharedMemory, HostSharedMemory, SharedMemory};
use super::shared_mem_snapshot::SharedMemorySnapshot;
use crate::sandbox::SandboxConfiguration;
use crate::sandbox::uninitialized::GuestBlob;
use crate::{Result, log_then_return, new_error};

cfg_if::cfg_if! {
    if #[cfg(feature = "init-paging")] {
        /// Paging Flags
        ///
        /// See the following links explaining paging, also see paging-development-notes.md in docs:
        ///
        /// * Very basic description: https://stackoverflow.com/a/26945892
        /// * More in-depth descriptions: https://wiki.osdev.org/Paging
        pub(crate) const PAGE_PRESENT: u64 = 1; // Page is Present
        pub(crate) const PAGE_RW: u64 = 1 << 1; // Page is Read/Write (if not set page is read only so long as the WP bit in CR0 is set to 1 - which it is in Hyperlight)
        pub(crate) const PAGE_USER: u64 = 1 << 2; // User/Supervisor (if this bit is set then the page is accessible by user mode code)
        pub(crate) const PAGE_NX: u64 = 1 << 63; // Execute Disable (if this bit is set then data in the page cannot be executed)`
        // The amount of memory that can be mapped per page table
        pub(super) const AMOUNT_OF_MEMORY_PER_PT: usize = 0x200_000;
    }
}

/// Read/write permissions flag for the 64-bit PDE
/// The page size for the 64-bit PDE
/// The size of stack guard cookies
pub(crate) const STACK_COOKIE_LEN: usize = 16;

/// A struct that is responsible for laying out and managing the memory
/// for a given `Sandbox`.
#[derive(Clone)]
pub(crate) struct SandboxMemoryManager<S> {
    /// Shared memory for the Sandbox
    pub(crate) shared_mem: S,
    /// The memory layout of the underlying shared memory
    pub(crate) layout: SandboxMemoryLayout,
    /// Pointer to where to load memory from
    pub(crate) load_addr: RawPtr,
    /// Offset for the execution entrypoint from `load_addr`
    pub(crate) entrypoint_offset: Offset,
    /// How many memory regions were mapped after sandbox creation
    pub(crate) mapped_rgns: u64,
}

impl<S> SandboxMemoryManager<S>
where
    S: SharedMemory,
{
    /// Create a new `SandboxMemoryManager` with the given parameters
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn new(
        layout: SandboxMemoryLayout,
        shared_mem: S,
        load_addr: RawPtr,
        entrypoint_offset: Offset,
    ) -> Self {
        Self {
            layout,
            shared_mem,
            load_addr,
            entrypoint_offset,
            mapped_rgns: 0,
        }
    }

    /// Get `SharedMemory` in `self` as a mutable reference
    pub(crate) fn get_shared_mem_mut(&mut self) -> &mut S {
        &mut self.shared_mem
    }

    /// Set up the hypervisor partition in the given `SharedMemory` parameter
    /// `shared_mem`, with the given memory size `mem_size`
    // TODO: This should perhaps happen earlier and use an
    // ExclusiveSharedMemory from the beginning.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    #[cfg(feature = "init-paging")]
    pub(crate) fn set_up_shared_memory(
        &mut self,
        mem_size: u64,
        regions: &mut [MemoryRegion],
    ) -> Result<u64> {
        let rsp: u64 = self.layout.get_top_of_user_stack_offset() as u64
            + SandboxMemoryLayout::BASE_ADDRESS as u64
            + self.layout.stack_size as u64
            // TODO: subtracting 0x28 was a requirement for MSVC. It should no longer be
            // necessary now, but, for some reason, without this, the `multiple_parameters`
            // test from `sandbox_host_tests` fails. We should investigate this further.
            // See issue #498 for more details.
            - 0x28;

        self.shared_mem.with_exclusivity(|shared_mem| {
            // Create PDL4 table with only 1 PML4E
            shared_mem.write_u64(
                SandboxMemoryLayout::PML4_OFFSET,
                SandboxMemoryLayout::PDPT_GUEST_ADDRESS as u64 | PAGE_PRESENT | PAGE_RW,
            )?;

            // Create PDPT with only 1 PDPTE
            shared_mem.write_u64(
                SandboxMemoryLayout::PDPT_OFFSET,
                SandboxMemoryLayout::PD_GUEST_ADDRESS as u64 | PAGE_PRESENT | PAGE_RW,
            )?;

            for i in 0..512 {
                let offset = SandboxMemoryLayout::PD_OFFSET + (i * 8);
                let val_to_write: u64 = (SandboxMemoryLayout::PT_GUEST_ADDRESS as u64
                    + (i * 4096) as u64)
                    | PAGE_PRESENT
                    | PAGE_RW;
                shared_mem.write_u64(offset, val_to_write)?;
            }

            // We only need to create enough PTEs to map the amount of memory we have
            // We need one PT for every 2MB of memory that is mapped
            // We can use the memory size to calculate the number of PTs we need
            // We round up mem_size/2MB

            let mem_size = usize::try_from(mem_size)?;

            let num_pages: usize = mem_size.div_ceil(AMOUNT_OF_MEMORY_PER_PT);

            // Create num_pages PT with 512 PTEs
            // Pre-allocate buffer for all page table entries to minimize shared memory writes
            let total_ptes = num_pages * 512;
            let mut pte_buffer = vec![0u64; total_ptes]; // Pre-allocate u64 buffer directly
            let mut cached_region_idx: Option<usize> = None; // Cache for optimized region lookup
            let mut pte_index = 0;

            for p in 0..num_pages {
                for i in 0..512 {
                    // Each PTE maps a 4KB page
                    let flags = match Self::get_page_flags(p, i, regions, &mut cached_region_idx) {
                        Ok(region_type) => match region_type {
                            // TODO: We parse and load the exe according to its sections and then
                            // have the correct flags set rather than just marking the entire binary as executable
                            MemoryRegionType::Code => PAGE_PRESENT | PAGE_RW | PAGE_USER,
                            MemoryRegionType::InitData => self
                                .layout
                                .init_data_permissions
                                .map(|perm| perm.translate_flags())
                                .unwrap_or(DEFAULT_GUEST_BLOB_MEM_FLAGS.translate_flags()),
                            MemoryRegionType::Stack => PAGE_PRESENT | PAGE_RW | PAGE_USER | PAGE_NX,
                            #[cfg(feature = "executable_heap")]
                            MemoryRegionType::Heap => PAGE_PRESENT | PAGE_RW | PAGE_USER,
                            #[cfg(not(feature = "executable_heap"))]
                            MemoryRegionType::Heap => PAGE_PRESENT | PAGE_RW | PAGE_USER | PAGE_NX,
                            // The guard page is marked RW and User so that if it gets written to we can detect it in the host
                            // If/When we implement an interrupt handler for page faults in the guest then we can remove this access and handle things properly there
                            MemoryRegionType::GuardPage => {
                                PAGE_PRESENT | PAGE_RW | PAGE_USER | PAGE_NX
                            }
                            MemoryRegionType::InputData => PAGE_PRESENT | PAGE_RW | PAGE_NX,
                            MemoryRegionType::OutputData => PAGE_PRESENT | PAGE_RW | PAGE_NX,
                            MemoryRegionType::Peb => PAGE_PRESENT | PAGE_RW | PAGE_NX,
                            // Host Function Definitions are readonly in the guest
                            MemoryRegionType::HostFunctionDefinitions => PAGE_PRESENT | PAGE_NX,
                            MemoryRegionType::PageTables => PAGE_PRESENT | PAGE_RW | PAGE_NX,
                        },
                        // If there is an error then the address isn't mapped so mark it as not present
                        Err(_) => 0,
                    };
                    let val_to_write = ((p << 21) as u64 | (i << 12) as u64) | flags;
                    // Write u64 directly to buffer - more efficient than converting to bytes
                    pte_buffer[pte_index] = val_to_write.to_le();
                    pte_index += 1;
                }
            }

            // Write the entire PTE buffer to shared memory in a single operation
            // Convert u64 buffer to bytes for writing to shared memory
            let pte_bytes = unsafe {
                std::slice::from_raw_parts(pte_buffer.as_ptr() as *const u8, pte_buffer.len() * 8)
            };
            shared_mem.copy_from_slice(pte_bytes, SandboxMemoryLayout::PT_OFFSET)?;
            Ok::<(), crate::HyperlightError>(())
        })??;

        Ok(rsp)
    }

    /// Optimized page flags getter that maintains state for sequential access patterns
    #[cfg(feature = "init-paging")]
    fn get_page_flags(
        p: usize,
        i: usize,
        regions: &[MemoryRegion],
        cached_region_idx: &mut Option<usize>,
    ) -> Result<MemoryRegionType> {
        let addr = (p << 21) + (i << 12);

        // First check if we're still in the cached region
        if let Some(cached_idx) = *cached_region_idx {
            if cached_idx < regions.len() && regions[cached_idx].guest_region.contains(&addr) {
                return Ok(regions[cached_idx].region_type);
            }
        }

        // If not in cached region, try adjacent regions first (common for sequential access)
        if let Some(cached_idx) = *cached_region_idx {
            // Check next region
            if cached_idx + 1 < regions.len()
                && regions[cached_idx + 1].guest_region.contains(&addr)
            {
                *cached_region_idx = Some(cached_idx + 1);
                return Ok(regions[cached_idx + 1].region_type);
            }
        }

        // Fall back to binary search for non-sequential access
        let idx = regions.binary_search_by(|region| {
            if region.guest_region.contains(&addr) {
                std::cmp::Ordering::Equal
            } else if region.guest_region.start > addr {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Less
            }
        });

        match idx {
            Ok(index) => {
                *cached_region_idx = Some(index);
                Ok(regions[index].region_type)
            }
            Err(_) => Err(new_error!("Could not find region for address: {}", addr)),
        }
    }

    /// Create a snapshot with the given mapped regions
    pub(crate) fn snapshot(
        &mut self,
        sandbox_id: u64,
        mapped_regions: Vec<MemoryRegion>,
    ) -> Result<SharedMemorySnapshot> {
        SharedMemorySnapshot::new(&mut self.shared_mem, sandbox_id, mapped_regions)
    }

    /// This function restores a memory snapshot from a given snapshot.
    pub(crate) fn restore_snapshot(&mut self, snapshot: &SharedMemorySnapshot) -> Result<()> {
        if self.shared_mem.mem_size() != snapshot.mem_size() {
            return Err(new_error!(
                "Snapshot size does not match current memory size: {} != {}",
                self.shared_mem.raw_mem_size(),
                snapshot.mem_size()
            ));
        }
        snapshot.restore_from_snapshot(&mut self.shared_mem)?;
        Ok(())
    }
}

impl SandboxMemoryManager<ExclusiveSharedMemory> {
    /// Load the binary represented by `pe_info` into memory, ensuring
    /// all necessary relocations are made prior to completing the load
    /// operation, then create a new `SharedMemory` to store the new PE
    /// file and a `SandboxMemoryLayout` to describe the layout of that
    /// new `SharedMemory`.
    ///
    /// Returns the following:
    ///
    /// - The newly-created `SharedMemory`
    /// - The `SandboxMemoryLayout` describing that `SharedMemory`
    /// - The offset to the entrypoint.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn load_guest_binary_into_memory(
        cfg: SandboxConfiguration,
        exe_info: ExeInfo,
        guest_blob: Option<&GuestBlob>,
    ) -> Result<(Self, super::exe::LoadInfo)> {
        let guest_blob_size = guest_blob.map(|b| b.data.len()).unwrap_or(0);
        let guest_blob_mem_flags = guest_blob.map(|b| b.permissions);

        let layout = SandboxMemoryLayout::new(
            cfg,
            exe_info.loaded_size(),
            usize::try_from(cfg.get_stack_size(&exe_info))?,
            usize::try_from(cfg.get_heap_size(&exe_info))?,
            guest_blob_size,
            guest_blob_mem_flags,
        )?;
        let mut shared_mem = ExclusiveSharedMemory::new(layout.get_memory_size()?)?;

        let load_addr: RawPtr = RawPtr::try_from(layout.get_guest_code_address())?;

        let entrypoint_offset = exe_info.entrypoint();

        let offset = layout.get_code_pointer_offset();

        {
            // write the code pointer to shared memory
            let load_addr_u64: u64 = load_addr.clone().into();
            shared_mem.write_u64(offset, load_addr_u64)?;
        }

        // The load method returns a LoadInfo which can also be a different type once the
        // `unwind_guest` feature is enabled.
        #[allow(clippy::let_unit_value)]
        let load_info = exe_info.load(
            load_addr.clone().try_into()?,
            &mut shared_mem.as_mut_slice()[layout.get_guest_code_offset()..],
        )?;

        Ok((
            Self::new(layout, shared_mem, load_addr, entrypoint_offset),
            load_info,
        ))
    }

    /// Writes host function details to memory
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn write_buffer_host_function_details(&mut self, buffer: &[u8]) -> Result<()> {
        let host_function_details = HostFunctionDetails::try_from(buffer).map_err(|e| {
            new_error!(
                "write_buffer_host_function_details: failed to convert buffer to HostFunctionDetails: {}",
                e
            )
        })?;

        let host_function_call_buffer: Vec<u8> = (&host_function_details).try_into().map_err(|_| {
            new_error!(
                "write_buffer_host_function_details: failed to convert HostFunctionDetails to Vec<u8>"
            )
        })?;

        let buffer_size = {
            let size_u64 = self
                .shared_mem
                .read_u64(self.layout.get_host_function_definitions_size_offset())?;
            usize::try_from(size_u64)
        }?;

        if host_function_call_buffer.len() > buffer_size {
            log_then_return!(
                "Host Function Details buffer is too big for the host_function_definitions buffer"
            );
        }

        self.shared_mem.copy_from_slice(
            host_function_call_buffer.as_slice(),
            self.layout.host_function_definitions_buffer_offset,
        )?;
        Ok(())
    }

    /// Set the stack guard to `cookie` using `layout` to calculate
    /// its location and `shared_mem` to write it.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn set_stack_guard(&mut self, cookie: &[u8; STACK_COOKIE_LEN]) -> Result<()> {
        let stack_offset = self.layout.get_top_of_user_stack_offset();
        self.shared_mem.copy_from_slice(cookie, stack_offset)
    }

    /// Wraps ExclusiveSharedMemory::build
    pub fn build(
        self,
    ) -> (
        SandboxMemoryManager<HostSharedMemory>,
        SandboxMemoryManager<GuestSharedMemory>,
    ) {
        let (hshm, gshm) = self.shared_mem.build();
        (
            SandboxMemoryManager {
                shared_mem: hshm,
                layout: self.layout,
                load_addr: self.load_addr.clone(),
                entrypoint_offset: self.entrypoint_offset,
                mapped_rgns: 0,
            },
            SandboxMemoryManager {
                shared_mem: gshm,
                layout: self.layout,
                load_addr: self.load_addr.clone(),
                entrypoint_offset: self.entrypoint_offset,
                mapped_rgns: 0,
            },
        )
    }
}

impl SandboxMemoryManager<HostSharedMemory> {
    /// Check the stack guard of the memory in `shared_mem`, using
    /// `layout` to calculate its location.
    ///
    /// Return `true`
    /// if `shared_mem` could be accessed properly and the guard
    /// matches `cookie`. If it could be accessed properly and the
    /// guard doesn't match `cookie`, return `false`. Otherwise, return
    /// a descriptive error.
    ///
    /// This method could be an associated function instead. See
    /// documentation at the bottom `set_stack_guard` for description
    /// of why it isn't.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn check_stack_guard(&self, cookie: [u8; STACK_COOKIE_LEN]) -> Result<bool> {
        let offset = self.layout.get_top_of_user_stack_offset();
        let test_cookie: [u8; STACK_COOKIE_LEN] = self.shared_mem.read(offset)?;
        let cmp_res = cookie.iter().cmp(test_cookie.iter());
        Ok(cmp_res == Ordering::Equal)
    }

    /// Get the address of the dispatch function in memory
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_pointer_to_dispatch_function(&self) -> Result<u64> {
        let guest_dispatch_function_ptr = self
            .shared_mem
            .read::<u64>(self.layout.get_dispatch_function_pointer_offset())?;

        // This pointer is written by the guest library but is accessible to
        // the guest engine so we should bounds check it before we return it.

        let guest_ptr = GuestPtr::try_from(RawPtr::from(guest_dispatch_function_ptr))?;
        guest_ptr.absolute()
    }

    /// Reads a host function call from memory
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_host_function_call(&mut self) -> Result<FunctionCall> {
        self.shared_mem.try_pop_buffer_into::<FunctionCall>(
            self.layout.output_data_buffer_offset,
            self.layout.sandbox_memory_config.get_output_data_size(),
        )
    }

    /// Writes a function call result to memory
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn write_response_from_host_method_call(&mut self, res: &ReturnValue) -> Result<()> {
        let function_call_ret_val_buffer = Vec::<u8>::try_from(res).map_err(|_| {
            new_error!(
                "write_response_from_host_method_call: failed to convert ReturnValue to Vec<u8>"
            )
        })?;
        self.shared_mem.push_buffer(
            self.layout.input_data_buffer_offset,
            self.layout.sandbox_memory_config.get_input_data_size(),
            function_call_ret_val_buffer.as_slice(),
        )
    }

    /// Writes a guest function call to memory
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn write_guest_function_call(&mut self, buffer: &[u8]) -> Result<()> {
        validate_guest_function_call_buffer(buffer).map_err(|e| {
            new_error!(
                "Guest function call buffer validation failed: {}",
                e.to_string()
            )
        })?;

        self.shared_mem.push_buffer(
            self.layout.input_data_buffer_offset,
            self.layout.sandbox_memory_config.get_input_data_size(),
            buffer,
        )
    }

    /// Reads a function call result from memory
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_guest_function_call_result(&mut self) -> Result<ReturnValue> {
        self.shared_mem.try_pop_buffer_into::<ReturnValue>(
            self.layout.output_data_buffer_offset,
            self.layout.sandbox_memory_config.get_output_data_size(),
        )
    }

    /// Read guest log data from the `SharedMemory` contained within `self`
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn read_guest_log_data(&mut self) -> Result<GuestLogData> {
        self.shared_mem.try_pop_buffer_into::<GuestLogData>(
            self.layout.output_data_buffer_offset,
            self.layout.sandbox_memory_config.get_output_data_size(),
        )
    }

    /// Get the guest error data
    pub(crate) fn get_guest_error(&mut self) -> Result<GuestError> {
        self.shared_mem.try_pop_buffer_into::<GuestError>(
            self.layout.output_data_buffer_offset,
            self.layout.sandbox_memory_config.get_output_data_size(),
        )
    }

    pub(crate) fn clear_io_buffers(&mut self) {
        // Clear the output data buffer
        loop {
            let Ok(_) = self.shared_mem.try_pop_buffer_into::<Vec<u8>>(
                self.layout.output_data_buffer_offset,
                self.layout.sandbox_memory_config.get_output_data_size(),
            ) else {
                break;
            };
        }
        // Clear the input data buffer
        loop {
            let Ok(_) = self.shared_mem.try_pop_buffer_into::<Vec<u8>>(
                self.layout.input_data_buffer_offset,
                self.layout.sandbox_memory_config.get_input_data_size(),
            ) else {
                break;
            };
        }
    }
}
