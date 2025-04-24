/*
Copyright 2024 The Hyperlight Authors.

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
use std::sync::{Arc, Mutex};

use hyperlight_common::flatbuffer_wrappers::function_call::{
    validate_guest_function_call_buffer, FunctionCall,
};
use hyperlight_common::flatbuffer_wrappers::function_types::ReturnValue;
use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
use tracing::{instrument, Span};

#[cfg(target_os = "windows")]
use super::loaded_lib::LoadedLib;
use super::ptr::RawPtr;
use super::ptr_offset::Offset;
use super::shared_mem::{ExclusiveSharedMemory, GuestSharedMemory, HostSharedMemory, SharedMemory};
use super::shared_mem_snapshot::SharedMemorySnapshot;
use crate::sandbox::sandbox_builder::{
    MemoryRegionFlags, SandboxMemorySections, BASE_ADDRESS, PDPT_OFFSET, PD_OFFSET, PT_OFFSET,
};
use crate::HyperlightError::NoMemorySnapshot;
use crate::{log_then_return, new_error, HyperlightError, Result};

/// Paging Flags
///
/// See the following links explaining paging, also see paging-development-notes.md in docs:
///
/// * Very basic description: https://stackoverflow.com/a/26945892
/// * More in-depth descriptions: https://wiki.osdev.org/Paging
const PAGE_PRESENT: u64 = 1; // Page is Present
const PAGE_RW: u64 = 1 << 1; // Page is Read/Write (if not set page is read only so long as the WP bit in CR0 is set to 1 - which it is in Hyperlight)
const PAGE_USER: u64 = 1 << 2; // User/Supervisor (if this bit is set then the page is accessible by user mode code)
const PAGE_NX: u64 = 1 << 63; // Execute Disable (if this bit is set then data in the page cannot be executed)

// The amount of memory that can be mapped per page table
pub(crate) const AMOUNT_OF_MEMORY_PER_PT: usize = 0x200_000;
pub(crate) const STACK_COOKIE_LEN: usize = 16;

/// SandboxMemoryManager is a struct that pairs a `SharedMemory` and a `SandboxMemorySections` and
/// allows you to snapshot and restore memory states.
#[derive(Clone)]
pub(crate) struct SandboxMemoryManager<S> {
    /// Shared memory for the Sandbox.
    ///
    /// This field is generic because S can be:
    /// - `ExclusiveSharedMemory`,
    /// - `HostSharedMemory`, or
    /// - `GuestSharedMemory`.
    pub(crate) shared_mem: S,

    /// Pointer to where to load memory from
    ///
    /// In in-process mode, this is the direct host memory address.
    /// When running in a VM, this is the base address of the VM (0x0).
    pub(crate) load_addr: RawPtr,

    /// Offset for the execution entrypoint from `load_addr`.
    ///
    /// This is obtained from the guest binary.
    pub(crate) entrypoint_offset: Offset,

    /// Memory sections
    pub(crate) memory_sections: SandboxMemorySections,

    /// Initial RSP value
    pub(crate) init_rsp: u64,

    /// A vector of memory snapshots that can be used to save and restore the state of the memory.
    snapshots: Arc<Mutex<Vec<SharedMemorySnapshot>>>,

    /// Stack guard for the memory
    pub(crate) stack_guard: [u8; STACK_COOKIE_LEN],

    /// This field must be present, even though it's not read,
    /// so that its underlying resources are properly dropped at
    /// the right time.
    #[cfg(target_os = "windows")]
    _lib: Option<LoadedLib>,
}

/// General implementations for setting up the `SandboxMemoryManager` and its underlying
/// memory.
impl<S> SandboxMemoryManager<S>
where
    S: SharedMemory,
{
    /// Create a new `SandboxMemoryManager`
    pub(crate) fn new(
        shared_mem: S,
        load_addr: RawPtr,
        entrypoint_offset: Offset,
        memory_sections: SandboxMemorySections,
        init_rsp: u64,
        #[cfg(target_os = "windows")] lib: Option<LoadedLib>,
    ) -> Self {
        Self {
            shared_mem,
            load_addr,
            entrypoint_offset,
            memory_sections,
            snapshots: Arc::new(Mutex::new(Vec::new())),
            stack_guard: Self::create_stack_guard(),
            init_rsp,
            #[cfg(target_os = "windows")]
            _lib: lib,
        }
    }

    /// Set up the hypervisor partition in the given shared memory, with the given memory size.
    // TODO: This should perhaps happen earlier and use an
    // ExclusiveSharedMemory from the beginning.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn set_up_shared_memory(&mut self) -> Result<()> {
        let memory_size = self.memory_sections.get_total_size();
        let memory_sections = self.memory_sections.clone();

        self.shared_mem.with_exclusivity(|shared_mem| {
            let pml4_offset = self
                .memory_sections
                .get_paging_structures_offset()
                .ok_or("PML4 offset not found")?;
            let pdpt_offset = pml4_offset + PDPT_OFFSET;
            let pd_offset = pml4_offset + PD_OFFSET;
            let pt_offset = pml4_offset + PT_OFFSET;

            // Create PML4 table with only 1 PML4E
            shared_mem.write_u64(pml4_offset, pdpt_offset as u64 | PAGE_PRESENT | PAGE_RW)?;

            // Create PDPT with only 1 PDPTE
            shared_mem.write_u64(pdpt_offset, pd_offset as u64 | PAGE_PRESENT | PAGE_RW)?;

            for i in 0..512 {
                let offset = pd_offset + (i * 8);

                let val_to_write: u64 =
                    (pt_offset as u64 + (i * 4096) as u64) | PAGE_PRESENT | PAGE_RW;
                shared_mem.write_u64(offset, val_to_write)?;
            }

            // - We only need to create enough PTEs to map the amount of memory we have.
            // - We need one PT for every 2MB of memory that is mapped.
            // - We can use the memory size to calculate the number of PTs we need.
            // - We round up mem_size/2MB.

            let num_pages: usize =
                ((memory_size + AMOUNT_OF_MEMORY_PER_PT - 1) / AMOUNT_OF_MEMORY_PER_PT) + 1;

            // Create num_pages PT with 512 PTEs
            for p in 0..num_pages {
                for i in 0..512 {
                    let offset = pt_offset + (p * 4096) + (i * 8);

                    // Each PTE maps a 4KB page
                    let val_to_write = ((p << 21) as u64 | (i << 12) as u64)
                        | Self::get_page_flags(p, i, &memory_sections);
                    shared_mem.write_u64(offset, val_to_write)?;
                }
            }
            Ok::<(), HyperlightError>(())
        })??;

        Ok(())
    }

    /// Check if we are running in-process or not
    pub(crate) fn is_in_process(&self) -> bool {
        // We can recognize if we are in process by checking if the load address
        // is the same as the base address of the memory layout.
        self.load_addr != RawPtr::from(BASE_ADDRESS as u64)
    }

    fn get_page_flags(p: usize, i: usize, sandbox_memory_sections: &SandboxMemorySections) -> u64 {
        let addr = (p << 21) + (i << 12);

        // Find the memory section that contains this address
        match sandbox_memory_sections.sections.range(..=addr).next_back() {
            Some((_, section))
                if (section.page_aligned_guest_offset
                    ..(section.page_aligned_guest_offset + section.page_aligned_size))
                    .contains(&addr) =>
            {
                Self::translate_flags(section.flags)
            }
            _ => 0, // If no section matches, default to not present
        }
    }

    // Translates MemoryRegionFlags into x86-style page flags
    fn translate_flags(flags: MemoryRegionFlags) -> u64 {
        let mut page_flags = 0;

        if flags.contains(MemoryRegionFlags::READ) {
            page_flags |= PAGE_PRESENT; // Mark page as present
        }

        if flags.contains(MemoryRegionFlags::WRITE) {
            page_flags |= PAGE_RW; // Allow read/write
        }

        if flags.contains(MemoryRegionFlags::STACK_GUARD) {
            page_flags |= PAGE_RW; // The guard page is marked RW so that if it gets written to we can detect it in the host
        }

        if flags.contains(MemoryRegionFlags::EXECUTE) {
            page_flags |= PAGE_USER; // Allow user access
        } else {
            page_flags |= PAGE_NX; // Mark as non-executable if EXECUTE is not set
        }

        page_flags
    }
}

/// Implementations for managing memory snapshots
impl<S> SandboxMemoryManager<S>
where
    S: SharedMemory,
{
    /// Create a memory snapshot and push it onto the stack of snapshots.
    ///
    /// It should be used when you want to save the state of the memory—for example, when evolving a
    /// sandbox to a new state.
    pub(crate) fn push_state(&mut self) -> Result<()> {
        let snapshot = SharedMemorySnapshot::new(&mut self.shared_mem)?;
        self.snapshots
            .try_lock()
            .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
            .push(snapshot);
        Ok(())
    }

    /// Restores a memory snapshot from the last snapshot in the list but does not pop the snapshot
    /// off the stack.
    ///
    /// It should be used when you want to restore the state of the memory to a previous state but
    /// still want to retain that state, for example after calling a function in the guest.
    pub(crate) fn restore_state_from_last_snapshot(&mut self) -> Result<()> {
        let mut snapshots = self
            .snapshots
            .try_lock()
            .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?;
        let last = snapshots.last_mut();
        if last.is_none() {
            log_then_return!(NoMemorySnapshot);
        }
        #[allow(clippy::unwrap_used)] // We know that last is not None because we checked it above
        let snapshot = last.unwrap();
        snapshot.restore_from_snapshot(&mut self.shared_mem)
    }

    /// Pops the last snapshot off the stack and restores the memory to the previous state.
    ///
    /// It should be used when you want to restore the state of the memory to a previous state and
    /// do not need to retain that state for example when devolving a sandbox to a previous state.
    pub(crate) fn pop_and_restore_state_from_snapshot(&mut self) -> Result<()> {
        let last = self
            .snapshots
            .try_lock()
            .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
            .pop();
        if last.is_none() {
            log_then_return!(NoMemorySnapshot);
        }
        self.restore_state_from_last_snapshot()
    }

    fn create_stack_guard() -> [u8; STACK_COOKIE_LEN] {
        rand::random::<[u8; STACK_COOKIE_LEN]>()
    }
}

/// Implementations over `ExclusiveSharedMemory` and loading guest binaries
impl SandboxMemoryManager<ExclusiveSharedMemory> {
    /// Wraps `ExclusiveSharedMemory::build`, giving you access to Host and Guest shared memories.
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
                load_addr: self.load_addr.clone(),
                entrypoint_offset: self.entrypoint_offset,
                memory_sections: self.memory_sections.clone(),
                snapshots: Arc::new(Mutex::new(Vec::new())),
                init_rsp: self.init_rsp,
                stack_guard: self.stack_guard,
                #[cfg(target_os = "windows")]
                _lib: self._lib,
            },
            SandboxMemoryManager {
                shared_mem: gshm,
                load_addr: self.load_addr.clone(),
                entrypoint_offset: self.entrypoint_offset,
                memory_sections: self.memory_sections,
                snapshots: Arc::new(Mutex::new(Vec::new())),
                init_rsp: self.init_rsp,
                stack_guard: self.stack_guard,
                #[cfg(target_os = "windows")]
                _lib: None,
            },
        )
    }
}

impl SandboxMemoryManager<HostSharedMemory> {
    /// Set the stack guard of the guest's custom guest memory region to a cookie.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn set_stack_guard(&mut self) -> Result<()> {
        let cookie = self.stack_guard;
        let offset = self
            .memory_sections
            .get_custom_guest_memory_section_offset();
        self.shared_mem.copy_from_slice(&cookie, offset)
    }

    /// Check the stack guard of the guest's custom guest memory region to
    /// ensure no stack overflows have occurred.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn check_stack_guard(&self) -> Result<()> {
        let cookie = self.stack_guard;
        // There's a stack guard right before the custom guest memory section
        let offset = self
            .memory_sections
            .get_custom_guest_memory_section_offset();
        let test_cookie: [u8; STACK_COOKIE_LEN] = self.shared_mem.read(offset)?;
        let cmp_res = cookie.iter().cmp(test_cookie.iter());
        match cmp_res {
            Ordering::Equal => Ok(()),
            _ => Err(HyperlightError::StackOverflow()),
        }
    }

    /// Reads a host function call from memory
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_host_function_call(&mut self) -> Result<FunctionCall> {
        let (ptr, size) = self
            .memory_sections
            .read_hyperlight_peb()?
            .get_output_data_guest_region();
        self.shared_mem
            .try_pop_buffer_into::<FunctionCall>(ptr as usize, size as usize)
    }

    /// Writes a function call result to memory
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn write_response_from_host_method_call(&mut self, res: &ReturnValue) -> Result<()> {
        let function_call_ret_val_buffer = Vec::<u8>::try_from(res).map_err(|_| {
            new_error!(
                "write_response_from_host_method_call: failed to convert ReturnValue to Vec<u8>"
            )
        })?;

        let (ptr, size) = self
            .memory_sections
            .read_hyperlight_peb()?
            .get_input_data_guest_region();

        self.shared_mem.push_buffer(
            ptr as usize,
            size as usize,
            function_call_ret_val_buffer.as_slice(),
        )
    }

    /// Writes a guest function call to memory
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn write_guest_function_call(
        &mut self,
        input_data_region: (u64, u64),
        buffer: &[u8],
    ) -> Result<()> {
        let (ptr, size) = input_data_region;

        validate_guest_function_call_buffer(buffer).map_err(|e| {
            new_error!(
                "Guest function call buffer validation failed: {}",
                e.to_string()
            )
        })?;

        self.shared_mem
            .push_buffer(ptr as usize, size as usize, buffer)
    }

    /// Reads a function call result from memory
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_guest_function_call_result(
        &mut self,
        output_data_region: (u64, u64),
    ) -> Result<ReturnValue> {
        let (output_ptr, output_size) = output_data_region;

        self.shared_mem
            .try_pop_buffer_into::<ReturnValue>(output_ptr as usize, output_size as usize)
    }

    /// Read guest log data from the `SharedMemory` contained within `self`
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn read_guest_log_data(&mut self) -> Result<GuestLogData> {
        let (ptr, size) = self
            .memory_sections
            .read_hyperlight_peb()?
            .get_output_data_guest_region();
        self.shared_mem
            .try_pop_buffer_into::<GuestLogData>(ptr as usize, size as usize)
    }

    /// Read guest panic data from the `SharedMemory` contained within `self`
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub fn read_guest_panic_context_data(&self) -> Result<Vec<u8>> {
        let offset = self
            .memory_sections
            .read_hyperlight_peb()?
            .get_guest_panic_context_guest_address() as usize;
        let size = self
            .memory_sections
            .read_hyperlight_peb()?
            .get_guest_panic_context_size() as usize;
        let mut vec_out = vec![0; size];
        self.shared_mem
            .copy_to_slice(vec_out.as_mut_slice(), offset)?;
        Ok(vec_out)
    }
}
