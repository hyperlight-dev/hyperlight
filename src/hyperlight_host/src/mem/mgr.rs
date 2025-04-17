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

use core::mem::size_of;
use std::cmp::Ordering;
use std::str::from_utf8;
use std::sync::{Arc, Mutex};

use hyperlight_common::flatbuffer_wrappers::function_call::{
    validate_guest_function_call_buffer, FunctionCall,
};
use hyperlight_common::flatbuffer_wrappers::function_types::ReturnValue;
use hyperlight_common::flatbuffer_wrappers::guest_error::{ErrorCode, GuestError};
use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
use serde_json::from_str;
use tracing::{instrument, Span};

#[cfg(target_os = "windows")]
use super::loaded_lib::LoadedLib;
use super::ptr::RawPtr;
use super::ptr_offset::Offset;
use super::shared_mem::{ExclusiveSharedMemory, GuestSharedMemory, HostSharedMemory, SharedMemory};
use super::shared_mem_snapshot::SharedMemorySnapshot;
use crate::error::HyperlightHostError;
use crate::sandbox::sandbox_builder::{
    MemoryRegionFlags, SandboxMemorySections, BASE_ADDRESS, PDPT_OFFSET, PD_OFFSET, PT_OFFSET,
};
use crate::HyperlightError::{
    ExceptionDataLengthIncorrect, ExceptionMessageTooBig, JsonConversionFailure, NoMemorySnapshot,
    UTF8SliceConversionFailure,
};
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
    pub(crate) fn check_stack_guard(&self) -> Result<bool> {
        let cookie = self.stack_guard;
        // There's a stack guard right before the custom guest memory section
        let offset = self
            .memory_sections
            .get_custom_guest_memory_section_offset();
        let test_cookie: [u8; STACK_COOKIE_LEN] = self.shared_mem.read(offset)?;
        let cmp_res = cookie.iter().cmp(test_cookie.iter());
        Ok(cmp_res == Ordering::Equal)
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

    /// Get the length of the host exception
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn get_host_error_length(&self) -> Result<i32> {
        let offset = self
            .memory_sections
            .read_hyperlight_peb()?
            .get_host_error_guest_address() as usize;
        // The host exception field is expected to contain a 32-bit length followed by the exception data.
        self.shared_mem.read::<i32>(offset)
    }

    /// Get a bool indicating if there is a host error
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn has_host_error(&self) -> Result<bool> {
        let offset = self
            .memory_sections
            .read_hyperlight_peb()?
            .get_host_error_guest_address() as usize;
        // The host exception field is expected to contain a 32-bit length followed by the exception data.
        let len = self.shared_mem.read::<i32>(offset)?;
        Ok(len != 0)
    }

    /// Get the error data that was written by the Hyperlight Host
    /// Returns a `Result` containing 'Unit' or an error.Error
    /// Writes the exception data to the buffer at `exception_data_ptr`.
    ///
    /// TODO: have this function return a Vec<u8> instead of requiring
    /// the user pass in a slice of the same length as returned by
    /// self.get_host_error_length()
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn get_host_error_data(&self, exception_data_slc: &mut [u8]) -> Result<()> {
        let offset = self
            .memory_sections
            .read_hyperlight_peb()?
            .get_host_error_guest_address() as usize;
        let len = self.get_host_error_length()?;

        let exception_data_slc_len = exception_data_slc.len();
        if exception_data_slc_len != len as usize {
            log_then_return!(ExceptionDataLengthIncorrect(len, exception_data_slc_len));
        }
        // The host exception field is expected to contain a 32-bit length followed by the exception data.
        self.shared_mem
            .copy_to_slice(exception_data_slc, offset + size_of::<i32>())?;
        Ok(())
    }

    /// Look for a `HyperlightError` generated by the host, and return
    /// an `Ok(Some(the_error))` if we succeeded in looking for one, and
    /// it was found. Return `Ok(None)` if we succeeded in looking for
    /// one, and it wasn't found. Return an `Err` if we did not succeed
    /// in looking for one.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_host_error(&self) -> Result<Option<HyperlightHostError>> {
        if self.has_host_error()? {
            let host_err_len = {
                let len_i32 = self.get_host_error_length()?;
                usize::try_from(len_i32)
            }?;
            // create a Vec<u8> of length host_err_len.
            // it's important we set the length, rather than just
            // the capacity, because self.get_host_error_data ensures
            // the length of the vec matches the return value of
            // self.get_host_error_length()
            let mut host_err_data: Vec<u8> = vec![0; host_err_len];
            self.get_host_error_data(&mut host_err_data)?;
            let host_err_json = from_utf8(&host_err_data).map_err(UTF8SliceConversionFailure)?;
            let host_err: HyperlightHostError =
                from_str(host_err_json).map_err(JsonConversionFailure)?;
            Ok(Some(host_err))
        } else {
            Ok(None)
        }
    }

    /// Get the guest error data
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_guest_error(&self) -> Result<GuestError> {
        // get memory buffer max size
        let guest_error_data_ptr = self
            .memory_sections
            .read_hyperlight_peb()?
            .get_guest_error_guest_address() as usize;
        let guest_error_data_size = self
            .memory_sections
            .read_hyperlight_peb()?
            .get_guest_error_data_size() as usize;

        // get guest error from layout and shared mem
        let mut guest_error_buffer = vec![b'0'; guest_error_data_size];
        self.shared_mem
            .copy_to_slice(guest_error_buffer.as_mut_slice(), guest_error_data_ptr)?;
        GuestError::try_from(guest_error_buffer.as_slice()).map_err(|e| {
            new_error!(
                "get_guest_error: failed to convert buffer to GuestError: {}",
                e
            )
        })
    }

    /// This function writes an error to guest memory and is intended to be
    /// used when the host's outb handler code raises an error.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn write_outb_error(
        &mut self,
        guest_error_msg: &[u8],
        host_exception_data: &[u8],
    ) -> Result<()> {
        let message = String::from_utf8(guest_error_msg.to_owned())?;
        let ge = GuestError::new(ErrorCode::OutbError, message);

        let guest_error_buffer: Vec<u8> = (&ge)
            .try_into()
            .map_err(|_| new_error!("write_outb_error: failed to convert GuestError to Vec<u8>"))?;

        let guest_error_data_ptr = self
            .memory_sections
            .read_hyperlight_peb()?
            .get_guest_error_guest_address();
        let guest_error_data_size = self
            .memory_sections
            .read_hyperlight_peb()?
            .get_guest_error_data_size();

        if guest_error_buffer.len() as u64 > guest_error_data_size {
            log_then_return!("The guest error message is too large to fit in the shared memory");
        }
        self.shared_mem
            .copy_from_slice(guest_error_buffer.as_slice(), guest_error_data_ptr as usize)?;

        let host_error_data_ptr = self
            .memory_sections
            .read_hyperlight_peb()?
            .get_host_error_guest_address() as usize;
        let host_error_data_size = self
            .memory_sections
            .read_hyperlight_peb()?
            .get_host_error_data_size() as usize;

        // First four bytes of host exception are length

        if host_exception_data.len() > host_error_data_size - size_of::<i32>() {
            log_then_return!(ExceptionMessageTooBig(
                host_exception_data.len(),
                host_error_data_size - size_of::<i32>()
            ));
        }

        self.shared_mem
            .write::<i32>(host_error_data_ptr, host_exception_data.len() as i32)?;
        self.shared_mem
            .copy_from_slice(host_exception_data, host_error_data_ptr + size_of::<i32>())?;

        Ok(())
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

// TODO(danbugs:297): bring back
// #[cfg(test)]
// mod tests {
//     #[cfg(all(target_os = "windows", inprocess))]
//     use serial_test::serial;
//
//     #[test]
//     fn load_guest_binary_common() {
//         let guests = vec![
//             rust_guest_as_pathbuf("simpleguest"),
//             rust_guest_as_pathbuf("callbackguest"),
//         ];
//         for guest in guests {
//             let guest_bytes = bytes_for_path(guest).unwrap();
//             let exe_info = ExeInfo::from_buf(guest_bytes.as_slice()).unwrap();
//             let stack_size_override = 0x3000;
//             let heap_size_override = 0x10000;
//             let mut cfg = SandboxConfiguration::default();
//             cfg.set_stack_size(stack_size_override);
//             cfg.set_heap_size(heap_size_override);
//             let (layout, shared_mem, _, _) =
//                 super::load_guest_binary_common(cfg, &exe_info, |_, _| Ok(RawPtr::from(100)))
//                     .unwrap();
//             assert_eq!(
//                 stack_size_override,
//                 u64::try_from(layout.stack_size).unwrap()
//             );
//             assert_eq!(heap_size_override, u64::try_from(layout.heap_size).unwrap());
//             assert_eq!(layout.get_memory_size().unwrap(), shared_mem.mem_size());
//         }
//     }
//
//     #[cfg(all(target_os = "windows", inprocess))]
//     #[test]
//     #[serial]
//     fn load_guest_binary_using_load_library() {
//         use hyperlight_testing::rust_guest_as_pathbuf;
//
//         use crate::mem::mgr::SandboxMemoryManager;
//
//         let cfg = SandboxConfiguration::default();
//         let guest_pe_path = rust_guest_as_pathbuf("simpleguest.exe");
//         let guest_pe_bytes = bytes_for_path(guest_pe_path.clone()).unwrap();
//         let mut pe_info = ExeInfo::from_buf(guest_pe_bytes.as_slice()).unwrap();
//         let _ = SandboxMemoryManager::load_guest_binary_using_load_library(
//             cfg,
//             guest_pe_path.to_str().unwrap(),
//             &mut pe_info,
//         )
//             .unwrap();
//
//         let guest_elf_path = rust_guest_as_pathbuf("simpleguest");
//         let guest_elf_bytes = bytes_for_path(guest_elf_path.clone()).unwrap();
//         let mut elf_info = ExeInfo::from_buf(guest_elf_bytes.as_slice()).unwrap();
//
//         let res = SandboxMemoryManager::load_guest_binary_using_load_library(
//             cfg,
//             guest_elf_path.to_str().unwrap(),
//             &mut elf_info,
//         );
//
//         match res {
//             Ok(_) => {
//                 panic!("loadlib with elf should fail");
//             }
//             Err(err) => {
//                 assert!(err
//                     .to_string()
//                     .contains("LoadLibrary can only be used with PE files"));
//             }
//         }
//     }
//
//     /// Don't write a host error, try to read it back, and verify we
//     /// successfully do the read but get no error back
//     #[test]
//     fn get_host_error_none() {
//         let cfg = SandboxConfiguration::default();
//         let layout = SandboxMemoryLayout::new(cfg, 0x10_000, 0x10_000, 0x10_000, 0x10_000).unwrap();
//         let mut eshm = ExclusiveSharedMemory::new(layout.get_memory_size().unwrap()).unwrap();
//         let mem_size = eshm.mem_size();
//         layout
//             .write(
//                 &mut eshm,
//                 SandboxMemoryLayout::BASE_ADDRESS,
//                 mem_size,
//                 false,
//             )
//             .unwrap();
//         let emgr = SandboxMemoryManager::new(
//             layout,
//             eshm,
//             false,
//             RawPtr::from(0),
//             Offset::from(0),
//             #[cfg(target_os = "windows")]
//             None,
//         );
//         let (hmgr, _) = emgr.build();
//         assert_eq!(None, hmgr.get_host_error().unwrap());
//     }
//
//     /// write a host error to shared memory, then try to read it back out
//     #[test]
//     fn round_trip_host_error() {
//         let cfg = SandboxConfiguration::default();
//         let layout = SandboxMemoryLayout::new(cfg, 0x10_000, 0x10_000, 0x10_000, 0x10_000).unwrap();
//         let mem_size = layout.get_memory_size().unwrap();
//         // write a host error and then try to read it back
//         let mut eshm = ExclusiveSharedMemory::new(mem_size).unwrap();
//         layout
//             .write(
//                 &mut eshm,
//                 SandboxMemoryLayout::BASE_ADDRESS,
//                 mem_size,
//                 false,
//             )
//             .unwrap();
//         let emgr = SandboxMemoryManager::new(
//             layout,
//             eshm,
//             false,
//             RawPtr::from(0),
//             Offset::from(0),
//             #[cfg(target_os = "windows")]
//             None,
//         );
//         let (mut hmgr, _) = emgr.build();
//         let err = HyperlightHostError {
//             message: "test message".to_string(),
//             source: "rust test".to_string(),
//         };
//         let err_json_bytes = {
//             let str = to_string(&err).unwrap();
//             str.into_bytes()
//         };
//         let err_json_msg = "test error message".to_string().into_bytes();
//         hmgr.write_outb_error(&err_json_msg, &err_json_bytes)
//             .unwrap();
//
//         let host_err_opt = hmgr
//             .get_host_error()
//             .expect("get_host_err should return an Ok");
//         assert!(host_err_opt.is_some());
//         assert_eq!(err, host_err_opt.unwrap());
//     }
// }
