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
use hyperlight_common::flatbuffer_wrappers::host_function_details::HostFunctionDetails;
use serde_json::from_str;
use tracing::{instrument, Span};

use super::exe::ExeInfo;
use super::layout::SandboxMemoryLayout;
#[cfg(target_os = "windows")]
use super::loaded_lib::LoadedLib;
use super::memory_region::{MemoryRegion, MemoryRegionType};
use super::ptr::{GuestPtr, RawPtr};
use super::ptr_offset::Offset;
use super::shared_mem::{ExclusiveSharedMemory, GuestSharedMemory, HostSharedMemory, SharedMemory};
use super::shared_mem_snapshot::SharedMemorySnapshot;
use crate::error::HyperlightError::{
    ExceptionDataLengthIncorrect, ExceptionMessageTooBig, JsonConversionFailure, NoMemorySnapshot,
    UTF8SliceConversionFailure,
};
use crate::error::HyperlightHostError;
use crate::sandbox::SandboxConfiguration;
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
pub(super) const AMOUNT_OF_MEMORY_PER_PT: usize = 0x200000;
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
    /// Whether the sandbox is running in-process
    inprocess: bool,
    /// Pointer to where to load memory from
    pub(crate) load_addr: RawPtr,
    /// Offset for the execution entrypoint from `load_addr`
    pub(crate) entrypoint_offset: Offset,
    /// A vector of memory snapshots that can be used to save and  restore the state of the memory
    /// This is used by the Rust Sandbox implementation (rather than the mem_snapshot field above which only exists to support current C API)
    snapshots: Arc<Mutex<Vec<SharedMemorySnapshot>>>,
    /// This field must be present, even though it's not read,
    /// so that its underlying resources are properly dropped at
    /// the right time.
    #[cfg(target_os = "windows")]
    _lib: Option<LoadedLib>,
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
        inprocess: bool,
        load_addr: RawPtr,
        entrypoint_offset: Offset,
        #[cfg(target_os = "windows")] lib: Option<LoadedLib>,
    ) -> Self {
        Self {
            layout,
            shared_mem,
            inprocess,
            load_addr,
            entrypoint_offset,
            snapshots: Arc::new(Mutex::new(Vec::new())),
            #[cfg(target_os = "windows")]
            _lib: lib,
        }
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn is_in_process(&self) -> bool {
        self.inprocess
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
    pub(crate) fn set_up_shared_memory(
        &mut self,
        mem_size: u64,
        regions: &mut [MemoryRegion],
    ) -> Result<u64> {
        // Add 0x200000 because that's the start of mapped memory
        // For MSVC, move rsp down by 0x28.  This gives the called 'main'
        // function the appearance that rsp was 16 byte aligned before
        // the 'call' that calls main (note we don't really have a return value
        // on the stack but some assembly instructions are expecting rsp have
        // started 0x8 bytes off of 16 byte alignment when 'main' is invoked.
        // We do 0x28 instead of 0x8 because MSVC can expect that there are
        // 0x20 bytes of space to write to by the called function.
        // I am not sure if this happens with the 'main' method, but we do this
        // just in case.
        //
        // NOTE: We do this also for GCC freestanding binaries because we
        // specify __attribute__((ms_abi)) on the start method
        let rsp: u64 = self.layout.get_top_of_user_stack_offset() as u64
            + SandboxMemoryLayout::BASE_ADDRESS as u64
            + self.layout.stack_size as u64
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
            // We round up mem_size/2MB and then we need to add 1 as we start our memory mapping at 0x200000

            let mem_size = usize::try_from(mem_size)?;

            let num_pages: usize =
                ((mem_size + AMOUNT_OF_MEMORY_PER_PT - 1) / AMOUNT_OF_MEMORY_PER_PT) + 1;

            // Create num_pages PT with 512 PTEs
            for p in 0..num_pages {
                for i in 0..512 {
                    let offset = SandboxMemoryLayout::PT_OFFSET + (p * 4096) + (i * 8);
                    // Each PTE maps a 4KB page
                    let val_to_write = if p == 0 {
                        (p << 21) as u64 | (i << 12) as u64
                    } else {
                        let flags = match Self::get_page_flags(p, i, regions) {
                            Ok(region_type) => match region_type {
                                // TODO: We parse and load the exe according to its sections and then
                                // have the correct flags set rather than just marking the entire binary as executable
                                MemoryRegionType::Code => PAGE_PRESENT | PAGE_RW | PAGE_USER,
                                MemoryRegionType::Stack => {
                                    PAGE_PRESENT | PAGE_RW | PAGE_USER | PAGE_NX
                                }
                                #[cfg(feature = "executable_heap")]
                                MemoryRegionType::Heap => PAGE_PRESENT | PAGE_RW | PAGE_USER,
                                #[cfg(not(feature = "executable_heap"))]
                                MemoryRegionType::Heap => {
                                    PAGE_PRESENT | PAGE_RW | PAGE_USER | PAGE_NX
                                }
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
                                MemoryRegionType::PanicContext => PAGE_PRESENT | PAGE_RW | PAGE_NX,
                                MemoryRegionType::GuestErrorData => {
                                    PAGE_PRESENT | PAGE_RW | PAGE_NX
                                }
                                // Host Exception Data are readonly in the guest
                                MemoryRegionType::HostExceptionData => PAGE_PRESENT | PAGE_NX,
                                MemoryRegionType::PageTables => PAGE_PRESENT | PAGE_RW | PAGE_NX,
                                MemoryRegionType::KernelStack => PAGE_PRESENT | PAGE_RW | PAGE_NX,
                                MemoryRegionType::BootStack => PAGE_PRESENT | PAGE_RW | PAGE_NX,
                            },
                            // If there is an error then the address isn't mapped so mark it as not present
                            Err(_) => 0,
                        };
                        ((p << 21) as u64 | (i << 12) as u64) | flags
                    };
                    shared_mem.write_u64(offset, val_to_write)?;
                }
            }
            Ok::<(), HyperlightError>(())
        })??;

        Ok(rsp)
    }

    fn get_page_flags(
        p: usize,
        i: usize,
        regions: &mut [MemoryRegion],
    ) -> Result<MemoryRegionType> {
        let addr = (p << 21) + (i << 12);

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
            Ok(index) => Ok(regions[index].region_type),
            Err(_) => Err(new_error!("Could not find region for address: {}", addr)),
        }
    }

    /// Get the process environment block (PEB) address assuming `start_addr`
    /// is the address of the start of memory, using the given
    /// `SandboxMemoryLayout` to calculate the address.
    ///
    /// For more details on PEBs, please see the following link:
    ///
    /// https://en.wikipedia.org/wiki/Process_Environment_Block
    #[cfg(inprocess)]
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_in_process_peb_address(&self, start_addr: u64) -> Result<u64> {
        Ok(start_addr + self.layout.get_in_process_peb_offset() as u64)
    }

    /// this function will create a memory snapshot and push it onto the stack of snapshots
    /// It should be used when you want to save the state of the memory, for example, when evolving a sandbox to a new state
    pub(crate) fn push_state(&mut self) -> Result<()> {
        let snapshot = SharedMemorySnapshot::new(&mut self.shared_mem)?;
        self.snapshots
            .try_lock()
            .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
            .push(snapshot);
        Ok(())
    }

    /// this function restores a memory snapshot from the last snapshot in the list but does not pop the snapshot
    /// off the stack
    /// It should be used when you want to restore the state of the memory to a previous state but still want to
    /// retain that state, for example after calling a function in the guest
    pub(crate) fn restore_state_from_last_snapshot(&mut self) -> Result<()> {
        let mut snapshots = self
            .snapshots
            .try_lock()
            .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?;
        let last = snapshots.last_mut();
        if last.is_none() {
            log_then_return!(NoMemorySnapshot);
        }
        let snapshot = last.unwrap();
        snapshot.restore_from_snapshot(&mut self.shared_mem)
    }

    /// this function pops the last snapshot off the stack and restores the memory to the previous state
    /// It should be used when you want to restore the state of the memory to a previous state and do not need to retain that state
    /// for example when devolving a sandbox to a previous state.
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

    /// Sets `addr` to the correct offset in the memory referenced by
    /// `shared_mem` to indicate the address of the outb pointer and context
    /// for calling outb function
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn set_outb_address_and_context(&mut self, addr: u64, context: u64) -> Result<()> {
        let pointer_offset = self.layout.get_outb_pointer_offset();
        let context_offset = self.layout.get_outb_context_offset();
        self.shared_mem.with_exclusivity(|excl| -> Result<()> {
            excl.write_u64(pointer_offset, addr)?;
            excl.write_u64(context_offset, context)?;
            Ok(())
        })?
    }
}

/// Common setup functionality for the
/// `load_guest_binary_{into_memory, using_load_library}` functions
///
/// Returns the newly created `SandboxMemoryLayout`, newly created
/// `SharedMemory`, load address as calculated by `load_addr_fn`,
/// and calculated entrypoint offset, in order.
#[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
fn load_guest_binary_common<F>(
    cfg: SandboxConfiguration,
    exe_info: &ExeInfo,
    load_addr_fn: F,
) -> Result<(SandboxMemoryLayout, ExclusiveSharedMemory, RawPtr, Offset)>
where
    F: FnOnce(&ExclusiveSharedMemory, &SandboxMemoryLayout) -> Result<RawPtr>,
{
    let layout = SandboxMemoryLayout::new(
        cfg,
        exe_info.loaded_size(),
        usize::try_from(cfg.get_stack_size(exe_info))?,
        usize::try_from(cfg.get_heap_size(exe_info))?,
    )?;
    let mut shared_mem = ExclusiveSharedMemory::new(layout.get_memory_size()?)?;

    let load_addr: RawPtr = load_addr_fn(&shared_mem, &layout)?;

    let entrypoint_offset = exe_info.entrypoint();

    let offset = layout.get_code_pointer_offset();

    {
        // write the code pointer to shared memory
        let load_addr_u64: u64 = load_addr.clone().into();
        shared_mem.write_u64(offset, load_addr_u64)?;
    }
    Ok((layout, shared_mem, load_addr, entrypoint_offset))
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
    /// - The offset to the entrypoint. This value means something different
    /// depending on whether we're using in-process mode or not:
    ///     - If we're using in-process mode, this value will be into
    ///     host memory
    ///     - If we're not running with in-memory mode, this value will be
    ///     into guest memory
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn load_guest_binary_into_memory(
        cfg: SandboxConfiguration,
        exe_info: ExeInfo,
        inprocess: bool,
    ) -> Result<(Self, super::exe::LoadInfo)> {
        let (layout, mut shared_mem, load_addr, entrypoint_offset) = load_guest_binary_common(
            cfg,
            &exe_info,
            |shared_mem: &ExclusiveSharedMemory, layout: &SandboxMemoryLayout| {
                let addr_usize = if inprocess {
                    // if we're running in-process, load_addr is the absolute
                    // address to the start of shared memory, plus the offset to
                    // code

                    // We also need to make the memory executable

                    shared_mem.make_memory_executable()?;
                    shared_mem.base_addr() + layout.get_guest_code_offset()
                } else {
                    // otherwise, we're running in a VM, so load_addr
                    // is the base address in a VM plus the code
                    // offset
                    layout.get_guest_code_address()
                };
                RawPtr::try_from(addr_usize)
            },
        )?;

        let load_info = exe_info.load(
            load_addr.clone().try_into()?,
            &mut shared_mem.as_mut_slice()[layout.get_guest_code_offset()..],
        )?;

        Ok((
            Self::new(
                layout,
                shared_mem,
                inprocess,
                load_addr,
                entrypoint_offset,
                #[cfg(target_os = "windows")]
                None,
            ),
            load_info,
        ))
    }

    /// Similar to load_guest_binary_into_memory, except only works on Windows
    /// and uses the
    /// [`LoadLibraryA`](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya)
    /// function.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn load_guest_binary_using_load_library(
        cfg: SandboxConfiguration,
        guest_bin_path: &str,
        exe_info: &mut ExeInfo,
    ) -> Result<(Self, super::exe::LoadInfo)> {
        #[cfg(target_os = "windows")]
        {
            if !matches!(exe_info, ExeInfo::PE(_)) {
                log_then_return!("LoadLibrary can only be used with PE files");
            }

            let lib = LoadedLib::load(guest_bin_path)?;
            let (layout, shared_mem, load_addr, entrypoint_offset) =
                load_guest_binary_common(cfg, exe_info, |_, _| Ok(lib.base_addr()))?;

            // make the memory executable when running in-process
            shared_mem.make_memory_executable()?;

            #[cfg(not(feature = "unwind_guest"))]
            let load_info = ();
            #[cfg(feature = "unwind_guest")]
            let load_info = Arc::new(super::exe::DummyUnwindInfo {});

            Ok((
                Self::new(
                    layout,
                    shared_mem,
                    true,
                    load_addr,
                    entrypoint_offset,
                    Some(lib),
                ),
                load_info,
            ))
        }
        #[cfg(target_os = "linux")]
        {
            let _ = (cfg, guest_bin_path, exe_info);
            log_then_return!("load_guest_binary_using_load_library is only available on Windows");
        }
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
                inprocess: self.inprocess,
                load_addr: self.load_addr.clone(),
                entrypoint_offset: self.entrypoint_offset,
                snapshots: Arc::new(Mutex::new(Vec::new())),
                #[cfg(target_os = "windows")]
                _lib: self._lib,
            },
            SandboxMemoryManager {
                shared_mem: gshm,
                layout: self.layout,
                inprocess: self.inprocess,
                load_addr: self.load_addr.clone(),
                entrypoint_offset: self.entrypoint_offset,
                snapshots: Arc::new(Mutex::new(Vec::new())),
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
        //
        // When executing with in-hypervisor mode, there is no danger from
        // the guest manipulating this memory location because the only
        // addresses that are valid are in its own address space.
        //
        // When executing in-process, maniulating this pointer could cause the
        // host to execute arbitrary functions.
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

    /// Get the length of the host exception
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn get_host_error_length(&self) -> Result<i32> {
        let offset = self.layout.get_host_exception_offset();
        // The host exception field is expected to contain a 32-bit length followed by the exception data.
        self.shared_mem.read::<i32>(offset)
    }

    /// Get a bool indicating if there is a host error
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn has_host_error(&self) -> Result<bool> {
        let offset = self.layout.get_host_exception_offset();
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
        let offset = self.layout.get_host_exception_offset();
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
    /// one and it wasn't found. Return an `Err` if we did not succeed
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
        let err_buffer_size_offset = self.layout.get_guest_error_buffer_size_offset();
        let max_err_buffer_size = self.shared_mem.read::<u64>(err_buffer_size_offset)?;

        // get guest error from layout and shared mem
        let mut guest_error_buffer = vec![b'0'; usize::try_from(max_err_buffer_size)?];
        let err_msg_offset = self.layout.guest_error_buffer_offset;
        self.shared_mem
            .copy_to_slice(guest_error_buffer.as_mut_slice(), err_msg_offset)?;
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

        let err_buffer_size_offset = self.layout.get_guest_error_buffer_size_offset();
        let max_err_buffer_size = self.shared_mem.read::<u64>(err_buffer_size_offset)?;

        if guest_error_buffer.len() as u64 > max_err_buffer_size {
            log_then_return!("The guest error message is too large to fit in the shared memory");
        }
        self.shared_mem.copy_from_slice(
            guest_error_buffer.as_slice(),
            self.layout.guest_error_buffer_offset,
        )?;

        let host_exception_offset = self.layout.get_host_exception_offset();
        let host_exception_size_offset = self.layout.get_host_exception_size_offset();
        let max_host_exception_size = {
            let size_u64 = self.shared_mem.read::<u64>(host_exception_size_offset)?;
            usize::try_from(size_u64)
        }?;

        // First four bytes of host exception are length

        if host_exception_data.len() > max_host_exception_size - size_of::<i32>() {
            log_then_return!(ExceptionMessageTooBig(
                host_exception_data.len(),
                max_host_exception_size - size_of::<i32>()
            ));
        }

        self.shared_mem
            .write::<i32>(host_exception_offset, host_exception_data.len() as i32)?;
        self.shared_mem.copy_from_slice(
            host_exception_data,
            host_exception_offset + size_of::<i32>(),
        )?;

        Ok(())
    }

    /// Read guest panic data from the `SharedMemory` contained within `self`
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub fn read_guest_panic_context_data(&self) -> Result<Vec<u8>> {
        let offset = self.layout.get_guest_panic_context_buffer_offset();
        let buffer_size = {
            let size_u64 = self
                .shared_mem
                .read::<u64>(self.layout.get_guest_panic_context_size_offset())?;
            usize::try_from(size_u64)
        }?;
        let mut vec_out = vec![0; buffer_size];
        self.shared_mem
            .copy_to_slice(vec_out.as_mut_slice(), offset)?;
        Ok(vec_out)
    }
}

#[cfg(test)]
mod tests {
    use hyperlight_testing::rust_guest_as_pathbuf;
    use serde_json::to_string;
    #[cfg(target_os = "windows")]
    use serial_test::serial;

    use super::SandboxMemoryManager;
    use crate::error::HyperlightHostError;
    use crate::mem::exe::ExeInfo;
    use crate::mem::layout::SandboxMemoryLayout;
    use crate::mem::ptr::RawPtr;
    use crate::mem::ptr_offset::Offset;
    use crate::mem::shared_mem::{ExclusiveSharedMemory, SharedMemory};
    use crate::sandbox::SandboxConfiguration;
    use crate::testing::bytes_for_path;

    #[test]
    fn load_guest_binary_common() {
        let guests = vec![
            rust_guest_as_pathbuf("simpleguest"),
            rust_guest_as_pathbuf("callbackguest"),
        ];
        for guest in guests {
            let guest_bytes = bytes_for_path(guest).unwrap();
            let exe_info = ExeInfo::from_buf(guest_bytes.as_slice()).unwrap();
            let stack_size_override = 0x3000;
            let heap_size_override = 0x10000;
            let mut cfg = SandboxConfiguration::default();
            cfg.set_stack_size(stack_size_override);
            cfg.set_heap_size(heap_size_override);
            let (layout, shared_mem, _, _) =
                super::load_guest_binary_common(cfg, &exe_info, |_, _| Ok(RawPtr::from(100)))
                    .unwrap();
            assert_eq!(
                stack_size_override,
                u64::try_from(layout.stack_size).unwrap()
            );
            assert_eq!(heap_size_override, u64::try_from(layout.heap_size).unwrap());
            assert_eq!(layout.get_memory_size().unwrap(), shared_mem.mem_size());
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[serial]
    fn load_guest_binary_using_load_library() {
        use hyperlight_testing::rust_guest_as_pathbuf;

        use crate::mem::mgr::SandboxMemoryManager;

        let cfg = SandboxConfiguration::default();
        let guest_pe_path = rust_guest_as_pathbuf("simpleguest.exe");
        let guest_pe_bytes = bytes_for_path(guest_pe_path.clone()).unwrap();
        let mut pe_info = ExeInfo::from_buf(guest_pe_bytes.as_slice()).unwrap();
        let _ = SandboxMemoryManager::load_guest_binary_using_load_library(
            cfg,
            guest_pe_path.to_str().unwrap(),
            &mut pe_info,
        )
        .unwrap();

        let guest_elf_path = rust_guest_as_pathbuf("simpleguest");
        let guest_elf_bytes = bytes_for_path(guest_elf_path.clone()).unwrap();
        let mut elf_info = ExeInfo::from_buf(guest_elf_bytes.as_slice()).unwrap();

        let res = SandboxMemoryManager::load_guest_binary_using_load_library(
            cfg,
            guest_elf_path.to_str().unwrap(),
            &mut elf_info,
        );

        match res {
            Ok(_) => {
                panic!("loadlib with elf should fail");
            }
            Err(err) => {
                assert!(err
                    .to_string()
                    .contains("LoadLibrary can only be used with PE files"));
            }
        }
    }

    /// Don't write a host error, try to read it back, and verify we
    /// successfully do the read but get no error back
    #[test]
    fn get_host_error_none() {
        let cfg = SandboxConfiguration::default();
        let layout = SandboxMemoryLayout::new(cfg, 0x10000, 0x10000, 0x10000).unwrap();
        let mut eshm = ExclusiveSharedMemory::new(layout.get_memory_size().unwrap()).unwrap();
        let mem_size = eshm.mem_size();
        layout
            .write(
                &mut eshm,
                SandboxMemoryLayout::BASE_ADDRESS,
                mem_size,
                false,
            )
            .unwrap();
        let emgr = SandboxMemoryManager::new(
            layout,
            eshm,
            false,
            RawPtr::from(0),
            Offset::from(0),
            #[cfg(target_os = "windows")]
            None,
        );
        let (hmgr, _) = emgr.build();
        assert_eq!(None, hmgr.get_host_error().unwrap());
    }

    /// write a host error to shared memory, then try to read it back out
    #[test]
    fn round_trip_host_error() {
        let cfg = SandboxConfiguration::default();
        let layout = SandboxMemoryLayout::new(cfg, 0x10000, 0x10000, 0x10000).unwrap();
        let mem_size = layout.get_memory_size().unwrap();
        // write a host error and then try to read it back
        let mut eshm = ExclusiveSharedMemory::new(mem_size).unwrap();
        layout
            .write(
                &mut eshm,
                SandboxMemoryLayout::BASE_ADDRESS,
                mem_size,
                false,
            )
            .unwrap();
        let emgr = SandboxMemoryManager::new(
            layout,
            eshm,
            false,
            RawPtr::from(0),
            Offset::from(0),
            #[cfg(target_os = "windows")]
            None,
        );
        let (mut hmgr, _) = emgr.build();
        let err = HyperlightHostError {
            message: "test message".to_string(),
            source: "rust test".to_string(),
        };
        let err_json_bytes = {
            let str = to_string(&err).unwrap();
            str.into_bytes()
        };
        let err_json_msg = "test error message".to_string().into_bytes();
        hmgr.write_outb_error(&err_json_msg, &err_json_bytes)
            .unwrap();

        let host_err_opt = hmgr
            .get_host_error()
            .expect("get_host_err should return an Ok");
        assert!(host_err_opt.is_some());
        assert_eq!(err, host_err_opt.unwrap());
    }
}
