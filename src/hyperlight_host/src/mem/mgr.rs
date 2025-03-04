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

use tracing::{instrument, Span};

use super::exe::ExeInfo;
use super::layout::SandboxMemoryLayout;
#[cfg(target_os = "windows")]
use super::loaded_lib::LoadedLib;
use super::memory_region::{MemoryRegion, MemoryRegionType};
use super::ptr::RawPtr;
use super::ptr_offset::Offset;
use super::shared_mem::{ExclusiveSharedMemory, GuestSharedMemory, HostSharedMemory, SharedMemory};
use super::shared_mem_snapshot::SharedMemorySnapshot;
use crate::error::HyperlightError::NoMemorySnapshot;
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

/// SandboxMemoryManager is a struct that pairs a `SharedMemory` and a `SandboxMemoryLayout` and
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

    /// The memory layout of the underlying shared memory
    pub(crate) layout: SandboxMemoryLayout,

    /// Pointer to where to load memory from
    ///
    /// In in-process mode, this is the direct host memory address.
    /// When running in a VM, this is the base address of the VM (0x0).
    pub(crate) load_addr: RawPtr,

    /// Offset for the execution entrypoint from `load_addr`.
    ///
    /// This is obtained from the guest binary.
    pub(crate) entrypoint_exe_offset: Offset,

    /// A vector of memory snapshots that can be used to save and restore the state of the memory.
    snapshots: Arc<Mutex<Vec<SharedMemorySnapshot>>>,

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
    fn new(
        layout: SandboxMemoryLayout,
        shared_mem: S,
        load_addr: RawPtr,
        entrypoint_exe_offset: Offset,
        #[cfg(target_os = "windows")] lib: Option<LoadedLib>,
    ) -> Self {
        Self {
            layout,
            shared_mem,
            load_addr,
            entrypoint_exe_offset,
            snapshots: Arc::new(Mutex::new(Vec::new())),
            #[cfg(target_os = "windows")]
            _lib: lib,
        }
    }

    /// Set up the hypervisor partition in the given shared memory, with the given memory size.
    // TODO: This should perhaps happen earlier and use an
    // ExclusiveSharedMemory from the beginning.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn set_up_shared_memory(
        &mut self,
        mem_size: u64,
        regions: &mut [MemoryRegion],
    ) -> Result<()> {
        self.shared_mem.with_exclusivity(|shared_mem| {
            // Create PML4 table with only 1 PML4E
            shared_mem.write_u64(
                self.layout.get_pml4_offset(),
                self.layout.get_pdpt_offset() as u64 | PAGE_PRESENT | PAGE_RW,
            )?;

            // Create PDPT with only 1 PDPTE
            shared_mem.write_u64(
                self.layout.get_pdpt_offset(),
                self.layout.get_pd_offset() as u64 | PAGE_PRESENT | PAGE_RW,
            )?;

            for i in 0..512 {
                let offset = self.layout.get_pd_offset() + (i * 8);
                let val_to_write: u64 = (self.layout.get_pt_offset() as u64 + (i * 4096) as u64)
                    | PAGE_PRESENT
                    | PAGE_RW;
                shared_mem.write_u64(offset, val_to_write)?;
            }

            // - We only need to create enough PTEs to map the amount of memory we have.
            // - We need one PT for every 2MB of memory that is mapped.
            // - We can use the memory size to calculate the number of PTs we need.
            // - We round up mem_size/2MB.

            let mem_size = usize::try_from(mem_size)?;

            let num_pages: usize =
                ((mem_size + AMOUNT_OF_MEMORY_PER_PT - 1) / AMOUNT_OF_MEMORY_PER_PT) + 1;

            // Create num_pages PT with 512 PTEs
            for p in 0..num_pages {
                for i in 0..512 {
                    let offset = self.layout.get_pt_offset() + (p * 4096) + (i * 8);
                    // Each PTE maps a 4KB page
                    let val_to_write = {
                        let flags = match Self::get_page_flags(p, i, regions) {
                            Ok(region_type) => match region_type {
                                // TODO: We parse and load the exe according to its sections and then
                                // have the correct flags set rather than just marking the entire binary
                                // as executable
                                MemoryRegionType::GuestCode => PAGE_PRESENT | PAGE_RW | PAGE_USER,
                                MemoryRegionType::PageTables => PAGE_PRESENT | PAGE_RW | PAGE_NX,
                                // TODO(danbugs:297): this sets the custom guest memory as executable
                                // by default. This should potentially be configurable.
                                MemoryRegionType::CustomGuestMemory => {
                                    PAGE_PRESENT | PAGE_RW | PAGE_USER
                                }
                            },
                            // If there is an error then the address isn't mapped so mark it as not
                            // present
                            Err(_) => 0,
                        };
                        ((p << 21) as u64 | (i << 12) as u64) | flags
                    };
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
        self.load_addr != RawPtr::from(SandboxMemoryLayout::BASE_ADDRESS as u64)
    }

    /// Get the page flags for a given page and index
    fn get_page_flags(
        p: usize,
        i: usize,
        regions: &mut [MemoryRegion],
    ) -> Result<MemoryRegionType> {
        let addr = (p << 21) + (i << 12);

        let idx = regions.binary_search_by(|region| {
            if region.guest_region.contains(&addr) {
                Ordering::Equal
            } else if region.guest_region.start > addr {
                Ordering::Greater
            } else {
                Ordering::Less
            }
        });

        match idx {
            Ok(index) => Ok(regions[index].region_type),
            Err(_) => Err(new_error!("Could not find region for address: {}", addr)),
        }
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
}

/// Common setup functionality for the `load_guest_binary_{into_memory, using_load_library}`
/// functions.
///
/// Returns the newly created `SandboxMemoryLayout`, newly created
/// `SharedMemory`, load address as calculated by `load_addr_fn`,
/// and calculated entrypoint exe offset, in order.
#[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
fn load_guest_binary_common<F>(
    cfg: SandboxConfiguration,
    exe_info: &ExeInfo,
    load_addr_fn: F,
) -> Result<(SandboxMemoryLayout, ExclusiveSharedMemory, RawPtr, Offset)>
where
    F: FnOnce(&ExclusiveSharedMemory) -> Result<RawPtr>,
{
    let layout = SandboxMemoryLayout::new(
        cfg,
        exe_info.loaded_size(),
    )?;
    let mut shared_mem = ExclusiveSharedMemory::new(layout.get_total_page_aligned_memory_size()?)?;

    let offset = layout.get_guest_code_offset();
    let load_addr: RawPtr = load_addr_fn(&shared_mem)?;

    // Write the code pointer to shared memory
    let load_addr_u64: u64 = load_addr.clone().into();
    shared_mem.write_u64(offset, load_addr_u64)?;

    let entrypoint_exe_offset = exe_info.entrypoint();


    Ok((layout, shared_mem, load_addr, entrypoint_exe_offset))
}

impl SandboxMemoryManager<HostSharedMemory> {
    /// Gets the custom guest memory
    // TODO(danbugs:297): currently, this is only used in the KVM backend
    // because test_custom_initialise is only used there.
    #[allow(dead_code)]
    pub(crate) fn get_custom_guest_memory(&self) -> Result<Vec<u8>> {
        let custom_guest_memory_offset = self.layout.get_custom_guest_memory_offset();
        let custom_guest_memory_size = self.layout.get_custom_guest_memory_size();
        let mut custom_guest_memory = vec![b'0'; custom_guest_memory_size];
        self.shared_mem.copy_to_slice(
            custom_guest_memory.as_mut_slice(),
            custom_guest_memory_offset,
        )?;

        Ok(custom_guest_memory)
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
                layout: self.layout,
                load_addr: self.load_addr.clone(),
                entrypoint_exe_offset: self.entrypoint_exe_offset,
                snapshots: Arc::new(Mutex::new(Vec::new())),
                #[cfg(target_os = "windows")]
                _lib: self._lib,
            },
            SandboxMemoryManager {
                shared_mem: gshm,
                layout: self.layout,
                load_addr: self.load_addr.clone(),
                entrypoint_exe_offset: self.entrypoint_exe_offset,
                snapshots: Arc::new(Mutex::new(Vec::new())),
                #[cfg(target_os = "windows")]
                _lib: None,
            },
        )
    }

    /// Load the binary represented by `exe_info` into memory, ensuring
    /// all necessary relocations are made prior to completing the load
    /// operation, then create a new `SharedMemory` to store the new exe
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
        exe_info: &mut ExeInfo,
        inprocess: bool,
    ) -> Result<Self> {
        let (layout, mut shared_mem, load_addr, entrypoint_exe_offset) = load_guest_binary_common(
            cfg,
            exe_info,
            |shared_mem: &ExclusiveSharedMemory| {
                let addr_usize = if inprocess {
                    // If we're running in-process, load_addr is the absolute
                    // address to the start of shared memory, plus the offset to
                    // code.

                    // We also need to make the memory executable.

                    shared_mem.make_memory_executable()?;
                    shared_mem.base_addr()
                } else {
                    // Otherwise, we're running in a VM, so `load_addr`
                    // is the base address in a VM
                    SandboxMemoryLayout::BASE_ADDRESS
                };
                RawPtr::try_from(addr_usize)
            },
        )?;

        exe_info.load(
            load_addr.clone().try_into()?,
            &mut shared_mem.as_mut_slice()[layout.get_guest_code_offset()..],
        )?;

        Ok(Self::new(
            layout,
            shared_mem,
            load_addr,
            entrypoint_exe_offset,
            #[cfg(target_os = "windows")]
            None,
        ))
    }

    /// Similar to `load_guest_binary_into_memory`, except only works on Windows and uses the
    /// [`LoadLibraryA`](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya)
    /// function.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn load_guest_binary_using_load_library(
        cfg: SandboxConfiguration,
        guest_bin_path: &str,
        exe_info: &mut ExeInfo,
    ) -> Result<Self> {
        #[cfg(target_os = "windows")]
        {
            if !matches!(exe_info, ExeInfo::PE(_)) {
                log_then_return!("LoadLibrary can only be used with PE files");
            }

            let lib = LoadedLib::load(guest_bin_path)?;
            let (layout, shared_mem, load_addr, entrypoint_exe_offset) =
                load_guest_binary_common(cfg, exe_info, |_| Ok(lib.base_addr()))?;

            // Make the memory executable when running in-process
            shared_mem.make_memory_executable()?;

            Ok(Self::new(
                layout,
                shared_mem,
                true,
                load_addr,
                entrypoint_exe_offset,
                Some(lib),
            ))
        }
        #[cfg(target_os = "linux")]
        {
            let _ = (cfg, guest_bin_path, exe_info);
            log_then_return!("load_guest_binary_using_load_library is only available on Windows");
        }
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
//         // TODO(danbugs:297): arbitrary value, change
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
//         // TODO(danbugs:297): arbitrary value, change
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
