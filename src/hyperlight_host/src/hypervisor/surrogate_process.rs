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

use core::ffi::c_void;
use std::collections::HashMap;
use std::collections::hash_map::Entry;

use hyperlight_common::mem::PAGE_SIZE_USIZE;
use tracing::{Span, instrument};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::{
    MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFileNuma2, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS,
    PAGE_READONLY, PAGE_READWRITE, UNMAP_VIEW_OF_FILE_FLAGS, UnmapViewOfFile2, VirtualProtectEx,
};
use windows::Win32::System::SystemServices::NUMA_NO_PREFERRED_NODE;

use super::surrogate_process_manager::get_surrogate_process_manager;
use super::wrappers::HandleWrapper;
use crate::HyperlightError::WindowsAPIError;
use crate::mem::memory_region::SurrogateMapping;
use crate::{Result, log_then_return};

#[derive(Debug)]
pub(crate) struct HandleMapping {
    pub(crate) use_count: u64,
    pub(crate) surrogate_base: *mut c_void,
    /// The mapping type used when this entry was first created.
    /// Used for debug assertions to catch conflicting re-maps.
    pub(crate) mapping_type: SurrogateMapping,
}

/// Contains details of a surrogate process to be used by a Sandbox for providing memory to a HyperV VM on Windows.
/// See surrogate_process_manager for details on why this is needed.
#[derive(Debug)]
pub(super) struct SurrogateProcess {
    /// The various mappings between handles in the host and surrogate process
    pub(crate) mappings: HashMap<usize, HandleMapping>,
    /// The handle to the surrogate process.
    pub(crate) process_handle: HandleWrapper,
}

impl SurrogateProcess {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn new(process_handle: HANDLE) -> Self {
        Self {
            mappings: HashMap::new(),
            process_handle: HandleWrapper::from(process_handle),
        }
    }

    /// Maps a file mapping handle into the surrogate process.
    ///
    /// The `mapping` parameter controls the page protection and guard page
    /// behaviour:
    /// - [`SurrogateMapping::SandboxMemory`]: uses `PAGE_READWRITE` and sets
    ///   guard pages (`PAGE_NOACCESS`) on the first and last pages.
    /// - [`SurrogateMapping::ReadOnlyFile`]: uses `PAGE_READONLY` with no
    ///   guard pages.
    ///
    /// If `host_base` was already mapped, the existing mapping is reused
    /// and the reference count is incremented (the `mapping` parameter is
    /// ignored in that case).
    pub(super) fn map(
        &mut self,
        handle: HandleWrapper,
        host_base: usize,
        host_size: usize,
        mapping: &SurrogateMapping,
    ) -> Result<*mut c_void> {
        match self.mappings.entry(host_base) {
            Entry::Occupied(mut oe) => {
                if oe.get().mapping_type != *mapping {
                    tracing::warn!(
                        "Conflicting SurrogateMapping for host_base {host_base:#x}: \
                         existing={:?}, requested={:?}",
                        oe.get().mapping_type,
                        mapping
                    );
                }
                oe.get_mut().use_count += 1;
                Ok(oe.get().surrogate_base)
            }
            Entry::Vacant(ve) => {
                // Derive the page protection from the mapping type
                let page_protection = match mapping {
                    SurrogateMapping::SandboxMemory => PAGE_READWRITE,
                    SurrogateMapping::ReadOnlyFile => PAGE_READONLY,
                };

                // Use MapViewOfFile2 to map memory into the surrogate process, the MapViewOfFile2 API is implemented in as an inline function in a windows header file
                // (see https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile2#remarks) so we use the same API it uses in the header file here instead of
                // MapViewOfFile2 which does not exist in the rust crate (see https://github.com/microsoft/windows-rs/issues/2595)
                let surrogate_base = unsafe {
                    MapViewOfFileNuma2(
                        handle.into(),
                        self.process_handle.into(),
                        0,
                        None,
                        host_size,
                        0,
                        page_protection.0,
                        NUMA_NO_PREFERRED_NODE,
                    )
                };

                if surrogate_base.Value.is_null() {
                    log_then_return!(
                        "MapViewOfFileNuma2 failed: {:?}",
                        std::io::Error::last_os_error()
                    );
                }

                // Only set guard pages for SandboxMemory mappings.
                // File-backed read-only mappings do not need guard pages
                // because the host does not write to them.
                if *mapping == SurrogateMapping::SandboxMemory {
                    let mut unused_out_old_prot_flags = PAGE_PROTECTION_FLAGS(0);

                    // the first page of the raw_size is the guard page
                    let first_guard_page_start = surrogate_base.Value;
                    if let Err(e) = unsafe {
                        VirtualProtectEx(
                            self.process_handle.into(),
                            first_guard_page_start,
                            PAGE_SIZE_USIZE,
                            PAGE_NOACCESS,
                            &mut unused_out_old_prot_flags,
                        )
                    } {
                        self.unmap_helper(surrogate_base.Value);
                        log_then_return!(WindowsAPIError(e.clone()));
                    }

                    // the last page of the raw_size is the guard page
                    let last_guard_page_start =
                        unsafe { first_guard_page_start.add(host_size - PAGE_SIZE_USIZE) };
                    if let Err(e) = unsafe {
                        VirtualProtectEx(
                            self.process_handle.into(),
                            last_guard_page_start,
                            PAGE_SIZE_USIZE,
                            PAGE_NOACCESS,
                            &mut unused_out_old_prot_flags,
                        )
                    } {
                        self.unmap_helper(surrogate_base.Value);
                        log_then_return!(WindowsAPIError(e.clone()));
                    }
                }

                ve.insert(HandleMapping {
                    use_count: 1,
                    surrogate_base: surrogate_base.Value,
                    mapping_type: *mapping,
                });
                Ok(surrogate_base.Value)
            }
        }
    }

    pub(super) fn unmap(&mut self, host_base: usize) {
        match self.mappings.entry(host_base) {
            Entry::Occupied(mut oe) => {
                oe.get_mut().use_count = oe.get().use_count.checked_sub(1).unwrap_or_else(|| {
                    tracing::error!(
                        "Surrogate unmap ref count underflow for host_base {:#x}",
                        host_base
                    );
                    0
                });
                if oe.get().use_count == 0 {
                    let entry = oe.remove();
                    self.unmap_helper(entry.surrogate_base);
                }
            }
            Entry::Vacant(_) => {
                tracing::error!(
                    "Attempted to unmap from surrogate a region at host_base {:#x} that was never mapped",
                    host_base
                );
                #[cfg(debug_assertions)]
                panic!("Attempted to unmap from surrogate a region that was never mapped");
            }
        }
    }

    fn unmap_helper(&self, surrogate_base: *mut c_void) {
        let memory_mapped_view_address = MEMORY_MAPPED_VIEW_ADDRESS {
            Value: surrogate_base,
        };
        let flags = UNMAP_VIEW_OF_FILE_FLAGS(0);
        if let Err(e) = unsafe {
            UnmapViewOfFile2(
                self.process_handle.into(),
                memory_mapped_view_address,
                flags,
            )
        } {
            tracing::error!(
                "Failed to free surrogate process resources (UnmapViewOfFile2 failed): {:?}",
                e
            );
        }
    }
}

impl Default for SurrogateProcess {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl Drop for SurrogateProcess {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn drop(&mut self) {
        for mapping in self.mappings.values() {
            self.unmap_helper(mapping.surrogate_base);
        }

        // we need to do this take so we can take ownership
        // of the SurrogateProcess being dropped. this is ok to
        // do because we are in the process of dropping ourselves
        // anyway.
        match get_surrogate_process_manager() {
            Ok(manager) => match manager.return_surrogate_process(self.process_handle) {
                Ok(_) => (),
                Err(e) => {
                    tracing::error!(
                        "Failed to return surrogate process to surrogate process manager when dropping : {:?}",
                        e
                    );
                }
            },
            Err(e) => {
                tracing::error!(
                    "Failed to get surrogate process manager when dropping SurrogateProcess: {:?}",
                    e
                );
            }
        }
    }
}
