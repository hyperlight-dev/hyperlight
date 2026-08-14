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

//! Host-side file mapping preparation for [`map_file_cow`].
//!
//! This module splits the file mapping operation into two phases:
//! - **Prepare** ([`prepare_file_cow`]): performs host-side OS calls
//!   (open file, create mapping) without requiring a VM.
//! - **Apply**: performed by the caller (either [`MultiUseSandbox::map_file_cow`]
//!   or [`evolve_impl_multi_use`]) to map the prepared region into
//!   the guest via [`HyperlightVm::map_region`].
//!
//! This separation allows [`UninitializedSandbox`] to accept
//! `map_file_cow` calls before the VM exists, deferring the VM-side
//! work until [`evolve()`].

use std::ffi::c_void;
use std::path::Path;

use tracing::{Span, instrument};

#[cfg(target_os = "windows")]
use crate::HyperlightError;
#[cfg(target_os = "windows")]
use crate::hypervisor::wrappers::HandleWrapper;
#[cfg(target_os = "macos")]
use crate::mem::memory_region::{HostGuestMemoryRegion, HostRegionBase, MemoryRegionKind};
#[cfg(target_os = "windows")]
use crate::mem::memory_region::{HostRegionBase, MemoryRegionKind};
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags, MemoryRegionType};
use crate::{Result, log_then_return};

/// A prepared (host-side) file mapping ready to be applied to a VM.
///
/// Created by [`prepare_file_cow`]. The host-side OS resources (file
/// mapping handle + view on Windows, mmap on Unix) are held here
/// until consumed by the VM-side apply step.
///
/// If dropped without being consumed, the `Drop` impl releases all
/// host-side resources — preventing leaks when an
/// [`UninitializedSandbox`] is dropped without evolving or when
/// apply fails.
#[must_use = "holds OS resources that leak if discarded — apply to a VM or let Drop clean up"]
pub(crate) struct PreparedFileMapping {
    /// The guest address where this file should be mapped.
    pub(crate) guest_base: u64,
    /// The page-aligned size of the mapping in bytes.
    pub(crate) size: usize,
    /// Host-side OS resources. `None` after successful consumption
    /// by the apply step (ownership transferred to the VM layer).
    pub(crate) host_resources: Option<HostFileResources>,
    /// The path of the mapped file. Retained on macOS so the HVF
    /// surrogate process can map the same file read-only by path.
    #[cfg(target_os = "macos")]
    pub(crate) path: std::path::PathBuf,
}

/// Platform-specific host-side file mapping resources.
pub(crate) enum HostFileResources {
    /// Windows: `CreateFileMappingW` handle + `MapViewOfFile` view.
    #[cfg(target_os = "windows")]
    Windows {
        mapping_handle: HandleWrapper,
        view_base: *mut c_void,
    },
    /// Unix: `mmap` base pointer.
    #[cfg(unix)]
    Unix {
        mmap_base: *mut c_void,
        mmap_size: usize,
    },
}

impl Drop for PreparedFileMapping {
    fn drop(&mut self) {
        // Clean up host resources if they haven't been consumed.
        if let Some(resources) = self.host_resources.take() {
            match resources {
                #[cfg(target_os = "windows")]
                HostFileResources::Windows {
                    mapping_handle,
                    view_base,
                } => unsafe {
                    use windows::Win32::Foundation::CloseHandle;
                    use windows::Win32::System::Memory::{
                        MEMORY_MAPPED_VIEW_ADDRESS, UnmapViewOfFile,
                    };
                    if let Err(e) = UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS { Value: view_base })
                    {
                        tracing::error!(
                            "PreparedFileMapping::drop: UnmapViewOfFile failed: {:?}",
                            e
                        );
                    }
                    if let Err(e) = CloseHandle(mapping_handle.into()) {
                        tracing::error!("PreparedFileMapping::drop: CloseHandle failed: {:?}", e);
                    }
                },
                #[cfg(unix)]
                HostFileResources::Unix {
                    mmap_base,
                    mmap_size,
                } => unsafe {
                    if libc::munmap(mmap_base, mmap_size) != 0 {
                        tracing::error!(
                            "PreparedFileMapping::drop: munmap failed: {:?}",
                            std::io::Error::last_os_error()
                        );
                    }
                },
            }
        }
    }
}

// SAFETY: The raw pointers in HostFileResources point to kernel-managed
// mappings (Windows file mapping views / Unix mmap regions), not aliased
// user-allocated heap memory. Ownership is fully contained within the
// struct, and cleanup APIs (UnmapViewOfFile, CloseHandle, munmap) are
// thread-safe.
unsafe impl Send for PreparedFileMapping {}

impl PreparedFileMapping {
    /// Build the [`MemoryRegion`] that describes this mapping for the
    /// VM layer. The host resources must still be present (not yet
    /// consumed).
    pub(crate) fn to_memory_region(&self) -> Result<MemoryRegion> {
        let resources = self.host_resources.as_ref().ok_or_else(|| {
            crate::HyperlightError::Error(
                "PreparedFileMapping resources already consumed".to_string(),
            )
        })?;

        match resources {
            #[cfg(target_os = "windows")]
            HostFileResources::Windows {
                mapping_handle,
                view_base,
            } => {
                let host_base = HostRegionBase {
                    from_handle: *mapping_handle,
                    handle_base: *view_base as usize,
                    handle_size: self.size,
                    offset: 0,
                };
                let host_end =
                    <crate::mem::memory_region::HostGuestMemoryRegion as MemoryRegionKind>::add(
                        host_base, self.size,
                    );
                let guest_start = self.guest_base as usize;
                let guest_end = guest_start.checked_add(self.size).ok_or_else(|| {
                    crate::HyperlightError::Error(format!(
                        "guest_region overflow: {:#x} + {:#x}",
                        guest_start, self.size
                    ))
                })?;
                Ok(MemoryRegion {
                    host_region: host_base..host_end,
                    guest_region: guest_start..guest_end,
                    flags: MemoryRegionFlags::READ | MemoryRegionFlags::EXECUTE,
                    region_type: MemoryRegionType::MappedFile,
                })
            }
            #[cfg(all(unix, not(target_os = "macos")))]
            HostFileResources::Unix {
                mmap_base,
                mmap_size,
            } => {
                let guest_start = self.guest_base as usize;
                let guest_end = guest_start.checked_add(self.size).ok_or_else(|| {
                    crate::HyperlightError::Error(format!(
                        "guest_region overflow: {:#x} + {:#x}",
                        guest_start, self.size
                    ))
                })?;
                Ok(MemoryRegion {
                    host_region: *mmap_base as usize
                        ..(*mmap_base as usize).wrapping_add(*mmap_size),
                    guest_region: guest_start..guest_end,
                    flags: MemoryRegionFlags::READ | MemoryRegionFlags::EXECUTE,
                    region_type: MemoryRegionType::MappedFile,
                })
            }
            #[cfg(target_os = "macos")]
            HostFileResources::Unix {
                mmap_base,
                mmap_size,
            } => {
                let guest_start = self.guest_base as usize;
                let guest_end = guest_start.checked_add(self.size).ok_or_else(|| {
                    crate::HyperlightError::Error(format!(
                        "guest_region overflow: {:#x} + {:#x}",
                        guest_start, self.size
                    ))
                })?;
                // MappedFile regions stay file-backed (the surrogate
                // maps them by path, not by shm object), so there is no
                // shm name to carry here; `base` is the host VA of the
                // mapping, used by the in-process HVF backend.
                let host_base = HostRegionBase {
                    name: String::new(),
                    offset: 0,
                    base: *mmap_base as usize,
                    path: Some(self.path.clone()),
                };
                let host_end =
                    <HostGuestMemoryRegion as MemoryRegionKind>::add(host_base.clone(), *mmap_size);
                Ok(MemoryRegion {
                    host_region: host_base..host_end,
                    guest_region: guest_start..guest_end,
                    flags: MemoryRegionFlags::READ | MemoryRegionFlags::EXECUTE,
                    region_type: MemoryRegionType::MappedFile,
                })
            }
        }
    }

    /// Mark the host resources as consumed — ownership has been
    /// transferred to the VM layer. After this call, `Drop` will
    /// not release them.
    pub(crate) fn mark_consumed(&mut self) {
        self.host_resources = None;
    }
}

/// Perform host-side file mapping preparation without requiring a VM.
///
/// Opens the file, creates a read-only mapping in the host process,
/// and returns a [`PreparedFileMapping`] that can be applied to the
/// VM later.
///
/// # Errors
///
/// Returns an error if the file cannot be opened, is empty, or the OS
/// mapping calls fail.
#[instrument(err(Debug), skip(file_path, guest_base), parent = Span::current())]
pub(crate) fn prepare_file_cow(file_path: &Path, guest_base: u64) -> Result<PreparedFileMapping> {
    // Validate alignment eagerly to fail fast before allocating OS resources.
    let page_size = page_size::get();
    if !(guest_base as usize).is_multiple_of(page_size) {
        log_then_return!(
            "map_file_cow: guest_base {:#x} is not page-aligned (page size: {:#x})",
            guest_base,
            page_size
        );
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawHandle;

        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Security::{
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
        };
        use windows::Win32::System::Memory::{
            CreateFileMappingW, FILE_MAP_READ, MapViewOfFile, PAGE_READONLY,
        };
        use windows::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION1;

        let file = std::fs::File::options().read(true).open(file_path)?;
        let file_size = file.metadata()?.len();
        if file_size == 0 {
            log_then_return!("map_file_cow: cannot map an empty file: {:?}", file_path);
        }
        let size = usize::try_from(file_size).map_err(|_| {
            HyperlightError::Error(format!(
                "File size {file_size} exceeds addressable range on this platform"
            ))
        })?;
        let size = size.div_ceil(page_size) * page_size;

        let file_handle = HANDLE(file.as_raw_handle());

        // Build a security descriptor with a NULL DACL (unrestricted
        // access) so the surrogate process can map the section via
        // MapViewOfFileNuma2. File-backed sections created with the
        // default DACL fail with ERROR_ACCESS_DENIED when mapped
        // cross-process on modern Windows.
        // https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Security/struct.SECURITY_DESCRIPTOR.html
        // https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/SystemServices/constant.SECURITY_DESCRIPTOR_REVISION1.html
        let mut sd = SECURITY_DESCRIPTOR::default();
        let psd = PSECURITY_DESCRIPTOR(std::ptr::addr_of_mut!(sd).cast());
        unsafe {
            windows::Win32::Security::InitializeSecurityDescriptor(
                psd,
                SECURITY_DESCRIPTOR_REVISION1,
            )
            .map_err(|e| {
                HyperlightError::Error(format!("InitializeSecurityDescriptor failed: {e}"))
            })?;
            windows::Win32::Security::SetSecurityDescriptorDacl(psd, true, None, false).map_err(
                |e| HyperlightError::Error(format!("SetSecurityDescriptorDacl failed: {e}")),
            )?;
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: psd.0,
            bInheritHandle: false.into(),
        };

        // Create a read-only file mapping object backed by the actual file.
        // Pass 0,0 for size to use the file's actual size — Windows will
        // NOT extend a read-only file, so requesting page-aligned size
        // would fail for files smaller than one page.
        let mapping_handle =
            unsafe { CreateFileMappingW(file_handle, Some(&sa), PAGE_READONLY, 0, 0, None) }
                .map_err(|e| HyperlightError::Error(format!("CreateFileMappingW failed: {e}")))?;

        // Map a read-only view into the host process.
        // Passing 0 for dwNumberOfBytesToMap maps the entire file; the OS
        // rounds up to the next page boundary and zero-fills the remainder.
        let view = unsafe { MapViewOfFile(mapping_handle, FILE_MAP_READ, 0, 0, 0) };
        if view.Value.is_null() {
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(mapping_handle);
            }
            log_then_return!(
                "MapViewOfFile failed: {:?}",
                std::io::Error::last_os_error()
            );
        }

        Ok(PreparedFileMapping {
            guest_base,
            size,
            host_resources: Some(HostFileResources::Windows {
                mapping_handle: HandleWrapper::from(mapping_handle),
                view_base: view.Value,
            }),
        })
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;

        let file = std::fs::File::options().read(true).open(file_path)?;
        let file_size = file.metadata()?.len();
        if file_size == 0 {
            log_then_return!("map_file_cow: cannot map an empty file: {:?}", file_path);
        }
        let size = usize::try_from(file_size).map_err(|_| {
            crate::HyperlightError::Error(format!(
                "File size {file_size} exceeds addressable range on this platform"
            ))
        })?;
        let size = size.div_ceil(page_size) * page_size;
        let base = unsafe {
            // MSHV's map_user_memory requires host-writable pages (the
            // kernel module calls get_user_pages with write access).
            // KVM's KVM_MEM_READONLY slots work with read-only host pages.
            // PROT_EXEC is never needed — the hypervisor backs guest R+X
            // pages without requiring host-side execute permission.
            #[cfg(mshv3)]
            let prot = libc::PROT_READ | libc::PROT_WRITE;
            #[cfg(not(mshv3))]
            let prot = libc::PROT_READ;

            libc::mmap(
                std::ptr::null_mut(),
                size,
                prot,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        if base == libc::MAP_FAILED {
            log_then_return!("mmap error: {:?}", std::io::Error::last_os_error());
        }

        Ok(PreparedFileMapping {
            guest_base,
            size,
            host_resources: Some(HostFileResources::Unix {
                mmap_base: base,
                mmap_size: size,
            }),
            #[cfg(target_os = "macos")]
            path: file_path.to_path_buf(),
        })
    }
}
