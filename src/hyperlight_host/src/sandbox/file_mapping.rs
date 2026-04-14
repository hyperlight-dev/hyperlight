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
#[cfg(target_os = "windows")]
use crate::mem::memory_region::{HostRegionBase, MemoryRegionKind};
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags, MemoryRegionType};
use crate::{Result, log_then_return};

/// A prepared (host-side) file mapping ready to be applied to a VM.
///
/// Created by [`prepare_file_cow`]. The host-side OS resources (file
/// mapping handle + view on Windows, mmap on Linux) are held here
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
    /// Null-terminated C-style label for this mapping (max 63 chars + null).
    #[allow(unused)]
    pub(crate) label: [u8; hyperlight_common::mem::FILE_MAPPING_LABEL_MAX_LEN + 1],
    /// Host-side OS resources. `None` after successful consumption
    /// by the apply step (ownership transferred to the VM layer).
    pub(crate) host_resources: Option<HostFileResources>,
}

/// Platform-specific host-side file mapping resources.
pub(crate) enum HostFileResources {
    /// Windows: `CreateFileMappingW` handle + `MapViewOfFile` view.
    #[cfg(target_os = "windows")]
    Windows {
        mapping_handle: HandleWrapper,
        view_base: *mut c_void,
    },
    /// Linux: `mmap` base pointer.
    #[cfg(target_os = "linux")]
    Linux {
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
                #[cfg(target_os = "linux")]
                HostFileResources::Linux {
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
// mappings (Windows file mapping views / Linux mmap regions), not aliased
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
            #[cfg(target_os = "linux")]
            HostFileResources::Linux {
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
        }
    }

    /// Mark the host resources as consumed — ownership has been
    /// transferred to the VM layer. After this call, `Drop` will
    /// not release them.
    pub(crate) fn mark_consumed(&mut self) {
        self.host_resources = None;
    }
}

/// Build a null-terminated C-style label from the provided string.
///
/// When `truncate_ok` is true (used for auto-derived labels from
/// filenames), labels longer than [`FILE_MAPPING_LABEL_MAX_LEN`] are
/// silently truncated with a warning. When false (explicit user
/// labels), overlength labels are rejected with an error.
///
/// # Errors
///
/// Returns an error if the label exceeds the max length (and truncation
/// is not allowed) or contains null bytes.
fn build_label(
    label: &str,
    truncate_ok: bool,
) -> Result<[u8; hyperlight_common::mem::FILE_MAPPING_LABEL_MAX_LEN + 1]> {
    use hyperlight_common::mem::FILE_MAPPING_LABEL_MAX_LEN;
    let bytes = label.as_bytes();
    if bytes.contains(&0) {
        log_then_return!("map_file_cow: label must not contain null bytes");
    }
    let effective = if bytes.len() > FILE_MAPPING_LABEL_MAX_LEN {
        if truncate_ok {
            tracing::warn!(
                "map_file_cow: auto-derived label truncated from {} to {} bytes: {:?}",
                bytes.len(),
                FILE_MAPPING_LABEL_MAX_LEN,
                label,
            );
            &bytes[..FILE_MAPPING_LABEL_MAX_LEN]
        } else {
            log_then_return!(
                "map_file_cow: label length {} exceeds maximum of {} bytes",
                bytes.len(),
                FILE_MAPPING_LABEL_MAX_LEN
            );
        }
    } else {
        bytes
    };
    let mut buf = [0u8; FILE_MAPPING_LABEL_MAX_LEN + 1];
    buf[..effective.len()].copy_from_slice(effective);
    // Remaining bytes are already zero (null terminator).
    Ok(buf)
}

/// Perform host-side file mapping preparation without requiring a VM.
///
/// Opens the file, creates a read-only mapping in the host process,
/// and returns a [`PreparedFileMapping`] that can be applied to the
/// VM later. An optional `label` identifies this mapping in the PEB
/// (defaults to the file name if `None`).
///
/// # Errors
///
/// Returns an error if the file cannot be opened, is empty, the label
/// is too long, or the OS mapping calls fail.
#[instrument(err(Debug), skip(file_path, guest_base, label), parent = Span::current())]
pub(crate) fn prepare_file_cow(
    file_path: &Path,
    guest_base: u64,
    label: Option<&str>,
) -> Result<PreparedFileMapping> {
    // Build the label — default to the file name if not provided.
    // Long default labels (from filenames) are truncated with a warning;
    // explicitly provided labels that are too long are rejected.
    let default_label;
    let (label_str, truncate_ok) = match label {
        Some(l) => (l, false),
        None => {
            default_label = file_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");
            (default_label as &str, true)
        }
    };
    let label_bytes = build_label(label_str, truncate_ok)?;

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
        use windows::Win32::System::Memory::{
            CreateFileMappingW, FILE_MAP_READ, MapViewOfFile, PAGE_READONLY,
        };

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

        // Create a read-only file mapping object backed by the actual file.
        // Pass 0,0 for size to use the file's actual size — Windows will
        // NOT extend a read-only file, so requesting page-aligned size
        // would fail for files smaller than one page.
        let mapping_handle =
            unsafe { CreateFileMappingW(file_handle, None, PAGE_READONLY, 0, 0, None) }
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
            label: label_bytes,
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
            label: label_bytes,
            host_resources: Some(HostFileResources::Linux {
                mmap_base: base,
                mmap_size: size,
            }),
        })
    }
}
