// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use std::os::raw::c_void;

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Memory::{MEMORY_MAPPED_VIEW_ADDRESS, UnmapViewOfFile};

use crate::hypervisor::wrappers::HandleWrapper;

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub(crate) use x86_64::*;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub(crate) use aarch64::*;

/// Set `bitmap` to the pages of [`DIRTY_PAGE_SIZE`] in `[gpa, gpa + size)`
/// the guest wrote since the last read, and clear them.
///
/// [`DIRTY_PAGE_SIZE`]: crate::mem::shared_mem::DIRTY_PAGE_SIZE
fn read_dirty_bitmap(
    partition: windows::Win32::System::Hypervisor::WHV_PARTITION_HANDLE,
    gpa: u64,
    size: usize,
    bitmap: &mut Vec<u64>,
) -> Result<(), super::HypervisorError> {
    use crate::mem::shared_mem::DIRTY_PAGE_SIZE;
    // Every word is written: resize only.
    bitmap.resize((size / DIRTY_PAGE_SIZE).div_ceil(64), 0);
    let len = u32::try_from(bitmap.len() * size_of::<u64>()).map_err(|_| {
        windows_result::Error::from_hresult(windows::Win32::Foundation::E_INVALIDARG)
    })?;
    // SAFETY: `bitmap` holds `len` bytes, which the call fills.
    unsafe {
        windows::Win32::System::Hypervisor::WHvQueryGpaRangeDirtyBitmap(
            partition,
            gpa,
            size as u64,
            Some(bitmap.as_mut_ptr()),
            len,
        )?
    };
    Ok(())
}

fn release_file_mapping(view_base: *mut c_void, mapping_handle: HandleWrapper) {
    unsafe {
        if let Err(error) = UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS { Value: view_base }) {
            tracing::error!("Failed to unmap file view at {view_base:?}: {error:?}");
        }
        if let Err(error) = CloseHandle(mapping_handle.into()) {
            tracing::error!("Failed to close file mapping handle: {error:?}");
        }
    }
}
