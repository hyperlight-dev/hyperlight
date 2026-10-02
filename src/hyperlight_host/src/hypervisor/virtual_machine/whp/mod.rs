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
