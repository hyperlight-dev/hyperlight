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

use tracing::{instrument, Span};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::{
    UnmapViewOfFile2, MEMORY_MAPPED_VIEW_ADDRESS, UNMAP_VIEW_OF_FILE_FLAGS,
};

use super::surrogate_process_manager::get_surrogate_process_manager;
use super::wrappers::HandleWrapper;

/// Contains details of a surrogate process to be used by a Sandbox for providing memory to a HyperV VM on Windows.
/// See surrogate_process_manager for details on why this is needed.
#[derive(Debug)]
pub(super) struct SurrogateProcess {
    /// The address of memory allocated in the surrogate process to be mapped to the VM.
    pub(crate) allocated_address: *mut c_void,
    /// The handle to the surrogate process.
    pub(crate) process_handle: HandleWrapper,
}

impl SurrogateProcess {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn new(allocated_address: *mut c_void, process_handle: HANDLE) -> Self {
        Self {
            allocated_address,
            process_handle: HandleWrapper::from(process_handle),
        }
    }
}

impl Default for SurrogateProcess {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn default() -> Self {
        let allocated_address = std::ptr::null_mut();
        Self::new(allocated_address, Default::default())
    }
}

impl Drop for SurrogateProcess {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn drop(&mut self) {
        let process_handle: HANDLE = self.process_handle.into();
        let memory_mapped_view_address = MEMORY_MAPPED_VIEW_ADDRESS {
            Value: self.allocated_address,
        };
        let flags = UNMAP_VIEW_OF_FILE_FLAGS(0);
        if let Err(e) =
            unsafe { UnmapViewOfFile2(process_handle, memory_mapped_view_address, flags) }
        {
            tracing::error!(
                "Failed to free surrogate process resources (UnmapViewOfFile2 failed): {:?}",
                e
            );
        }

        // we need to do this take so we can take ownership
        // of the SurrogateProcess being dropped. this is ok to
        // do because we are in the process of dropping ourselves
        // anyway.
        match get_surrogate_process_manager() {
            Ok(manager) => match manager.return_surrogate_process(self.process_handle) {
                Ok(_) => (),
                Err(e) => {
                    tracing::error!("Failed to return surrogate process to surrogate process manager when dropping : {:?}", e);
                    return;
                }
            },
            Err(e) => {
                tracing::error!(
                    "Failed to get surrogate process manager when dropping SurrogateProcess: {:?}",
                    e
                );
                return;
            }
        }
    }
}
