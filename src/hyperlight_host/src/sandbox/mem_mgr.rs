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

use tracing::{Span, instrument};

use crate::Result;
use crate::mem::layout::SandboxMemoryLayout;
use crate::mem::mgr::{STACK_COOKIE_LEN, SandboxMemoryManager};
use crate::mem::shared_mem::{
    ExclusiveSharedMemory, GuestSharedMemory, HostSharedMemory, SharedMemory,
};

/// StackCookie
pub type StackCookie = [u8; STACK_COOKIE_LEN];

/// A container with methods for accessing `SandboxMemoryManager` and other
/// related objects
#[derive(Clone)]
pub(crate) struct MemMgrWrapper<S>(SandboxMemoryManager<S>, StackCookie);

impl<S: SharedMemory> MemMgrWrapper<S> {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn new(mgr: SandboxMemoryManager<S>, stack_cookie: StackCookie) -> Self {
        Self(mgr, stack_cookie)
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn unwrap_mgr(&self) -> &SandboxMemoryManager<S> {
        &self.0
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn unwrap_mgr_mut(&mut self) -> &mut SandboxMemoryManager<S> {
        &mut self.0
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_stack_cookie(&self) -> &StackCookie {
        &self.1
    }
}

impl<S: SharedMemory> AsMut<SandboxMemoryManager<S>> for MemMgrWrapper<S> {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn as_mut(&mut self) -> &mut SandboxMemoryManager<S> {
        self.unwrap_mgr_mut()
    }
}

impl<S: SharedMemory> AsRef<SandboxMemoryManager<S>> for MemMgrWrapper<S> {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn as_ref(&self) -> &SandboxMemoryManager<S> {
        self.unwrap_mgr()
    }
}

impl MemMgrWrapper<ExclusiveSharedMemory> {
    pub(crate) fn build(
        self,
    ) -> (
        MemMgrWrapper<HostSharedMemory>,
        SandboxMemoryManager<GuestSharedMemory>,
    ) {
        let (hshm, gshm) = self.0.build();
        (MemMgrWrapper(hshm, self.1), gshm)
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn write_memory_layout(&mut self, run_inprocess: bool) -> Result<()> {
        let mgr = self.unwrap_mgr_mut();
        let layout = mgr.layout;
        let shared_mem = mgr.get_shared_mem_mut();
        let mem_size = shared_mem.mem_size();
        let guest_offset = if run_inprocess {
            shared_mem.base_addr()
        } else {
            SandboxMemoryLayout::BASE_ADDRESS
        };
        layout.write(shared_mem, guest_offset, mem_size, run_inprocess)
    }
}

impl MemMgrWrapper<HostSharedMemory> {
    /// Check the stack guard against the given `stack_cookie`.
    ///
    /// Return `Ok(true)` if the given cookie matches the one in guest memory,
    /// and `Ok(false)` otherwise. Return `Err` if it could not be found or
    /// there was some other error.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn check_stack_guard(&self) -> Result<bool> {
        self.unwrap_mgr()
            .check_stack_guard(*self.get_stack_cookie())
    }
}
