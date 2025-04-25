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

use std::sync::{Arc, Mutex};

use tracing::{instrument, Span};

#[cfg(gdb)]
use crate::hypervisor::handlers::{DbgMemAccessHandlerCaller, DbgMemAccessHandlerWrapper};
use crate::hypervisor::handlers::{
    MemAccessHandler, MemAccessHandlerFunction, MemAccessHandlerWrapper,
};
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::shared_mem::HostSharedMemory;
use crate::Result;

#[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
pub(super) fn handle_mem_access_impl(
    wrapper: &SandboxMemoryManager<HostSharedMemory>,
) -> Result<()> {
    wrapper.check_stack_guard()
}

#[instrument(skip_all, parent = Span::current(), level= "Trace")]
pub(crate) fn mem_access_handler_wrapper(
    wrapper: SandboxMemoryManager<HostSharedMemory>,
) -> MemAccessHandlerWrapper {
    let mem_access_func: MemAccessHandlerFunction =
        Box::new(move || handle_mem_access_impl(&wrapper));
    let mem_access_hdl = MemAccessHandler::from(mem_access_func);
    Arc::new(Mutex::new(mem_access_hdl))
}

#[cfg(gdb)]
struct DbgMemAccessContainer {
    wrapper: SandboxMemoryManager<crate::sandbox::HostSharedMemory>,
}

#[cfg(gdb)]
impl DbgMemAccessHandlerCaller for DbgMemAccessContainer {
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn read(&mut self, addr: usize, data: &mut [u8]) -> crate::Result<()> {
        self.wrapper.shared_mem.copy_to_slice(data, addr)
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn write(&mut self, addr: usize, data: &[u8]) -> crate::Result<()> {
        self.wrapper.shared_mem.copy_from_slice(data, addr)
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn get_code_offset(&mut self) -> crate::Result<usize> {
        Ok(self
            .wrapper
            .memory_sections
            .get_guest_code_offset()
            .unwrap())
    }
}

#[cfg(gdb)]
#[instrument(skip_all, parent = Span::current(), level= "Trace")]
pub(crate) fn dbg_mem_access_handler_wrapper(
    wrapper: SandboxMemoryManager<crate::sandbox::HostSharedMemory>,
) -> DbgMemAccessHandlerWrapper {
    let container = DbgMemAccessContainer { wrapper };

    Arc::new(Mutex::new(container))
}
