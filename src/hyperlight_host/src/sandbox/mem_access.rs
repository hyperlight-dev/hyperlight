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

#[instrument(skip_all, parent = Span::current(), level= "Trace")]
pub(crate) fn mem_access_handler_wrapper(
) -> MemAccessHandlerWrapper {
    let mem_access_func: MemAccessHandlerFunction =
        Box::new(move || Ok(()));
    let mem_access_hdl = MemAccessHandler::from(mem_access_func);
    Arc::new(Mutex::new(mem_access_hdl))
}

#[cfg(gdb)]
struct DbgMemAccessContainer {
    wrapper: SandboxMemoryManager<HostSharedMemory>,
}

#[cfg(gdb)]
impl DbgMemAccessHandlerCaller for DbgMemAccessContainer {
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn read(&mut self, addr: usize, data: &mut [u8]) -> Result<()> {
        self.wrapper
            .unwrap_mgr_mut()
            .get_shared_mem_mut()
            .copy_to_slice(data, addr)
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn write(&mut self, addr: usize, data: &[u8]) -> Result<()> {
        self.wrapper
            .unwrap_mgr_mut()
            .get_shared_mem_mut()
            .copy_from_slice(data, addr)
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn get_code_offset(&mut self) -> Result<usize> {
        Ok(self.wrapper.unwrap_mgr().layout.get_guest_code_address())
    }
}

#[cfg(gdb)]
#[instrument(skip_all, parent = Span::current(), level= "Trace")]
pub(crate) fn dbg_mem_access_handler_wrapper(
    wrapper: SandboxMemoryManager<HostSharedMemory>,
) -> DbgMemAccessHandlerWrapper {
    let container = DbgMemAccessContainer { wrapper };

    Arc::new(Mutex::new(container))
}
