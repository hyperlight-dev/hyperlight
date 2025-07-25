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

#[cfg(gdb)]
use std::sync::{Arc, Mutex};

use tracing::{Span, instrument};

use super::mem_mgr::MemMgrWrapper;
use crate::error::HyperlightError::StackOverflow;
#[cfg(gdb)]
use crate::hypervisor::handlers::{DbgMemAccessHandlerCaller, DbgMemAccessHandlerWrapper};
use crate::mem::shared_mem::HostSharedMemory;
use crate::{Result, log_then_return};

#[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
pub(crate) fn handle_mem_access(wrapper: &MemMgrWrapper<HostSharedMemory>) -> Result<()> {
    if !wrapper.check_stack_guard()? {
        log_then_return!(StackOverflow());
    }

    Ok(())
}

#[cfg(gdb)]
struct DbgMemAccessContainer {
    wrapper: MemMgrWrapper<HostSharedMemory>,
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
    wrapper: MemMgrWrapper<HostSharedMemory>,
) -> DbgMemAccessHandlerWrapper {
    let container = DbgMemAccessContainer { wrapper };

    Arc::new(Mutex::new(container))
}
