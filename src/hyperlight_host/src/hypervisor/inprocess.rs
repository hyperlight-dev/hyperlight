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

use std::fmt::Debug;
use std::os::raw::c_void;

#[cfg(gdb)]
use super::handlers::DbgMemAccessHandlerWrapper;
use super::{HyperlightExit, Hypervisor};
#[cfg(crashdump)]
use crate::mem::memory_region::MemoryRegion;
use crate::sandbox::leaked_outb::LeakedOutBWrapper;
use crate::Result;

/// Arguments passed to inprocess driver
pub struct InprocessArgs<'a> {
    /// raw ptr to guest's entrypoint fn. Since we are in-process mode, this is a ptr in the host's address space
    pub entrypoint_raw: u64,
    /// raw ptr to peb structure. Since we are in-process mode, this is a ptr in the host's address space
    pub peb_ptr_raw: u64,
    // compiler can't tell that we are actually using this in a deeply unsafe way.
    #[allow(dead_code)]
    pub(crate) leaked_outb_wrapper: LeakedOutBWrapper<'a>,
}

/// Arguments passed to inprocess driver
pub struct InprocessDriver<'a> {
    args: InprocessArgs<'a>,
}

impl Debug for InprocessArgs<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InprocessArgs")
            .field("entrypoint_raw", &self.entrypoint_raw)
            .field("peb_ptr_raw", &self.peb_ptr_raw)
            .finish()
    }
}

impl<'a> InprocessDriver<'a> {
    /// Create a new InprocessDriver. This should only be used in testing/debugging,
    /// since it doesn't run the guest code in a hypervisor
    pub fn new(args: InprocessArgs<'a>) -> Result<Self> {
        Ok(Self { args })
    }
}

impl Debug for InprocessDriver<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InprocessDriver")
            .field("args", &self.args)
            .finish()
    }
}

impl<'a> Hypervisor for InprocessDriver<'a> {
    fn initialise(
        &mut self,
        _peb_addr: crate::mem::ptr::RawPtr,
        seed: u64,
        page_size: u32,
        _outb_handle_fn: super::handlers::OutBHandlerWrapper,
        _mem_access_fn: super::handlers::MemAccessHandlerWrapper,
        _hv_handler: Option<super::hypervisor_handler::HypervisorHandler>,
        #[cfg(gdb)] _dbg_mem_access_fn: DbgMemAccessHandlerWrapper,
    ) -> crate::Result<()> {
        let entrypoint_fn: extern "win64" fn(u64, u64, u64, u64) =
            unsafe { std::mem::transmute(self.args.entrypoint_raw as *const c_void) };

        entrypoint_fn(
            self.args.peb_ptr_raw,
            seed,
            page_size as u64,
            log::max_level() as u64,
        );

        Ok(())
    }

    fn dispatch_call_from_host(
        &mut self,
        dispatch_func_addr: crate::mem::ptr::RawPtr,
        _outb_handle_fn: super::handlers::OutBHandlerWrapper,
        _mem_access_fn: super::handlers::MemAccessHandlerWrapper,
        _hv_handler: Option<super::hypervisor_handler::HypervisorHandler>,
        #[cfg(gdb)] _dbg_mem_access_fn: DbgMemAccessHandlerWrapper,
    ) -> crate::Result<()> {
        let ptr: u64 = dispatch_func_addr.into();
        let dispatch_func: extern "win64" fn() =
            unsafe { std::mem::transmute(ptr as *const c_void) };

        dispatch_func();
        Ok(())
    }

    fn handle_io(
        &mut self,
        _port: u16,
        _data: Vec<u8>,
        _rip: u64,
        _instruction_length: u64,
        _outb_handle_fn: super::handlers::OutBHandlerWrapper,
    ) -> crate::Result<()> {
        unimplemented!("handle_io should not be needed since we are in in-process mode")
    }

    fn run(&mut self) -> Result<HyperlightExit> {
        unimplemented!("run should not be needed since we are in in-process mode")
    }

    fn as_mut_hypervisor(&mut self) -> &mut dyn Hypervisor {
        self
    }

    #[cfg(target_os = "windows")]
    fn get_partition_handle(&self) -> windows::Win32::System::Hypervisor::WHV_PARTITION_HANDLE {
        unimplemented!("get_partition_handle should not be needed since we are in in-process mode")
    }

    #[cfg(crashdump)]
    fn get_memory_regions(&self) -> &[MemoryRegion] {
        unimplemented!("get_memory_regions is not supported since we are in in-process mode")
    }
}
