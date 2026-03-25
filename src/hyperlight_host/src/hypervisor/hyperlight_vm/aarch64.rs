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

// TODO(aarch64): implement arch-specific HyperlightVm methods

use std::sync::Arc;

use super::{
    AccessPageTableError, CreateHyperlightVmError, DispatchGuestCallError, HyperlightVm,
    InitializeError,
};
#[cfg(gdb)]
use crate::hypervisor::gdb::{DebugCommChannel, DebugMsg, DebugResponse};
use crate::hypervisor::regs::CommonSpecialRegisters;
use crate::hypervisor::virtual_machine::RegisterError;
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::shared_mem::{GuestSharedMemory, HostSharedMemory};
use crate::sandbox::SandboxConfiguration;
use crate::sandbox::host_funcs::FunctionRegistry;
use crate::sandbox::snapshot::NextAction;
#[cfg(feature = "mem_profile")]
use crate::sandbox::trace::MemTraceInfo;
#[cfg(crashdump)]
use crate::sandbox::uninitialized::SandboxRuntimeConfig;

impl HyperlightVm {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        _snapshot_mem: GuestSharedMemory,
        _scratch_mem: GuestSharedMemory,
        _pml4_addr: u64,
        _entrypoint: NextAction,
        _rsp_gva: u64,
        _config: &SandboxConfiguration,
        #[cfg(gdb)] _gdb_conn: Option<DebugCommChannel<DebugResponse, DebugMsg>>,
        #[cfg(crashdump)] _rt_cfg: SandboxRuntimeConfig,
        #[cfg(feature = "mem_profile")] _trace_info: MemTraceInfo,
    ) -> std::result::Result<Self, CreateHyperlightVmError> {
        unimplemented!("new")
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn initialise(
        &mut self,
        _peb_addr: crate::mem::ptr::RawPtr,
        _seed: u64,
        _page_size: u32,
        _mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
        _host_funcs: &Arc<std::sync::Mutex<FunctionRegistry>>,
        _guest_max_log_level: Option<tracing_core::LevelFilter>,
        #[cfg(gdb)] _dbg_mem_access_fn: Arc<
            std::sync::Mutex<SandboxMemoryManager<HostSharedMemory>>,
        >,
    ) -> Result<(), InitializeError> {
        unimplemented!("initialise")
    }

    pub(crate) fn dispatch_call_from_host(
        &mut self,
        _mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
        _host_funcs: &Arc<std::sync::Mutex<FunctionRegistry>>,
        #[cfg(gdb)] _dbg_mem_access_fn: Arc<
            std::sync::Mutex<SandboxMemoryManager<HostSharedMemory>>,
        >,
    ) -> Result<(), DispatchGuestCallError> {
        unimplemented!("dispatch_call_from_host")
    }

    pub(crate) fn get_root_pt(&self) -> Result<u64, AccessPageTableError> {
        unimplemented!("get_root_pt")
    }

    pub(crate) fn get_snapshot_sregs(
        &mut self,
    ) -> Result<CommonSpecialRegisters, AccessPageTableError> {
        unimplemented!("get_snapshot_sregs")
    }

    pub(crate) fn reset_vm_state(&mut self) -> std::result::Result<(), RegisterError> {
        unimplemented!("reset_vm_state")
    }

    pub(crate) fn restore_sregs(
        &mut self,
        _cr3: u64,
        _sregs: &CommonSpecialRegisters,
    ) -> std::result::Result<(), RegisterError> {
        unimplemented!("restore_sregs")
    }
}
