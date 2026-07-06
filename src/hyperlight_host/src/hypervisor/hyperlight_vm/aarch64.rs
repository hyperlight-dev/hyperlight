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
use crate::hypervisor::InterruptHandleImpl;
#[cfg(any(kvm, mshv3))]
use crate::hypervisor::LinuxInterruptHandle;
#[cfg(gdb)]
use crate::hypervisor::gdb::{DebugCommChannel, DebugMsg, DebugResponse};
use crate::hypervisor::hyperlight_vm::get_guest_log_filter;
use crate::hypervisor::regs::{CommonFpu, CommonRegisters, CommonSpecialRegisters};
#[cfg(kvm)]
use crate::hypervisor::virtual_machine::kvm::KvmVm;
use crate::hypervisor::virtual_machine::{
    HypervisorType, RegisterError, ResetVcpuError, VirtualMachine, VmError,
    get_available_hypervisor,
};
use crate::mem::mgr::{SandboxMemoryManager, SnapshotSharedMemory};
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
    #[cfg_attr(target_os = "macos", allow(unused))]
    pub(crate) fn new(
        snapshot_mem: SnapshotSharedMemory<GuestSharedMemory>,
        scratch_mem: GuestSharedMemory,
        root_pt_addr: u64,
        next_action: NextAction,
        rsp_gva: u64,
        page_size: usize,
        config: &SandboxConfiguration,
        #[cfg(gdb)] _gdb_conn: Option<DebugCommChannel<DebugResponse, DebugMsg>>,
        #[cfg(crashdump)] _rt_cfg: SandboxRuntimeConfig,
        #[cfg(feature = "mem_profile")] _trace_info: MemTraceInfo,
    ) -> std::result::Result<Self, CreateHyperlightVmError> {
        // TODO: support gdb on aarch64
        type VmType = Box<dyn VirtualMachine>;
        let vm: VmType = match get_available_hypervisor() {
            #[cfg(kvm)]
            Some(HypervisorType::Kvm) => Box::new(KvmVm::new().map_err(VmError::CreateVm)?),
            // TODO: mshv support
            #[cfg(mshv3)]
            Some(HypervisorType::Mshv) => return Err(CreateHyperlightVmError::NoHypervisorFound),
            #[cfg(hvf)]
            Some(HypervisorType::Hvf) => return Err(CreateHyperlightVmError::NoHypervisorFound),
            None => return Err(CreateHyperlightVmError::NoHypervisorFound),
        };
        vm.set_sregs(&CommonSpecialRegisters::defaults(root_pt_addr))
            .map_err(VmError::Register)?;
        #[cfg(any(kvm, mshv3))]
        let interrupt_handle: Arc<dyn InterruptHandleImpl> =
            Arc::new(LinuxInterruptHandle::new(config));

        let snapshot_slot = 0u32;
        let scratch_slot = 1u32;
        let vm_can_reset_vcpu = vm.can_reset_vcpu();
        let mut ret = Self {
            vm,
            next_action,
            rsp_gva,
            interrupt_handle,
            page_size,

            next_slot: scratch_slot + 1,
            freed_slots: Vec::new(),

            snapshot_slot,
            snapshot_memory: None,
            scratch_slot,
            scratch_memory: None,

            mmap_regions: Vec::new(),

            vm_can_reset_vcpu,
            pending_tlb_flush: false,
        };
        ret.update_snapshot_mapping(snapshot_mem)?;
        ret.update_scratch_mapping(scratch_mem)?;
        Ok(ret)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn initialise(
        &mut self,
        peb_addr: crate::mem::ptr::RawPtr,
        seed: u64,
        mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
        host_funcs: &Arc<std::sync::Mutex<FunctionRegistry>>,
        guest_max_log_level: Option<tracing_core::LevelFilter>,
        #[cfg(gdb)] dbg_mem_access_fn: Arc<
            std::sync::Mutex<SandboxMemoryManager<HostSharedMemory>>,
        >,
    ) -> Result<(), InitializeError> {
        let NextAction::Initialise(initialise) = self.next_action else {
            return Ok(());
        };
        let mut x: [u64; 31] = [0; 31];
        x[0] = peb_addr.into();
        x[1] = seed;
        x[2] = self.page_size as u64;
        x[3] = get_guest_log_filter(guest_max_log_level);
        let regs = CommonRegisters {
            pc: initialise,
            sp: self.rsp_gva,
            x,
            // start up with interrupts disabled in EL1t
            pstate: 0b11 << 6 | 0b100,
        };
        self.vm.set_regs(&regs)?;

        self.run(
            mem_mgr,
            host_funcs,
            #[cfg(gdb)]
            dbg_mem_access_fn,
        )
        .map_err(InitializeError::Run)?;

        let regs = self.vm.regs()?;
        if !regs.sp.is_multiple_of(16) {
            return Err(InitializeError::InvalidStackPointer(regs.sp));
        }
        self.rsp_gva = regs.sp;
        self.next_action = NextAction::Call(regs.x[0]);

        Ok(())
    }

    pub(crate) fn dispatch_call_from_host(
        &mut self,
        mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
        host_funcs: &Arc<std::sync::Mutex<FunctionRegistry>>,
        #[cfg(gdb)] dbg_mem_access_fn: Arc<
            std::sync::Mutex<SandboxMemoryManager<HostSharedMemory>>,
        >,
    ) -> Result<(), DispatchGuestCallError> {
        let NextAction::Call(dispatch_func_addr) = self.next_action else {
            return Err(DispatchGuestCallError::Uninitialized);
        };
        let mut regs = CommonRegisters {
            pc: dispatch_func_addr,
            sp: self.rsp_gva,
            // start with interrupts disabled in EL1t
            pstate: 0b11 << 6 | 0b100,
            ..Default::default()
        };
        if self.pending_tlb_flush {
            regs.pc += 4;
        }
        self.vm
            .set_regs(&regs)
            .map_err(DispatchGuestCallError::SetupRegs)?;
        self.vm
            .set_fpu(&CommonFpu::default())
            .map_err(DispatchGuestCallError::SetupRegs)?;
        let result = self
            .run(
                mem_mgr,
                host_funcs,
                #[cfg(gdb)]
                dbg_mem_access_fn,
            )
            .map_err(DispatchGuestCallError::Run);
        self.pending_tlb_flush = false;
        result
    }

    pub(crate) fn get_root_pt(&self) -> Result<u64, AccessPageTableError> {
        let sregs = self.vm.sregs()?;
        Ok(sregs.ttbr0_el1 & ((1 << 48) - 2))
    }

    pub(crate) fn get_snapshot_sregs(
        &mut self,
    ) -> Result<CommonSpecialRegisters, AccessPageTableError> {
        let x = self.vm.sregs()?;
        Ok(x)
    }

    pub(crate) fn reset_vcpu(
        &mut self,
        cr3: u64,
        sregs: &CommonSpecialRegisters,
    ) -> std::result::Result<(), ResetVcpuError> {
        debug_assert!(
            self.vm_can_reset_vcpu,
            "No fallback path for vcpu reset on aarch64"
        );
        self.vm.reset_vcpu()?;
        self.apply_sregs(cr3, sregs)?;
        Ok(())
    }

    pub(crate) fn apply_sregs(
        &mut self,
        cr3: u64,
        sregs: &CommonSpecialRegisters,
    ) -> std::result::Result<(), RegisterError> {
        let mut sregs = *sregs;
        sregs.ttbr0_el1 = cr3 & ((1 << 48) - 2);
        self.pending_tlb_flush = true;

        self.vm.set_sregs(&sregs)
    }
}
