// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use std::collections::VecDeque;

use super::*;
#[cfg(target_arch = "x86_64")]
use crate::hypervisor::regs::MsrEntry;
use crate::hypervisor::regs::{
    CommonDebugRegs, CommonFpu, CommonRegisters, CommonSpecialRegisters,
};
#[cfg(target_arch = "x86_64")]
use crate::hypervisor::virtual_machine::CreateVmError;
use crate::hypervisor::virtual_machine::{HypervisorError, VirtualMachine};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VmOperation {
    Map(MemoryRegionType),
    Unmap(MemoryRegionType),
    #[cfg(target_arch = "x86_64")]
    SetRegs,
    #[cfg(target_arch = "x86_64")]
    SetDebugRegs,
    #[cfg(target_arch = "x86_64")]
    ResetXsave,
    #[cfg(target_arch = "x86_64")]
    SetSregs,
    #[cfg(target_arch = "x86_64")]
    SetMsrs,
    #[cfg(target_arch = "aarch64")]
    ResetVcpu,
}

#[derive(Clone, Debug)]
pub(crate) struct VmFaultPlan {
    operations: Arc<Mutex<VecDeque<VmOperation>>>,
}

impl VmFaultPlan {
    fn new(operations: impl IntoIterator<Item = VmOperation>) -> Self {
        Self {
            operations: Arc::new(Mutex::new(operations.into_iter().collect())),
        }
    }

    pub(crate) fn is_consumed(&self) -> bool {
        self.operations.lock().unwrap().is_empty()
    }

    fn should_fail(&self, operation: VmOperation) -> bool {
        let mut operations = self.operations.lock().unwrap();
        if operations.front() == Some(&operation) {
            operations.pop_front();
            true
        } else {
            false
        }
    }
}

#[derive(Debug)]
struct FaultInjectingVirtualMachine {
    inner: Option<Box<dyn VirtualMachine>>,
    fault_plan: VmFaultPlan,
}

impl FaultInjectingVirtualMachine {
    fn new(
        inner: Box<dyn VirtualMachine>,
        operations: impl IntoIterator<Item = VmOperation>,
    ) -> (Self, VmFaultPlan) {
        let fault_plan = VmFaultPlan::new(operations);
        (
            Self {
                inner: Some(inner),
                fault_plan: fault_plan.clone(),
            },
            fault_plan,
        )
    }

    fn placeholder() -> Self {
        Self {
            inner: None,
            fault_plan: VmFaultPlan::new([]),
        }
    }

    fn inner(&self) -> &dyn VirtualMachine {
        self.inner.as_deref().expect("placeholder VM was used")
    }

    fn inner_mut(&mut self) -> &mut dyn VirtualMachine {
        self.inner.as_deref_mut().expect("placeholder VM was used")
    }

    fn should_fail(&self, operation: VmOperation) -> bool {
        self.fault_plan.should_fail(operation)
    }

    fn injected_error() -> HypervisorError {
        HypervisorError::Injected
    }
}

impl VirtualMachine for FaultInjectingVirtualMachine {
    unsafe fn map_memory(
        &mut self,
        region: (u32, &MemoryRegion),
    ) -> std::result::Result<(), MapMemoryError> {
        if self.should_fail(VmOperation::Map(region.1.region_type)) {
            return Err(MapMemoryError::Hypervisor(Self::injected_error()));
        }
        // SAFETY: The decorator forwards the caller's preconditions unchanged.
        unsafe { self.inner_mut().map_memory(region) }
    }

    fn unmap_memory(
        &mut self,
        region: (u32, &MemoryRegion),
    ) -> std::result::Result<(), UnmapMemoryError> {
        if self.should_fail(VmOperation::Unmap(region.1.region_type)) {
            return Err(UnmapMemoryError::Hypervisor(Self::injected_error()));
        }
        self.inner_mut().unmap_memory(region)
    }

    fn run_vcpu(
        &mut self,
        #[cfg(feature = "trace_guest")] tc: &mut crate::sandbox::trace::TraceContext,
    ) -> std::result::Result<VmExit, RunVcpuError> {
        self.inner_mut().run_vcpu(
            #[cfg(feature = "trace_guest")]
            tc,
        )
    }

    fn regs(&self) -> std::result::Result<CommonRegisters, RegisterError> {
        self.inner().regs()
    }

    fn set_regs(&mut self, regs: &CommonRegisters) -> std::result::Result<(), RegisterError> {
        #[cfg(target_arch = "x86_64")]
        if self.should_fail(VmOperation::SetRegs) {
            return Err(RegisterError::SetRegs(Self::injected_error()));
        }
        self.inner_mut().set_regs(regs)
    }

    fn fpu(&self) -> std::result::Result<CommonFpu, RegisterError> {
        self.inner().fpu()
    }

    fn set_fpu(&mut self, fpu: &CommonFpu) -> std::result::Result<(), RegisterError> {
        self.inner_mut().set_fpu(fpu)
    }

    fn sregs(&self) -> std::result::Result<CommonSpecialRegisters, RegisterError> {
        self.inner().sregs()
    }

    fn set_sregs(
        &mut self,
        sregs: &CommonSpecialRegisters,
    ) -> std::result::Result<(), RegisterError> {
        #[cfg(target_arch = "x86_64")]
        if self.should_fail(VmOperation::SetSregs) {
            return Err(RegisterError::SetSregs(Self::injected_error()));
        }
        self.inner_mut().set_sregs(sregs)
    }

    fn debug_regs(&self) -> std::result::Result<CommonDebugRegs, RegisterError> {
        self.inner().debug_regs()
    }

    fn set_debug_regs(&self, drs: &CommonDebugRegs) -> std::result::Result<(), RegisterError> {
        #[cfg(target_arch = "x86_64")]
        if self.should_fail(VmOperation::SetDebugRegs) {
            return Err(RegisterError::SetDebugRegs(Self::injected_error()));
        }
        self.inner().set_debug_regs(drs)
    }

    #[cfg(target_arch = "x86_64")]
    fn msrs(&self, indices: &[u32]) -> std::result::Result<Vec<MsrEntry>, RegisterError> {
        self.inner().msrs(indices)
    }

    #[cfg(target_arch = "x86_64")]
    fn set_msrs(&self, msrs: &[MsrEntry]) -> std::result::Result<(), RegisterError> {
        if self.should_fail(VmOperation::SetMsrs) {
            return Err(RegisterError::SetMsrs(Self::injected_error()));
        }
        self.inner().set_msrs(msrs)
    }

    #[cfg(target_arch = "x86_64")]
    fn msr_reset_indices(
        &self,
        guest_msrs: &[u32],
    ) -> std::result::Result<Vec<u32>, CreateVmError> {
        self.inner().msr_reset_indices(guest_msrs)
    }

    #[cfg(not(target_arch = "aarch64"))]
    fn xsave(&self) -> std::result::Result<Vec<u8>, RegisterError> {
        self.inner().xsave()
    }

    #[cfg(not(target_arch = "aarch64"))]
    fn reset_xsave(&self) -> std::result::Result<(), RegisterError> {
        #[cfg(target_arch = "x86_64")]
        if self.should_fail(VmOperation::ResetXsave) {
            return Err(RegisterError::SetXsave(Self::injected_error()));
        }
        self.inner().reset_xsave()
    }

    #[cfg(not(target_arch = "aarch64"))]
    fn set_xsave(&self, xsave: &[u32]) -> std::result::Result<(), RegisterError> {
        self.inner().set_xsave(xsave)
    }

    #[cfg(all(test, target_arch = "x86_64"))]
    fn xcr0(&self) -> std::result::Result<u64, RegisterError> {
        self.inner().xcr0()
    }

    #[cfg(target_arch = "x86_64")]
    fn set_xcr0(&self, value: u64) -> std::result::Result<(), RegisterError> {
        self.inner().set_xcr0(value)
    }

    #[cfg(target_arch = "aarch64")]
    fn can_reset_vcpu(&self) -> bool {
        self.inner().can_reset_vcpu()
    }

    #[cfg(target_arch = "aarch64")]
    fn reset_vcpu(&mut self) -> std::result::Result<(), ResetVcpuError> {
        if self.should_fail(VmOperation::ResetVcpu) {
            return Err(ResetVcpuError::Hypervisor(Self::injected_error()));
        }
        self.inner_mut().reset_vcpu()
    }

    #[cfg(target_os = "windows")]
    fn partition_handle(&self) -> windows::Win32::System::Hypervisor::WHV_PARTITION_HANDLE {
        self.inner().partition_handle()
    }
}

impl HyperlightVm {
    pub(crate) fn inject_vm_faults(
        &mut self,
        operations: impl IntoIterator<Item = VmOperation>,
    ) -> VmFaultPlan {
        let placeholder = Box::new(FaultInjectingVirtualMachine::placeholder());
        let inner = std::mem::replace(&mut self.vm, placeholder);
        let (vm, fault_plan) = FaultInjectingVirtualMachine::new(inner, operations);
        self.vm = Box::new(vm);
        fault_plan
    }

    #[allow(clippy::type_complexity, reason = "test-only mapping state")]
    pub(crate) fn base_mapping_state(&self) -> (Option<(usize, usize)>, Option<(usize, usize)>) {
        let snapshot = self
            .snapshot_memory
            .as_ref()
            .map(|memory| (memory.base_addr(), memory.mem_size()));
        let scratch = self
            .scratch_memory
            .as_ref()
            .map(|memory| (memory.base_addr(), memory.mem_size()));
        (snapshot, scratch)
    }
}
