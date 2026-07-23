/*
Copyright 2026 The Hyperlight Authors.

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

//! Direct (in-process) HVF backend.
//!
//! Used when surrogates are disabled (`HYPERLIGHT_MAX_SURROGATES=0`). Only
//! one [`HvfVm`] can exist per process — HVF's one-VM-per-process limit —
//! which is enforced by [`NoSurrogateGuard`] so a second VM fails with a
//! clean error instead of a raw `HV_BUSY`.

use std::sync::atomic::{AtomicBool, Ordering};

use hyperlight_hvf::core::{self, HvfError, Perms};

use crate::hypervisor::regs::{CommonFpu, CommonRegisters, CommonSpecialRegisters};
use crate::hypervisor::virtual_machine::{
    CreateVmError, MapMemoryError, RegisterError, ResetVcpuError, RunVcpuError, UnmapMemoryError,
    VirtualMachine, VmExit,
};
#[cfg(feature = "trace_guest")]
use crate::sandbox::trace::TraceContext as SandboxTraceContext;

/// Set while a direct-mode VM exists in this process; cleared when the
/// [`NoSurrogateGuard`] stored on the [`HvfVm`] is dropped.
static DIRECT_VM_ACTIVE: AtomicBool = AtomicBool::new(false);

/// RAII guard that sets [`DIRECT_VM_ACTIVE`] on creation and clears it on
/// drop. Stored as a field on [`HvfVm`] so the flag stays set for exactly
/// the lifetime of the VM (mirrors WHP's `NoSurrogateGuard`).
#[derive(Debug)]
struct NoSurrogateGuard;

impl NoSurrogateGuard {
    fn acquire() -> std::result::Result<Self, CreateVmError> {
        if DIRECT_VM_ACTIVE.swap(true, Ordering::SeqCst) {
            return Err(CreateVmError::SurrogateProcess(
                "HYPERLIGHT_MAX_SURROGATES=0 limits the process to a single VM; \
                 a VM is already active"
                    .into(),
            ));
        }
        Ok(Self)
    }
}

impl Drop for NoSurrogateGuard {
    fn drop(&mut self) {
        DIRECT_VM_ACTIVE.store(false, Ordering::SeqCst);
    }
}

/// The direct (in-process) HVF implementation of a single-vcpu VM.
#[derive(Debug)]
pub(crate) struct HvfVm {
    inner: core::Vm,
    /// Clears [`DIRECT_VM_ACTIVE`] when this VM is dropped.
    _no_surrogate_guard: NoSurrogateGuard,
}

impl HvfVm {
    pub(crate) fn new() -> std::result::Result<Self, CreateVmError> {
        let guard = NoSurrogateGuard::acquire()?;
        Ok(Self {
            inner: core::Vm::new().map_err(|e| CreateVmError::CreateVmFd(e.into()))?,
            _no_surrogate_guard: guard,
        })
    }

    /// The raw HVF vCPU ID, used to construct the local interrupt handle
    /// (`hv_vcpus_exit` may be called from any thread).
    pub(crate) fn vcpu_id(&self) -> u64 {
        self.inner.vcpu_id()
    }
}

impl VirtualMachine for HvfVm {
    unsafe fn map_memory(
        &mut self,
        (slot, region): (u32, &crate::mem::memory_region::MemoryRegion),
    ) -> std::result::Result<(), MapMemoryError> {
        let perms = Perms {
            read: region
                .flags
                .contains(crate::mem::memory_region::MemoryRegionFlags::READ),
            write: region
                .flags
                .contains(crate::mem::memory_region::MemoryRegionFlags::WRITE),
            exec: region
                .flags
                .contains(crate::mem::memory_region::MemoryRegionFlags::EXECUTE),
        };
        // SAFETY: the caller guarantees the host region is valid and outlives
        // the mapping (see the trait's `map_memory` contract).
        unsafe {
            self.inner.map_memory(
                slot,
                region.guest_region.start as u64,
                usize::from(region.host_region.start.clone()),
                region.guest_region.end - region.guest_region.start,
                perms,
            )
        }
        .map_err(|e| MapMemoryError::Hypervisor(e.into()))
    }

    fn unmap_memory(
        &mut self,
        (slot, region): (u32, &crate::mem::memory_region::MemoryRegion),
    ) -> std::result::Result<(), UnmapMemoryError> {
        self.inner
            .unmap_memory(
                slot,
                region.guest_region.start as u64,
                region.guest_region.end - region.guest_region.start,
            )
            .map_err(|e| UnmapMemoryError::Hypervisor(e.into()))
    }

    fn run_vcpu(
        &mut self,
        #[cfg(feature = "trace_guest")] tc: &mut SandboxTraceContext,
    ) -> std::result::Result<VmExit, RunVcpuError> {
        #[cfg(feature = "trace_guest")]
        let _ = tc;
        match self.inner.run_vcpu() {
            Ok(exit) => Ok(exit.into()),
            Err(HvfError::NoInstructionSyndrome) => Err(RunVcpuError::ParseGpaAccessInfo),
            Err(e) => Err(RunVcpuError::Unknown(e.into())),
        }
    }

    fn regs(&self) -> std::result::Result<CommonRegisters, RegisterError> {
        self.inner
            .regs()
            .map(Into::into)
            .map_err(|e| RegisterError::GetRegs(e.into()))
    }

    fn set_regs(&self, regs: &CommonRegisters) -> std::result::Result<(), RegisterError> {
        self.inner
            .set_regs(&regs.into())
            .map_err(|e| RegisterError::SetRegs(e.into()))
    }

    fn fpu(&self) -> std::result::Result<CommonFpu, RegisterError> {
        self.inner
            .fpu()
            .map(Into::into)
            .map_err(|e| RegisterError::GetFpu(e.into()))
    }

    fn set_fpu(&self, fpu: &CommonFpu) -> std::result::Result<(), RegisterError> {
        self.inner
            .set_fpu(&fpu.into())
            .map_err(|e| RegisterError::SetFpu(e.into()))
    }

    fn sregs(&self) -> std::result::Result<CommonSpecialRegisters, RegisterError> {
        self.inner
            .sregs()
            .map(Into::into)
            .map_err(|e| RegisterError::GetSregs(e.into()))
    }

    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> std::result::Result<(), RegisterError> {
        self.inner
            .set_sregs(&sregs.into())
            .map_err(|e| RegisterError::SetSregs(e.into()))
    }

    fn debug_regs(
        &self,
    ) -> std::result::Result<crate::hypervisor::regs::CommonDebugRegs, RegisterError> {
        todo!("debug registers are not supported on aarch64")
    }

    fn set_debug_regs(
        &self,
        _drs: &crate::hypervisor::regs::CommonDebugRegs,
    ) -> std::result::Result<(), RegisterError> {
        todo!("debug registers are not supported on aarch64")
    }

    fn can_reset_vcpu(&self) -> bool {
        true
    }

    fn reset_vcpu(&mut self) -> std::result::Result<(), ResetVcpuError> {
        // HVF has no "vcpu init" operation like KVM's KVM_ARM_VCPU_INIT;
        // `core::Vm::reset_vcpu` emulates it. Special registers are
        // applied separately by the caller (`apply_sregs`).
        self.inner
            .reset_vcpu()
            .map_err(|e| ResetVcpuError::Hypervisor(e.into()))
    }
}
