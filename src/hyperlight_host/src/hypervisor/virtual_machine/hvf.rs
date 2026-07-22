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

//! Direct HVF (Hypervisor.framework) backend for macOS on aarch64.
//!
//! This is the single-VM-per-process backend: HVF binds a VM to its creating
//! process, so only one sandbox backed by [`HvfVm`] can exist in a process at
//! a time. Multi-sandbox support uses the surrogate-process backend instead
//! (see `super::hvf_surrogate`), which delegates each sandbox's VM to a
//! helper process. The actual HVF logic lives in the shared
//! [`hyperlight_hvf::core`] crate; this file adapts it to the
//! [`VirtualMachine`] trait.

use hyperlight_hvf::core::{self, FpuState, HvfError, Perms, Regs, Sregs};
use tracing::{Span, instrument};

use crate::hypervisor::regs::{CommonFpu, CommonRegisters, CommonSpecialRegisters};
use crate::hypervisor::virtual_machine::{
    CreateVmError, HypervisorError, MapMemoryError, RegisterError, RunVcpuError, UnmapMemoryError,
    VirtualMachine, VmExit,
};

/// Return `true` if Hypervisor.framework is available.
///
/// Requires the calling binary to hold the `com.apple.security.hypervisor`
/// entitlement; unsigned test binaries must be ad-hoc codesigned with it.
#[instrument(skip_all, parent = Span::current(), level = "Trace")]
pub(crate) fn is_hypervisor_present() -> bool {
    core::is_hypervisor_present()
}

impl From<HvfError> for HypervisorError {
    fn from(e: HvfError) -> Self {
        match e {
            HvfError::Hv(code) => HypervisorError::HvfError(code),
            HvfError::NoInstructionSyndrome => HypervisorError::HvfError(0),
        }
    }
}

impl From<Regs> for CommonRegisters {
    fn from(r: Regs) -> Self {
        CommonRegisters {
            x: r.x,
            sp: r.sp,
            pc: r.pc,
            pstate: r.pstate,
        }
    }
}

impl From<&CommonRegisters> for Regs {
    fn from(r: &CommonRegisters) -> Self {
        Regs {
            x: r.x,
            sp: r.sp,
            pc: r.pc,
            pstate: r.pstate,
        }
    }
}

impl From<FpuState> for CommonFpu {
    fn from(f: FpuState) -> Self {
        CommonFpu {
            v: f.v,
            fpsr: f.fpsr,
            fpcr: f.fpcr,
        }
    }
}

impl From<&CommonFpu> for FpuState {
    fn from(f: &CommonFpu) -> Self {
        FpuState {
            v: f.v,
            fpsr: f.fpsr,
            fpcr: f.fpcr,
        }
    }
}

impl From<Sregs> for CommonSpecialRegisters {
    fn from(s: Sregs) -> Self {
        CommonSpecialRegisters {
            ttbr0_el1: s.ttbr0_el1,
            tcr_el1: s.tcr_el1,
            mair_el1: s.mair_el1,
            sctlr_el1: s.sctlr_el1,
            cpacr_el1: s.cpacr_el1,
            vbar_el1: s.vbar_el1,
            sp_el1: s.sp_el1,
        }
    }
}

impl From<&CommonSpecialRegisters> for Sregs {
    fn from(s: &CommonSpecialRegisters) -> Self {
        Sregs {
            ttbr0_el1: s.ttbr0_el1,
            tcr_el1: s.tcr_el1,
            mair_el1: s.mair_el1,
            sctlr_el1: s.sctlr_el1,
            cpacr_el1: s.cpacr_el1,
            vbar_el1: s.vbar_el1,
            sp_el1: s.sp_el1,
        }
    }
}

impl From<core::VmExit> for VmExit {
    fn from(e: core::VmExit) -> Self {
        match e {
            core::VmExit::Halt => VmExit::Halt(),
            core::VmExit::IoOut(port, data) => VmExit::IoOut(port, data),
            core::VmExit::MmioRead(addr) => VmExit::MmioRead(addr),
            core::VmExit::MmioWrite(addr) => VmExit::MmioWrite(addr),
            core::VmExit::Cancelled => VmExit::Cancelled(),
            core::VmExit::Unknown(msg) => VmExit::Unknown(msg),
        }
    }
}

/// The direct (in-process) HVF implementation of a single-vcpu VM.
#[derive(Debug)]
pub(crate) struct HvfVm {
    inner: core::Vm,
}

impl HvfVm {
    pub(crate) fn new() -> std::result::Result<Self, CreateVmError> {
        Ok(Self {
            inner: core::Vm::new().map_err(|e| CreateVmError::CreateVmFd(e.into()))?,
        })
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

    fn vcpu_id(&self) -> u64 {
        self.inner.vcpu_id()
    }
}
