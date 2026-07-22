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

//! HVF (Hypervisor.framework) backends for macOS on aarch64.
//!
//! Two [`VirtualMachine`] implementations exist:
//!
//! - [`direct::HvfVm`]: the single-VM-per-process backend — HVF binds a VM
//!   to its creating process, so only one sandbox backed by it can exist in
//!   a process at a time. Used when surrogates are disabled
//!   (`HYPERLIGHT_MAX_SURROGATES=0`).
//! - [`surrogate::HvfSurrogateVm`]: delegates each sandbox's VM to a
//!   surrogate helper process over the [`hyperlight_hvf::proto`] IPC
//!   protocol, allowing multiple concurrent sandboxes.
//!
//! The actual HVF logic lives in the shared [`hyperlight_hvf::core`] crate;
//! this module adapts it to the [`VirtualMachine`] trait and hosts the
//! register/exit conversions shared by both backends.

use hyperlight_hvf::core::{self, FpuState, HvfError, Regs, Sregs};
use tracing::{Span, instrument};

use crate::hypervisor::regs::{CommonFpu, CommonRegisters, CommonSpecialRegisters};
use crate::hypervisor::virtual_machine::{HypervisorError, VmExit};

pub(crate) mod direct;
pub(crate) mod surrogate;

pub(crate) use direct::HvfVm;
pub(crate) use surrogate::HvfSurrogateVm;

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
