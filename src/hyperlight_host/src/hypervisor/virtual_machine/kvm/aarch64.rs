/*
Copyright 2025 The Hyperlight Authors.

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

// TODO(aarch64): implement KVM backend

use tracing::{Span, instrument};

use crate::hypervisor::virtual_machine::CreateVmError;

/// Return `true` if the KVM API is available
#[instrument(skip_all, parent = Span::current(), level = "Trace")]
pub(crate) fn is_hypervisor_present() -> bool {
    // TODO(aarch64): implement KVM detection
    false
}

/// A KVM implementation of a single-vcpu VM
#[derive(Debug)]
pub(crate) struct KvmVm {
    _placeholder: (),
}

impl KvmVm {
    pub(crate) fn new() -> std::result::Result<Self, CreateVmError> {
        unimplemented!("KvmVm::new")
    }
}

impl VirtualMachine for KvmVm {
    fn regs(&self) -> std::result::Result<CommonRegisters, RegisterError> {
        use crate::hypervisor::regs::kvm_reg::{X, SP, PC, PSTATE};
        let mut x: [u64; 31] = [0; 31];
        for i in 0..31 {
            x[i] = X[i].get(RegisterError::GetSregs, &self.vcpu_fd)?;
        }
        Ok(CommonRegisters {
            x,
            sp: SP.get(RegisterError::GetSregs, &self.vcpu_fd)?,
            pc: PC.get(RegisterError::GetSregs, &self.vcpu_fd)?,
            pstate: PSTATE.get(RegisterError::GetSregs, &self.vcpu_fd)?,
        })
    }

    fn set_regs(&self, regs: &CommonRegisters) -> std::result::Result<(), RegisterError> {
        use crate::hypervisor::regs::kvm_reg::{X, SP, PC, PSTATE};
        for i in 0..31 {
            X[i].set(RegisterError::SetSregs, &self.vcpu_fd, regs.x[i])?;
        }
        SP.set(RegisterError::SetSregs, &self.vcpu_fd, regs.sp)?;
        PC.set(RegisterError::SetSregs, &self.vcpu_fd, regs.pc)?;
        PSTATE.set(RegisterError::SetSregs, &self.vcpu_fd, regs.pstate)?;

        Ok(())
    }

    fn fpu(&self) -> Result<CommonFpu, RegisterError> {
        use crate::hypervisor::regs::kvm_reg::{V, FPSR, FPCR};
        let mut v: [u128; 32] = [0; 32];
        for i in 0..32 {
            v[i] = V[i].get(RegisterError::GetFpu, &self.vcpu_fd)?;
        }
        Ok(CommonFpu {
            v,
            fpsr: FPSR.get(RegisterError::GetFpu, &self.vcpu_fd)?,
            fpcr: FPCR.get(RegisterError::GetFpu, &self.vcpu_fd)?,
        })
    }

    fn set_fpu(&self, fpu: &CommonFpu) -> Result<(), RegisterError> {
        use crate::hypervisor::regs::kvm_reg::{V, FPSR, FPCR};
        for i in 0..32 {
            V[i].set(RegisterError::SetFpu, &self.vcpu_fd, fpu.v[0])?;
        }
        FPSR.set(RegisterError::SetFpu, &self.vcpu_fd, fpu.fpsr)?;
        FPCR.set(RegisterError::SetFpu, &self.vcpu_fd, fpu.fpcr)?;
        Ok(())
    }

    fn sregs(&self) -> Result<CommonSpecialRegisters, RegisterError> {
        use crate::hypervisor::regs::kvm_reg::{
            TTBR0_EL1, TCR_EL1, MAIR_EL1, SCTLR_EL1, CPACR_EL1, VBAR_EL1, SP_EL1,
        };
        Ok(CommonSpecialRegisters {
            ttbr0_el1: TTBR0_EL1.get(RegisterError::GetSregs, &self.vcpu_fd)?,
            tcr_el1: TCR_EL1.get(RegisterError::GetSregs, &self.vcpu_fd)?,
            mair_el1: MAIR_EL1.get(RegisterError::GetSregs, &self.vcpu_fd)?,
            sctlr_el1: SCTLR_EL1.get(RegisterError::GetSregs, &self.vcpu_fd)?,
            cpacr_el1: CPACR_EL1.get(RegisterError::GetSregs, &self.vcpu_fd)?,
            vbar_el1: VBAR_EL1.get(RegisterError::GetSregs, &self.vcpu_fd)?,
            sp_el1: SP_EL1.get(RegisterError::GetSregs, &self.vcpu_fd)?,
        })
    }

    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> Result<(), RegisterError> {
        use crate::hypervisor::regs::kvm_reg::{
            TTBR0_EL1, TCR_EL1, MAIR_EL1, SCTLR_EL1, CPACR_EL1, VBAR_EL1, SP_EL1,
        };
        TTBR0_EL1.set(RegisterError::SetSregs, &self.vcpu_fd, sregs.ttbr0_el1)?;
        TCR_EL1.set(RegisterError::SetSregs, &self.vcpu_fd, sregs.tcr_el1)?;
        MAIR_EL1.set(RegisterError::SetSregs, &self.vcpu_fd, sregs.mair_el1)?;
        SCTLR_EL1.set(RegisterError::SetSregs, &self.vcpu_fd, sregs.sctlr_el1)?;
        CPACR_EL1.set(RegisterError::SetSregs, &self.vcpu_fd, sregs.cpacr_el1)?;
        VBAR_EL1.set(RegisterError::SetSregs, &self.vcpu_fd, sregs.vbar_el1)?;
        SP_EL1.set(RegisterError::SetSregs, &self.vcpu_fd, sregs.sp_el1)?;

        Ok(())
    }

    fn debug_regs(
        &self,
    ) -> std::result::Result<crate::hypervisor::regs::CommonDebugRegs, RegisterError> {
        todo!()
    }

    fn set_debug_regs(
        &self,
        _drs: &crate::hypervisor::regs::CommonDebugRegs,
    ) -> std::result::Result<(), RegisterError> {
        todo!()
    }

    fn xsave(&self) -> std::result::Result<Vec<u8>, RegisterError> {
        unimplemented!("aarch64 does not support XSAVE operations")
    }

    fn reset_xsave(&self) -> std::result::Result<(), RegisterError> {
        unimplemented!("aarch64 does not support XSAVE operations")
    }

    #[cfg(test)]
    fn set_xsave(&self, xsave: &[u32]) -> std::result::Result<(), RegisterError> {
        unimplemented!("aarch64 does not support XSAVE operations")
    }

    }
}
