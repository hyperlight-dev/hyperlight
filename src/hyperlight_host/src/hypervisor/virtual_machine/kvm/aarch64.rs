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
    fn regs(&self) -> std::result::Result<crate::hypervisor::regs::CommonRegisters, RegisterError> {
        use crate::hypervisor::regs::CommonRegisters;
        use crate::hypervisor::regs::kvm_reg::get_reg;
        fn err(e: kvm_ioctls::Error) -> RegisterError {
            RegisterError::GetSregs(e.into())
        }
        Ok(CommonRegisters {
            x: [
                get_reg!(&self.vcpu_fd, err, X0, u64)?,
                get_reg!(&self.vcpu_fd, err, X1, u64)?,
                get_reg!(&self.vcpu_fd, err, X2, u64)?,
                get_reg!(&self.vcpu_fd, err, X3, u64)?,
                get_reg!(&self.vcpu_fd, err, X4, u64)?,
                get_reg!(&self.vcpu_fd, err, X5, u64)?,
                get_reg!(&self.vcpu_fd, err, X6, u64)?,
                get_reg!(&self.vcpu_fd, err, X7, u64)?,
                get_reg!(&self.vcpu_fd, err, X8, u64)?,
                get_reg!(&self.vcpu_fd, err, X9, u64)?,
                get_reg!(&self.vcpu_fd, err, X10, u64)?,
                get_reg!(&self.vcpu_fd, err, X11, u64)?,
                get_reg!(&self.vcpu_fd, err, X12, u64)?,
                get_reg!(&self.vcpu_fd, err, X13, u64)?,
                get_reg!(&self.vcpu_fd, err, X14, u64)?,
                get_reg!(&self.vcpu_fd, err, X15, u64)?,
                get_reg!(&self.vcpu_fd, err, X16, u64)?,
                get_reg!(&self.vcpu_fd, err, X17, u64)?,
                get_reg!(&self.vcpu_fd, err, X18, u64)?,
                get_reg!(&self.vcpu_fd, err, X19, u64)?,
                get_reg!(&self.vcpu_fd, err, X20, u64)?,
                get_reg!(&self.vcpu_fd, err, X21, u64)?,
                get_reg!(&self.vcpu_fd, err, X22, u64)?,
                get_reg!(&self.vcpu_fd, err, X23, u64)?,
                get_reg!(&self.vcpu_fd, err, X24, u64)?,
                get_reg!(&self.vcpu_fd, err, X25, u64)?,
                get_reg!(&self.vcpu_fd, err, X26, u64)?,
                get_reg!(&self.vcpu_fd, err, X27, u64)?,
                get_reg!(&self.vcpu_fd, err, X28, u64)?,
                get_reg!(&self.vcpu_fd, err, X29, u64)?,
                get_reg!(&self.vcpu_fd, err, X30, u64)?,
            ],
            sp: get_reg!(&self.vcpu_fd, err, SP, u64)?,
            pc: get_reg!(&self.vcpu_fd, err, PC, u64)?,
            pstate: get_reg!(&self.vcpu_fd, err, PSTATE, u64)?,
        })
    }

    fn set_regs(&self, regs: &CommonRegisters) -> std::result::Result<(), RegisterError> {
        use crate::hypervisor::regs::kvm_reg::set_reg;
        fn err(e: kvm_ioctls::Error) -> RegisterError {
            RegisterError::SetSregs(e.into())
        }
        set_reg!(&self.vcpu_fd, err, X0, u64, regs.x[0])?;
        set_reg!(&self.vcpu_fd, err, X1, u64, regs.x[1])?;
        set_reg!(&self.vcpu_fd, err, X2, u64, regs.x[2])?;
        set_reg!(&self.vcpu_fd, err, X3, u64, regs.x[3])?;
        set_reg!(&self.vcpu_fd, err, X4, u64, regs.x[4])?;
        set_reg!(&self.vcpu_fd, err, X5, u64, regs.x[5])?;
        set_reg!(&self.vcpu_fd, err, X6, u64, regs.x[6])?;
        set_reg!(&self.vcpu_fd, err, X7, u64, regs.x[7])?;
        set_reg!(&self.vcpu_fd, err, X8, u64, regs.x[8])?;
        set_reg!(&self.vcpu_fd, err, X9, u64, regs.x[9])?;
        set_reg!(&self.vcpu_fd, err, X10, u64, regs.x[10])?;
        set_reg!(&self.vcpu_fd, err, X11, u64, regs.x[11])?;
        set_reg!(&self.vcpu_fd, err, X12, u64, regs.x[12])?;
        set_reg!(&self.vcpu_fd, err, X13, u64, regs.x[13])?;
        set_reg!(&self.vcpu_fd, err, X14, u64, regs.x[14])?;
        set_reg!(&self.vcpu_fd, err, X15, u64, regs.x[15])?;
        set_reg!(&self.vcpu_fd, err, X16, u64, regs.x[16])?;
        set_reg!(&self.vcpu_fd, err, X17, u64, regs.x[17])?;
        set_reg!(&self.vcpu_fd, err, X18, u64, regs.x[18])?;
        set_reg!(&self.vcpu_fd, err, X19, u64, regs.x[19])?;
        set_reg!(&self.vcpu_fd, err, X20, u64, regs.x[20])?;
        set_reg!(&self.vcpu_fd, err, X21, u64, regs.x[21])?;
        set_reg!(&self.vcpu_fd, err, X22, u64, regs.x[22])?;
        set_reg!(&self.vcpu_fd, err, X23, u64, regs.x[23])?;
        set_reg!(&self.vcpu_fd, err, X24, u64, regs.x[24])?;
        set_reg!(&self.vcpu_fd, err, X25, u64, regs.x[25])?;
        set_reg!(&self.vcpu_fd, err, X26, u64, regs.x[26])?;
        set_reg!(&self.vcpu_fd, err, X27, u64, regs.x[27])?;
        set_reg!(&self.vcpu_fd, err, X28, u64, regs.x[28])?;
        set_reg!(&self.vcpu_fd, err, X29, u64, regs.x[29])?;
        set_reg!(&self.vcpu_fd, err, X30, u64, regs.x[30])?;
        set_reg!(&self.vcpu_fd, err, SP, u64, regs.sp)?;
        set_reg!(&self.vcpu_fd, err, PC, u64, regs.pc)?;
        set_reg!(&self.vcpu_fd, err, PSTATE, u64, regs.pstate)?;

        Ok(())
    }

    fn fpu(&self) -> Result<CommonFpu, RegisterError> {
        use crate::hypervisor::regs::CommonFpu;
        use crate::hypervisor::regs::kvm_reg::get_reg;
        fn err(e: kvm_ioctls::Error) -> RegisterError {
            RegisterError::GetFpu(e.into())
        }
        Ok(CommonFpu {
            v: [
                get_reg!(&self.vcpu_fd, err, V0, u128)?,
                get_reg!(&self.vcpu_fd, err, V1, u128)?,
                get_reg!(&self.vcpu_fd, err, V2, u128)?,
                get_reg!(&self.vcpu_fd, err, V3, u128)?,
                get_reg!(&self.vcpu_fd, err, V4, u128)?,
                get_reg!(&self.vcpu_fd, err, V5, u128)?,
                get_reg!(&self.vcpu_fd, err, V6, u128)?,
                get_reg!(&self.vcpu_fd, err, V7, u128)?,
                get_reg!(&self.vcpu_fd, err, V8, u128)?,
                get_reg!(&self.vcpu_fd, err, V9, u128)?,
                get_reg!(&self.vcpu_fd, err, V10, u128)?,
                get_reg!(&self.vcpu_fd, err, V11, u128)?,
                get_reg!(&self.vcpu_fd, err, V12, u128)?,
                get_reg!(&self.vcpu_fd, err, V13, u128)?,
                get_reg!(&self.vcpu_fd, err, V14, u128)?,
                get_reg!(&self.vcpu_fd, err, V15, u128)?,
                get_reg!(&self.vcpu_fd, err, V16, u128)?,
                get_reg!(&self.vcpu_fd, err, V17, u128)?,
                get_reg!(&self.vcpu_fd, err, V18, u128)?,
                get_reg!(&self.vcpu_fd, err, V19, u128)?,
                get_reg!(&self.vcpu_fd, err, V20, u128)?,
                get_reg!(&self.vcpu_fd, err, V21, u128)?,
                get_reg!(&self.vcpu_fd, err, V22, u128)?,
                get_reg!(&self.vcpu_fd, err, V23, u128)?,
                get_reg!(&self.vcpu_fd, err, V24, u128)?,
                get_reg!(&self.vcpu_fd, err, V25, u128)?,
                get_reg!(&self.vcpu_fd, err, V26, u128)?,
                get_reg!(&self.vcpu_fd, err, V27, u128)?,
                get_reg!(&self.vcpu_fd, err, V28, u128)?,
                get_reg!(&self.vcpu_fd, err, V29, u128)?,
                get_reg!(&self.vcpu_fd, err, V30, u128)?,
                get_reg!(&self.vcpu_fd, err, V31, u128)?,
            ],
            fpsr: get_reg!(&self.vcpu_fd, err, FPSR, u32)?,
            fpcr: get_reg!(&self.vcpu_fd, err, FPCR, u32)?,
        })
    }

    fn set_fpu(&self, fpu: &CommonFpu) -> Result<(), RegisterError> {
        use crate::hypervisor::regs::kvm_reg::set_reg;
        fn err(e: kvm_ioctls::Error) -> RegisterError {
            RegisterError::SetFpu(e.into())
        }
        set_reg!(&self.vcpu_fd, err, V0, u128, fpu.v[0])?;
        set_reg!(&self.vcpu_fd, err, V1, u128, fpu.v[1])?;
        set_reg!(&self.vcpu_fd, err, V2, u128, fpu.v[2])?;
        set_reg!(&self.vcpu_fd, err, V3, u128, fpu.v[3])?;
        set_reg!(&self.vcpu_fd, err, V4, u128, fpu.v[4])?;
        set_reg!(&self.vcpu_fd, err, V5, u128, fpu.v[5])?;
        set_reg!(&self.vcpu_fd, err, V6, u128, fpu.v[6])?;
        set_reg!(&self.vcpu_fd, err, V7, u128, fpu.v[7])?;
        set_reg!(&self.vcpu_fd, err, V8, u128, fpu.v[8])?;
        set_reg!(&self.vcpu_fd, err, V9, u128, fpu.v[9])?;
        set_reg!(&self.vcpu_fd, err, V10, u128, fpu.v[10])?;
        set_reg!(&self.vcpu_fd, err, V11, u128, fpu.v[11])?;
        set_reg!(&self.vcpu_fd, err, V12, u128, fpu.v[12])?;
        set_reg!(&self.vcpu_fd, err, V13, u128, fpu.v[13])?;
        set_reg!(&self.vcpu_fd, err, V14, u128, fpu.v[14])?;
        set_reg!(&self.vcpu_fd, err, V15, u128, fpu.v[15])?;
        set_reg!(&self.vcpu_fd, err, V16, u128, fpu.v[16])?;
        set_reg!(&self.vcpu_fd, err, V17, u128, fpu.v[17])?;
        set_reg!(&self.vcpu_fd, err, V18, u128, fpu.v[18])?;
        set_reg!(&self.vcpu_fd, err, V19, u128, fpu.v[19])?;
        set_reg!(&self.vcpu_fd, err, V20, u128, fpu.v[20])?;
        set_reg!(&self.vcpu_fd, err, V21, u128, fpu.v[21])?;
        set_reg!(&self.vcpu_fd, err, V22, u128, fpu.v[22])?;
        set_reg!(&self.vcpu_fd, err, V23, u128, fpu.v[23])?;
        set_reg!(&self.vcpu_fd, err, V24, u128, fpu.v[24])?;
        set_reg!(&self.vcpu_fd, err, V25, u128, fpu.v[25])?;
        set_reg!(&self.vcpu_fd, err, V26, u128, fpu.v[26])?;
        set_reg!(&self.vcpu_fd, err, V27, u128, fpu.v[27])?;
        set_reg!(&self.vcpu_fd, err, V28, u128, fpu.v[28])?;
        set_reg!(&self.vcpu_fd, err, V29, u128, fpu.v[29])?;
        set_reg!(&self.vcpu_fd, err, V30, u128, fpu.v[30])?;
        set_reg!(&self.vcpu_fd, err, V31, u128, fpu.v[31])?;
        set_reg!(&self.vcpu_fd, err, FPSR, u32, fpu.fpsr)?;
        set_reg!(&self.vcpu_fd, err, FPCR, u32, fpu.fpcr)?;
        Ok(())
    }

    fn sregs(&self) -> Result<CommonSpecialRegisters, RegisterError> {
        use crate::hypervisor::regs::kvm_reg::get_reg;
        fn err(e: kvm_ioctls::Error) -> RegisterError {
            RegisterError::GetSregs(e.into())
        }
        Ok(CommonSpecialRegisters {
            ttbr0_el1: get_reg!(&self.vcpu_fd, err, TTBR0_EL1, u64)?,
            tcr_el1: get_reg!(&self.vcpu_fd, err, TCR_EL1, u64)?,
            mair_el1: get_reg!(&self.vcpu_fd, err, MAIR_EL1, u64)?,
            sctlr_el1: get_reg!(&self.vcpu_fd, err, SCTLR_EL1, u64)?,
            cpacr_el1: get_reg!(&self.vcpu_fd, err, CPACR_EL1, u64)?,
            vbar_el1: get_reg!(&self.vcpu_fd, err, VBAR_EL1, u64)?,
            sp_el1: get_reg!(&self.vcpu_fd, err, SP_EL1, u64)?,
        })
    }

    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> Result<(), RegisterError> {
        use crate::hypervisor::regs::kvm_reg::set_reg;
        fn err(e: kvm_ioctls::Error) -> RegisterError {
            RegisterError::SetSregs(e.into())
        }
        set_reg!(&self.vcpu_fd, err, TTBR0_EL1, u64, sregs.ttbr0_el1)?;
        set_reg!(&self.vcpu_fd, err, TCR_EL1, u64, sregs.tcr_el1)?;
        set_reg!(&self.vcpu_fd, err, MAIR_EL1, u64, sregs.mair_el1)?;
        set_reg!(&self.vcpu_fd, err, SCTLR_EL1, u64, sregs.sctlr_el1)?;
        set_reg!(&self.vcpu_fd, err, CPACR_EL1, u64, sregs.cpacr_el1)?;
        set_reg!(&self.vcpu_fd, err, VBAR_EL1, u64, sregs.vbar_el1)?;
        set_reg!(&self.vcpu_fd, err, SP_EL1, u64, sregs.sp_el1)?;
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
