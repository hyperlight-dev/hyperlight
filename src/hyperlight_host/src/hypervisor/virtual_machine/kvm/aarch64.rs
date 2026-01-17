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

//! aarch64-specific KVM implementation for register handling.
//!
//! On aarch64, KVM does not provide bulk register access via `get_regs`/`set_regs`.
//! Instead, we must use `get_one_reg`/`set_one_reg` for each register individually.

use crate::hypervisor::arch::{CommonFpu, CommonRegisters, CommonSpecialRegisters};
use crate::Result;

use super::KvmVm;

// TODO: Define register IDs for aarch64
// const KVM_REG_ARM64: u64 = 0x6000000000000000;
// const KVM_REG_SIZE_U64: u64 = 0x0030000000000000;
// const KVM_REG_ARM_CORE: u64 = 0x0010 << 16;

impl KvmVm {
    pub(super) fn get_regs_arch(&self) -> Result<CommonRegisters> {
        // TODO: Implement using get_one_reg for each x0-x30, sp, pc, pstate
        todo!("aarch64 KVM register access not yet implemented")
    }

    pub(super) fn set_regs_arch(&self, _regs: &CommonRegisters) -> Result<()> {
        // TODO: Implement using set_one_reg for each x0-x30, sp, pc, pstate
        todo!("aarch64 KVM register access not yet implemented")
    }

    pub(super) fn get_fpu_arch(&self) -> Result<CommonFpu> {
        // TODO: Implement using get_one_reg for v0-v31, fpcr, fpsr
        todo!("aarch64 KVM FPU register access not yet implemented")
    }

    pub(super) fn set_fpu_arch(&self, _fpu: &CommonFpu) -> Result<()> {
        // TODO: Implement using set_one_reg for v0-v31, fpcr, fpsr
        todo!("aarch64 KVM FPU register access not yet implemented")
    }

    pub(super) fn get_sregs_arch(&self) -> Result<CommonSpecialRegisters> {
        // TODO: Implement using get_one_reg for system registers
        todo!("aarch64 KVM system register access not yet implemented")
    }

    pub(super) fn set_sregs_arch(&self, _sregs: &CommonSpecialRegisters) -> Result<()> {
        // TODO: Implement using set_one_reg for system registers
        todo!("aarch64 KVM system register access not yet implemented")
    }

    #[cfg(crashdump)]
    pub(super) fn get_xsave_arch(&self) -> Result<Vec<u8>> {
        // xsave is x86-specific, aarch64 would need a different approach for FPU state
        todo!("aarch64 does not have xsave - need alternative for FPU state dump")
    }
}
