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

//! x86_64-specific KVM implementation for register handling and debugging.

use kvm_bindings::{kvm_fpu, kvm_regs, kvm_sregs};

use crate::hypervisor::arch::{CommonFpu, CommonRegisters, CommonSpecialRegisters};
use crate::Result;

use super::KvmVm;

impl KvmVm {
    pub(super) fn get_regs_arch(&self) -> Result<CommonRegisters> {
        let kvm_regs = self.vcpu_fd.get_regs()?;
        Ok((&kvm_regs).into())
    }

    pub(super) fn set_regs_arch(&self, regs: &CommonRegisters) -> Result<()> {
        let kvm_regs: kvm_regs = regs.into();
        self.vcpu_fd.set_regs(&kvm_regs)?;
        Ok(())
    }

    pub(super) fn get_fpu_arch(&self) -> Result<CommonFpu> {
        let kvm_fpu = self.vcpu_fd.get_fpu()?;
        Ok((&kvm_fpu).into())
    }

    pub(super) fn set_fpu_arch(&self, fpu: &CommonFpu) -> Result<()> {
        let kvm_fpu: kvm_fpu = fpu.into();
        self.vcpu_fd.set_fpu(&kvm_fpu)?;
        Ok(())
    }

    pub(super) fn get_sregs_arch(&self) -> Result<CommonSpecialRegisters> {
        let kvm_sregs = self.vcpu_fd.get_sregs()?;
        Ok((&kvm_sregs).into())
    }

    pub(super) fn set_sregs_arch(&self, sregs: &CommonSpecialRegisters) -> Result<()> {
        let kvm_sregs: kvm_sregs = sregs.into();
        self.vcpu_fd.set_sregs(&kvm_sregs)?;
        Ok(())
    }

    #[cfg(crashdump)]
    pub(super) fn get_xsave_arch(&self) -> Result<Vec<u8>> {
        let xsave = self.vcpu_fd.get_xsave()?;
        Ok(xsave
            .region
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect())
    }
}

#[cfg(gdb)]
use crate::hypervisor::gdb::DebuggableVm;

#[cfg(gdb)]
impl DebuggableVm for KvmVm {
    fn translate_gva(&self, gva: u64) -> Result<u64> {
        use crate::HyperlightError;

        let gpa = self.vcpu_fd.translate_gva(gva)?;
        if gpa.valid == 0 {
            Err(HyperlightError::TranslateGuestAddress(gva))
        } else {
            Ok(gpa.physical_address)
        }
    }

    fn set_debug(&mut self, enable: bool) -> Result<()> {
        use kvm_bindings::{KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_USE_HW_BP, KVM_GUESTDBG_USE_SW_BP};

        log::info!("Setting debug to {}", enable);
        if enable {
            self.debug_regs.control |=
                KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP | KVM_GUESTDBG_USE_SW_BP;
        } else {
            self.debug_regs.control &=
                !(KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP | KVM_GUESTDBG_USE_SW_BP);
        }
        self.vcpu_fd.set_guest_debug(&self.debug_regs)?;
        Ok(())
    }

    fn set_single_step(&mut self, enable: bool) -> Result<()> {
        use kvm_bindings::KVM_GUESTDBG_SINGLESTEP;

        use crate::hypervisor::virtual_machine::VirtualMachine;

        log::info!("Setting single step to {}", enable);
        if enable {
            self.debug_regs.control |= KVM_GUESTDBG_SINGLESTEP;
        } else {
            self.debug_regs.control &= !KVM_GUESTDBG_SINGLESTEP;
        }
        self.vcpu_fd.set_guest_debug(&self.debug_regs)?;

        // Set TF Flag to enable Traps
        let mut regs = self.regs()?;
        if enable {
            regs.rflags |= 1 << 8;
        } else {
            regs.rflags &= !(1 << 8);
        }
        self.set_regs(&regs)?;
        Ok(())
    }

    fn add_hw_breakpoint(&mut self, addr: u64) -> Result<()> {
        use crate::hypervisor::gdb::arch::MAX_NO_OF_HW_BP;
        use crate::new_error;

        // Check if breakpoint already exists
        if self.debug_regs.arch.debugreg[..4].contains(&addr) {
            return Ok(());
        }

        // Find the first available LOCAL (L0–L3) slot
        let i = (0..MAX_NO_OF_HW_BP)
            .position(|i| self.debug_regs.arch.debugreg[7] & (1 << (i * 2)) == 0)
            .ok_or_else(|| new_error!("Tried to add more than 4 hardware breakpoints"))?;

        // Assign to corresponding debug register
        self.debug_regs.arch.debugreg[i] = addr;

        // Enable LOCAL bit
        self.debug_regs.arch.debugreg[7] |= 1 << (i * 2);

        self.vcpu_fd.set_guest_debug(&self.debug_regs)?;
        Ok(())
    }

    fn remove_hw_breakpoint(&mut self, addr: u64) -> Result<()> {
        use crate::new_error;

        // Find the index of the breakpoint
        let index = self.debug_regs.arch.debugreg[..4]
            .iter()
            .position(|&a| a == addr)
            .ok_or_else(|| new_error!("Tried to remove non-existing hw-breakpoint"))?;

        // Clear the address
        self.debug_regs.arch.debugreg[index] = 0;

        // Disable LOCAL bit
        self.debug_regs.arch.debugreg[7] &= !(1 << (index * 2));

        self.vcpu_fd.set_guest_debug(&self.debug_regs)?;
        Ok(())
    }
}
