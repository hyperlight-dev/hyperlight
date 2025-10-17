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

use std::collections::HashMap;

use kvm_bindings::{
    KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_SINGLESTEP, KVM_GUESTDBG_USE_HW_BP, KVM_GUESTDBG_USE_SW_BP,
    kvm_debug_exit_arch, kvm_guest_debug,
};
use kvm_ioctls::VcpuFd;

use super::arch::{MAX_NO_OF_HW_BP, SW_BP_SIZE, vcpu_stop_reason};
use super::{GuestDebug, VcpuStopReason};
use crate::hypervisor::regs::{CommonFpu, CommonRegisters};
use crate::{HyperlightError, Result, new_error};

/// KVM Debug struct
/// This struct is used to abstract the internal details of the kvm
/// guest debugging settings
#[derive(Default)]
pub(crate) struct KvmDebug {
    /// vCPU stepping state
    single_step: bool,

    /// Array of addresses for HW breakpoints
    hw_breakpoints: Vec<u64>,
    /// Saves the bytes modified to enable SW breakpoints
    sw_breakpoints: HashMap<u64, [u8; SW_BP_SIZE]>,

    /// Sent to KVM for enabling guest debug
    dbg_cfg: kvm_guest_debug,
}

impl KvmDebug {
    pub(crate) fn new() -> Self {
        let dbg = kvm_guest_debug {
            control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP,
            ..Default::default()
        };

        Self {
            single_step: false,
            hw_breakpoints: vec![],
            sw_breakpoints: HashMap::new(),
            dbg_cfg: dbg,
        }
    }

    /// Returns the instruction pointer from the stopped vCPU
    fn get_instruction_pointer(&self, vcpu_fd: &VcpuFd) -> Result<u64> {
        let regs = vcpu_fd
            .get_regs()
            .map_err(|e| new_error!("Could not retrieve registers from vCPU: {:?}", e))?;

        Ok(regs.rip)
    }

    /// This method sets the kvm debugreg fields to enable breakpoints at
    /// specific addresses
    ///
    /// The first 4 debug registers are used to set the addresses
    /// The 4th and 5th debug registers are obsolete and not used
    /// The 7th debug register is used to enable the breakpoints
    /// For more information see: DEBUG REGISTERS chapter in the architecture
    /// manual
    fn set_debug_config(&mut self, vcpu_fd: &VcpuFd, step: bool) -> Result<()> {
        let addrs = &self.hw_breakpoints;

        self.dbg_cfg.arch.debugreg = [0; 8];
        for (k, addr) in addrs.iter().enumerate() {
            self.dbg_cfg.arch.debugreg[k] = *addr;
            self.dbg_cfg.arch.debugreg[7] |= 1 << (k * 2);
        }

        if !addrs.is_empty() {
            self.dbg_cfg.control |= KVM_GUESTDBG_USE_HW_BP;
        } else {
            self.dbg_cfg.control &= !KVM_GUESTDBG_USE_HW_BP;
        }

        if step {
            self.dbg_cfg.control |= KVM_GUESTDBG_SINGLESTEP;
        } else {
            self.dbg_cfg.control &= !KVM_GUESTDBG_SINGLESTEP;
        }

        log::debug!("Setting bp: {:?} cfg: {:?}", addrs, self.dbg_cfg);
        vcpu_fd
            .set_guest_debug(&self.dbg_cfg)
            .map_err(|e| new_error!("Could not set guest debug: {:?}", e))?;

        self.single_step = step;

        Ok(())
    }

    /// Get the reason the vCPU has stopped
    pub(crate) fn get_stop_reason(
        &mut self,
        vcpu_fd: &VcpuFd,
        debug_exit: kvm_debug_exit_arch,
        entrypoint: u64,
    ) -> Result<VcpuStopReason> {
        let rip = self.get_instruction_pointer(vcpu_fd)?;
        let rip = self.translate_gva(vcpu_fd, rip)?;

        // Check if the vCPU stopped because of a hardware breakpoint
        let reason = vcpu_stop_reason(
            self.single_step,
            rip,
            debug_exit.dr6,
            entrypoint,
            debug_exit.exception,
            &self.hw_breakpoints,
            &self.sw_breakpoints,
        );

        if let VcpuStopReason::EntryPointBp = reason {
            // In case the hw breakpoint is the entry point, remove it to
            // avoid hanging here as gdb does not remove breakpoints it
            // has not set.
            // Gdb expects the target to be stopped when connected.
            self.remove_hw_breakpoint(vcpu_fd, entrypoint)?;
        }

        Ok(reason)
    }
}

impl GuestDebug for KvmDebug {
    type Vcpu = VcpuFd;

    fn is_hw_breakpoint(&self, addr: &u64) -> bool {
        self.hw_breakpoints.contains(addr)
    }
    fn is_sw_breakpoint(&self, addr: &u64) -> bool {
        self.sw_breakpoints.contains_key(addr)
    }
    fn save_hw_breakpoint(&mut self, addr: &u64) -> bool {
        if self.hw_breakpoints.len() >= MAX_NO_OF_HW_BP {
            false
        } else {
            self.hw_breakpoints.push(*addr);

            true
        }
    }
    fn save_sw_breakpoint_data(&mut self, addr: u64, data: [u8; 1]) {
        _ = self.sw_breakpoints.insert(addr, data);
    }
    fn delete_hw_breakpoint(&mut self, addr: &u64) {
        self.hw_breakpoints.retain(|&a| a != *addr);
    }
    fn delete_sw_breakpoint_data(&mut self, addr: &u64) -> Option<[u8; 1]> {
        self.sw_breakpoints.remove(addr)
    }

    fn read_regs(&self, vcpu_fd: &Self::Vcpu) -> Result<(CommonRegisters, CommonFpu)> {
        log::debug!("Read registers");
        let regs = vcpu_fd
            .get_regs()
            .map_err(|e| new_error!("Could not read guest registers: {:?}", e))?;

        let fpu_data = vcpu_fd
            .get_fpu()
            .map_err(|e| new_error!("Could not read guest FPU registers: {:?}", e))?;
        let mut fpu: CommonFpu = CommonFpu::from(&fpu_data);

        // Read MXCSR from XSAVE (MXCSR is at byte offset 24 -> u32 index 6)
        // 11.5.10 Mode-Specific XSAVE/XRSTOR State Management
        match vcpu_fd.get_xsave() {
            Ok(xsave) => {
                fpu.mxcsr = xsave.region[6];
            }
            Err(e) => {
                log::warn!("Failed to read XSAVE for MXCSR: {:?}", e);
            }
        }

        Ok((CommonRegisters::from(&regs), fpu))
    }

    fn set_single_step(&mut self, vcpu_fd: &Self::Vcpu, enable: bool) -> Result<()> {
        self.set_debug_config(vcpu_fd, enable)
    }

    fn translate_gva(&self, vcpu_fd: &Self::Vcpu, gva: u64) -> Result<u64> {
        let tr = vcpu_fd
            .translate_gva(gva)
            .map_err(|_| HyperlightError::TranslateGuestAddress(gva))?;

        if tr.valid == 0 {
            Err(HyperlightError::TranslateGuestAddress(gva))
        } else {
            Ok(tr.physical_address)
        }
    }

    fn write_regs(
        &self,
        vcpu_fd: &Self::Vcpu,
        regs: &CommonRegisters,
        fpu: &CommonFpu,
    ) -> Result<()> {
        log::debug!("Write registers");
        let new_regs = regs.into();

        vcpu_fd
            .set_regs(&new_regs)
            .map_err(|e| new_error!("Could not write guest registers: {:?}", e))?;

        // Only xmm and mxcsr is piped though in the given fpu, so only set those
        let mut current_fpu: CommonFpu = (&vcpu_fd.get_fpu()?).into();
        current_fpu.mxcsr = fpu.mxcsr;
        current_fpu.xmm = fpu.xmm;
        vcpu_fd
            .set_fpu(&(&current_fpu).into())
            .map_err(|e| new_error!("Could not write guest registers: {:?}", e))?;

        // Read XMM registers from FPU state
        // note kvm get_fpu doesn't actually set or read the mxcsr value
        // https://elixir.bootlin.com/linux/v6.16/source/arch/x86/kvm/x86.c#L12229
        // Update MXCSR using XSAVE region entry 6 (MXCSR) if available.
        let mut xsave = match vcpu_fd.get_xsave() {
            Ok(xsave) => xsave,
            Err(e) => {
                return Err(new_error!("Could not write guest registers: {:?}", e));
            }
        };

        xsave.region[6] = fpu.mxcsr;
        unsafe {
            vcpu_fd
                .set_xsave(&xsave)
                .map_err(|e| new_error!("Could not write guest registers: {:?}", e))?
        };

        Ok(())
    }
}
