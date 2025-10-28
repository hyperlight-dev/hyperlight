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

#[cfg(mshv3)]
extern crate mshv_bindings;
#[cfg(mshv3)]
extern crate mshv_ioctls;

use std::collections::HashMap;

use mshv_bindings::{
    DebugRegisters, HV_TRANSLATE_GVA_VALIDATE_READ, HV_TRANSLATE_GVA_VALIDATE_WRITE,
};
use mshv_ioctls::VcpuFd;

use super::arch::{MAX_NO_OF_HW_BP, SW_BP_SIZE, vcpu_stop_reason};
use super::{GuestDebug, VcpuStopReason};
use crate::hypervisor::regs::{CommonFpu, CommonRegisters};
use crate::{HyperlightError, Result, new_error};

#[derive(Debug, Default)]
pub(crate) struct MshvDebug {
    /// vCPU stepping state
    single_step: bool,

    /// Array of addresses for HW breakpoints
    hw_breakpoints: Vec<u64>,
    /// Saves the bytes modified to enable SW breakpoints
    sw_breakpoints: HashMap<u64, [u8; SW_BP_SIZE]>,

    /// Debug registers
    dbg_cfg: DebugRegisters,
}

impl MshvDebug {
    pub(crate) fn new() -> Self {
        Self {
            single_step: false,
            hw_breakpoints: vec![],
            sw_breakpoints: HashMap::new(),
            dbg_cfg: DebugRegisters::default(),
        }
    }

    /// Returns the instruction pointer from the stopped vCPU
    fn get_instruction_pointer(&self, vcpu_fd: &VcpuFd) -> Result<u64> {
        let regs = vcpu_fd
            .get_regs()
            .map_err(|e| new_error!("Could not retrieve registers from vCPU: {:?}", e))?;

        Ok(regs.rip)
    }

    /// This method sets the vCPU debug register fields to enable breakpoints at
    /// specific addresses
    ///
    /// The first 4 debug registers are used to set the addresses
    /// The 4th and 5th debug registers are obsolete and not used
    /// The 7th debug register is used to enable the breakpoints
    /// For more information see: DEBUG REGISTERS chapter in the architecture
    /// manual
    fn set_debug_config(&mut self, vcpu_fd: &VcpuFd, step: bool) -> Result<()> {
        let addrs = &self.hw_breakpoints;

        let mut dbg_cfg = DebugRegisters::default();
        for (k, addr) in addrs.iter().enumerate() {
            match k {
                0 => {
                    dbg_cfg.dr0 = *addr;
                }
                1 => {
                    dbg_cfg.dr1 = *addr;
                }
                2 => {
                    dbg_cfg.dr2 = *addr;
                }
                3 => {
                    dbg_cfg.dr3 = *addr;
                }
                _ => {
                    Err(new_error!("Tried to set more than 4 HW breakpoints"))?;
                }
            }
            dbg_cfg.dr7 |= 1 << (k * 2);
        }

        self.dbg_cfg = dbg_cfg;
        vcpu_fd
            .set_debug_regs(&self.dbg_cfg)
            .map_err(|e| new_error!("Could not set guest debug: {:?}", e))?;

        self.single_step = step;

        let mut regs = vcpu_fd
            .get_regs()
            .map_err(|e| new_error!("Could not get registers: {:?}", e))?;

        // Set TF Flag to enable Traps
        if self.single_step {
            regs.rflags |= 1 << 8;
        } else {
            regs.rflags &= !(1 << 8);
        }

        vcpu_fd
            .set_regs(&regs)
            .map_err(|e| new_error!("Could not set registers: {:?}", e))?;

        Ok(())
    }

    /// Returns the vCPU stop reason
    pub(crate) fn get_stop_reason(
        &mut self,
        vcpu_fd: &VcpuFd,
        exception: u16,
        entrypoint: u64,
    ) -> Result<VcpuStopReason> {
        let regs = vcpu_fd
            .get_debug_regs()
            .map_err(|e| new_error!("Cannot retrieve debug registers from vCPU: {}", e))?;

        // DR6 register contains debug state related information
        let debug_status = regs.dr6;

        let rip = self.get_instruction_pointer(vcpu_fd)?;
        let rip = self.translate_gva(vcpu_fd, rip)?;

        let reason = vcpu_stop_reason(
            self.single_step,
            rip,
            debug_status,
            entrypoint,
            exception as u32,
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

impl GuestDebug for MshvDebug {
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
        let regs = CommonRegisters::from(&regs);

        let fpu_data = vcpu_fd
            .get_fpu()
            .map_err(|e| new_error!("Could not read guest FPU registers: {:?}", e))?;
        let fpu = CommonFpu::from(&fpu_data);

        Ok((regs, fpu))
    }

    fn set_single_step(&mut self, vcpu_fd: &Self::Vcpu, enable: bool) -> Result<()> {
        self.set_debug_config(vcpu_fd, enable)
    }

    fn translate_gva(&self, vcpu_fd: &Self::Vcpu, gva: u64) -> Result<u64> {
        let flags = (HV_TRANSLATE_GVA_VALIDATE_READ | HV_TRANSLATE_GVA_VALIDATE_WRITE) as u64;
        let (addr, _) = vcpu_fd
            .translate_gva(gva, flags)
            .map_err(|_| HyperlightError::TranslateGuestAddress(gva))?;

        Ok(addr)
    }

    fn write_regs(
        &self,
        vcpu_fd: &Self::Vcpu,
        regs: &CommonRegisters,
        fpu: &CommonFpu,
    ) -> Result<()> {
        log::debug!("Write registers");

        vcpu_fd
            .set_regs(&regs.into())
            .map_err(|e| new_error!("Could not write guest registers: {:?}", e))?;

        // Only xmm and mxcsr is piped though in the given fpu, so only set those
        let mut current_fpu: CommonFpu = (&vcpu_fd.get_fpu()?).into();
        current_fpu.mxcsr = fpu.mxcsr;
        current_fpu.xmm = fpu.xmm;

        vcpu_fd
            .set_fpu(&(&current_fpu).into())
            .map_err(|e| new_error!("Could not write guest registers: {:?}", e))
    }
}
