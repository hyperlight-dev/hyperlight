/*
Copyright 2024 The Hyperlight Authors.

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

use windows::Win32::System::Hypervisor::WHV_VP_EXCEPTION_CONTEXT;

use super::arch::{MAX_NO_OF_HW_BP, vcpu_stop_reason};
use super::{GuestDebug, SW_BP_SIZE, VcpuStopReason, X86_64Regs};
use crate::hypervisor::windows_hypervisor_platform::VMProcessor;
use crate::hypervisor::wrappers::{WHvDebugRegisters, WHvGeneralRegisters};
use crate::{HyperlightError, Result, new_error};

/// KVM Debug struct
/// This struct is used to abstract the internal details of the kvm
/// guest debugging settings
#[derive(Default)]
pub(crate) struct HypervDebug {
    /// vCPU stepping state
    single_step: bool,

    /// Array of addresses for HW breakpoints
    hw_breakpoints: Vec<u64>,
    /// Saves the bytes modified to enable SW breakpoints
    sw_breakpoints: HashMap<u64, [u8; SW_BP_SIZE]>,

    /// Debug registers
    dbg_cfg: WHvDebugRegisters,
}

impl HypervDebug {
    pub(crate) fn new() -> Self {
        Self {
            single_step: false,
            hw_breakpoints: vec![],
            sw_breakpoints: HashMap::new(),
            dbg_cfg: WHvDebugRegisters::default(),
        }
    }

    /// Returns the instruction pointer from the stopped vCPU
    fn get_instruction_pointer(&self, vcpu_fd: &VMProcessor) -> Result<u64> {
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
    fn set_debug_config(&mut self, vcpu_fd: &VMProcessor, step: bool) -> Result<()> {
        let addrs = &self.hw_breakpoints;

        let mut dbg_cfg = WHvDebugRegisters::default();

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
            regs.rflags |= 1 << 8; // Set the TF flag
        } else {
            regs.rflags &= !(1 << 8); // Clear the TF flag
        }

        vcpu_fd
            .set_general_purpose_registers(&regs)
            .map_err(|e| new_error!("Could not set guest registers: {:?}", e))?;

        Ok(())
    }

    /// Get the reason the vCPU has stopped
    pub(crate) fn get_stop_reason(
        &mut self,
        vcpu_fd: &VMProcessor,
        exception: WHV_VP_EXCEPTION_CONTEXT,
        entrypoint: u64,
    ) -> Result<VcpuStopReason> {
        let rip = self.get_instruction_pointer(vcpu_fd)?;
        let rip = self.translate_gva(vcpu_fd, rip)?;

        let debug_regs = vcpu_fd
            .get_debug_regs()
            .map_err(|e| new_error!("Could not retrieve registers from vCPU: {:?}", e))?;

        // Check if the vCPU stopped because of a hardware breakpoint
        let reason = vcpu_stop_reason(
            self.single_step,
            rip,
            debug_regs.dr6,
            entrypoint,
            exception.ExceptionType as u32,
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

impl GuestDebug for HypervDebug {
    type Vcpu = VMProcessor;

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

    fn read_regs(&self, vcpu_fd: &Self::Vcpu, regs: &mut X86_64Regs) -> Result<()> {
        log::debug!("Read registers");
        let vcpu_regs = vcpu_fd
            .get_regs()
            .map_err(|e| new_error!("Could not read guest registers: {:?}", e))?;

        regs.rax = vcpu_regs.rax;
        regs.rbx = vcpu_regs.rbx;
        regs.rcx = vcpu_regs.rcx;
        regs.rdx = vcpu_regs.rdx;
        regs.rsi = vcpu_regs.rsi;
        regs.rdi = vcpu_regs.rdi;
        regs.rbp = vcpu_regs.rbp;
        regs.rsp = vcpu_regs.rsp;
        regs.r8 = vcpu_regs.r8;
        regs.r9 = vcpu_regs.r9;
        regs.r10 = vcpu_regs.r10;
        regs.r11 = vcpu_regs.r11;
        regs.r12 = vcpu_regs.r12;
        regs.r13 = vcpu_regs.r13;
        regs.r14 = vcpu_regs.r14;
        regs.r15 = vcpu_regs.r15;

        regs.rip = vcpu_regs.rip;
        regs.rflags = vcpu_regs.rflags;

        // Fetch XMM from WHVP
        if let Ok(fpu) = vcpu_fd.get_fpu() {
            regs.xmm = [
                fpu.xmm0, fpu.xmm1, fpu.xmm2, fpu.xmm3, fpu.xmm4, fpu.xmm5, fpu.xmm6, fpu.xmm7,
                fpu.xmm8, fpu.xmm9, fpu.xmm10, fpu.xmm11, fpu.xmm12, fpu.xmm13, fpu.xmm14,
                fpu.xmm15,
            ];
            regs.mxcsr = fpu.mxcsr;
        } else {
            log::warn!("Failed to read FPU/XMM via WHVP for debug registers");
        }

        Ok(())
    }

    fn set_single_step(&mut self, vcpu_fd: &Self::Vcpu, enable: bool) -> Result<()> {
        self.set_debug_config(vcpu_fd, enable)
    }

    fn translate_gva(&self, vcpu_fd: &Self::Vcpu, gva: u64) -> Result<u64> {
        vcpu_fd
            .translate_gva(gva)
            .map_err(|_| HyperlightError::TranslateGuestAddress(gva))
    }

    fn write_regs(&self, vcpu_fd: &Self::Vcpu, regs: &X86_64Regs) -> Result<()> {
        log::debug!("Write registers");
        let gprs = WHvGeneralRegisters {
            rax: regs.rax,
            rbx: regs.rbx,
            rcx: regs.rcx,
            rdx: regs.rdx,
            rsi: regs.rsi,
            rdi: regs.rdi,
            rbp: regs.rbp,
            rsp: regs.rsp,
            r8: regs.r8,
            r9: regs.r9,
            r10: regs.r10,
            r11: regs.r11,
            r12: regs.r12,
            r13: regs.r13,
            r14: regs.r14,
            r15: regs.r15,

            rip: regs.rip,
            rflags: regs.rflags,
        };

        vcpu_fd
            .set_general_purpose_registers(&gprs)
            .map_err(|e| new_error!("Could not write guest registers: {:?}", e))?;

        // Load existing FPU state, replace XMM and MXCSR, and write it back.
        let mut fpu = match vcpu_fd.get_fpu() {
            Ok(f) => f,
            Err(e) => {
                return Err(new_error!("Could not write guest registers: {:?}", e));
            }
        };

        fpu.xmm0 = regs.xmm[0];
        fpu.xmm1 = regs.xmm[1];
        fpu.xmm2 = regs.xmm[2];
        fpu.xmm3 = regs.xmm[3];
        fpu.xmm4 = regs.xmm[4];
        fpu.xmm5 = regs.xmm[5];
        fpu.xmm6 = regs.xmm[6];
        fpu.xmm7 = regs.xmm[7];
        fpu.xmm8 = regs.xmm[8];
        fpu.xmm9 = regs.xmm[9];
        fpu.xmm10 = regs.xmm[10];
        fpu.xmm11 = regs.xmm[11];
        fpu.xmm12 = regs.xmm[12];
        fpu.xmm13 = regs.xmm[13];
        fpu.xmm14 = regs.xmm[14];
        fpu.xmm15 = regs.xmm[15];
        fpu.mxcsr = regs.mxcsr;

        vcpu_fd
            .set_fpu(&fpu)
            .map_err(|e| new_error!("Could not write guest registers: {:?}", e))
    }
}
