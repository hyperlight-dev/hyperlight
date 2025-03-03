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

use std::sync::{Arc, Mutex};

use hyperlight_common::mem::PAGE_SIZE;

use super::{VcpuStopReason, X86_64Regs};
use crate::hypervisor::handlers::DbgMemAccessHandlerCaller;
use crate::mem::layout::SandboxMemoryLayout;
use crate::{new_error, HyperlightError, Result};

/// Software Breakpoint size in memory
pub const SW_BP_SIZE: usize = 1;
/// Software Breakpoint opcode - INT3
/// Check page 7-28 Vol. 3A of Intel 64 and IA-32
/// Architectures Software Developer's Manual
const SW_BP_OP: u8 = 0xCC;
/// Software Breakpoint written to memory
pub const SW_BP: [u8; SW_BP_SIZE] = [SW_BP_OP];
/// Max number of supported hw breakpoints
const MAX_NO_OF_HW_BP: usize = 4;

/// This trait is used to define a common way of interacting with a vCPU to
/// allow debugging functionality
pub trait GuestVcpuDebug {
    /// Type that wraps the vCPU functionality
    type Vcpu;

    /// Returns true whether the provided address is a hardware breakpoint
    fn is_hw_breakpoint(&self, addr: &u64) -> bool;
    /// Stores the address of the hw breakpoint
    fn save_hw_breakpoint(&mut self, addr: &u64) -> bool;
    /// Deletes the address of the hw breakpoint from storage
    fn delete_hw_breakpoint(&mut self, addr: &u64);

    /// Read registers
    fn read_regs(&self, vcpu_fd: &Self::Vcpu, regs: &mut X86_64Regs) -> Result<()>;
    /// Enables or disables stepping and sets the vCPU debug configuration
    fn set_single_step(&mut self, vcpu_fd: &Self::Vcpu, enable: bool) -> Result<()>;
    /// Translates the guest address to physical address
    fn translate_gva(&self, vcpu_fd: &Self::Vcpu, gva: u64) -> Result<u64>;
    /// Write registers
    fn write_regs(&self, vcpu_fd: &Self::Vcpu, regs: &X86_64Regs) -> Result<()>;

    /// Adds hardware breakpoint
    fn add_hw_breakpoint(&mut self, vcpu_fd: &Self::Vcpu, addr: u64) -> Result<bool> {
        let addr = self.translate_gva(vcpu_fd, addr)?;

        if self.is_hw_breakpoint(&addr) {
            Ok(true)
        } else {
            let res = self.save_hw_breakpoint(&addr);
            if res {
                self.set_single_step(vcpu_fd, false)?;
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }
    /// Removes hardware breakpoint
    fn remove_hw_breakpoint(&mut self, vcpu_fd: &Self::Vcpu, addr: u64) -> Result<bool> {
        let addr = self.translate_gva(vcpu_fd, addr)?;

        if self.is_hw_breakpoint(&addr) {
            self.delete_hw_breakpoint(&addr);
            self.set_single_step(vcpu_fd, false)?;

            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Trait used for defining memory debugging functionality
pub trait GuestMemoryDebug: GuestVcpuDebug {
    /// Returns true whether the provided address is a software breakpoint
    fn is_sw_breakpoint(&self, addr: &u64) -> bool;
    /// Stores the data that the sw breakpoint op code replaces
    fn save_sw_breakpoint_data(&mut self, addr: u64, data: [u8; 1]);
    /// Retrieves the saved data that the sw breakpoint op code replaces
    fn delete_sw_breakpoint_data(&mut self, addr: &u64) -> Option<[u8; 1]>;

    /// Overwrites the guest memory with the SW Breakpoint op code that instructs
    /// the vCPU to stop when is executed and stores the overwritten data to be
    /// able to restore it
    fn add_sw_breakpoint(
        &mut self,
        vcpu_fd: &Self::Vcpu,
        addr: u64,
        dbg_mem_access_fn: Arc<Mutex<dyn DbgMemAccessHandlerCaller>>,
    ) -> Result<bool> {
        let addr = self.translate_gva(vcpu_fd, addr)?;

        if self.is_sw_breakpoint(&addr) {
            return Ok(true);
        }

        // Write breakpoint OP code to write to guest memory
        let mut save_data = [0; SW_BP_SIZE];
        self.read_addrs(vcpu_fd, addr, &mut save_data[..], dbg_mem_access_fn.clone())?;
        self.write_addrs(vcpu_fd, addr, &SW_BP, dbg_mem_access_fn)?;

        // Save guest memory to restore when breakpoint is removed
        self.save_sw_breakpoint_data(addr, save_data);

        Ok(true)
    }

    /// Copies the data from the guest memory address to the provided slice
    /// The address is checked to be a valid guest address
    fn read_addrs(
        &mut self,
        vcpu_fd: &Self::Vcpu,
        mut gva: u64,
        mut data: &mut [u8],
        dbg_mem_access_fn: Arc<Mutex<dyn DbgMemAccessHandlerCaller>>,
    ) -> Result<()> {
        let data_len = data.len();
        log::debug!("Read addr: {:X} len: {:X}", gva, data_len);

        while !data.is_empty() {
            let gpa = self.translate_gva(vcpu_fd, gva)?;

            let read_len = std::cmp::min(
                data.len(),
                (PAGE_SIZE - (gpa & (PAGE_SIZE - 1))).try_into().unwrap(),
            );
            let offset = gpa as usize - SandboxMemoryLayout::BASE_ADDRESS;

            dbg_mem_access_fn
                .try_lock()
                .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
                .read(offset, &mut data[..read_len])?;

            data = &mut data[read_len..];
            gva += read_len as u64;
        }

        Ok(())
    }

    /// Restores the overwritten data to the guest memory
    fn remove_sw_breakpoint(
        &mut self,
        vcpu_fd: &Self::Vcpu,
        addr: u64,
        dbg_mem_access_fn: Arc<Mutex<dyn DbgMemAccessHandlerCaller>>,
    ) -> Result<bool> {
        let addr = self.translate_gva(vcpu_fd, addr)?;

        if self.is_sw_breakpoint(&addr) {
            let save_data = self
                .delete_sw_breakpoint_data(&addr)
                .ok_or_else(|| new_error!("Expected to contain the sw breakpoint address"))?;

            // Restore saved data to the guest's memory
            self.write_addrs(vcpu_fd, addr, &save_data, dbg_mem_access_fn)?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Copies the data from the provided slice to the guest memory address
    /// The address is checked to be a valid guest address
    fn write_addrs(
        &mut self,
        vcpu_fd: &Self::Vcpu,
        mut gva: u64,
        mut data: &[u8],
        dbg_mem_access_fn: Arc<Mutex<dyn DbgMemAccessHandlerCaller>>,
    ) -> Result<()> {
        let data_len = data.len();
        log::debug!("Write addr: {:X} len: {:X}", gva, data_len);

        while !data.is_empty() {
            let gpa = self.translate_gva(vcpu_fd, gva)?;

            let write_len = std::cmp::min(
                data.len(),
                (PAGE_SIZE - (gpa & (PAGE_SIZE - 1))).try_into().unwrap(),
            );
            let offset = gpa as usize - SandboxMemoryLayout::BASE_ADDRESS;

            dbg_mem_access_fn
                .try_lock()
                .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
                .write(offset, data)?;

            data = &data[write_len..];
            gva += write_len as u64;
        }

        Ok(())
    }
}

#[cfg(kvm)]
pub mod kvm {
    use std::collections::HashMap;

    use kvm_bindings::{
        kvm_guest_debug, kvm_regs, KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_SINGLESTEP,
        KVM_GUESTDBG_USE_HW_BP, KVM_GUESTDBG_USE_SW_BP,
    };
    use kvm_ioctls::VcpuFd;

    use super::*;
    use crate::{new_error, Result};

    /// KVM Debug struct
    /// This struct is used to abstract the internal details of the kvm
    /// guest debugging settings
    #[derive(Default)]
    pub struct KvmDebug {
        /// vCPU stepping state
        pub single_step: bool,

        /// Array of addresses for HW breakpoints
        pub hw_breakpoints: Vec<u64>,
        /// Saves the bytes modified to enable SW breakpoints
        pub sw_breakpoints: HashMap<u64, [u8; SW_BP_SIZE]>,

        /// Sent to KVM for enabling guest debug
        pub dbg_cfg: kvm_guest_debug,
    }

    impl KvmDebug {
        pub fn new() -> Self {
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
        pub fn get_stop_reason(&self, vcpu_fd: &VcpuFd, entrypoint: u64) -> Result<VcpuStopReason> {
            if self.single_step {
                return Ok(VcpuStopReason::DoneStep);
            }

            let ip = self.get_instruction_pointer(vcpu_fd)?;
            let gpa = self.translate_gva(vcpu_fd, ip)?;

            if self.sw_breakpoints.contains_key(&gpa) {
                return Ok(VcpuStopReason::SwBp);
            }

            if self.hw_breakpoints.contains(&gpa) {
                return Ok(VcpuStopReason::HwBp);
            }

            if gpa == entrypoint {
                return Ok(VcpuStopReason::HwBp);
            }

            Ok(VcpuStopReason::Unknown)
        }
    }

    impl GuestVcpuDebug for KvmDebug {
        type Vcpu = VcpuFd;

        fn is_hw_breakpoint(&self, addr: &u64) -> bool {
            self.hw_breakpoints.contains(addr)
        }
        fn save_hw_breakpoint(&mut self, addr: &u64) -> bool {
            if self.hw_breakpoints.len() >= MAX_NO_OF_HW_BP {
                false
            } else {
                self.hw_breakpoints.push(*addr);

                true
            }
        }
        fn delete_hw_breakpoint(&mut self, addr: &u64) {
            self.hw_breakpoints.retain(|&a| a != *addr);
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

            Ok(())
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

        fn write_regs(&self, vcpu_fd: &Self::Vcpu, regs: &X86_64Regs) -> Result<()> {
            log::debug!("Write registers");
            let new_regs = kvm_regs {
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
                .set_regs(&new_regs)
                .map_err(|e| new_error!("Could not write guest registers: {:?}", e))
        }
    }

    impl GuestMemoryDebug for KvmDebug {
        fn is_sw_breakpoint(&self, addr: &u64) -> bool {
            self.sw_breakpoints.contains_key(addr)
        }
        fn save_sw_breakpoint_data(&mut self, addr: u64, data: [u8; 1]) {
            _ = self.sw_breakpoints.insert(addr, data);
        }
        fn delete_sw_breakpoint_data(&mut self, addr: &u64) -> Option<[u8; 1]> {
            self.sw_breakpoints.remove(addr)
        }
    }
}
