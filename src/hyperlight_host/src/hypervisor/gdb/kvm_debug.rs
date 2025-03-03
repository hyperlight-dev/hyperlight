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

use kvm_bindings::{
    kvm_guest_debug, KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_SINGLESTEP, KVM_GUESTDBG_USE_HW_BP,
    KVM_GUESTDBG_USE_SW_BP,
};
use kvm_ioctls::VcpuFd;

use super::*;
use crate::{new_error, Result};

/// KVM Debug struct
/// This struct is used to abstract the internal details of the kvm
/// guest debugging settings
#[derive(Default)]
pub(crate) struct KvmDebug {
    /// vCPU stepping state
    pub(crate) single_step: bool,

    /// Array of addresses for HW breakpoints
    pub(crate) hw_breakpoints: Vec<u64>,
    /// Saves the bytes modified to enable SW breakpoints
    pub(crate) sw_breakpoints: HashMap<u64, [u8; SW_BP_SIZE]>,

    /// Sent to KVM for enabling guest debug
    dbg_cfg: kvm_guest_debug,
}

impl KvmDebug {
    const MAX_NO_OF_HW_BP: usize = 4;

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

    /// This method sets the kvm debugreg fields to enable breakpoints at
    /// specific addresses
    ///
    /// The first 4 debug registers are used to set the addresses
    /// The 4th and 5th debug registers are obsolete and not used
    /// The 7th debug register is used to enable the breakpoints
    /// For more information see: DEBUG REGISTERS chapter in the architecture
    /// manual
    pub(crate) fn set_debug_config(&mut self, vcpu_fd: &VcpuFd, step: bool) -> Result<()> {
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

    /// Method that adds a breakpoint
    pub(crate) fn add_breakpoint(&mut self, vcpu_fd: &VcpuFd, addr: u64) -> Result<bool> {
        if self.hw_breakpoints.len() >= Self::MAX_NO_OF_HW_BP {
            Ok(false)
        } else if self.hw_breakpoints.contains(&addr) {
            Ok(true)
        } else {
            self.hw_breakpoints.push(addr);
            self.set_debug_config(vcpu_fd, self.single_step)?;

            Ok(true)
        }
    }

    /// Method that removes a breakpoint
    pub(crate) fn remove_breakpoint(&mut self, vcpu_fd: &VcpuFd, addr: u64) -> Result<bool> {
        if self.hw_breakpoints.contains(&addr) {
            self.hw_breakpoints.retain(|&a| a != addr);
            self.set_debug_config(vcpu_fd, self.single_step)?;

            Ok(true)
        } else {
            Ok(false)
        }
    }
}
