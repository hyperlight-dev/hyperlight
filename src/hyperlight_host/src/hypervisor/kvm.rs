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

use kvm_bindings::{
    kvm_debug_exit_arch, kvm_debugregs, kvm_guest_debug, kvm_userspace_memory_region,
    KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_SINGLESTEP, KVM_GUESTDBG_USE_HW_BP, KVM_MEM_READONLY,
};
use kvm_ioctls::Cap::UserMemory;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use tracing::{instrument, Span};

use super::gdb::VcpuStopReason;
use super::handlers::DbgMemAccessHandlerCaller;
use super::HyperlightExit;
use crate::fpuregs::CommonFpu;
use crate::hypervisor::gdb::{DR6_BS_FLAG_MASK, DR6_HW_BP_FLAGS_MASK};
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::regs::CommonRegisters;
use crate::sregs::CommonSpecialRegisters;
use crate::vm::Vm;
use crate::{log_then_return, new_error, HyperlightError, Result};

/// Return `true` if the KVM API is available, version 12, and has UserMemory capability, or `false` otherwise
pub(crate) fn is_hypervisor_present() -> bool {
    if let Ok(kvm) = Kvm::new() {
        let api_version = kvm.get_api_version();
        match api_version {
            version if version == 12 && kvm.check_extension(UserMemory) => true,
            12 => {
                log::info!("KVM does not have KVM_CAP_USER_MEMORY capability");
                false
            }
            version => {
                log::info!("KVM GET_API_VERSION returned {}, expected 12", version);
                false
            }
        }
    } else {
        log::info!("KVM is not available on this system");
        false
    }
}

/// A KVM implementation of a single-vcpu VM
#[derive(Debug)]
pub(super) struct KvmVm {
    kvm_fd: Kvm,
    vm_fd: VmFd,
    vcpu_fd: VcpuFd,

    next_debug: usize,
    debug: kvm_guest_debug,
}

impl KvmVm {
    /// Create a new instance of a `KvmVm`
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(super) fn new() -> Result<Self> {
        let kvm_fd = Kvm::new()?;
        let vm_fd = kvm_fd.create_vm_with_type(0)?;
        let vcpu_fd = vm_fd.create_vcpu(0)?;

        Ok(Self {
            kvm_fd,
            vm_fd,
            vcpu_fd,
            debug: kvm_guest_debug::default(),
            next_debug: 0,
        })
    }

    /// TODO this has been slightly modified in this PR
    fn get_debug_stop_reason(&mut self, debug_exit: kvm_debug_exit_arch) -> Result<VcpuStopReason> {
        /// Exception id for SW breakpoint
        const SW_BP_ID: u32 = 3;

        let CommonRegisters { rip, .. } = self.get_regs()?;

        // If the BS flag in DR6 register is set, it means a single step
        // instruction triggered the exit
        // Check page 19-4 Vol. 3B of Intel 64 and IA-32
        // Architectures Software Developer's Manual
        if debug_exit.dr6 & DR6_BS_FLAG_MASK != 0 {
            return Ok(VcpuStopReason::DoneStep);
        }
        // If any of the B0-B3 flags in DR6 register is set, it means a
        // hardware breakpoint triggered the exit
        // Check page 19-4 Vol. 3B of Intel 64 and IA-32
        // Architectures Software Developer's Manual
        if DR6_HW_BP_FLAGS_MASK & debug_exit.dr6 != 0 {
            let gpa = self.translate_gva(rip)?;
            if gpa == 0x31310 {
                self.remove_hw_breakpoint(gpa).unwrap();
            }
            println!("gpa: {:#x}", gpa);
            return Ok(VcpuStopReason::HwBp);
        }

        // If the exception ID matches #BP (3) - it means a software breakpoint
        // caused the exit
        if debug_exit.exception == SW_BP_ID {
            return Ok(VcpuStopReason::SwBp);
        }

        // Log an error and provide internal debugging info for fixing
        log::error!("The vCPU exited because of an unknown debug reason");
        Ok(VcpuStopReason::Unknown)
    }
}

impl Vm for KvmVm {
    fn get_regs(&self) -> Result<CommonRegisters> {
        let kvm_regs = self.vcpu_fd.get_regs()?;
        Ok(kvm_regs.into())
    }

    fn set_regs(&self, regs: &CommonRegisters) -> Result<()> {
        let kvm_regs = regs.clone().into();
        Ok(self.vcpu_fd.set_regs(&kvm_regs)?)
    }

    fn get_sregs(&self) -> Result<CommonSpecialRegisters> {
        Ok(self.vcpu_fd.get_sregs()?.into())
    }

    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> Result<()> {
        Ok(self.vcpu_fd.set_sregs(&sregs.clone().into())?)
    }

    fn get_fpu(&self) -> Result<CommonFpu> {
        Ok(self.vcpu_fd.get_fpu()?.into())
    }

    fn set_fpu(&self, fpu: &CommonFpu) -> Result<()> {
        Ok(self.vcpu_fd.set_fpu(&fpu.clone().into())?)
    }

    unsafe fn map_memory(&self, regions: &[MemoryRegion]) -> Result<()> {
        regions.iter().enumerate().try_for_each(|(i, region)| {
            let kvm_region = kvm_userspace_memory_region {
                slot: i as u32,
                guest_phys_addr: region.guest_region.start as u64,
                memory_size: (region.guest_region.end - region.guest_region.start) as u64,
                userspace_addr: region.host_region.start as u64,
                flags: match region.flags {
                    MemoryRegionFlags::READ => KVM_MEM_READONLY,
                    _ => 0, // normal, RWX
                },
            };
            unsafe { self.vm_fd.set_user_memory_region(kvm_region) }
        })?;
        Ok(())
    }

    fn run_vcpu(&mut self) -> Result<HyperlightExit> {
        match self.vcpu_fd.run() {
            Ok(VcpuExit::Hlt) => Ok(HyperlightExit::Halt()),
            Ok(VcpuExit::IoOut(port, data)) => Ok(HyperlightExit::IoOut(port, data.to_vec())),
            Ok(VcpuExit::MmioRead(addr, _)) => Ok(HyperlightExit::MmioRead(addr)),
            Ok(VcpuExit::MmioWrite(addr, _)) => Ok(HyperlightExit::MmioWrite(addr)),
            #[cfg(gdb)]
            // KVM provides architecture specific information about the vCPU state when exiting
            Ok(VcpuExit::Debug(debug_exit)) => {
                log::error!("KVM VCPU DEBUG EXIT");
                match self.get_debug_stop_reason(debug_exit) {
                    Ok(reason) => Ok(HyperlightExit::Debug(reason)),
                    Err(e) => {
                        log_then_return!("Error getting stop reason: {:?}", e);
                    }
                }
            }
            Err(e) => match e.errno() {
                // In case of the gdb feature, the timeout is not enabled, this
                // exit is because of a signal sent from the gdb thread to the
                // hypervisor thread to cancel execution
                #[cfg(gdb)]
                libc::EINTR => Ok(HyperlightExit::Debug(VcpuStopReason::Interrupt)),
                // we send a signal to the thread to cancel execution this results in EINTR being returned by KVM so we return Cancelled
                #[cfg(not(gdb))]
                libc::EINTR => Ok(HyperlightExit::Cancelled()),
                libc::EAGAIN => Ok(HyperlightExit::Retry()),
                _ => {
                    crate::debug!("KVM Error -Details: Address: {} \n {:#?}", e, &self);
                    log_then_return!("Error running VCPU {:?}", e);
                }
            },
            Ok(other) => {
                let err_msg = format!("Unexpected KVM Exit {:?}", other);
                crate::debug!("KVM Other Exit Details: {:#?}", &self);
                Ok(HyperlightExit::Unknown(err_msg))
            }
        }
    }

    fn interrupt_handle(&self) -> crate::vm::InterruptHandle {
        todo!()
    }

    // --- DEBUGGING RELATED BELOW ---

    fn enable_debug(&mut self) -> Result<()> {
        self.debug.control |= KVM_GUESTDBG_ENABLE;
        Ok(())
    }

    fn disable_debug(&mut self) -> Result<()> {
        todo!()
    }

    fn set_single_step(&mut self, enable: bool) -> Result<()> {
        log::info!("Setting single step to {}", enable);
        if enable {
            self.debug.control |= KVM_GUESTDBG_SINGLESTEP;
        } else {
            self.debug.control &= !KVM_GUESTDBG_SINGLESTEP;
        }
        // Set TF Flag to enable Traps
        let mut regs = self.get_regs()?;
        if enable {
            regs.rflags |= 1 << 8;
        } else {
            regs.rflags &= !(1 << 8);
        }
        self.set_regs(&regs)?;
        Ok(())
    }

    fn add_sw_breakpoint(
        &mut self,
        addr: u64,
        dbg_mem_access_fn: Arc<Mutex<dyn DbgMemAccessHandlerCaller>>,
    ) -> Result<()> {
        log::info!("Setting sw (hw) breakpoint");
        self.add_hw_breakpoint(addr)
    }

    fn add_hw_breakpoint(&mut self, addr: u64) -> Result<()> {
        log::info!("Setting hw breakpoint");
        if self.next_debug >= 4 {
            return Err(new_error!("Tried to add more than 4 hardware breakpoints"));
        }
        self.debug.control |= KVM_GUESTDBG_USE_HW_BP;
        self.debug.arch.debugreg[self.next_debug] = addr;
        self.debug.arch.debugreg[7] |= 1 << (self.next_debug * 2);
        self.next_debug += 1;
        self.vcpu_fd.set_guest_debug(&self.debug)?;

        Ok(())
    }

    fn remove_sw_breakpoint(
        &mut self,
        addr: u64,
        dbg_mem_access_fn: Arc<Mutex<dyn DbgMemAccessHandlerCaller>>,
    ) -> Result<()> {
        self.remove_hw_breakpoint(addr)
    }

    fn remove_hw_breakpoint(&mut self, addr: u64) -> Result<()> {
        // Find the index of the breakpoint
        let index = self.debug.arch.debugreg[..4]
            .iter()
            .position(|&a| a == addr)
            .ok_or_else(|| new_error!("Hardware breakpoint not found"))?;

        // Clear the address and disable the corresponding bit
        self.debug.arch.debugreg[index] = 0;
        self.debug.arch.debugreg[7] &= !(1 << (index * 2));

        // Decrement next_debug only if this was the last one
        if index == self.next_debug - 1 {
            self.next_debug -= 1;
        }

        self.vcpu_fd.set_guest_debug(&self.debug)?;
        Ok(())
    }

    fn translate_gva(&self, gva: u64) -> Result<u64> {
        let gpa = self.vcpu_fd.translate_gva(gva)?;
        if gpa.valid == 0 {
            Err(HyperlightError::TranslateGuestAddress(gva))
        } else {
            Ok(gpa.physical_address)
        }
    }
}
