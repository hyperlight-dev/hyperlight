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

#[cfg(gdb)]
use std::collections::HashMap;
use std::sync::LazyLock;

#[cfg(gdb)]
use kvm_bindings::kvm_guest_debug;
use kvm_bindings::{kvm_userspace_memory_region, KVM_MEM_READONLY};
use kvm_ioctls::Cap::UserMemory;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use tracing::{instrument, Span};

use super::regs::{CommonFpu, CommonRegisters, CommonSpecialRegisters};
use super::vm::{HyperlightExit, Vm};
#[cfg(gdb)]
use crate::hypervisor::vm::DebugExit;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::{log_then_return, new_error, Result};

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
    vm_fd: VmFd,
    vcpu_fd: VcpuFd,

    #[cfg(gdb)]
    debug: KvmDebug,
}

#[cfg(gdb)]
#[derive(Debug, Default)]
struct KvmDebug {
    regs: kvm_guest_debug,
    sw_breakpoints: HashMap<u64, u8>, // addr -> original instruction
}

static KVM: LazyLock<Result<Kvm>> =
    LazyLock::new(|| Kvm::new().map_err(|e| new_error!("Failed to open /dev/kvm: {}", e)));

impl KvmVm {
    /// Create a new instance of a `KvmVm`
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(super) fn new() -> Result<Self> {
        let hv = KVM
            .as_ref()
            .map_err(|e| new_error!("Failed to create KVM instance: {}", e))?;
        let vm_fd = hv.create_vm_with_type(0)?;
        let vcpu_fd = vm_fd.create_vcpu(0)?;

        Ok(Self {
            vm_fd,
            vcpu_fd,
            #[cfg(gdb)]
            debug: KvmDebug::default(),
        })
    }
}

impl Vm for KvmVm {
    fn get_regs(&self) -> Result<CommonRegisters> {
        Ok((&self.vcpu_fd.get_regs()?).into())
    }

    fn set_regs(&self, regs: &CommonRegisters) -> Result<()> {
        Ok(self.vcpu_fd.set_regs(&regs.into())?)
    }

    fn get_sregs(&self) -> Result<CommonSpecialRegisters> {
        Ok((&self.vcpu_fd.get_sregs()?).into())
    }

    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> Result<()> {
        Ok(self.vcpu_fd.set_sregs(&sregs.into())?)
    }

    fn get_fpu(&self) -> Result<CommonFpu> {
        Ok((&self.vcpu_fd.get_fpu()?).into())
    }

    fn set_fpu(&self, fpu: &CommonFpu) -> Result<()> {
        Ok(self.vcpu_fd.set_fpu(&fpu.into())?)
    }

    unsafe fn map_memory(&mut self, regions: &[MemoryRegion]) -> Result<()> {
        if regions.is_empty() {
            return Err(new_error!("No memory regions to map"));
        }

        regions.iter().enumerate().try_for_each(|(i, region)| {
            let kvm_region = kvm_userspace_memory_region {
                slot: i as u32,
                guest_phys_addr: region.guest_region.start as u64,
                memory_size: region.guest_region.len() as u64,
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
            Ok(VcpuExit::Debug(debug_exit)) => Ok(HyperlightExit::Debug(DebugExit::Debug {
                dr6: debug_exit.dr6,
                exception: debug_exit.exception,
            })),
            Err(e) => match e.errno() {
                // In case of the gdb feature, the timeout is not enabled, this
                // exit is because of a signal sent from the gdb thread to the
                // hypervisor thread to cancel execution (e.g. Ctrl+C from GDB)
                #[cfg(gdb)]
                libc::EINTR => Ok(HyperlightExit::Debug(DebugExit::Interrupt)),
                // we send a signal to the thread to cancel execution. This results in EINTR being returned
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

    // --- DEBUGGING RELATED BELOW ---

    #[cfg(gdb)]
    fn translate_gva(&self, gva: u64) -> Result<u64> {
        use crate::HyperlightError;

        let gpa = self.vcpu_fd.translate_gva(gva)?;
        if gpa.valid == 0 {
            Err(HyperlightError::TranslateGuestAddress(gva))
        } else {
            Ok(gpa.physical_address)
        }
    }

    #[cfg(gdb)]
    fn set_debug(&mut self, enable: bool) -> Result<()> {
        use kvm_bindings::{KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_USE_HW_BP, KVM_GUESTDBG_USE_SW_BP};

        log::info!("Setting debug to {}", enable);
        if enable {
            self.debug.regs.control |=
                KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP | KVM_GUESTDBG_USE_SW_BP;
        } else {
            self.debug.regs.control &=
                !(KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP | KVM_GUESTDBG_USE_SW_BP);
        }
        self.vcpu_fd.set_guest_debug(&self.debug.regs)?;
        Ok(())
    }

    #[cfg(gdb)]
    fn set_single_step(&mut self, enable: bool) -> Result<()> {
        use kvm_bindings::KVM_GUESTDBG_SINGLESTEP;

        log::info!("Setting single step to {}", enable);
        if enable {
            self.debug.regs.control |= KVM_GUESTDBG_SINGLESTEP;
        } else {
            self.debug.regs.control &= !KVM_GUESTDBG_SINGLESTEP;
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

    #[cfg(gdb)]
    fn add_hw_breakpoint(&mut self, addr: u64) -> Result<()> {
        use crate::hypervisor::gdb::arch::MAX_NO_OF_HW_BP;
        use crate::new_error;

        // Find the first available LOCAL (L0–L3) slot
        let i = (0..MAX_NO_OF_HW_BP)
            .position(|i| self.debug.regs.arch.debugreg[7] & (1 << (i * 2)) == 0)
            .ok_or_else(|| new_error!("Tried to add more than 4 hardware breakpoints"))?;

        // Assign to corresponding debug register
        self.debug.regs.arch.debugreg[i] = addr;

        // Enable LOCAL bit
        self.debug.regs.arch.debugreg[7] |= 1 << (i * 2);

        self.vcpu_fd.set_guest_debug(&self.debug.regs)?;
        Ok(())
    }

    #[cfg(gdb)]
    fn remove_hw_breakpoint(&mut self, addr: u64) -> Result<()> {
        use crate::new_error;

        // Find the index of the breakpoint
        let index = self.debug.regs.arch.debugreg[..4]
            .iter()
            .position(|&a| a == addr)
            .ok_or_else(|| new_error!("Tried to remove non-existing hw-breakpoint"))?;

        // Clear the address
        self.debug.regs.arch.debugreg[index] = 0;
        // Disable LOCAL bit
        self.debug.regs.arch.debugreg[7] &= !(1 << (index * 2));

        self.vcpu_fd.set_guest_debug(&self.debug.regs)?;
        Ok(())
    }

    #[cfg(gdb)]
    fn add_sw_breakpoint(
        &mut self,
        addr: u64,
        dbg_mem_access_fn: std::sync::Arc<
            std::sync::Mutex<dyn super::handlers::DbgMemAccessHandlerCaller>,
        >,
    ) -> Result<()> {
        use super::gdb::arch::SW_BP_SIZE;
        use crate::hypervisor::gdb::arch::SW_BP;

        let mut save_data = [0; SW_BP_SIZE];
        let mut mem = dbg_mem_access_fn.lock().unwrap();
        mem.read(addr as usize, &mut save_data[..])?;
        mem.write(addr as usize, &SW_BP)?;
        self.debug.sw_breakpoints.insert(addr, save_data[0]);
        Ok(())
    }

    #[cfg(gdb)]
    fn remove_sw_breakpoint(
        &mut self,
        addr: u64,
        dbg_mem_access_fn: std::sync::Arc<
            std::sync::Mutex<dyn super::handlers::DbgMemAccessHandlerCaller>,
        >,
    ) -> Result<()> {
        let original_instr = self.debug.sw_breakpoints.remove(&addr).unwrap();
        dbg_mem_access_fn
            .lock()
            .unwrap()
            .write(addr as usize, &[original_instr])?;
        Ok(())
    }
}
