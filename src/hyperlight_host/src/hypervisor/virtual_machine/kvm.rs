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

use std::sync::LazyLock;

#[cfg(gdb)]
use kvm_bindings::kvm_guest_debug;
use kvm_bindings::{kvm_fpu, kvm_regs, kvm_sregs, kvm_userspace_memory_region};
use kvm_ioctls::Cap::UserMemory;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use tracing::{Span, instrument};

#[cfg(gdb)]
use crate::hypervisor::gdb::DebuggableVm;
use crate::hypervisor::regs::{CommonFpu, CommonRegisters, CommonSpecialRegisters};
use crate::hypervisor::virtual_machine::{VirtualMachine, VmExit};
use crate::mem::memory_region::MemoryRegion;
use crate::sandbox::trace::context::TraceContext as SandboxTraceContext;
use crate::{Result, new_error};

/// Return `true` if the KVM API is available, version 12, and has UserMemory capability, or `false` otherwise
#[instrument(skip_all, parent = Span::current(), level = "Trace")]
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
pub(crate) struct KvmVm {
    vm_fd: VmFd,
    vcpu_fd: VcpuFd,

    // KVM as opposed to mshv/whp has no way to get current debug regs, so need to keep a copy here
    #[cfg(gdb)]
    debug_regs: kvm_guest_debug,
}

static KVM: LazyLock<Result<Kvm>> =
    LazyLock::new(|| Kvm::new().map_err(|e| new_error!("Failed to open /dev/kvm: {}", e)));

impl KvmVm {
    /// Create a new instance of a `KvmVm`
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn new() -> Result<Self> {
        let hv = KVM
            .as_ref()
            .map_err(|e| new_error!("Failed to create KVM instance: {}", e))?;
        let vm_fd = hv.create_vm_with_type(0)?;
        let vcpu_fd = vm_fd.create_vcpu(0)?;

        Ok(Self {
            vm_fd,
            vcpu_fd,
            #[cfg(gdb)]
            debug_regs: kvm_guest_debug::default(),
        })
    }
}

impl VirtualMachine for KvmVm {
    unsafe fn map_memory(&mut self, (slot, region): (u32, &MemoryRegion)) -> Result<()> {
        let mut kvm_region: kvm_userspace_memory_region = region.into();
        kvm_region.slot = slot;
        unsafe { self.vm_fd.set_user_memory_region(kvm_region)? };
        Ok(())
    }

    fn unmap_memory(&mut self, (slot, region): (u32, &MemoryRegion)) -> Result<()> {
        let mut kvm_region: kvm_userspace_memory_region = region.into();
        kvm_region.slot = slot;
        // Setting memory_size to 0 unmaps the slot's region
        // From https://docs.kernel.org/virt/kvm/api.html
        // > Deleting a slot is done by passing zero for memory_size.
        kvm_region.memory_size = 0;
        unsafe { self.vm_fd.set_user_memory_region(kvm_region) }?;
        Ok(())
    }

    fn run_vcpu(&mut self, tc: &SandboxTraceContext) -> Result<VmExit> {
        #[cfg(feature = "trace_guest")]
        tc.setup_guest_trace(Span::current().context());

        match self.vcpu_fd.run() {
            Ok(VcpuExit::Hlt) => Ok(VmExit::Halt()),
            Ok(VcpuExit::IoOut(port, data)) => Ok(VmExit::IoOut(port, data.to_vec())),
            Ok(VcpuExit::MmioRead(addr, _)) => Ok(VmExit::MmioRead(addr)),
            Ok(VcpuExit::MmioWrite(addr, _)) => Ok(VmExit::MmioWrite(addr)),
            #[cfg(gdb)]
            Ok(VcpuExit::Debug(debug_exit)) => Ok(VmExit::Debug {
                dr6: debug_exit.dr6,
                exception: debug_exit.exception,
            }),
            Err(e) => match e.errno() {
                // InterruptHandle::kill() sends a signal (SIGRTMIN+offset) to interrupt the vcpu, which causes EINTR
                libc::EINTR => Ok(VmExit::Cancelled()),
                libc::EAGAIN => Ok(VmExit::Retry()),
                _ => Ok(VmExit::Unknown(format!("Unknown KVM VCPU error: {}", e))),
            },
            Ok(other) => Ok(VmExit::Unknown(format!(
                "Unknown KVM VCPU exit: {:?}",
                other
            ))),
        }
    }

    fn regs(&self) -> Result<CommonRegisters> {
        let kvm_regs = self.vcpu_fd.get_regs()?;
        Ok((&kvm_regs).into())
    }

    fn set_regs(&self, regs: &CommonRegisters) -> Result<()> {
        let kvm_regs: kvm_regs = regs.into();
        self.vcpu_fd.set_regs(&kvm_regs)?;
        Ok(())
    }

    fn fpu(&self) -> Result<CommonFpu> {
        let kvm_fpu = self.vcpu_fd.get_fpu()?;
        Ok((&kvm_fpu).into())
    }

    fn set_fpu(&self, fpu: &CommonFpu) -> Result<()> {
        let kvm_fpu: kvm_fpu = fpu.into();
        self.vcpu_fd.set_fpu(&kvm_fpu)?;
        Ok(())
    }

    fn sregs(&self) -> Result<CommonSpecialRegisters> {
        let kvm_sregs = self.vcpu_fd.get_sregs()?;
        Ok((&kvm_sregs).into())
    }

    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> Result<()> {
        let kvm_sregs: kvm_sregs = sregs.into();
        self.vcpu_fd.set_sregs(&kvm_sregs)?;
        Ok(())
    }

    #[cfg(crashdump)]
    fn xsave(&self) -> Result<Vec<u8>> {
        let xsave = self.vcpu_fd.get_xsave()?;
        Ok(xsave
            .region
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect())
    }
}

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
