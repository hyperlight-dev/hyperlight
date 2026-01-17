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
use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::Cap::UserMemory;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use tracing::{Span, instrument};

use crate::hypervisor::arch::{CommonFpu, CommonRegisters, CommonSpecialRegisters};
use crate::hypervisor::virtual_machine::{VirtualMachine, VmExit};
use crate::mem::memory_region::MemoryRegion;
use crate::{Result, new_error};

// Include architecture-specific implementations
#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "aarch64")]
mod aarch64;

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
    // --- Shared methods (same on all architectures) ---

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

    fn run_vcpu(&mut self) -> Result<VmExit> {
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

    // --- Architecture-specific methods (delegate to arch modules) ---

    fn regs(&self) -> Result<CommonRegisters> {
        self.get_regs_arch()
    }

    fn set_regs(&self, regs: &CommonRegisters) -> Result<()> {
        self.set_regs_arch(regs)
    }

    fn fpu(&self) -> Result<CommonFpu> {
        self.get_fpu_arch()
    }

    fn set_fpu(&self, fpu: &CommonFpu) -> Result<()> {
        self.set_fpu_arch(fpu)
    }

    fn sregs(&self) -> Result<CommonSpecialRegisters> {
        self.get_sregs_arch()
    }

    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> Result<()> {
        self.set_sregs_arch(sregs)
    }

    #[cfg(crashdump)]
    fn xsave(&self) -> Result<Vec<u8>> {
        self.get_xsave_arch()
    }
}
