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
use kvm_bindings::{
    KVM_CAP_X86_USER_SPACE_MSR, KVM_MSR_EXIT_REASON_FILTER, KVM_MSR_FILTER_DEFAULT_DENY,
    KVM_MSR_FILTER_READ, KVM_MSR_FILTER_WRITE, kvm_debugregs, kvm_enable_cap, kvm_msr_filter,
    kvm_msr_filter_range, kvm_userspace_memory_region, kvm_xsave,
};
use kvm_ioctls::Cap::{self, UserMemory};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use tracing::{Span, instrument};

use crate::hypervisor::regs::{
    CommonDebugRegs, CommonFpu, CommonRegisters, CommonSpecialRegisters,
};
use crate::hypervisor::vm::{Vm, VmExit};
use crate::mem::memory_region::MemoryRegion;
use crate::{Result, new_error};

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

impl Vm for KvmVm {
    fn regs(&self) -> Result<CommonRegisters> {
        Ok((&self.vcpu_fd.get_regs()?).into())
    }

    fn set_regs(&self, regs: &CommonRegisters) -> Result<()> {
        Ok(self.vcpu_fd.set_regs(&regs.into())?)
    }

    fn sregs(&self) -> Result<CommonSpecialRegisters> {
        Ok((&self.vcpu_fd.get_sregs()?).into())
    }

    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> Result<()> {
        Ok(self.vcpu_fd.set_sregs(&sregs.into())?)
    }

    fn fpu(&self) -> Result<CommonFpu> {
        Ok((&self.vcpu_fd.get_fpu()?).into())
    }

    fn set_fpu(&self, fpu: &CommonFpu) -> Result<()> {
        Ok(self.vcpu_fd.set_fpu(&fpu.into())?)
    }

    fn xsave(&self) -> Result<Vec<u8>> {
        let xsave = self.vcpu_fd.get_xsave()?;
        Ok(xsave
            .region
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect())
    }

    fn set_xsave(&self, xsave: &[u32; 1024]) -> Result<()> {
        if self.vm_fd.check_extension_int(Cap::Xsave2) as usize != xsave.len() * size_of::<u32>() {
            return Err(new_error!(
                "KVM_CAP_XSAVE2 not supported: {}",
                self.vm_fd.check_extension_int(Cap::Xsave2)
            ));
        }
        let xsave = kvm_xsave {
            region: *xsave,
            ..Default::default()
        };
        // we made sure above that SET_XSAVE only copies 4096 bytes
        unsafe { self.vcpu_fd.set_xsave(&xsave)? };

        Ok(())
    }

    fn debug_regs(&self) -> Result<CommonDebugRegs> {
        let kvm_debug_regs = self.vcpu_fd.get_debug_regs()?;
        Ok(kvm_debug_regs.into())
    }

    fn set_debug_regs(&self, drs: &CommonDebugRegs) -> Result<()> {
        let kvm_debug_regs: kvm_debugregs = drs.into();
        self.vcpu_fd.set_debug_regs(&kvm_debug_regs)?;
        Ok(())
    }

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

            /* Note from KVM docs:
            For KVM_EXIT_X86_RDMSR and KVM_EXIT_X86_WRMSR the corresponding operations are complete (and guest state is consistent)
            only after userspace has re-entered the kernel with KVM_RUN. The kernel side will first finish incomplete operations and then check for pending signals.

            The pending state of the operation is not preserved in state which is visible to userspace, thus userspace should ensure that the operation
            is completed before performing a live migration. Userspace can re-enter the guest with an unmasked signal pending or with the immediate_exit field
            set to complete pending operations without allowing any further instructions to be executed.
            */
            Ok(VcpuExit::X86Rdmsr(msr_exit)) => {
                let msr_index = msr_exit.index;
                *msr_exit.error = 1;
                self.vcpu_fd.set_kvm_immediate_exit(1);
                let exit = self.vcpu_fd.run().unwrap_err();
                if exit.errno() != libc::EINTR {
                    return Err(new_error!(
                        "Expected EINTR after immediate exit run, got {:?}",
                        exit
                    ));
                }
                Ok(VmExit::MsrRead(msr_index))
            }
            Ok(VcpuExit::X86Wrmsr(msr_exit)) => {
                let msr_index = msr_exit.index;
                let value = msr_exit.data;
                *msr_exit.error = 1;
                self.vcpu_fd.set_kvm_immediate_exit(1);
                let exit = self.vcpu_fd.run().unwrap_err();
                if exit.errno() != libc::EINTR {
                    return Err(new_error!(
                        "Expected EINTR after immediate exit run, got {:?}",
                        exit
                    ));
                }
                Ok(VmExit::MsrWrite { msr_index, value })
            }
            #[cfg(gdb)]
            Ok(VcpuExit::Debug(debug_exit)) => Ok(VmExit::Debug {
                dr6: debug_exit.dr6,
                exception: debug_exit.exception,
            }),
            Err(e) => match e.errno() {
                libc::EINTR => Ok(VmExit::Cancelled()),
                libc::EAGAIN => Ok(VmExit::Retry()),

                other => Ok(VmExit::Unknown(format!(
                    "Unknown KVM VCPU error: {}",
                    other
                ))),
            },
            Ok(other) => Ok(VmExit::Unknown(format!(
                "Unknown KVM VCPU exit: {:?}",
                other
            ))),
        }
    }

    fn enable_msr_intercept(&mut self) -> Result<()> {
        let cap = kvm_enable_cap {
            cap: KVM_CAP_X86_USER_SPACE_MSR,
            flags: 0,
            args: [KVM_MSR_EXIT_REASON_FILTER as u64, 0, 0, 0],
            pad: [0; 64],
        };
        self.vm_fd.enable_cap(&cap)?;

        // Deny all MSR accesses using KVM_MSR_FILTER_DEFAULT_DENY.
        // We need at least one range (even a minimal dummy range) because
        // "Calling this ioctl with an empty set of ranges (all nmsrs == 0) disables MSR filtering.
        // In that mode, KVM_MSR_FILTER_DEFAULT_DENY is invalid and causes an error."
        // So we create a minimal range covering just 1 MSR with a bitmap of 0 (deny).
        // All other MSRs will be denied by the default policy.
        let mut bitmap = vec![0u8; 1]; // 1 byte covers 8 MSRs, all bits set to 0 (deny)
        let mut ranges = [kvm_msr_filter_range::default(); 16];
        ranges[0] = kvm_msr_filter_range {
            flags: KVM_MSR_FILTER_READ | KVM_MSR_FILTER_WRITE,
            nmsrs: 1, // Cover just 1 MSR
            base: 0,  // Starting at MSR index 0
            bitmap: bitmap.as_mut_ptr(),
        };

        let filter = kvm_msr_filter {
            flags: KVM_MSR_FILTER_DEFAULT_DENY,
            ranges,
        };
        // Safety: The bitmap pointer is valid and nmsrs is set correctly
        unsafe { self.vm_fd.set_msr_filter(&filter)? };

        Ok(())
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
            self.debug_regs.control |=
                KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP | KVM_GUESTDBG_USE_SW_BP;
        } else {
            self.debug_regs.control &=
                !(KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP | KVM_GUESTDBG_USE_SW_BP);
        }
        self.vcpu_fd.set_guest_debug(&self.debug_regs)?;
        Ok(())
    }

    #[cfg(gdb)]
    fn set_single_step(&mut self, enable: bool) -> Result<()> {
        use kvm_bindings::KVM_GUESTDBG_SINGLESTEP;

        log::info!("Setting single step to {}", enable);
        if enable {
            self.debug_regs.control |= KVM_GUESTDBG_SINGLESTEP;
        } else {
            self.debug_regs.control &= !KVM_GUESTDBG_SINGLESTEP;
        }
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

    #[cfg(gdb)]
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

    #[cfg(gdb)]
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

#[test]
fn test() {
    let msr_feature_index_list = KVM.as_ref().unwrap().get_msr_index_list().unwrap();
    msr_feature_index_list.as_slice().iter().for_each(|msr| {
        println!("Writable MSR: 0x{:08X}", msr);
    });
    println!(
        "Total Writable MSRs: {}",
        msr_feature_index_list.as_slice().len()
    );
    // println!("msr_feature_index_list: {:?}", msr_feature_index_list);
}
