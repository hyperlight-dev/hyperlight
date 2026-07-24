/*
Copyright 2025 The Hyperlight Authors.

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

// TODO(aarch64): implement KVM backend

use std::sync::LazyLock;

use hyperlight_common::outb::VmAction;
use kvm_bindings::{
    KVM_CAP_ARM_NISV_TO_USER, KVM_EXIT_ARM_NISV, KVMIO, kvm_enable_cap, kvm_userspace_memory_region,
};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use tracing::{Span, instrument};

use crate::hypervisor::regs::{CommonFpu, CommonRegisters, CommonSpecialRegisters};
use crate::hypervisor::virtual_machine::{
    CreateVmError, HypervisorError, MapMemoryError, RegisterError, ResetVcpuError, RunVcpuError,
    UnmapMemoryError, VirtualMachine, VmExit,
};

static KVM: LazyLock<std::result::Result<Kvm, CreateVmError>> =
    LazyLock::new(|| Kvm::new().map_err(|e| CreateVmError::HypervisorNotAvailable(e.into())));

/// Return `true` if the KVM API is available
#[instrument(skip_all, parent = Span::current(), level = "Trace")]
pub(crate) fn is_hypervisor_present() -> bool {
    if let Ok(kvm) = KVM.as_ref() {
        let api_version = kvm.get_api_version();
        api_version == 12
    } else {
        false
    }
}

/// A KVM implementation of a single-vcpu VM
#[derive(Debug)]
pub(crate) struct KvmVm {
    vm_fd: VmFd,
    vcpu_fd: VcpuFd,
}

impl KvmVm {
    pub(self) fn vcpu_init(&mut self) -> Result<(), HypervisorError> {
        let mut kvi = kvm_bindings::kvm_vcpu_init::default();
        self.vm_fd.get_preferred_target(&mut kvi)?;
        self.vcpu_fd.vcpu_init(&kvi)?;
        Ok(())
    }
    pub(crate) fn new() -> std::result::Result<Self, CreateVmError> {
        let hv = KVM.as_ref().map_err(|e| e.clone())?;
        let vm_fd = hv
            .create_vm_with_type(0)
            .map_err(|e| CreateVmError::CreateVmFd(e.into()))?;
        if vm_fd.check_extension_raw(KVM_CAP_ARM_NISV_TO_USER as u64) != 0 {
            // Available since Linux 5.5. Needed for the workaround
            // described below for KVM misbehaviour when a cache
            // maintenance operation is applied to a VA that is paged
            // out at Stage 2.
            //
            // When this cap is not available, there is a (small)
            // chance that self-modifying code inside the VM will
            // cause [`run_vcpu`] to fail, ultimately poisoning the
            // sandbox. With this capability, the relevant code will
            // instead be retried.
            let cap: kvm_enable_cap = kvm_enable_cap {
                cap: KVM_CAP_ARM_NISV_TO_USER,
                ..Default::default()
            };
            unsafe {
                vmm_sys_util::ioctl_iow_nr!(KVM_ENABLE_CAP, KVMIO, 0xa3, kvm_enable_cap);
                vmm_sys_util::ioctl::ioctl_with_ref(&vm_fd, KVM_ENABLE_CAP(), &cap);
            }
        }

        let vcpu_fd = vm_fd
            .create_vcpu(0)
            .map_err(|e| CreateVmError::CreateVcpuFd(e.into()))?;

        let mut to_ret = Self { vm_fd, vcpu_fd };
        to_ret
            .vcpu_init()
            .map_err(CreateVmError::SetPartitionProperty)?;
        Ok(to_ret)
    }

    fn run_immediate_exit(&mut self) -> Result<(), Result<HypervisorError, String>> {
        self.vcpu_fd.set_kvm_immediate_exit(1u8);
        let ret = loop {
            let r = self.vcpu_fd.run();
            if let Err(e) = r {
                match e.errno() {
                    libc::EINTR => break Ok(()),
                    libc::EAGAIN => continue,
                    _ => break Err(Ok(e.into())),
                }
            } else {
                break Err(Err(format!(
                    "KVM run for state quiescence exited without EINTR: {:?}",
                    r
                )));
            }
        };
        self.vcpu_fd.set_kvm_immediate_exit(0u8);
        ret
    }
}

impl VirtualMachine for KvmVm {
    unsafe fn map_memory(
        &mut self,
        (slot, region): (u32, &crate::mem::memory_region::MemoryRegion),
    ) -> std::result::Result<(), crate::hypervisor::virtual_machine::MapMemoryError> {
        let mut kvm_region: kvm_userspace_memory_region = region.into();
        kvm_region.slot = slot;
        unsafe { self.vm_fd.set_user_memory_region(kvm_region) }
            .map_err(|e| MapMemoryError::Hypervisor(e.into()))
    }

    fn unmap_memory(
        &mut self,
        (slot, region): (u32, &crate::mem::memory_region::MemoryRegion),
    ) -> std::result::Result<(), crate::hypervisor::virtual_machine::UnmapMemoryError> {
        let mut kvm_region: kvm_userspace_memory_region = region.into();
        kvm_region.slot = slot;
        // Setting memory_size to 0 unmaps the slot's region
        // From https://docs.kernel.org/virt/kvm/api.html
        // > Deleting a slot is done by passing zero for memory_size.
        kvm_region.memory_size = 0;
        unsafe { self.vm_fd.set_user_memory_region(kvm_region) }
            .map_err(|e| UnmapMemoryError::Hypervisor(e.into()))
    }

    fn run_vcpu(
        &mut self,
        #[cfg(feature = "trace_guest")] tc: &mut SandboxTraceContext,
    ) -> std::result::Result<
        crate::hypervisor::virtual_machine::VmExit,
        crate::hypervisor::virtual_machine::RunVcpuError,
    > {
        let exit = loop {
            let mut exit = self.vcpu_fd.run();
            if let Ok(VcpuExit::Unsupported(KVM_EXIT_ARM_NISV)) = exit {
                // [`VcpuExit`] borrows the [`Vcpu`] which produced
                // it, but that lifetime isn't used in this case. End
                // the borrow early by re-constructing the value while
                // preserving the possibility for more tests to be
                // inserted after this one.
                exit = Ok(VcpuExit::Unsupported(KVM_EXIT_ARM_NISV));
                // If a readonly-at-stage-2 page is paged out at stage
                // 2, KVM does not correctly handle the page fault due
                // to Stage 2 translation that occurs when cache
                // maintenance operations must resolve the page
                // address in order to execute. KVM incorrectly treats
                // the fault as an indication that the guest is making
                // an MMIO access the details of which are not
                // captured in NISV.
                //
                // Guest code tries to reduce the chance of this
                // happening by making a data access shortly before
                // the cache cleaning instructions. However, this is
                // possibly racy, since KVM could page out the
                // relevant Stage 2 translation in between the data
                // access and the cache maintenance operation. In
                // order to account for this case, we detect it and
                // cooperate with code inside the VM to re-fault-in
                // the page and re-try the cache maintenance operation
                // in question.
                //
                // The calling convention for this is: any cache
                // maintenance operation should be executed with the
                // Zero flag cleared. If it fails for this reason,
                // Hyperlight will increment PC to the next
                // instruction as usual, but set the Zero flag. The
                // guest should detect this and attempt to fault in
                // the page and re-try the operation.
                use crate::hypervisor::regs::kvm_reg::{PC, PSTATE};
                let pc = PC.get(RunVcpuError::Unknown, &self.vcpu_fd)?;
                let pstate = PSTATE.get(RunVcpuError::Unknown, &self.vcpu_fd)?;

                const Z_BIT: u64 = 1 << 30;
                // Because we got here from the NISV mmio exit path,
                // we know that ESR_EL2.EC codes for a Data Abort, and
                // we can assume the relevant encoding of ESR_EL2.ISS
                const ESR_EL2_ISS_CM: u64 = 1 << 8;

                let esr_iss = unsafe {
                    // SAFETY: KVM_EXIT_ARM_NISV implies this is the arm_nisv variant.
                    self.vcpu_fd.get_kvm_run().__bindgen_anon_1.arm_nisv.esr_iss
                };
                if esr_iss & ESR_EL2_ISS_CM != 0 && pstate & Z_BIT == 0 {
                    // if ESR_EL2.ISS.CM is set, the abort was caused
                    // by a Cache Maintenance instruction. Assume that
                    // any Cache Maintenance instruction in the VM is
                    // part of a Hyperlight-aware sequence and can
                    // deal with it.
                    PSTATE.set(RunVcpuError::Unknown, &self.vcpu_fd, pstate | Z_BIT)?;
                    PC.set(RunVcpuError::Unknown, &self.vcpu_fd, pc + 4)?;
                    continue;
                }
            }
            break exit;
        };
        match exit {
            Ok(VcpuExit::MmioWrite(addr, data)) => {
                let io_page_gpa = const { hyperlight_common::layout::io_page().unwrap().0 };
                if addr >= io_page_gpa
                    && let off = (addr - io_page_gpa) as usize
                    && off < hyperlight_common::vmem::PAGE_SIZE
                {
                    let port = off / core::mem::size_of::<u64>();
                    if port == VmAction::Halt as usize {
                        // As per [1]:
                        // > For KVM_EXIT_IO [...] the corresponding operations are complete
                        // > (and guest state is consistent) only after userspace has re-entered
                        // > the kernel with KVM_RUN. The kernel side will first finish
                        // > incomplete operations and then check for pending signals.
                        // >
                        // > The pending state of the operation is not preserved in state which
                        // > is visible to userspace, thus userspace should ensure that the
                        // > operation is completed before performing a live
                        // > migration. Userspace can re-enter the guest with an unmasked signal
                        // > pending or with the immediate_exit field set to complete pending
                        // > operations without allowing any further instructions to be
                        // > executed.
                        //
                        // On AArch64, the incomplete operation state includes incrementing the
                        // program counter past the faulting I/O instruction. Since a halt exit
                        // is used to logically end a thread of execution, we will likely start
                        // executing from somewhere else again after, in which case such a
                        // program counter increment would be undesirable. Therefore, in the hlt
                        // case, re-enter the kernel with immediate_exit set right away to clear
                        // that state.
                        //
                        // We assume that this pattern is not required in any other case,
                        // because any error that prevents the guest code from fully unwinding
                        // its stack and running "to completion" (i.e. to a halt exit) should
                        // poison the sandbox, and the vcpu reset on sandbox reset needed to
                        // un-poison it will take care of clearing the necessary state.
                        self.run_immediate_exit()
                            .map_err(|e| RunVcpuError::FlushMmioPending(format!("{:?}", e)))?;
                        Ok(VmExit::Halt())
                    } else {
                        Ok(VmExit::IoOut(port as u16, data.to_vec()))
                    }
                } else {
                    Ok(VmExit::MmioWrite(addr))
                }
            }
            Ok(VcpuExit::MmioRead(addr, _)) => Ok(VmExit::MmioRead(addr)),
            Err(e) => match e.errno() {
                libc::EINTR => Ok(VmExit::Cancelled()),
                libc::EAGAIN => Ok(VmExit::Retry()),
                _ => Err(RunVcpuError::Unknown(e.into())),
            },
            Ok(other) => Ok(VmExit::Unknown(format!(
                "Unknown KVM VCPU exit: {:?}",
                other
            ))),
        }
    }

    fn regs(&self) -> std::result::Result<CommonRegisters, RegisterError> {
        use crate::hypervisor::regs::kvm_reg::{PC, PSTATE, SP, X};
        let mut x: [u64; 31] = [0; 31];
        for (i, xi) in X.iter().enumerate() {
            x[i] = xi.get(RegisterError::GetSregs, &self.vcpu_fd)?;
        }
        Ok(CommonRegisters {
            x,
            sp: SP.get(RegisterError::GetSregs, &self.vcpu_fd)?,
            pc: PC.get(RegisterError::GetSregs, &self.vcpu_fd)?,
            pstate: PSTATE.get(RegisterError::GetSregs, &self.vcpu_fd)?,
        })
    }

    fn set_regs(&mut self, regs: &CommonRegisters) -> std::result::Result<(), RegisterError> {
        use crate::hypervisor::regs::kvm_reg::{PC, PSTATE, SP, X};
        for (i, xi) in X.iter().enumerate() {
            xi.set(RegisterError::SetSregs, &self.vcpu_fd, regs.x[i])?;
        }
        SP.set(RegisterError::SetSregs, &self.vcpu_fd, regs.sp)?;
        PC.set(RegisterError::SetSregs, &self.vcpu_fd, regs.pc)?;
        PSTATE.set(RegisterError::SetSregs, &self.vcpu_fd, regs.pstate)?;

        Ok(())
    }

    fn fpu(&self) -> Result<CommonFpu, RegisterError> {
        use crate::hypervisor::regs::kvm_reg::{FPCR, FPSR, V};
        let mut v: [u128; 32] = [0; 32];
        for (i, vi) in V.iter().enumerate() {
            v[i] = vi.get(RegisterError::GetFpu, &self.vcpu_fd)?;
        }
        Ok(CommonFpu {
            v,
            fpsr: FPSR.get(RegisterError::GetFpu, &self.vcpu_fd)?,
            fpcr: FPCR.get(RegisterError::GetFpu, &self.vcpu_fd)?,
        })
    }

    fn set_fpu(&mut self, fpu: &CommonFpu) -> Result<(), RegisterError> {
        use crate::hypervisor::regs::kvm_reg::{FPCR, FPSR, V};
        for (i, vi) in V.iter().enumerate() {
            vi.set(RegisterError::SetFpu, &self.vcpu_fd, fpu.v[i])?;
        }
        FPSR.set(RegisterError::SetFpu, &self.vcpu_fd, fpu.fpsr)?;
        FPCR.set(RegisterError::SetFpu, &self.vcpu_fd, fpu.fpcr)?;
        Ok(())
    }

    fn sregs(&self) -> Result<CommonSpecialRegisters, RegisterError> {
        use crate::hypervisor::regs::kvm_reg::{
            CPACR_EL1, MAIR_EL1, SCTLR_EL1, SP_EL1, TCR_EL1, TTBR0_EL1, VBAR_EL1,
        };
        Ok(CommonSpecialRegisters {
            ttbr0_el1: TTBR0_EL1.get(RegisterError::GetSregs, &self.vcpu_fd)?,
            tcr_el1: TCR_EL1.get(RegisterError::GetSregs, &self.vcpu_fd)?,
            mair_el1: MAIR_EL1.get(RegisterError::GetSregs, &self.vcpu_fd)?,
            sctlr_el1: SCTLR_EL1.get(RegisterError::GetSregs, &self.vcpu_fd)?,
            cpacr_el1: CPACR_EL1.get(RegisterError::GetSregs, &self.vcpu_fd)?,
            vbar_el1: VBAR_EL1.get(RegisterError::GetSregs, &self.vcpu_fd)?,
            sp_el1: SP_EL1.get(RegisterError::GetSregs, &self.vcpu_fd)?,
        })
    }

    fn set_sregs(&mut self, sregs: &CommonSpecialRegisters) -> Result<(), RegisterError> {
        use crate::hypervisor::regs::kvm_reg::{
            CPACR_EL1, MAIR_EL1, SCTLR_EL1, SP_EL1, TCR_EL1, TTBR0_EL1, VBAR_EL1,
        };
        TTBR0_EL1.set(RegisterError::SetSregs, &self.vcpu_fd, sregs.ttbr0_el1)?;
        TCR_EL1.set(RegisterError::SetSregs, &self.vcpu_fd, sregs.tcr_el1)?;
        MAIR_EL1.set(RegisterError::SetSregs, &self.vcpu_fd, sregs.mair_el1)?;
        SCTLR_EL1.set(RegisterError::SetSregs, &self.vcpu_fd, sregs.sctlr_el1)?;
        CPACR_EL1.set(RegisterError::SetSregs, &self.vcpu_fd, sregs.cpacr_el1)?;
        VBAR_EL1.set(RegisterError::SetSregs, &self.vcpu_fd, sregs.vbar_el1)?;
        SP_EL1.set(RegisterError::SetSregs, &self.vcpu_fd, sregs.sp_el1)?;

        Ok(())
    }

    fn debug_regs(
        &self,
    ) -> std::result::Result<crate::hypervisor::regs::CommonDebugRegs, RegisterError> {
        todo!()
    }

    fn set_debug_regs(
        &self,
        _drs: &crate::hypervisor::regs::CommonDebugRegs,
    ) -> std::result::Result<(), RegisterError> {
        todo!()
    }

    fn can_reset_vcpu(&self) -> bool {
        true
    }
    fn reset_vcpu(&mut self) -> Result<(), ResetVcpuError> {
        self.run_immediate_exit().map_err(|e| {
            e.map(ResetVcpuError::Hypervisor)
                .map_err(ResetVcpuError::Unknown)
                .unwrap_or_else(|e| e)
        })?;
        self.vcpu_init().map_err(ResetVcpuError::Hypervisor)?;
        self.run_immediate_exit().map_err(|e| {
            e.map(ResetVcpuError::Hypervisor)
                .map_err(ResetVcpuError::Unknown)
                .unwrap_or_else(|e| e)
        })?;
        Ok(())
    }
}
