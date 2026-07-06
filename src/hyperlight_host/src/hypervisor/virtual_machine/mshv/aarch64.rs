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

use std::sync::LazyLock;

use hyperlight_common::outb::VmAction;
use mshv_bindings::{
    hv_message_type, hv_message_type_HVMSG_GPA_INTERCEPT, hv_message_type_HVMSG_UNMAPPED_GPA,
    hv_register_assoc, hv_register_name_HV_ARM64_REGISTER_CPACR_EL1,
    hv_register_name_HV_ARM64_REGISTER_FPCR, hv_register_name_HV_ARM64_REGISTER_FPSR,
    hv_register_name_HV_ARM64_REGISTER_MAIR_EL1, hv_register_name_HV_ARM64_REGISTER_PC,
    hv_register_name_HV_ARM64_REGISTER_Q0, hv_register_name_HV_ARM64_REGISTER_SCTLR_EL1,
    hv_register_name_HV_ARM64_REGISTER_SP_EL1, hv_register_name_HV_ARM64_REGISTER_TCR_EL1,
    hv_register_name_HV_ARM64_REGISTER_TTBR0_EL1, hv_register_name_HV_ARM64_REGISTER_VBAR_EL1,
    hv_register_value, hv_u128, mshv_create_partition_v2, mshv_user_mem_region,
};
use mshv_ioctls::{Mshv, VcpuFd, VmFd};
use tracing::{Span, instrument};

use crate::hypervisor::regs::{
    CommonDebugRegs, CommonFpu, CommonRegisters, CommonSpecialRegisters,
};
use crate::hypervisor::virtual_machine::{
    CreateVmError, MapMemoryError, RegisterError, ResetVcpuError, RunVcpuError, UnmapMemoryError,
    VirtualMachine, VmExit,
};
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};

static MSHV: LazyLock<std::result::Result<Mshv, CreateVmError>> =
    LazyLock::new(|| Mshv::new().map_err(|e| CreateVmError::HypervisorNotAvailable(e.into())));

/// Determine whether the MSHV hypervisor API is available on aarch64.
#[instrument(skip_all, parent = Span::current(), level = "Trace")]
pub(crate) fn is_hypervisor_present() -> bool {
    match Mshv::new() {
        Ok(_) => true,
        Err(_) => {
            tracing::info!("MSHV is not available on this system");
            false
        }
    }
}

/// An MSHV implementation of a single-vcpu VM for aarch64.
#[derive(Debug)]
pub(crate) struct MshvVm {
    vm_fd: VmFd,
    vcpu_fd: VcpuFd,
}

impl MshvVm {
    /// Create a new MSHV VM instance for aarch64.
    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn new() -> std::result::Result<Self, CreateVmError> {
        let mshv = MSHV.as_ref().map_err(|e| e.clone())?;

        let pr: mshv_create_partition_v2 = Default::default();
        let vm_fd = mshv
            .create_vm_with_args(&pr)
            .map_err(|e| CreateVmError::CreateVmFd(e.into()))?;

        vm_fd
            .initialize()
            .map_err(|e| CreateVmError::InitializeVm(e.into()))?;

        let vcpu_fd = vm_fd
            .create_vcpu(0)
            .map_err(|e| CreateVmError::CreateVcpuFd(e.into()))?;

        Ok(Self { vm_fd, vcpu_fd })
    }

    /// Helper to get a single 64-bit register by name.
    fn get_reg64(&self, name: u32) -> Result<u64, RegisterError> {
        let mut reg = [hv_register_assoc {
            name,
            ..Default::default()
        }];
        self.vcpu_fd
            .get_reg(&mut reg)
            .map_err(|e| RegisterError::GetRegs(e.into()))?;
        Ok(unsafe { reg[0].value.reg64 })
    }

    /// Helper to set a single 64-bit register by name.
    fn set_reg64(&self, name: u32, value: u64) -> Result<(), RegisterError> {
        self.vcpu_fd
            .set_reg(&[hv_register_assoc {
                name,
                value: hv_register_value { reg64: value },
                ..Default::default()
            }])
            .map_err(|e| RegisterError::SetRegs(e.into()))
    }

    /// Helper to get a single 128-bit register (Q/SIMD) by name.
    fn get_reg128(&self, name: u32) -> Result<u128, RegisterError> {
        let mut reg = [hv_register_assoc {
            name,
            ..Default::default()
        }];
        self.vcpu_fd
            .get_reg(&mut reg)
            .map_err(|e| RegisterError::GetFpu(e.into()))?;
        let v = unsafe { reg[0].value.reg128 };
        Ok((v.high_part as u128) << 64 | v.low_part as u128)
    }

    /// Helper to set a single 128-bit register (Q/SIMD) by name.
    fn set_reg128(&self, name: u32, value: u128) -> Result<(), RegisterError> {
        self.vcpu_fd
            .set_reg(&[hv_register_assoc {
                name,
                value: hv_register_value {
                    reg128: hv_u128 {
                        low_part: value as u64,
                        high_part: (value >> 64) as u64,
                    },
                },
                ..Default::default()
            }])
            .map_err(|e| RegisterError::SetFpu(e.into()))
    }
}

impl VirtualMachine for MshvVm {
    unsafe fn map_memory(
        &mut self,
        (_slot, region): (u32, &MemoryRegion),
    ) -> std::result::Result<(), MapMemoryError> {
        let mshv_region: mshv_user_mem_region = region.into();
        self.vm_fd
            .map_user_memory(mshv_region)
            .map_err(|e| MapMemoryError::Hypervisor(e.into()))
    }

    fn unmap_memory(
        &mut self,
        (_slot, region): (u32, &MemoryRegion),
    ) -> std::result::Result<(), UnmapMemoryError> {
        let mshv_region: mshv_user_mem_region = region.into();
        self.vm_fd
            .unmap_user_memory(mshv_region)
            .map_err(|e| UnmapMemoryError::Hypervisor(e.into()))
    }

    fn run_vcpu(
        &mut self,
        #[cfg(feature = "trace_guest")] _tc: &mut crate::sandbox::trace::TraceContext,
    ) -> std::result::Result<VmExit, RunVcpuError> {
        const UNMAPPED_GPA_MESSAGE: hv_message_type = hv_message_type_HVMSG_UNMAPPED_GPA;
        const INVALID_GPA_ACCESS_MESSAGE: hv_message_type = hv_message_type_HVMSG_GPA_INTERCEPT;

        loop {
            let exit_reason = self.vcpu_fd.run();

            match exit_reason {
                Ok(m) => {
                    let msg_type = m.header.message_type;
                    match msg_type {
                        UNMAPPED_GPA_MESSAGE | INVALID_GPA_ACCESS_MESSAGE => {
                            let mem_msg = m
                                .to_memory_info()
                                .map_err(|_| RunVcpuError::DecodeIOMessage(msg_type))?;
                            let gpa = mem_msg.guest_physical_address;

                            // On aarch64, I/O is performed via MMIO writes to
                            // the I/O page, similar to the KVM backend.
                            let io_page_gpa =
                                const { hyperlight_common::layout::io_page().unwrap().0 };
                            let access_type = mem_msg.header.intercept_access_type;
                            let is_write = access_type != 0;

                            if is_write
                                && gpa >= io_page_gpa
                                && (gpa - io_page_gpa) < hyperlight_common::vmem::PAGE_SIZE as u64
                            {
                                let off = (gpa - io_page_gpa) as usize;
                                let port = off / core::mem::size_of::<u64>();

                                // Advance PC past the faulting instruction.
                                // MSHV does not auto-advance PC on intercepts.
                                let pc = mem_msg.header.pc;
                                let instruction_length = mem_msg.header.instruction_length as u64;
                                self.vcpu_fd
                                    .set_reg(&[hv_register_assoc {
                                        name: hv_register_name_HV_ARM64_REGISTER_PC,
                                        value: hv_register_value {
                                            reg64: pc + instruction_length,
                                        },
                                        ..Default::default()
                                    }])
                                    .map_err(|e| RunVcpuError::IncrementRip(e.into()))?;

                                if port == VmAction::Halt as usize {
                                    return Ok(VmExit::Halt());
                                } else {
                                    // The data value is read from the I/O page
                                    // by the host; pass the offset as context.
                                    return Ok(VmExit::IoOut(
                                        port as u16,
                                        (off as u64).to_le_bytes().to_vec(),
                                    ));
                                }
                            } else {
                                // Non-I/O page memory access
                                return match MemoryRegionFlags::try_from(mem_msg)
                                    .map_err(|_| RunVcpuError::ParseGpaAccessInfo)
                                {
                                    Ok(MemoryRegionFlags::READ) => Ok(VmExit::MmioRead(gpa)),
                                    Ok(MemoryRegionFlags::WRITE) => Ok(VmExit::MmioWrite(gpa)),
                                    Ok(_) => Ok(VmExit::Unknown("Unknown MMIO access".to_string())),
                                    Err(e) => Err(e),
                                };
                            }
                        }
                        other => {
                            return Ok(VmExit::Unknown(format!(
                                "Unknown MSHV VCPU exit: {:?}",
                                other
                            )));
                        }
                    }
                }
                Err(e) => match e.errno() {
                    libc::EINTR => {
                        return Ok(VmExit::Cancelled());
                    }
                    libc::EAGAIN => {
                        return Ok(VmExit::Retry());
                    }
                    _ => return Err(RunVcpuError::Unknown(e.into())),
                },
            }
        }
    }

    fn regs(&self) -> std::result::Result<CommonRegisters, RegisterError> {
        let mshv_regs = self
            .vcpu_fd
            .get_regs()
            .map_err(|e| RegisterError::GetRegs(e.into()))?;
        Ok(CommonRegisters {
            x: mshv_regs.regs,
            sp: mshv_regs.sp,
            pc: mshv_regs.pc,
            pstate: mshv_regs.pstate,
        })
    }

    fn set_regs(&self, regs: &CommonRegisters) -> std::result::Result<(), RegisterError> {
        use mshv_bindings::StandardRegisters;
        let mshv_regs = StandardRegisters {
            regs: regs.x,
            sp: regs.sp,
            pc: regs.pc,
            pstate: regs.pstate,
            // sp_el1 and elr_el1 are managed via special registers
            sp_el1: 0,
            elr_el1: 0,
            fpsr: 0,
            fpcr: 0,
        };
        self.vcpu_fd
            .set_regs(&mshv_regs)
            .map_err(|e| RegisterError::SetRegs(e.into()))
    }

    fn fpu(&self) -> std::result::Result<CommonFpu, RegisterError> {
        let mut v: [u128; 32] = [0; 32];
        for i in 0..32u32 {
            v[i as usize] = self.get_reg128(hv_register_name_HV_ARM64_REGISTER_Q0 + i)?;
        }
        let fpsr = self.get_reg64(hv_register_name_HV_ARM64_REGISTER_FPSR)? as u32;
        let fpcr = self.get_reg64(hv_register_name_HV_ARM64_REGISTER_FPCR)? as u32;
        Ok(CommonFpu { v, fpsr, fpcr })
    }

    fn set_fpu(&self, fpu: &CommonFpu) -> std::result::Result<(), RegisterError> {
        for i in 0..32u32 {
            self.set_reg128(hv_register_name_HV_ARM64_REGISTER_Q0 + i, fpu.v[i as usize])?;
        }
        self.set_reg64(hv_register_name_HV_ARM64_REGISTER_FPSR, fpu.fpsr as u64)?;
        self.set_reg64(hv_register_name_HV_ARM64_REGISTER_FPCR, fpu.fpcr as u64)?;
        Ok(())
    }

    fn sregs(&self) -> std::result::Result<CommonSpecialRegisters, RegisterError> {
        Ok(CommonSpecialRegisters {
            ttbr0_el1: self.get_reg64(hv_register_name_HV_ARM64_REGISTER_TTBR0_EL1)?,
            tcr_el1: self.get_reg64(hv_register_name_HV_ARM64_REGISTER_TCR_EL1)?,
            mair_el1: self.get_reg64(hv_register_name_HV_ARM64_REGISTER_MAIR_EL1)?,
            sctlr_el1: self.get_reg64(hv_register_name_HV_ARM64_REGISTER_SCTLR_EL1)?,
            cpacr_el1: self.get_reg64(hv_register_name_HV_ARM64_REGISTER_CPACR_EL1)?,
            vbar_el1: self.get_reg64(hv_register_name_HV_ARM64_REGISTER_VBAR_EL1)?,
            sp_el1: self.get_reg64(hv_register_name_HV_ARM64_REGISTER_SP_EL1)?,
        })
    }

    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> std::result::Result<(), RegisterError> {
        self.set_reg64(
            hv_register_name_HV_ARM64_REGISTER_TTBR0_EL1,
            sregs.ttbr0_el1,
        )?;
        self.set_reg64(hv_register_name_HV_ARM64_REGISTER_TCR_EL1, sregs.tcr_el1)?;
        self.set_reg64(hv_register_name_HV_ARM64_REGISTER_MAIR_EL1, sregs.mair_el1)?;
        self.set_reg64(
            hv_register_name_HV_ARM64_REGISTER_SCTLR_EL1,
            sregs.sctlr_el1,
        )?;
        self.set_reg64(
            hv_register_name_HV_ARM64_REGISTER_CPACR_EL1,
            sregs.cpacr_el1,
        )?;
        self.set_reg64(hv_register_name_HV_ARM64_REGISTER_VBAR_EL1, sregs.vbar_el1)?;
        self.set_reg64(hv_register_name_HV_ARM64_REGISTER_SP_EL1, sregs.sp_el1)?;
        Ok(())
    }

    fn debug_regs(&self) -> std::result::Result<CommonDebugRegs, RegisterError> {
        // Debug register support on aarch64 MSHV is not yet implemented
        Ok(CommonDebugRegs::default())
    }

    fn set_debug_regs(&self, _drs: &CommonDebugRegs) -> std::result::Result<(), RegisterError> {
        // Debug register support on aarch64 MSHV is not yet implemented
        Ok(())
    }

    fn can_reset_vcpu(&self) -> bool {
        true
    }

    fn reset_vcpu(&mut self) -> Result<(), ResetVcpuError> {
        // Reset the vCPU by zeroing all general-purpose registers
        use mshv_bindings::StandardRegisters;
        let regs = StandardRegisters::default();
        self.vcpu_fd
            .set_regs(&regs)
            .map_err(|e| ResetVcpuError::Hypervisor(e.into()))?;
        Ok(())
    }
}
