// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use std::sync::LazyLock;

use hyperlight_common::outb::VmAction;
use mshv_bindings::{
    hv_message_type, hv_message_type_HVMSG_GPA_INTERCEPT, hv_message_type_HVMSG_UNMAPPED_GPA,
    hv_partition_property_code_HV_PARTITION_PROPERTY_GIC_LPI_INT_ID_BITS,
    hv_partition_property_code_HV_PARTITION_PROPERTY_GIC_PPI_OVERFLOW_INTERRUPT_FROM_CNTV,
    hv_partition_property_code_HV_PARTITION_PROPERTY_GIC_PPI_PERFORMANCE_MONITORS_INTERRUPT,
    hv_partition_property_code_HV_PARTITION_PROPERTY_GICD_BASE_ADDRESS,
    hv_partition_property_code_HV_PARTITION_PROPERTY_GITS_TRANSLATER_BASE_ADDRESS,
    hv_register_assoc, hv_register_name_HV_ARM64_REGISTER_CPACR_EL1,
    hv_register_name_HV_ARM64_REGISTER_FP, hv_register_name_HV_ARM64_REGISTER_FPCR,
    hv_register_name_HV_ARM64_REGISTER_FPSR, hv_register_name_HV_ARM64_REGISTER_GICR_BASE_GPA,
    hv_register_name_HV_ARM64_REGISTER_LR, hv_register_name_HV_ARM64_REGISTER_MAIR_EL1,
    hv_register_name_HV_ARM64_REGISTER_PC, hv_register_name_HV_ARM64_REGISTER_PSTATE,
    hv_register_name_HV_ARM64_REGISTER_Q0, hv_register_name_HV_ARM64_REGISTER_SCTLR_EL1,
    hv_register_name_HV_ARM64_REGISTER_SP_EL0, hv_register_name_HV_ARM64_REGISTER_SP_EL1,
    hv_register_name_HV_ARM64_REGISTER_TCR_EL1, hv_register_name_HV_ARM64_REGISTER_TTBR0_EL1,
    hv_register_name_HV_ARM64_REGISTER_VBAR_EL1, hv_register_name_HV_ARM64_REGISTER_X0,
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

fn mmio_write_info(syndrome: u64) -> Option<(u32, usize)> {
    const ISV: u64 = 1 << 24;
    const WNR: u64 = 1 << 6;

    if syndrome & (ISV | WNR) != ISV | WNR {
        return None;
    }

    let source_register = ((syndrome >> 16) & 0x1f) as u32;
    let access_size = 1usize << ((syndrome >> 22) & 0x3);
    Some((source_register, access_size))
}

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
    mapped_regions: Vec<mshv_user_mem_region>,
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

        for (property, value) in [
            (
                hv_partition_property_code_HV_PARTITION_PROPERTY_GICD_BASE_ADDRESS,
                0xffff0000,
            ),
            (
                hv_partition_property_code_HV_PARTITION_PROPERTY_GITS_TRANSLATER_BASE_ADDRESS,
                0xeff68000,
            ),
            (
                hv_partition_property_code_HV_PARTITION_PROPERTY_GIC_LPI_INT_ID_BITS,
                1,
            ),
            (
                hv_partition_property_code_HV_PARTITION_PROPERTY_GIC_PPI_OVERFLOW_INTERRUPT_FROM_CNTV,
                0x1b,
            ),
            (
                hv_partition_property_code_HV_PARTITION_PROPERTY_GIC_PPI_PERFORMANCE_MONITORS_INTERRUPT,
                0x17,
            ),
        ] {
            vm_fd
                .set_partition_property(property, value)
                .map_err(|e| CreateVmError::SetPartitionProperty(e.into()))?;
        }

        vm_fd
            .initialize()
            .map_err(|e| CreateVmError::InitializeVm(e.into()))?;

        let vcpu_fd = vm_fd
            .create_vcpu(0)
            .map_err(|e| CreateVmError::CreateVcpuFd(e.into()))?;
        vcpu_fd
            .set_reg(&[hv_register_assoc {
                name: hv_register_name_HV_ARM64_REGISTER_GICR_BASE_GPA,
                value: hv_register_value { reg64: 0xeffee000 },
                ..Default::default()
            }])
            .map_err(|e| CreateVmError::SetPartitionProperty(e.into()))?;

        Ok(Self {
            vm_fd,
            vcpu_fd,
            mapped_regions: Vec::new(),
        })
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
}

impl VirtualMachine for MshvVm {
    unsafe fn map_memory(
        &mut self,
        (_slot, region): (u32, &MemoryRegion),
    ) -> std::result::Result<(), MapMemoryError> {
        let mshv_region: mshv_user_mem_region = region.into();
        self.vm_fd
            .map_user_memory(mshv_region)
            .map_err(|e| MapMemoryError::Hypervisor(e.into()))?;
        self.mapped_regions.push(mshv_region);
        Ok(())
    }

    fn unmap_memory(
        &mut self,
        (_slot, region): (u32, &MemoryRegion),
    ) -> std::result::Result<(), UnmapMemoryError> {
        let mshv_region: mshv_user_mem_region = region.into();
        self.vm_fd
            .unmap_user_memory(mshv_region)
            .map_err(|e| UnmapMemoryError::Hypervisor(e.into()))?;
        self.mapped_regions.retain(|mapped| {
            mapped.guest_pfn != mshv_region.guest_pfn
                || mapped.size != mshv_region.size
                || mapped.userspace_addr != mshv_region.userspace_addr
        });
        Ok(())
    }

    fn run_vcpu(
        &mut self,
        #[cfg(feature = "trace_guest")] _tc: &mut crate::sandbox::trace::TraceContext,
    ) -> std::result::Result<VmExit, RunVcpuError> {
        const UNMAPPED_GPA_MESSAGE: hv_message_type = hv_message_type_HVMSG_UNMAPPED_GPA;
        const INVALID_GPA_ACCESS_MESSAGE: hv_message_type = hv_message_type_HVMSG_GPA_INTERCEPT;

        match self.vcpu_fd.run() {
            Ok(m) => {
                let msg_type = m.header.message_type;
                match msg_type {
                    UNMAPPED_GPA_MESSAGE | INVALID_GPA_ACCESS_MESSAGE => {
                        let mem_msg = m
                            .to_memory_info()
                            .map_err(|_| RunVcpuError::DecodeIOMessage(msg_type))?;
                        let gpa = mem_msg.guest_physical_address;
                        let io_page_gpa = const { hyperlight_common::layout::io_page().unwrap().0 };
                        let is_write = mem_msg.header.intercept_access_type == 1;

                        if is_write
                            && gpa >= io_page_gpa
                            && (gpa - io_page_gpa) < hyperlight_common::vmem::PAGE_SIZE as u64
                        {
                            let off = (gpa - io_page_gpa) as usize;
                            let port = off / core::mem::size_of::<u64>();
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
                            }

                            let (source_register, access_size) = mmio_write_info(mem_msg.syndrome)
                                .ok_or(RunVcpuError::ParseGpaAccessInfo)?;
                            let value = if source_register == 31 {
                                0
                            } else {
                                self.get_reg64(
                                    hv_register_name_HV_ARM64_REGISTER_X0 + source_register,
                                )
                                .map_err(|e| match e {
                                    RegisterError::GetRegs(error) => RunVcpuError::Unknown(error),
                                    _ => unreachable!("get_reg64 returned a non-get error"),
                                })?
                            };
                            Ok(VmExit::IoOut(
                                port as u16,
                                value.to_le_bytes()[..access_size].to_vec(),
                            ))
                        } else {
                            match MemoryRegionFlags::try_from(mem_msg)
                                .map_err(|_| RunVcpuError::ParseGpaAccessInfo)?
                            {
                                MemoryRegionFlags::READ => Ok(VmExit::MmioRead(gpa)),
                                MemoryRegionFlags::WRITE => Ok(VmExit::MmioWrite(gpa)),
                                _ => Ok(VmExit::Unknown("Unknown MMIO access".to_string())),
                            }
                        }
                    }
                    other => Ok(VmExit::Unknown(format!(
                        "Unknown MSHV VCPU exit: {:?}",
                        other
                    ))),
                }
            }
            Err(e) => match e.errno() {
                libc::EINTR => Ok(VmExit::Cancelled()),
                libc::EAGAIN => Ok(VmExit::Retry()),
                _ => Err(RunVcpuError::Unknown(e.into())),
            },
        }
    }

    fn regs(&self) -> std::result::Result<CommonRegisters, RegisterError> {
        let mshv_regs = self
            .vcpu_fd
            .get_regs()
            .map_err(|e| RegisterError::GetRegs(e.into()))?;
        Ok(CommonRegisters {
            x: mshv_regs.regs,
            sp: self.get_reg64(hv_register_name_HV_ARM64_REGISTER_SP_EL0)?,
            pc: mshv_regs.pc,
            pstate: mshv_regs.pstate,
        })
    }

    fn set_regs(&self, regs: &CommonRegisters) -> std::result::Result<(), RegisterError> {
        let mut mshv_regs = Vec::with_capacity(34);
        for (index, value) in regs.x[..29].iter().enumerate() {
            mshv_regs.push(hv_register_assoc {
                name: hv_register_name_HV_ARM64_REGISTER_X0 + index as u32,
                value: hv_register_value { reg64: *value },
                ..Default::default()
            });
        }
        mshv_regs.extend([
            hv_register_assoc {
                name: hv_register_name_HV_ARM64_REGISTER_FP,
                value: hv_register_value { reg64: regs.x[29] },
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_ARM64_REGISTER_LR,
                value: hv_register_value { reg64: regs.x[30] },
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_ARM64_REGISTER_SP_EL0,
                value: hv_register_value { reg64: regs.sp },
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_ARM64_REGISTER_PC,
                value: hv_register_value { reg64: regs.pc },
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_ARM64_REGISTER_PSTATE,
                value: hv_register_value { reg64: regs.pstate },
                ..Default::default()
            },
        ]);
        self.vcpu_fd
            .set_reg(&mshv_regs)
            .map_err(|e| RegisterError::SetRegs(e.into()))
    }

    fn fpu(&self) -> std::result::Result<CommonFpu, RegisterError> {
        let mut regs: Vec<_> = (0..32)
            .map(|index| hv_register_assoc {
                name: hv_register_name_HV_ARM64_REGISTER_Q0 + index,
                ..Default::default()
            })
            .collect();
        regs.extend([
            hv_register_assoc {
                name: hv_register_name_HV_ARM64_REGISTER_FPSR,
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_ARM64_REGISTER_FPCR,
                ..Default::default()
            },
        ]);
        self.vcpu_fd
            .get_reg(&mut regs)
            .map_err(|e| RegisterError::GetFpu(e.into()))?;

        let mut v: [u128; 32] = [0; 32];
        for (value, reg) in v.iter_mut().zip(&regs[..32]) {
            let reg128 = unsafe { reg.value.reg128 };
            *value = (reg128.high_part as u128) << 64 | reg128.low_part as u128;
        }
        let fpsr = unsafe { regs[32].value.reg64 } as u32;
        let fpcr = unsafe { regs[33].value.reg64 } as u32;
        Ok(CommonFpu { v, fpsr, fpcr })
    }

    fn set_fpu(&self, fpu: &CommonFpu) -> std::result::Result<(), RegisterError> {
        let mut regs: Vec<_> = fpu
            .v
            .iter()
            .enumerate()
            .map(|(index, value)| hv_register_assoc {
                name: hv_register_name_HV_ARM64_REGISTER_Q0 + index as u32,
                value: hv_register_value {
                    reg128: hv_u128 {
                        low_part: *value as u64,
                        high_part: (*value >> 64) as u64,
                    },
                },
                ..Default::default()
            })
            .collect();
        regs.extend([
            hv_register_assoc {
                name: hv_register_name_HV_ARM64_REGISTER_FPSR,
                value: hv_register_value {
                    reg64: fpu.fpsr as u64,
                },
                ..Default::default()
            },
            hv_register_assoc {
                name: hv_register_name_HV_ARM64_REGISTER_FPCR,
                value: hv_register_value {
                    reg64: fpu.fpcr as u64,
                },
                ..Default::default()
            },
        ]);
        self.vcpu_fd
            .set_reg(&regs)
            .map_err(|e| RegisterError::SetFpu(e.into()))
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
        let mut replacement = Self::new().map_err(|e| ResetVcpuError::Unknown(e.to_string()))?;
        for region in &self.mapped_regions {
            replacement
                .vm_fd
                .map_user_memory(*region)
                .map_err(|e| ResetVcpuError::Hypervisor(e.into()))?;
        }
        replacement.mapped_regions.clone_from(&self.mapped_regions);
        *self = replacement;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::mmio_write_info;

    #[test]
    fn decodes_mmio_write_syndrome() {
        assert_eq!(mmio_write_info(0x93c8_8047), Some((8, 8)));
    }

    #[test]
    fn rejects_invalid_mmio_write_syndrome() {
        assert_eq!(mmio_write_info(0), None);
        assert_eq!(mmio_write_info(1 << 24), None);
        assert_eq!(mmio_write_info(1 << 6), None);
    }
}
