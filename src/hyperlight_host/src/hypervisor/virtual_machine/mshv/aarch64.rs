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

#[cfg(gdb)]
use crate::hypervisor::gdb::{DebugError, DebugMemoryView, DebuggableVm, VcpuStopReason};
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

#[cfg(gdb)]
const HARDWARE_BREAKPOINTS: usize = 2;
#[cfg(gdb)]
const MDSCR_MDE: u64 = 1 << 15;
#[cfg(gdb)]
const MDSCR_KDE: u64 = 1 << 13;
#[cfg(gdb)]
const PSTATE_SS: u64 = 1 << 21;
#[cfg(gdb)]
const PSTATE_D: u64 = 1 << 9;

#[cfg(gdb)]
#[derive(Clone, Copy, Debug, Default)]
struct DebugState {
    enabled: bool,
    single_step: bool,
    hardware_breakpoints: [Option<u64>; HARDWARE_BREAKPOINTS],
}

// MSHV 0.7 omits this payload. The layout follows HvArm64HypercallInterceptMessage
// in OpenVMM's vm/hv1/hvdef/src/lib.rs.
#[cfg(gdb)]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct HypercallInterceptMessage {
    header: mshv_bindings::hv_arm64_intercept_message_header,
    immediate: u16,
    reserved: u16,
    flags: u32,
    x: [u64; 18],
}

#[cfg(gdb)]
const _: () = {
    assert!(std::mem::size_of::<HypercallInterceptMessage>() == 176);
    assert!(std::mem::offset_of!(HypercallInterceptMessage, immediate) == 24);
    assert!(std::mem::offset_of!(HypercallInterceptMessage, x) == 32);
};

#[cfg(gdb)]
fn hypercall_context(
    message: &mshv_bindings::hv_message,
) -> Result<HypercallInterceptMessage, RunVcpuError> {
    if message.header.message_type != mshv_bindings::hv_message_type_HVMSG_HYPERCALL_INTERCEPT
        || usize::from(message.header.payload_size)
            < std::mem::size_of::<HypercallInterceptMessage>()
    {
        return Err(RunVcpuError::DecodeIOMessage(message.header.message_type));
    }
    // SAFETY: The message type and payload length match the ARM64 hypercall ABI.
    // The payload contains only integer fields and may be unaligned.
    Ok(unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(message.u.payload).cast()) })
}

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
    #[cfg(gdb)]
    debug_state: DebugState,
    #[cfg(gdb)]
    debug_exception_return: Option<u64>,
    #[cfg(gdb)]
    debug_step_pending: bool,
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

        #[cfg(gdb)]
        vm_fd
            .install_intercept(mshv_bindings::mshv_install_intercept {
                access_type_mask: mshv_bindings::HV_INTERCEPT_ACCESS_MASK_EXECUTE,
                intercept_type: mshv_bindings::hv_intercept_type_HV_INTERCEPT_TYPE_HYPERCALL,
                ..Default::default()
            })
            .map_err(|e| CreateVmError::InitializeDebug(e.to_string()))?;

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
            #[cfg(gdb)]
            debug_state: DebugState::default(),
            #[cfg(gdb)]
            debug_exception_return: None,
            #[cfg(gdb)]
            debug_step_pending: false,
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

    #[cfg(gdb)]
    fn write_hardware_breakpoint(
        &self,
        slot: usize,
        address: Option<u64>,
    ) -> Result<(), RegisterError> {
        let regs = [
            (
                mshv_bindings::hv_register_name_HV_ARM64_REGISTER_DBGBVR0_EL1 + slot as u32,
                address.unwrap_or(0),
            ),
            (
                mshv_bindings::hv_register_name_HV_ARM64_REGISTER_DBGBCR0_EL1 + slot as u32,
                if address.is_some() {
                    (15 << 5) | (1 << 1) | 1
                } else {
                    0
                },
            ),
        ]
        .map(|(name, value)| hv_register_assoc {
            name,
            value: hv_register_value { reg64: value },
            ..Default::default()
        });
        self.vcpu_fd
            .set_reg(&regs)
            .map_err(|e| RegisterError::SetDebugRegs(e.into()))
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

        #[cfg(gdb)]
        if std::mem::take(&mut self.debug_step_pending) {
            return Ok(VmExit::Debug {
                reason: VcpuStopReason::DoneStep,
            });
        }
        match self.vcpu_fd.run() {
            Ok(m) => {
                let msg_type = m.header.message_type;
                match msg_type {
                    #[cfg(gdb)]
                    mshv_bindings::hv_message_type_HVMSG_HYPERCALL_INTERCEPT => {
                        let context = hypercall_context(&m)?;
                        let intercepted_pc = context.header.pc;
                        if self.debug_state.enabled
                            && context.immediate
                                == hyperlight_common::arch::exn::DEBUG_EXCEPTION_HVC
                        {
                            let mut regs = [hv_register_assoc {
                                name: mshv_bindings::hv_register_name_HV_ARM64_REGISTER_ESR_EL1,
                                ..Default::default()
                            }];
                            self.vcpu_fd
                                .get_reg(&mut regs)
                                .map_err(|e| RunVcpuError::Unknown(e.into()))?;
                            // SAFETY: ESR_EL1 is a 64-bit system register.
                            let ec = unsafe { regs[0].value.reg64 } >> 26;
                            let reason = match ec {
                                0x30 | 0x31 => Some(VcpuStopReason::HwBp),
                                0x32 | 0x33 => Some(VcpuStopReason::DoneStep),
                                0x3c => Some(VcpuStopReason::SwBp),
                                _ => None,
                            };
                            // Debug events return through ERET. Other exceptions
                            // resume the ordinary exception prologue.
                            let pc =
                                intercepted_pc.wrapping_add(if reason.is_some() { 4 } else { 12 });
                            self.vcpu_fd
                                .set_reg(&[hv_register_assoc {
                                    name: hv_register_name_HV_ARM64_REGISTER_PC,
                                    value: hv_register_value { reg64: pc },
                                    ..Default::default()
                                }])
                                .map_err(|e| RunVcpuError::IncrementRip(e.into()))?;
                            if let Some(reason) = reason {
                                self.debug_exception_return = Some(pc);
                                return Ok(VmExit::Debug { reason });
                            }
                            return Ok(VmExit::Retry());
                        }
                        Ok(VmExit::Unknown(format!(
                            "Unsupported ARM64 hypercall immediate {:#x} at PC={:#x}",
                            context.immediate, intercepted_pc
                        )))
                    }
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
                                        reg64: pc.wrapping_add(instruction_length),
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
                            #[cfg(gdb)]
                            {
                                self.debug_step_pending = self.debug_state.single_step;
                            }
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
        #[allow(unused_mut)]
        let mut mshv_regs = self
            .vcpu_fd
            .get_regs()
            .map_err(|e| RegisterError::GetRegs(e.into()))?;
        #[cfg(gdb)]
        if self.debug_exception_return == Some(mshv_regs.pc) {
            mshv_regs.pc =
                self.get_reg64(mshv_bindings::hv_register_name_HV_ARM64_REGISTER_ELR_EL1)?;
            mshv_regs.pstate =
                self.get_reg64(mshv_bindings::hv_register_name_HV_ARM64_REGISTER_SPSR_EL1)?;
        }
        Ok(CommonRegisters {
            x: mshv_regs.regs,
            sp: self.get_reg64(if mshv_regs.pstate & 1 == 0 {
                hv_register_name_HV_ARM64_REGISTER_SP_EL0
            } else {
                hv_register_name_HV_ARM64_REGISTER_SP_EL1
            })?,
            pc: mshv_regs.pc,
            pstate: mshv_regs.pstate,
        })
    }

    fn set_regs(&mut self, regs: &CommonRegisters) -> std::result::Result<(), RegisterError> {
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
                name: if regs.pstate & 1 == 0 {
                    hv_register_name_HV_ARM64_REGISTER_SP_EL0
                } else {
                    hv_register_name_HV_ARM64_REGISTER_SP_EL1
                },
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
        #[cfg(gdb)]
        if let Some(return_pc) = self.debug_exception_return
            && self.get_reg64(hv_register_name_HV_ARM64_REGISTER_PC)? == return_pc
        {
            mshv_regs[32].name = mshv_bindings::hv_register_name_HV_ARM64_REGISTER_ELR_EL1;
            mshv_regs[33].name = mshv_bindings::hv_register_name_HV_ARM64_REGISTER_SPSR_EL1;
        }
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

    fn set_fpu(&mut self, fpu: &CommonFpu) -> std::result::Result<(), RegisterError> {
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
        let mut regs = [
            hv_register_name_HV_ARM64_REGISTER_TTBR0_EL1,
            hv_register_name_HV_ARM64_REGISTER_TCR_EL1,
            hv_register_name_HV_ARM64_REGISTER_MAIR_EL1,
            hv_register_name_HV_ARM64_REGISTER_SCTLR_EL1,
            hv_register_name_HV_ARM64_REGISTER_CPACR_EL1,
            hv_register_name_HV_ARM64_REGISTER_VBAR_EL1,
            hv_register_name_HV_ARM64_REGISTER_SP_EL1,
        ]
        .map(|name| hv_register_assoc {
            name,
            ..Default::default()
        });
        self.vcpu_fd
            .get_reg(&mut regs)
            .map_err(|e| RegisterError::GetRegs(e.into()))?;

        // SAFETY: Each requested register contains a 64-bit value.
        Ok(unsafe {
            CommonSpecialRegisters {
                ttbr0_el1: regs[0].value.reg64,
                tcr_el1: regs[1].value.reg64,
                mair_el1: regs[2].value.reg64,
                sctlr_el1: regs[3].value.reg64,
                cpacr_el1: regs[4].value.reg64,
                vbar_el1: regs[5].value.reg64,
                sp_el1: regs[6].value.reg64,
            }
        })
    }

    fn set_sregs(
        &mut self,
        sregs: &CommonSpecialRegisters,
    ) -> std::result::Result<(), RegisterError> {
        let regs = [
            (
                hv_register_name_HV_ARM64_REGISTER_TTBR0_EL1,
                sregs.ttbr0_el1,
            ),
            (hv_register_name_HV_ARM64_REGISTER_TCR_EL1, sregs.tcr_el1),
            (hv_register_name_HV_ARM64_REGISTER_MAIR_EL1, sregs.mair_el1),
            (
                hv_register_name_HV_ARM64_REGISTER_SCTLR_EL1,
                sregs.sctlr_el1,
            ),
            (
                hv_register_name_HV_ARM64_REGISTER_CPACR_EL1,
                sregs.cpacr_el1,
            ),
            (hv_register_name_HV_ARM64_REGISTER_VBAR_EL1, sregs.vbar_el1),
            (hv_register_name_HV_ARM64_REGISTER_SP_EL1, sregs.sp_el1),
        ]
        .map(|(name, value)| hv_register_assoc {
            name,
            value: hv_register_value { reg64: value },
            ..Default::default()
        });
        self.vcpu_fd
            .set_reg(&regs)
            .map_err(|e| RegisterError::SetRegs(e.into()))
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
        #[cfg(gdb)]
        if self.debug_state.enabled {
            replacement
                .set_debug(true)
                .map_err(|e| ResetVcpuError::Unknown(e.to_string()))?;
            for address in self.debug_state.hardware_breakpoints.iter().flatten() {
                replacement
                    .add_hw_breakpoint(*address)
                    .map_err(|e| ResetVcpuError::Unknown(e.to_string()))?;
            }
            replacement
                .set_single_step(self.debug_state.single_step)
                .map_err(|e| ResetVcpuError::Unknown(e.to_string()))?;
        }
        *self = replacement;
        Ok(())
    }
}

#[cfg(gdb)]
impl DebuggableVm for MshvVm {
    fn translate_gva(&self, gva: u64, memory: &DebugMemoryView<'_>) -> Result<u64, DebugError> {
        let root =
            self.get_reg64(hv_register_name_HV_ARM64_REGISTER_TTBR0_EL1)? & 0x0000_ffff_ffff_f000;
        memory.translate_gva(gva, root)
    }

    fn set_debug(&mut self, enable: bool) -> Result<(), DebugError> {
        if !enable {
            self.set_single_step(false)?;
            for slot in 0..HARDWARE_BREAKPOINTS {
                self.write_hardware_breakpoint(slot, None)?;
            }
            self.debug_state.hardware_breakpoints.fill(None);
        }
        let name = mshv_bindings::hv_register_name_HV_ARM64_REGISTER_MDSCR_EL1;
        let value = self.get_reg64(name)?;
        let value = if enable {
            value | MDSCR_MDE | MDSCR_KDE
        } else {
            value & !(MDSCR_MDE | MDSCR_KDE | 1)
        };
        self.vcpu_fd
            .set_reg(&[hv_register_assoc {
                name,
                value: hv_register_value { reg64: value },
                ..Default::default()
            }])
            .map_err(|e| RegisterError::SetDebugRegs(e.into()))?;
        self.debug_state.enabled = enable;
        Ok(())
    }

    fn set_single_step(&mut self, enable: bool) -> Result<(), DebugError> {
        self.debug_step_pending = false;
        let mut regs = self.regs()?;
        regs.pstate = if enable {
            (regs.pstate | PSTATE_SS) & !PSTATE_D
        } else {
            regs.pstate & !PSTATE_SS
        };
        self.set_regs(&regs)?;
        let name = mshv_bindings::hv_register_name_HV_ARM64_REGISTER_MDSCR_EL1;
        let value = self.get_reg64(name)?;
        self.vcpu_fd
            .set_reg(&[hv_register_assoc {
                name,
                value: hv_register_value {
                    reg64: if enable { value | 1 } else { value & !1 },
                },
                ..Default::default()
            }])
            .map_err(|e| RegisterError::SetDebugRegs(e.into()))?;
        self.debug_state.single_step = enable;
        Ok(())
    }

    fn add_hw_breakpoint(&mut self, addr: u64) -> Result<(), DebugError> {
        if !addr.is_multiple_of(4) {
            return Err(DebugError::Unsupported(
                "unaligned ARM64 hardware breakpoint",
            ));
        }
        if self.debug_state.hardware_breakpoints.contains(&Some(addr)) {
            return Ok(());
        }
        let slot = self
            .debug_state
            .hardware_breakpoints
            .iter()
            .position(Option::is_none)
            .ok_or(DebugError::TooManyHwBreakpoints(HARDWARE_BREAKPOINTS))?;
        self.write_hardware_breakpoint(slot, Some(addr))?;
        self.debug_state.hardware_breakpoints[slot] = Some(addr);
        Ok(())
    }

    fn remove_hw_breakpoint(&mut self, addr: u64) -> Result<(), DebugError> {
        let slot = self
            .debug_state
            .hardware_breakpoints
            .iter()
            .position(|value| *value == Some(addr))
            .ok_or(DebugError::HwBreakpointNotFound(addr))?;
        self.write_hardware_breakpoint(slot, None)?;
        self.debug_state.hardware_breakpoints[slot] = None;
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

#[cfg(all(test, gdb))]
mod debug_tests {
    use super::*;

    #[test]
    fn mmio_single_step_stops_before_the_following_instruction() {
        use crate::mem::memory_region::MemoryRegionType;
        use crate::mem::shared_mem::ExclusiveSharedMemory;

        let mut memory = ExclusiveSharedMemory::new(hyperlight_common::vmem::PAGE_SIZE).unwrap();
        for (index, instruction) in [0xf900_0001u32, 0xd280_1322, 0x1400_0000]
            .into_iter()
            .enumerate()
        {
            memory
                .copy_from_slice(&instruction.to_le_bytes(), index * 4)
                .unwrap();
        }
        let hvc =
            0xd400_0002u32 | ((hyperlight_common::arch::exn::DEBUG_EXCEPTION_HVC as u32) << 5);
        memory.copy_from_slice(&hvc.to_le_bytes(), 0x800).unwrap();
        memory
            .copy_from_slice(&0xd69f_03e0u32.to_le_bytes(), 0x804)
            .unwrap();
        let host = memory.as_slice().as_ptr() as usize;
        let region = MemoryRegion {
            guest_region: 0..hyperlight_common::vmem::PAGE_SIZE,
            host_region: host..host + hyperlight_common::vmem::PAGE_SIZE,
            flags: MemoryRegionFlags::READ | MemoryRegionFlags::EXECUTE,
            region_type: MemoryRegionType::Code,
        };
        let mut vm = MshvVm::new().unwrap();
        // SAFETY: `memory` outlives the VM and the guest mapping is read-only.
        unsafe { vm.map_memory((0, &region)).unwrap() };
        vm.vcpu_fd
            .set_reg(&[
                hv_register_assoc {
                    name: mshv_bindings::hv_register_name_HV_ARM64_REGISTER_SCTLR_EL1,
                    value: hv_register_value {
                        reg64: crate::hypervisor::regs::SCTLR_EL1_RES1,
                    },
                    ..Default::default()
                },
                hv_register_assoc {
                    name: hv_register_name_HV_ARM64_REGISTER_VBAR_EL1,
                    value: hv_register_value { reg64: 0x800 },
                    ..Default::default()
                },
            ])
            .unwrap();
        let mut regs = CommonRegisters {
            pstate: 0x3c4,
            ..Default::default()
        };
        regs.x[0] = hyperlight_common::layout::io_page().unwrap().0 + 109 * 8;
        regs.x[1] = 0x55;
        regs.x[2] = 0xaa;
        vm.set_regs(&regs).unwrap();
        vm.set_debug(true).unwrap();
        vm.set_single_step(true).unwrap();
        assert!(matches!(
            vm.run_vcpu(#[cfg(feature = "trace_guest")] &mut crate::sandbox::trace::TraceContext::new()).unwrap(),
            VmExit::IoOut(109, data) if data == 0x55u64.to_le_bytes()
        ));
        assert!(matches!(
            vm.run_vcpu(
                #[cfg(feature = "trace_guest")]
                &mut crate::sandbox::trace::TraceContext::new()
            )
            .unwrap(),
            VmExit::Debug {
                reason: VcpuStopReason::DoneStep
            }
        ));
        let regs = vm.regs().unwrap();
        assert_eq!(regs.pc, 4);
        assert_eq!(regs.x[2], 0xaa);
        vm.set_single_step(true).unwrap();
        assert!(matches!(
            vm.run_vcpu(
                #[cfg(feature = "trace_guest")]
                &mut crate::sandbox::trace::TraceContext::new()
            )
            .unwrap(),
            VmExit::Debug {
                reason: VcpuStopReason::DoneStep
            }
        ));
        let regs = vm.regs().unwrap();
        assert_eq!(regs.pc, 8);
        assert_eq!(regs.x[2], 0x99);
    }

    #[test]
    fn decodes_hypercall_context_and_rejects_truncated_payload() {
        let context = HypercallInterceptMessage {
            header: mshv_bindings::hv_arm64_intercept_message_header {
                pc: 0x1234,
                instruction_length: 4,
                ..Default::default()
            },
            immediate: hyperlight_common::arch::exn::DEBUG_EXCEPTION_HVC,
            ..Default::default()
        };
        let mut message = mshv_bindings::hv_message::default();
        message.header.message_type = mshv_bindings::hv_message_type_HVMSG_HYPERCALL_INTERCEPT;
        message.header.payload_size = std::mem::size_of_val(&context) as u8;
        // SAFETY: The payload holds 240 bytes. The 176-byte context contains
        // only integers and is written without alignment assumptions.
        unsafe {
            std::ptr::write_unaligned(std::ptr::addr_of_mut!(message.u.payload).cast(), context);
        }
        let decoded = hypercall_context(&message).unwrap();
        let pc = decoded.header.pc;
        assert_eq!(pc, 0x1234);
        assert_eq!(decoded.immediate, context.immediate);
        message.header.payload_size -= 1;
        assert!(matches!(
            hypercall_context(&message),
            Err(RunVcpuError::DecodeIOMessage(_))
        ));
        message.header.payload_size += 1;
        message.header.message_type = hv_message_type_HVMSG_GPA_INTERCEPT;
        assert!(matches!(
            hypercall_context(&message),
            Err(RunVcpuError::DecodeIOMessage(_))
        ));
    }

    #[test]
    fn hardware_breakpoints_survive_reset_and_detach_clears_debug_state() {
        let mut vm = MshvVm::new().unwrap();
        vm.set_debug(true).unwrap();
        vm.add_hw_breakpoint(0).unwrap();
        vm.add_hw_breakpoint(0).unwrap();
        vm.add_hw_breakpoint(0x1000).unwrap();
        assert!(matches!(
            vm.add_hw_breakpoint(0x2000),
            Err(DebugError::TooManyHwBreakpoints(2))
        ));
        assert!(vm.add_hw_breakpoint(1).is_err());
        vm.remove_hw_breakpoint(0).unwrap();
        assert!(matches!(
            vm.remove_hw_breakpoint(0),
            Err(DebugError::HwBreakpointNotFound(0))
        ));
        vm.add_hw_breakpoint(0x2000).unwrap();
        vm.set_single_step(true).unwrap();
        vm.reset_vcpu().unwrap();
        assert_eq!(
            vm.get_reg64(mshv_bindings::hv_register_name_HV_ARM64_REGISTER_MDSCR_EL1)
                .unwrap()
                & (MDSCR_MDE | MDSCR_KDE | 1),
            MDSCR_MDE | MDSCR_KDE | 1
        );
        for (slot, address) in [0x2000, 0x1000].into_iter().enumerate() {
            assert_eq!(
                vm.get_reg64(
                    mshv_bindings::hv_register_name_HV_ARM64_REGISTER_DBGBVR0_EL1 + slot as u32
                )
                .unwrap(),
                address
            );
        }
        vm.set_debug(false).unwrap();
        assert_eq!(
            vm.get_reg64(mshv_bindings::hv_register_name_HV_ARM64_REGISTER_MDSCR_EL1)
                .unwrap()
                & (MDSCR_MDE | MDSCR_KDE | 1),
            0
        );
        for slot in 0..HARDWARE_BREAKPOINTS {
            assert_eq!(
                vm.get_reg64(
                    mshv_bindings::hv_register_name_HV_ARM64_REGISTER_DBGBCR0_EL1 + slot as u32
                )
                .unwrap(),
                0
            );
        }
    }

    #[test]
    fn debug_register_access_uses_exception_context_and_active_stack() {
        let mut vm = MshvVm::new().unwrap();
        let regs = [
            (
                mshv_bindings::hv_register_name_HV_ARM64_REGISTER_ELR_EL1,
                0x1000,
            ),
            (
                mshv_bindings::hv_register_name_HV_ARM64_REGISTER_SPSR_EL1,
                0x3c5,
            ),
            (hv_register_name_HV_ARM64_REGISTER_PC, 0x2000),
            (hv_register_name_HV_ARM64_REGISTER_SP_EL0, 0x9000),
            (hv_register_name_HV_ARM64_REGISTER_SP_EL1, 0x8000),
        ]
        .map(|(name, value)| hv_register_assoc {
            name,
            value: hv_register_value { reg64: value },
            ..Default::default()
        });
        vm.vcpu_fd.set_reg(&regs).unwrap();
        vm.debug_exception_return = Some(0x2000);
        let mut regs = vm.regs().unwrap();
        assert_eq!(regs.pc, 0x1000);
        assert_eq!(regs.sp, 0x8000);
        regs.pc += 4;
        regs.sp += 16;
        regs.pstate = 0x3c4;
        vm.set_regs(&regs).unwrap();
        assert_eq!(
            vm.get_reg64(mshv_bindings::hv_register_name_HV_ARM64_REGISTER_ELR_EL1)
                .unwrap(),
            0x1004
        );
        assert_eq!(
            vm.get_reg64(mshv_bindings::hv_register_name_HV_ARM64_REGISTER_SPSR_EL1)
                .unwrap(),
            0x3c4
        );
        assert_eq!(
            vm.get_reg64(hv_register_name_HV_ARM64_REGISTER_PC).unwrap(),
            0x2000
        );
        assert_eq!(
            vm.get_reg64(hv_register_name_HV_ARM64_REGISTER_SP_EL0)
                .unwrap(),
            0x8010
        );
        assert_eq!(
            vm.get_reg64(hv_register_name_HV_ARM64_REGISTER_SP_EL1)
                .unwrap(),
            0x8000
        );
        vm.vcpu_fd
            .set_reg(&[
                hv_register_assoc {
                    name: hv_register_name_HV_ARM64_REGISTER_PC,
                    value: hv_register_value { reg64: 0x2004 },
                    ..Default::default()
                },
                hv_register_assoc {
                    name: hv_register_name_HV_ARM64_REGISTER_PSTATE,
                    value: hv_register_value { reg64: 0x3c4 },
                    ..Default::default()
                },
            ])
            .unwrap();
        let mut regs = vm.regs().unwrap();
        assert_eq!(regs.pc, 0x2004);
        assert_eq!(regs.sp, 0x8010);
        regs.pc += 4;
        vm.set_regs(&regs).unwrap();
        assert_eq!(
            vm.get_reg64(hv_register_name_HV_ARM64_REGISTER_PC).unwrap(),
            0x2008
        );
        assert_eq!(
            vm.get_reg64(mshv_bindings::hv_register_name_HV_ARM64_REGISTER_ELR_EL1)
                .unwrap(),
            0x1004
        );
    }
}
