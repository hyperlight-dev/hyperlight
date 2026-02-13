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

#[cfg(gdb)]
use std::fmt::Debug;
use std::sync::LazyLock;

#[cfg(gdb)]
use mshv_bindings::{DebugRegisters, hv_message_type_HVMSG_X64_EXCEPTION_INTERCEPT};
use mshv_bindings::{
    FloatingPointUnit, HV_INTERCEPT_ACCESS_MASK_READ, HV_INTERCEPT_ACCESS_MASK_WRITE,
    HV_INTERCEPT_ACCESS_READ, HV_INTERCEPT_ACCESS_WRITE, SpecialRegisters, StandardRegisters,
    XSave, hv_intercept_type_HV_INTERCEPT_TYPE_X64_MSR, hv_message_type,
    hv_message_type_HVMSG_GPA_INTERCEPT, hv_message_type_HVMSG_UNMAPPED_GPA,
    hv_message_type_HVMSG_X64_HALT, hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT,
    hv_message_type_HVMSG_X64_MSR_INTERCEPT,
    hv_partition_property_code_HV_PARTITION_PROPERTY_SYNTHETIC_PROC_FEATURES,
    hv_partition_synthetic_processor_features, hv_register_assoc,
    hv_register_name_HV_X64_REGISTER_RIP, hv_register_value, mshv_install_intercept,
    mshv_user_mem_region, msr_to_hv_reg_name,
};
use mshv_ioctls::{Mshv, VcpuFd, VmFd};
use tracing::{Span, instrument};
#[cfg(feature = "trace_guest")]
use tracing_opentelemetry::OpenTelemetrySpanExt;

#[cfg(gdb)]
use crate::hypervisor::gdb::{DebugError, DebuggableVm};
use crate::hypervisor::regs::{
    CommonDebugRegs, CommonFpu, CommonRegisters, CommonSpecialRegisters, FP_CONTROL_WORD_DEFAULT,
    MXCSR_DEFAULT,
};
#[cfg(all(test, feature = "init-paging"))]
use crate::hypervisor::virtual_machine::XSAVE_BUFFER_SIZE;
use crate::hypervisor::virtual_machine::{
    CreateVmError, MapMemoryError, RegisterError, RunVcpuError, UnmapMemoryError, VirtualMachine,
    VmExit, XSAVE_MIN_SIZE,
};
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
#[cfg(feature = "trace_guest")]
use crate::sandbox::trace::TraceContext as SandboxTraceContext;

/// Determine whether the HyperV for Linux hypervisor API is present
/// and functional.
#[instrument(skip_all, parent = Span::current(), level = "Trace")]
pub(crate) fn is_hypervisor_present() -> bool {
    match Mshv::new() {
        Ok(_) => true,
        Err(_) => {
            log::info!("MSHV is not available on this system");
            false
        }
    }
}

/// A MSHV implementation of a single-vcpu VM
#[derive(Debug)]
pub(crate) struct MshvVm {
    vm_fd: VmFd,
    vcpu_fd: VcpuFd,
}

static MSHV: LazyLock<std::result::Result<Mshv, CreateVmError>> =
    LazyLock::new(|| Mshv::new().map_err(|e| CreateVmError::HypervisorNotAvailable(e.into())));

impl MshvVm {
    /// Create a new instance of a MshvVm
    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn new() -> std::result::Result<Self, CreateVmError> {
        let mshv = MSHV.as_ref().map_err(|e| e.clone())?;

        let pr = Default::default();
        // It's important to avoid create_vm() and explicitly use
        // create_vm_with_args() with an empty arguments structure
        // here, because otherwise the partition is set up with a SynIC.
        let vm_fd = mshv
            .create_vm_with_args(&pr)
            .map_err(|e| CreateVmError::CreateVmFd(e.into()))?;

        let vcpu_fd = {
            let features: hv_partition_synthetic_processor_features = Default::default();
            vm_fd
                .set_partition_property(
                    hv_partition_property_code_HV_PARTITION_PROPERTY_SYNTHETIC_PROC_FEATURES,
                    unsafe { features.as_uint64[0] },
                )
                .map_err(|e| CreateVmError::SetPartitionProperty(e.into()))?;
            vm_fd
                .initialize()
                .map_err(|e| CreateVmError::InitializeVm(e.into()))?;

            vm_fd
                .create_vcpu(0)
                .map_err(|e| CreateVmError::CreateVcpuFd(e.into()))?
        };

        Ok(Self { vm_fd, vcpu_fd })
    }
}

impl VirtualMachine for MshvVm {
    fn enable_msr_intercept(&mut self) -> std::result::Result<(), CreateVmError> {
        let intercept = mshv_install_intercept {
            access_type_mask: HV_INTERCEPT_ACCESS_MASK_WRITE | HV_INTERCEPT_ACCESS_MASK_READ,
            intercept_type: hv_intercept_type_HV_INTERCEPT_TYPE_X64_MSR,
            intercept_parameter: Default::default(),
        };
        self.vm_fd
            .install_intercept(intercept)
            .map_err(|e| CreateVmError::EnableMsrIntercept(e.into()))?;
        Ok(())
    }

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
        #[cfg(feature = "trace_guest")] tc: &mut SandboxTraceContext,
    ) -> std::result::Result<VmExit, RunVcpuError> {
        const HALT_MESSAGE: hv_message_type = hv_message_type_HVMSG_X64_HALT;
        const IO_PORT_INTERCEPT_MESSAGE: hv_message_type =
            hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT;
        const UNMAPPED_GPA_MESSAGE: hv_message_type = hv_message_type_HVMSG_UNMAPPED_GPA;
        const INVALID_GPA_ACCESS_MESSAGE: hv_message_type = hv_message_type_HVMSG_GPA_INTERCEPT;
        const MSR_MESSAGE: hv_message_type = hv_message_type_HVMSG_X64_MSR_INTERCEPT;
        #[cfg(gdb)]
        const EXCEPTION_INTERCEPT: hv_message_type = hv_message_type_HVMSG_X64_EXCEPTION_INTERCEPT;

        // setup_trace_guest must be called right before vcpu_run.run() call, because
        // it sets the guest span, no other traces or spans must be setup in between these calls.
        #[cfg(feature = "trace_guest")]
        tc.setup_guest_trace(Span::current().context());
        let exit_reason = self.vcpu_fd.run();

        let result = match exit_reason {
            Ok(m) => match m.header.message_type {
                HALT_MESSAGE => VmExit::Halt(),
                IO_PORT_INTERCEPT_MESSAGE => {
                    let io_message = m
                        .to_ioport_info()
                        .map_err(|_| RunVcpuError::DecodeIOMessage(m.header.message_type))?;
                    let port_number = io_message.port_number;
                    let rip = io_message.header.rip;
                    let rax = io_message.rax;
                    let instruction_length = io_message.header.instruction_length() as u64;

                    // mshv, unlike kvm, does not automatically increment RIP
                    self.vcpu_fd
                        .set_reg(&[hv_register_assoc {
                            name: hv_register_name_HV_X64_REGISTER_RIP,
                            value: hv_register_value {
                                reg64: rip + instruction_length,
                            },
                            ..Default::default()
                        }])
                        .map_err(|e| RunVcpuError::IncrementRip(e.into()))?;
                    VmExit::IoOut(port_number, rax.to_le_bytes().to_vec())
                }
                UNMAPPED_GPA_MESSAGE => {
                    let mimo_message = m
                        .to_memory_info()
                        .map_err(|_| RunVcpuError::DecodeIOMessage(m.header.message_type))?;
                    let addr = mimo_message.guest_physical_address;
                    match MemoryRegionFlags::try_from(mimo_message)
                        .map_err(|_| RunVcpuError::ParseGpaAccessInfo)?
                    {
                        MemoryRegionFlags::READ => VmExit::MmioRead(addr),
                        MemoryRegionFlags::WRITE => VmExit::MmioWrite(addr),
                        _ => VmExit::Unknown("Unknown MMIO access".to_string()),
                    }
                }
                INVALID_GPA_ACCESS_MESSAGE => {
                    let mimo_message = m
                        .to_memory_info()
                        .map_err(|_| RunVcpuError::DecodeIOMessage(m.header.message_type))?;
                    let gpa = mimo_message.guest_physical_address;
                    let access_info = MemoryRegionFlags::try_from(mimo_message)
                        .map_err(|_| RunVcpuError::ParseGpaAccessInfo)?;
                    match access_info {
                        MemoryRegionFlags::READ => VmExit::MmioRead(gpa),
                        MemoryRegionFlags::WRITE => VmExit::MmioWrite(gpa),
                        _ => VmExit::Unknown("Unknown MMIO access".to_string()),
                    }
                }
                MSR_MESSAGE => {
                    let msr_message = m
                        .to_msr_info()
                        .map_err(|_| RunVcpuError::DecodeMsrMessage(m.header.message_type))?;
                    let edx = msr_message.rdx;
                    let eax = msr_message.rax;
                    let written_value = (edx << 32) | eax;
                    let access = msr_message.header.intercept_access_type as u32;
                    match access {
                        HV_INTERCEPT_ACCESS_READ => VmExit::MsrRead(msr_message.msr_number),
                        HV_INTERCEPT_ACCESS_WRITE => VmExit::MsrWrite {
                            msr_index: msr_message.msr_number,
                            value: written_value,
                        },
                        _ => VmExit::Unknown(format!("Unknown MSR access type={}", access)),
                    }
                }
                #[cfg(gdb)]
                EXCEPTION_INTERCEPT => {
                    let ex_info = m
                        .to_exception_info()
                        .map_err(|_| RunVcpuError::DecodeIOMessage(m.header.message_type))?;
                    let DebugRegisters { dr6, .. } = self
                        .vcpu_fd
                        .get_debug_regs()
                        .map_err(|e| RunVcpuError::GetDr6(e.into()))?;
                    VmExit::Debug {
                        dr6,
                        exception: ex_info.exception_vector as u32,
                    }
                }
                other => VmExit::Unknown(format!("Unknown MSHV VCPU exit: {:?}", other)),
            },
            Err(e) => match e.errno() {
                // InterruptHandle::kill() sends a signal (SIGRTMIN+offset) to interrupt the vcpu, which causes EINTR
                libc::EINTR => VmExit::Cancelled(),
                libc::EAGAIN => VmExit::Retry(),
                _ => Err(RunVcpuError::Unknown(e.into()))?,
            },
        };
        Ok(result)
    }

    fn regs(&self) -> std::result::Result<CommonRegisters, RegisterError> {
        let mshv_regs = self
            .vcpu_fd
            .get_regs()
            .map_err(|e| RegisterError::GetRegs(e.into()))?;
        Ok((&mshv_regs).into())
    }

    fn set_regs(&self, regs: &CommonRegisters) -> std::result::Result<(), RegisterError> {
        let mshv_regs: StandardRegisters = regs.into();
        self.vcpu_fd
            .set_regs(&mshv_regs)
            .map_err(|e| RegisterError::SetRegs(e.into()))?;
        Ok(())
    }

    fn fpu(&self) -> std::result::Result<CommonFpu, RegisterError> {
        let mshv_fpu = self
            .vcpu_fd
            .get_fpu()
            .map_err(|e| RegisterError::GetFpu(e.into()))?;
        Ok((&mshv_fpu).into())
    }

    fn set_fpu(&self, fpu: &CommonFpu) -> std::result::Result<(), RegisterError> {
        let mshv_fpu: FloatingPointUnit = fpu.into();
        self.vcpu_fd
            .set_fpu(&mshv_fpu)
            .map_err(|e| RegisterError::SetFpu(e.into()))?;
        Ok(())
    }

    fn sregs(&self) -> std::result::Result<CommonSpecialRegisters, RegisterError> {
        let mshv_sregs = self
            .vcpu_fd
            .get_sregs()
            .map_err(|e| RegisterError::GetSregs(e.into()))?;
        Ok((&mshv_sregs).into())
    }

    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> std::result::Result<(), RegisterError> {
        let mshv_sregs: SpecialRegisters = sregs.into();
        self.vcpu_fd
            .set_sregs(&mshv_sregs)
            .map_err(|e| RegisterError::SetSregs(e.into()))?;
        Ok(())
    }

    fn debug_regs(&self) -> std::result::Result<CommonDebugRegs, RegisterError> {
        let debug_regs = self
            .vcpu_fd
            .get_debug_regs()
            .map_err(|e| RegisterError::GetDebugRegs(e.into()))?;
        Ok(debug_regs.into())
    }

    fn set_debug_regs(&self, drs: &CommonDebugRegs) -> std::result::Result<(), RegisterError> {
        let mshv_debug_regs = drs.into();
        self.vcpu_fd
            .set_debug_regs(&mshv_debug_regs)
            .map_err(|e| RegisterError::SetDebugRegs(e.into()))?;
        Ok(())
    }

    #[allow(dead_code)]
    fn xsave(&self) -> std::result::Result<Vec<u8>, RegisterError> {
        let xsave = self
            .vcpu_fd
            .get_xsave()
            .map_err(|e| RegisterError::GetXsave(e.into()))?;
        Ok(xsave.buffer.to_vec())
    }

    fn reset_xsave(&self) -> std::result::Result<(), RegisterError> {
        let current_xsave = self
            .vcpu_fd
            .get_xsave()
            .map_err(|e| RegisterError::GetXsave(e.into()))?;
        if current_xsave.buffer.len() < XSAVE_MIN_SIZE {
            // Minimum: 512 legacy + 64 header
            return Err(RegisterError::XsaveSizeMismatch {
                expected: XSAVE_MIN_SIZE as u32,
                actual: current_xsave.buffer.len() as u32,
            });
        }

        let mut buf = XSave::default(); // default is zeroed 4KB buffer

        // Copy XCOMP_BV (offset 520-527) - preserves feature mask + compacted bit
        buf.buffer[520..528].copy_from_slice(&current_xsave.buffer[520..528]);

        // XSAVE area layout from Intel SDM Vol. 1 Section 13.4.1:
        // - Bytes 0-1: FCW (x87 FPU Control Word)
        // - Bytes 24-27: MXCSR
        // - Bytes 512-519: XSTATE_BV (bitmap of valid state components)
        buf.buffer[0..2].copy_from_slice(&FP_CONTROL_WORD_DEFAULT.to_le_bytes());
        buf.buffer[24..28].copy_from_slice(&MXCSR_DEFAULT.to_le_bytes());
        // XSTATE_BV = 0x3: bits 0,1 = x87 + SSE valid. Explicitly tell hypervisor
        // to apply the legacy region from this buffer for consistent behavior.
        buf.buffer[512..520].copy_from_slice(&0x3u64.to_le_bytes());

        self.vcpu_fd
            .set_xsave(&buf)
            .map_err(|e| RegisterError::SetXsave(e.into()))?;
        Ok(())
    }

    #[cfg(test)]
    #[cfg(feature = "init-paging")]
    fn set_xsave(&self, xsave: &[u32]) -> std::result::Result<(), RegisterError> {
        if std::mem::size_of_val(xsave) != XSAVE_BUFFER_SIZE {
            return Err(RegisterError::XsaveSizeMismatch {
                expected: XSAVE_BUFFER_SIZE as u32,
                actual: std::mem::size_of_val(xsave) as u32,
            });
        }

        // Safety: all valid u32 values are 4 valid u8 values
        let (prefix, bytes, suffix) = unsafe { xsave.align_to() };
        if !prefix.is_empty() || !suffix.is_empty() {
            return Err(RegisterError::InvalidXsaveAlignment);
        }
        let buf = XSave {
            buffer: bytes
                .try_into()
                .expect("xsave slice has correct length and prefix and suffix are empty"),
        };
        self.vcpu_fd
            .set_xsave(&buf)
            .map_err(|e| RegisterError::SetXsave(e.into()))?;
        Ok(())
    }

    fn reset_msrs(&self) -> std::result::Result<(), RegisterError> {
        use mshv_bindings::{hv_register_name, hv_register_name_HV_X64_REGISTER_U_XSS};

        use super::MSRS_TO_RESET;

        /// Extends `msr_to_hv_reg_name` with mappings missing from
        /// mshv-bindings (e.g. IA32_XSS 0xDA0, whose constant is
        /// incorrectly set to the HV register name value 0x8008B).
        fn msr_to_hv_reg(msr_index: u32) -> Result<hv_register_name, RegisterError> {
            msr_to_hv_reg_name(msr_index).or(match msr_index {
                0xDA0 => Ok(hv_register_name_HV_X64_REGISTER_U_XSS),
                _ => Err(RegisterError::UnknownMsr(msr_index)),
            })
        }

        for &(msr_index, value) in MSRS_TO_RESET {
            let name = msr_to_hv_reg(msr_index)?;
            let assoc = hv_register_assoc {
                name,
                value: hv_register_value { reg64: value },
                ..Default::default()
            };
            self.vcpu_fd
                .set_reg(&[assoc])
                .map_err(|e| RegisterError::ResetMsr {
                    index: msr_index,
                    source: e.into(),
                })?;
        }

        Ok(())
    }
}

#[cfg(gdb)]
impl DebuggableVm for MshvVm {
    fn translate_gva(&self, gva: u64) -> std::result::Result<u64, DebugError> {
        use mshv_bindings::{HV_TRANSLATE_GVA_VALIDATE_READ, HV_TRANSLATE_GVA_VALIDATE_WRITE};

        let flags = (HV_TRANSLATE_GVA_VALIDATE_READ | HV_TRANSLATE_GVA_VALIDATE_WRITE) as u64;
        let (addr, _) = self
            .vcpu_fd
            .translate_gva(gva, flags)
            .map_err(|_| DebugError::TranslateGva(gva))?;

        Ok(addr)
    }

    fn set_debug(&mut self, enabled: bool) -> std::result::Result<(), DebugError> {
        use mshv_bindings::{
            HV_INTERCEPT_ACCESS_MASK_EXECUTE, HV_INTERCEPT_ACCESS_MASK_NONE,
            hv_intercept_parameters, hv_intercept_type_HV_INTERCEPT_TYPE_EXCEPTION,
            mshv_install_intercept,
        };

        use crate::hypervisor::gdb::arch::{BP_EX_ID, DB_EX_ID};

        let access_type_mask = if enabled {
            HV_INTERCEPT_ACCESS_MASK_EXECUTE
        } else {
            HV_INTERCEPT_ACCESS_MASK_NONE
        };

        for vector in [DB_EX_ID, BP_EX_ID] {
            self.vm_fd
                .install_intercept(mshv_install_intercept {
                    access_type_mask,
                    intercept_type: hv_intercept_type_HV_INTERCEPT_TYPE_EXCEPTION,
                    intercept_parameter: hv_intercept_parameters {
                        exception_vector: vector as u16,
                    },
                })
                .map_err(|e| DebugError::Intercept {
                    enable: enabled,
                    inner: e.into(),
                })?;
        }
        Ok(())
    }

    fn set_single_step(&mut self, enable: bool) -> std::result::Result<(), DebugError> {
        let mut regs = self.regs()?;
        if enable {
            regs.rflags |= 1 << 8;
        } else {
            regs.rflags &= !(1 << 8);
        }
        self.set_regs(&regs)?;
        Ok(())
    }

    fn add_hw_breakpoint(&mut self, addr: u64) -> std::result::Result<(), DebugError> {
        use crate::hypervisor::gdb::arch::MAX_NO_OF_HW_BP;

        let mut regs = self.debug_regs()?;

        // Check if breakpoint already exists
        if [regs.dr0, regs.dr1, regs.dr2, regs.dr3].contains(&addr) {
            return Ok(());
        }

        // Find the first available LOCAL (L0–L3) slot
        let i = (0..MAX_NO_OF_HW_BP)
            .position(|i| regs.dr7 & (1 << (i * 2)) == 0)
            .ok_or(DebugError::TooManyHwBreakpoints(MAX_NO_OF_HW_BP))?;

        // Assign to corresponding debug register
        *[&mut regs.dr0, &mut regs.dr1, &mut regs.dr2, &mut regs.dr3][i] = addr;

        // Enable LOCAL bit
        regs.dr7 |= 1 << (i * 2);

        self.set_debug_regs(&regs)?;
        Ok(())
    }

    fn remove_hw_breakpoint(&mut self, addr: u64) -> std::result::Result<(), DebugError> {
        let mut debug_regs = self.debug_regs()?;

        let regs = [
            &mut debug_regs.dr0,
            &mut debug_regs.dr1,
            &mut debug_regs.dr2,
            &mut debug_regs.dr3,
        ];

        if let Some(i) = regs.iter().position(|&&mut reg| reg == addr) {
            // Clear the address
            *regs[i] = 0;
            // Disable LOCAL bit
            debug_regs.dr7 &= !(1 << (i * 2));
            self.set_debug_regs(&debug_regs)?;
            Ok(())
        } else {
            Err(DebugError::HwBreakpointNotFound(addr))
        }
    }
}
