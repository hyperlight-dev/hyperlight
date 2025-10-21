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

#[cfg(mshv2)]
extern crate mshv_bindings2 as mshv_bindings;
#[cfg(mshv2)]
extern crate mshv_ioctls2 as mshv_ioctls;

#[cfg(mshv3)]
extern crate mshv_bindings3 as mshv_bindings;
#[cfg(mshv3)]
extern crate mshv_ioctls3 as mshv_ioctls;

#[cfg(gdb)]
use std::fmt::Debug;
use std::sync::LazyLock;

#[cfg(gdb)]
use mshv_bindings::DebugRegisters;
#[cfg(mshv2)]
use mshv_bindings::hv_message;
#[cfg(gdb)]
use mshv_bindings::hv_message_type_HVMSG_X64_EXCEPTION_INTERCEPT;
use mshv_bindings::{
    hv_message_type, hv_message_type_HVMSG_GPA_INTERCEPT, hv_message_type_HVMSG_UNMAPPED_GPA,
    hv_message_type_HVMSG_X64_HALT, hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT, hv_register_assoc,
    hv_register_name_HV_X64_REGISTER_RIP, hv_register_value, mshv_user_mem_region,
};
#[cfg(mshv3)]
use mshv_bindings::{
    hv_partition_property_code_HV_PARTITION_PROPERTY_SYNTHETIC_PROC_FEATURES,
    hv_partition_synthetic_processor_features,
};
use mshv_ioctls::{Mshv, VcpuFd, VmFd};
use tracing::{Span, instrument};

use crate::hypervisor::regs::{CommonFpu, CommonRegisters, CommonSpecialRegisters};
use crate::hypervisor::vm::{Vm, VmExit};
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::{Result, new_error};

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

static MSHV: LazyLock<Result<Mshv>> =
    LazyLock::new(|| Mshv::new().map_err(|e| new_error!("Failed to open /dev/mshv: {}", e)));

impl MshvVm {
    /// Create a new instance of a MshvVm
    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn new() -> Result<Self> {
        let hv = MSHV
            .as_ref()
            .map_err(|e| new_error!("Failed to create MSHV instance: {}", e))?;
        let pr = Default::default();
        #[cfg(mshv2)]
        let vm_fd = hv.create_vm_with_config(&pr)?;
        #[cfg(mshv3)]
        let vm_fd = {
            // It's important to avoid create_vm() and explicitly use
            // create_vm_with_args() with an empty arguments structure
            // here, because otherwise the partition is set up with a SynIC.

            let vm_fd = hv.create_vm_with_args(&pr)?;
            let features: hv_partition_synthetic_processor_features = Default::default();
            vm_fd.set_partition_property(
                hv_partition_property_code_HV_PARTITION_PROPERTY_SYNTHETIC_PROC_FEATURES,
                unsafe { features.as_uint64[0] },
            )?;
            vm_fd.initialize()?;
            vm_fd
        };

        let vcpu_fd = vm_fd.create_vcpu(0)?;

        Ok(Self { vm_fd, vcpu_fd })
    }
}

impl Vm for MshvVm {
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
        self.vcpu_fd.set_sregs(&sregs.into())?;
        Ok(())
    }

    fn fpu(&self) -> Result<CommonFpu> {
        Ok((&self.vcpu_fd.get_fpu()?).into())
    }

    fn set_fpu(&self, fpu: &CommonFpu) -> Result<()> {
        self.vcpu_fd.set_fpu(&fpu.into())?;
        Ok(())
    }

    #[cfg(crashdump)]
    fn xsave(&self) -> Result<Vec<u8>> {
        let xsave = self.vcpu_fd.get_xsave()?;
        Ok(xsave.buffer.to_vec())
    }

    /// # Safety
    /// The caller must ensure that the memory region is valid and points to valid memory,
    /// and lives long enough for the VM to use it.
    unsafe fn map_memory(&mut self, (_slot, region): (u32, &MemoryRegion)) -> Result<()> {
        let mshv_region: mshv_user_mem_region = region.into();
        self.vm_fd.map_user_memory(mshv_region)?;
        Ok(())
    }

    fn unmap_memory(&mut self, (_slot, region): (u32, &MemoryRegion)) -> Result<()> {
        let mshv_region: mshv_user_mem_region = region.into();
        self.vm_fd.unmap_user_memory(mshv_region)?;
        Ok(())
    }

    fn run_vcpu(&mut self) -> Result<VmExit> {
        const HALT: hv_message_type = hv_message_type_HVMSG_X64_HALT;
        const IO_PORT: hv_message_type = hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT;
        const UNMAPPED_GPA: hv_message_type = hv_message_type_HVMSG_UNMAPPED_GPA;
        const INVALID_GPA: hv_message_type = hv_message_type_HVMSG_GPA_INTERCEPT;
        #[cfg(gdb)]
        const EXCEPTION_INTERCEPT: hv_message_type = hv_message_type_HVMSG_X64_EXCEPTION_INTERCEPT;

        #[cfg(mshv2)]
        let run_result = {
            let hv_message: hv_message = Default::default();
            self.vcpu_fd.run(hv_message)
        };
        #[cfg(mshv3)]
        let run_result = self.vcpu_fd.run();

        let result = match run_result {
            Ok(m) => match m.header.message_type {
                HALT => VmExit::Halt(),
                IO_PORT => {
                    let io_message = m.to_ioport_info().map_err(mshv_ioctls::MshvError::from)?;
                    let port_number = io_message.port_number;
                    let rax = io_message.rax;
                    // mshv, unlike kvm, does not automatically increment RIP
                    self.vcpu_fd.set_reg(&[hv_register_assoc {
                        name: hv_register_name_HV_X64_REGISTER_RIP,
                        value: hv_register_value {
                            reg64: io_message.header.rip
                                + io_message.header.instruction_length() as u64,
                        },
                        ..Default::default()
                    }])?;
                    VmExit::IoOut(port_number, rax.to_le_bytes().to_vec())
                }
                UNMAPPED_GPA => {
                    let mimo_message = m.to_memory_info().map_err(mshv_ioctls::MshvError::from)?;
                    let addr = mimo_message.guest_physical_address;
                    match MemoryRegionFlags::try_from(mimo_message)? {
                        MemoryRegionFlags::READ => VmExit::MmioRead(addr),
                        MemoryRegionFlags::WRITE => VmExit::MmioWrite(addr),
                        _ => VmExit::Unknown("Unknown MMIO access".to_string()),
                    }
                }
                INVALID_GPA => {
                    let mimo_message = m.to_memory_info().map_err(mshv_ioctls::MshvError::from)?;
                    let gpa = mimo_message.guest_physical_address;
                    let access_info = MemoryRegionFlags::try_from(mimo_message)?;
                    match access_info {
                        MemoryRegionFlags::READ => VmExit::MmioRead(gpa),
                        MemoryRegionFlags::WRITE => VmExit::MmioWrite(gpa),
                        _ => VmExit::Unknown("Unknown MMIO access".to_string()),
                    }
                }
                #[cfg(gdb)]
                EXCEPTION_INTERCEPT => {
                    let exception_message = m
                        .to_exception_info()
                        .map_err(mshv_ioctls::MshvError::from)?;
                    let DebugRegisters { dr6, .. } = self.vcpu_fd.get_debug_regs()?;
                    VmExit::Debug {
                        dr6,
                        exception: exception_message.exception_vector as u32,
                    }
                }
                other => VmExit::Unknown(format!("Unknown MSHV VCPU exit: {:?}", other)),
            },
            Err(e) => match e.errno() {
                libc::EINTR => VmExit::Cancelled(),
                libc::EAGAIN => VmExit::Retry(),
                _ => VmExit::Unknown(format!("Unknown MSHV VCPU error: {}", e)),
            },
        };
        Ok(result)
    }

    // -- DEBUGGING RELATED BELOW ---

    #[cfg(gdb)]
    fn translate_gva(&self, gva: u64) -> Result<u64> {
        use mshv_bindings::{HV_TRANSLATE_GVA_VALIDATE_READ, HV_TRANSLATE_GVA_VALIDATE_WRITE};

        use crate::HyperlightError;

        let flags = (HV_TRANSLATE_GVA_VALIDATE_READ | HV_TRANSLATE_GVA_VALIDATE_WRITE) as u64;
        let (addr, _) = self
            .vcpu_fd
            .translate_gva(gva, flags)
            .map_err(|_| HyperlightError::TranslateGuestAddress(gva))?;

        Ok(addr)
    }

    #[cfg(gdb)]
    fn set_debug(&mut self, enabled: bool) -> Result<()> {
        use mshv_bindings::{
            HV_INTERCEPT_ACCESS_MASK_EXECUTE, hv_intercept_parameters,
            hv_intercept_type_HV_INTERCEPT_TYPE_EXCEPTION, mshv_install_intercept,
        };

        use crate::hypervisor::gdb::arch::{BP_EX_ID, DB_EX_ID};
        use crate::new_error;

        if enabled {
            self.vm_fd
                .install_intercept(mshv_install_intercept {
                    access_type_mask: HV_INTERCEPT_ACCESS_MASK_EXECUTE,
                    intercept_type: hv_intercept_type_HV_INTERCEPT_TYPE_EXCEPTION,
                    // Exception handler #DB (1)
                    intercept_parameter: hv_intercept_parameters {
                        exception_vector: DB_EX_ID as u16,
                    },
                })
                .map_err(|e| new_error!("Cannot install debug exception intercept: {}", e))?;

            // Install intercept for #BP (3) exception
            self.vm_fd
                .install_intercept(mshv_install_intercept {
                    access_type_mask: HV_INTERCEPT_ACCESS_MASK_EXECUTE,
                    intercept_type: hv_intercept_type_HV_INTERCEPT_TYPE_EXCEPTION,
                    // Exception handler #BP (3)
                    intercept_parameter: hv_intercept_parameters {
                        exception_vector: BP_EX_ID as u16,
                    },
                })
                .map_err(|e| new_error!("Cannot install breakpoint exception intercept: {}", e))?;
        } else {
            // There doesn't seem to be any way to remove installed intercepts. But that's okay.
        }
        Ok(())
    }

    #[cfg(gdb)]
    fn set_single_step(&mut self, enable: bool) -> Result<()> {
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

        let mut debug_regs = self.vcpu_fd.get_debug_regs()?;

        // Check if breakpoint already exists
        if [
            debug_regs.dr0,
            debug_regs.dr1,
            debug_regs.dr2,
            debug_regs.dr3,
        ]
        .contains(&addr)
        {
            return Ok(());
        }

        // Find the first available LOCAL (L0–L3) slot
        let i = (0..MAX_NO_OF_HW_BP)
            .position(|i| debug_regs.dr7 & (1 << (i * 2)) == 0)
            .ok_or_else(|| new_error!("Tried to add more than 4 hardware breakpoints"))?;

        // Assign to corresponding debug register
        *[
            &mut debug_regs.dr0,
            &mut debug_regs.dr1,
            &mut debug_regs.dr2,
            &mut debug_regs.dr3,
        ][i] = addr;

        // Enable LOCAL bit
        debug_regs.dr7 |= 1 << (i * 2);

        self.vcpu_fd.set_debug_regs(&debug_regs)?;
        Ok(())
    }

    #[cfg(gdb)]
    fn remove_hw_breakpoint(&mut self, addr: u64) -> Result<()> {
        use crate::new_error;

        let mut debug_regs = self.vcpu_fd.get_debug_regs()?;

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
            self.vcpu_fd.set_debug_regs(&debug_regs)?;
            Ok(())
        } else {
            Err(new_error!("Tried to remove non-existing hw-breakpoint"))
        }
    }
}
