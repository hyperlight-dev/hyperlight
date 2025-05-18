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

#[cfg(mshv2)]
extern crate mshv_bindings2 as mshv_bindings;
#[cfg(mshv2)]
extern crate mshv_ioctls2 as mshv_ioctls;

#[cfg(mshv3)]
extern crate mshv_bindings3 as mshv_bindings;
#[cfg(mshv3)]
extern crate mshv_ioctls3 as mshv_ioctls;

#[cfg(gdb)]
use std::collections::HashMap;
#[cfg(gdb)]
use std::fmt::Debug;
use std::sync::LazyLock;

#[cfg(mshv2)]
use mshv_bindings::hv_message;
#[cfg(gdb)]
use mshv_bindings::hv_message_type_HVMSG_X64_EXCEPTION_INTERCEPT;
#[cfg(gdb)]
use mshv_bindings::DebugRegisters;
use mshv_bindings::{
    hv_message_type, hv_message_type_HVMSG_GPA_INTERCEPT, hv_message_type_HVMSG_UNMAPPED_GPA,
    hv_message_type_HVMSG_X64_HALT, hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT, hv_register_assoc,
    hv_register_name_HV_X64_REGISTER_RIP, hv_register_value,
};
#[cfg(mshv3)]
use mshv_bindings::{
    hv_partition_property_code_HV_PARTITION_PROPERTY_SYNTHETIC_PROC_FEATURES,
    hv_partition_synthetic_processor_features,
};
use mshv_ioctls::{Mshv, VcpuFd, VmFd};
use tracing::{instrument, Span};

#[cfg(gdb)]
use super::handlers::DbgMemAccessHandlerCaller;
use super::regs::{CommonFpu, CommonRegisters, CommonSpecialRegisters};
use super::vm::{HyperlightExit, Vm};
#[cfg(gdb)]
use crate::hypervisor::vm::DebugExit;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::{log_then_return, new_error, Result};

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
pub(super) struct MshvVm {
    vm_fd: VmFd,
    vcpu_fd: VcpuFd,

    #[cfg(gdb)]
    debug: MshvDebug,
}

#[cfg(gdb)]
#[derive(Debug, Default)]
struct MshvDebug {
    regs: DebugRegisters,
    sw_breakpoints: HashMap<u64, u8>, // addr -> original instruction
}

static MSHV: LazyLock<Result<Mshv>> =
    LazyLock::new(|| Mshv::new().map_err(|e| new_error!("Failed to open /dev/mshv: {}", e)));

impl MshvVm {
    /// Create a new instance of a MshvVm
    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    pub(super) fn new() -> Result<Self> {
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
            vm_fd.hvcall_set_partition_property(
                hv_partition_property_code_HV_PARTITION_PROPERTY_SYNTHETIC_PROC_FEATURES,
                unsafe { features.as_uint64[0] },
            )?;
            vm_fd.initialize()?;
            vm_fd
        };

        let vcpu_fd = vm_fd.create_vcpu(0)?;

        Ok(Self {
            vm_fd,
            vcpu_fd,
            #[cfg(gdb)]
            debug: MshvDebug::default(),
        })
    }
}

impl Vm for MshvVm {
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
        self.vcpu_fd.set_sregs(&sregs.into())?;
        Ok(())
    }

    fn get_fpu(&self) -> Result<CommonFpu> {
        Ok((&self.vcpu_fd.get_fpu()?).into())
    }

    fn set_fpu(&self, fpu: &CommonFpu) -> Result<()> {
        self.vcpu_fd.set_fpu(&fpu.into())?;
        Ok(())
    }

    unsafe fn map_memory(&mut self, regions: &[MemoryRegion]) -> Result<()> {
        if regions.is_empty() {
            return Err(new_error!("No memory regions to map"));
        }

        regions.iter().try_for_each(|region| {
            let mshv_region = region.clone().into();
            self.vm_fd.map_user_memory(mshv_region)
        })?;
        Ok(())
    }

    fn run_vcpu(&mut self) -> Result<HyperlightExit> {
        const HALT: hv_message_type = hv_message_type_HVMSG_X64_HALT;
        const IO_PORT: hv_message_type = hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT;
        const UNMAPPED_GPA: hv_message_type = hv_message_type_HVMSG_UNMAPPED_GPA;
        const INVALID_GPA: hv_message_type = hv_message_type_HVMSG_GPA_INTERCEPT;
        #[cfg(gdb)]
        const EXCEPTION_INTERCEPT: hv_message_type = hv_message_type_HVMSG_X64_EXCEPTION_INTERCEPT;

        #[cfg(mshv2)]
        let run_result = {
            let hv_message: hv_message = Default::default();
            &self.vcpu_fd.run(hv_message)
        };
        #[cfg(mshv3)]
        let run_result = &self.vcpu_fd.run();

        let result = match run_result {
            Ok(m) => match m.header.message_type {
                HALT => {
                    crate::debug!("mshv - Halt Details : {:#?}", &self);
                    HyperlightExit::Halt()
                }
                IO_PORT => {
                    let io_message = m.to_ioport_info()?;
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
                    crate::debug!("mshv IO Details : \nPort : {}\n{:#?}", port_number, &self);
                    HyperlightExit::IoOut(port_number, rax.to_le_bytes().to_vec())
                }
                UNMAPPED_GPA => {
                    let mimo_message = m.to_memory_info()?;
                    let addr = mimo_message.guest_physical_address;
                    crate::debug!(
                        "mshv MMIO unmapped GPA -Details: Address: {} \n {:#?}",
                        addr,
                        &self
                    );
                    match MemoryRegionFlags::try_from(mimo_message)? {
                        MemoryRegionFlags::READ => HyperlightExit::MmioRead(addr),
                        MemoryRegionFlags::WRITE => HyperlightExit::MmioWrite(addr),
                        _ => HyperlightExit::Unknown("Unknown MMIO access".to_string()),
                    }
                }
                INVALID_GPA => {
                    let mimo_message = m.to_memory_info()?;
                    let gpa = mimo_message.guest_physical_address;
                    let access_info = MemoryRegionFlags::try_from(mimo_message)?;
                    match access_info {
                        MemoryRegionFlags::READ => HyperlightExit::MmioRead(gpa),
                        MemoryRegionFlags::WRITE => HyperlightExit::MmioWrite(gpa),
                        _ => HyperlightExit::Unknown("Unknown MMIO access".to_string()),
                    }
                }
                // The only case an intercept exit is expected is when debugging is enabled
                // and the intercepts are installed.
                // Provide the extra information about the exception to accurately determine
                // the stop reason
                #[cfg(gdb)]
                EXCEPTION_INTERCEPT => {
                    let exception_message = m.to_exception_info()?;
                    let DebugRegisters { dr6, .. } = self.vcpu_fd.get_debug_regs()?;
                    HyperlightExit::Debug(DebugExit::Debug {
                        dr6,
                        exception: exception_message.exception_vector as u32,
                    })
                }
                other => {
                    crate::debug!("mshv Other Exit: Exit: {:#?} \n {:#?}", other, &self);
                    log_then_return!("unknown Hyper-V run message type {:?}", other);
                }
            },
            Err(e) => match e.errno() {
                // In case of the gdb feature, the timeout is not enabled, this
                // exit is because of a signal sent from the gdb thread to the
                // hypervisor thread to cancel execution (e.g. Ctrl+C from GDB)
                #[cfg(gdb)]
                libc::EINTR => HyperlightExit::Debug(DebugExit::Interrupt),
                // we send a signal to the thread to cancel execution. This results in EINTR being returned
                #[cfg(not(gdb))]
                libc::EINTR => HyperlightExit::Cancelled(),
                libc::EAGAIN => HyperlightExit::Retry(),
                _ => {
                    crate::debug!("mshv Error - Details: Error: {} \n {:#?}", e, &self);
                    log_then_return!("Error running VCPU {:?}", e);
                }
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
            hv_intercept_parameters, hv_intercept_type_HV_INTERCEPT_TYPE_EXCEPTION,
            mshv_install_intercept, HV_INTERCEPT_ACCESS_MASK_EXECUTE,
        };

        use crate::new_error;

        if enabled {
            self.vm_fd
                .install_intercept(mshv_install_intercept {
                    access_type_mask: HV_INTERCEPT_ACCESS_MASK_EXECUTE,
                    intercept_type: hv_intercept_type_HV_INTERCEPT_TYPE_EXCEPTION,
                    // Exception handler #DB (1)
                    intercept_parameter: hv_intercept_parameters {
                        exception_vector: 0x1,
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
                        exception_vector: 0x3,
                    },
                })
                .map_err(|e| new_error!("Cannot install breakpoint exception intercept: {}", e))?;
        } else {
            // There doesn't seem to be any way to remove installed intercepts. But that seems fine.
        }
        Ok(())
    }

    #[cfg(gdb)]
    fn set_single_step(&mut self, enable: bool) -> Result<()> {
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
            .position(|i| self.debug.regs.dr7 & (1 << (i * 2)) == 0)
            .ok_or_else(|| new_error!("Tried to add more than 4 hardware breakpoints"))?;

        // Assign to corresponding debug register
        *[
            &mut self.debug.regs.dr0,
            &mut self.debug.regs.dr1,
            &mut self.debug.regs.dr2,
            &mut self.debug.regs.dr3,
        ][i] = addr;

        // Enable LOCAL bit
        self.debug.regs.dr7 |= 1 << (i * 2);

        self.vcpu_fd.set_debug_regs(&self.debug.regs)?;
        Ok(())
    }

    #[cfg(gdb)]
    fn remove_hw_breakpoint(&mut self, addr: u64) -> Result<()> {
        use crate::new_error;

        let regs = [
            &mut self.debug.regs.dr0,
            &mut self.debug.regs.dr1,
            &mut self.debug.regs.dr2,
            &mut self.debug.regs.dr3,
        ];

        if let Some(i) = regs.iter().position(|&&mut reg| reg == addr) {
            // Clear the address
            *regs[i] = 0;
            // Disable LOCAL bit
            self.debug.regs.dr7 &= !(1 << (i * 2));
            self.vcpu_fd.set_debug_regs(&self.debug.regs)?;
            Ok(())
        } else {
            Err(new_error!("Tried to remove non-existing hw-breakpoint"))
        }
    }

    #[cfg(gdb)]
    fn add_sw_breakpoint(
        &mut self,
        addr: u64,
        dbg_mem_access_fn: std::sync::Arc<std::sync::Mutex<dyn DbgMemAccessHandlerCaller>>,
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
        dbg_mem_access_fn: std::sync::Arc<std::sync::Mutex<dyn DbgMemAccessHandlerCaller>>,
    ) -> Result<()> {
        let original_instr = self.debug.sw_breakpoints.remove(&addr).unwrap();
        dbg_mem_access_fn
            .lock()
            .unwrap()
            .write(addr as usize, &[original_instr])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::memory_region::MemoryRegionVecBuilder;
    use crate::mem::shared_mem::{ExclusiveSharedMemory, SharedMemory};

    #[rustfmt::skip]
    const CODE: [u8; 12] = [
        0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
        0x00, 0xd8, /* add %bl, %al */
        0x04, b'0', /* add $'0', %al */
        0xee, /* out %al, (%dx) */
        /* send a 0 to indicate we're done */
        0xb0, b'\0', /* mov $'\0', %al */
        0xee, /* out %al, (%dx) */
        0xf4, /* HLT */
    ];

    fn shared_mem_with_code(
        code: &[u8],
        mem_size: usize,
        load_offset: usize,
    ) -> Result<Box<ExclusiveSharedMemory>> {
        if load_offset > mem_size {
            log_then_return!(
                "code load offset ({}) > memory size ({})",
                load_offset,
                mem_size
            );
        }
        let mut shared_mem = ExclusiveSharedMemory::new(mem_size)?;
        shared_mem.copy_from_slice(code, load_offset)?;
        Ok(Box::new(shared_mem))
    }

    #[test]
    fn create_mshv_vm() {
        if !super::is_hypervisor_present() {
            return;
        }
        const MEM_SIZE: usize = 0x3000;
        let gm = shared_mem_with_code(CODE.as_slice(), MEM_SIZE, 0).unwrap();
        let mut regions = MemoryRegionVecBuilder::new(0, gm.base_addr());
        regions.push_page_aligned(
            MEM_SIZE,
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE | MemoryRegionFlags::EXECUTE,
            crate::mem::memory_region::MemoryRegionType::Code,
        );
        let mut mshv_vm = super::MshvVm::new().unwrap();
        unsafe {
            mshv_vm.map_memory(&regions.build()).unwrap();
        }
    }
}
