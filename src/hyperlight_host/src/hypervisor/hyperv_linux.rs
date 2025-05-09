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

use std::fmt::Debug;

#[cfg(mshv2)]
use mshv_bindings::hv_message;
#[cfg(gdb)]
use mshv_bindings::hv_message_type_HVMSG_X64_EXCEPTION_INTERCEPT;
use mshv_bindings::{
    hv_message_type, hv_message_type_HVMSG_GPA_INTERCEPT, hv_message_type_HVMSG_UNMAPPED_GPA,
    hv_message_type_HVMSG_X64_HALT, hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT,
};
#[cfg(mshv3)]
use mshv_bindings::{
    hv_partition_property_code_HV_PARTITION_PROPERTY_SYNTHETIC_PROC_FEATURES,
    hv_partition_synthetic_processor_features,
};
use mshv_bindings2::{
    hv_register_assoc, hv_register_name_HV_X64_REGISTER_RIP, hv_register_value, DebugRegisters,
};
use mshv_ioctls::{Mshv, VcpuFd, VmFd};
use tracing::{instrument, Span};

use super::handlers::DbgMemAccessHandlerCaller;
use super::HyperlightExit;
use crate::fpuregs::CommonFpu;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::regs::CommonRegisters;
use crate::sregs::CommonSpecialRegisters;
use crate::vm::Vm;
use crate::{log_then_return, HyperlightError, Result};

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
    mshv_fd: Mshv,
    vm_fd: VmFd,
    vcpu_fd: VcpuFd,
}

impl MshvVm {
    /// Create a new instance of a MshvVm
    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    pub(super) fn new() -> Result<Self> {
        let mshv_fd = Mshv::new()?;
        let pr = Default::default();
        #[cfg(mshv2)]
        let vm_fd = mshv_fd.create_vm_with_config(&pr)?;
        #[cfg(mshv3)]
        let vm_fd = {
            // It's important to avoid create_vm() and explicitly use
            // create_vm_with_args() with an empty arguments structure
            // here, because otherwise the partition is set up with a SynIC.

            let vm_fd = mshv.create_vm_with_args(&pr)?;
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
            mshv_fd: mshv_fd,
            vm_fd,
            vcpu_fd,
        })
    }
}

impl Vm for MshvVm {
    fn get_regs(&self) -> Result<CommonRegisters> {
        let mshv_regs = self.vcpu_fd.get_regs()?;
        Ok(mshv_regs.into())
    }

    fn set_regs(&self, regs: &CommonRegisters) -> Result<()> {
        let mshv_regs = regs.clone().into();
        Ok(self.vcpu_fd.set_regs(&mshv_regs)?)
    }

    fn get_sregs(&self) -> Result<CommonSpecialRegisters> {
        let mshv_sregs = self.vcpu_fd.get_sregs()?;
        Ok(mshv_sregs.into())
    }

    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> Result<()> {
        let mshv_sregs = sregs.clone().into();
        self.vcpu_fd.set_sregs(&mshv_sregs)?;
        Ok(())
    }

    fn get_fpu(&self) -> Result<CommonFpu> {
        Ok(self.vcpu_fd.get_fpu()?.into())
    }

    fn set_fpu(&self, fpu: &CommonFpu) -> Result<()> {
        self.vcpu_fd.set_fpu(&fpu.clone().into())?;
        Ok(())
    }

    unsafe fn map_memory(&self, regions: &[MemoryRegion]) -> Result<()> {
        regions.iter().try_for_each(|region| {
            let mshv_region = region.clone().into();
            self.vm_fd.map_user_memory(mshv_region)
        })?;
        Ok(())
    }

    fn run_vcpu(&mut self) -> Result<HyperlightExit> {
        const HALT_MESSAGE: hv_message_type = hv_message_type_HVMSG_X64_HALT;
        const IO_PORT_INTERCEPT_MESSAGE: hv_message_type =
            hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT;
        const UNMAPPED_GPA_MESSAGE: hv_message_type = hv_message_type_HVMSG_UNMAPPED_GPA;
        const INVALID_GPA_ACCESS_MESSAGE: hv_message_type = hv_message_type_HVMSG_GPA_INTERCEPT;
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
                HALT_MESSAGE => {
                    crate::debug!("mshv - Halt Details : {:#?}", &self);
                    HyperlightExit::Halt()
                }
                IO_PORT_INTERCEPT_MESSAGE => {
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
                UNMAPPED_GPA_MESSAGE => {
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
                INVALID_GPA_ACCESS_MESSAGE => {
                    let mimo_message = m.to_memory_info()?;
                    let gpa = mimo_message.guest_physical_address;
                    let access_info = MemoryRegionFlags::try_from(mimo_message)?;
                    crate::debug!(
                        "mshv MMIO invalid GPA access -Details: Address: {} \n {:#?}",
                        gpa,
                        &self
                    );
                    log_then_return!(HyperlightError::MemoryAccessViolation(
                        gpa,
                        access_info,
                        todo!(),
                    ));
                }
                // The only case an intercept exit is expected is when debugging is enabled
                // and the intercepts are installed
                #[cfg(gdb)]
                EXCEPTION_INTERCEPT => {
                    let exception_message = m.to_exception_info()?;
                    let DebugRegisters { dr6, .. } = self.vcpu_fd.get_debug_regs()?;
                    HyperlightExit::Debug {
                        dr6: dr6,
                        exception: exception_message.exception_vector as u32,
                    }
                }
                other => {
                    crate::debug!("mshv Other Exit: Exit: {:#?} \n {:#?}", other, &self);
                    log_then_return!("unknown Hyper-V run message type {:?}", other);
                }
            },
            Err(e) => match e.errno() {
                // we send a signal to the thread to cancel execution this results in EINTR being returned by KVM so we return Cancelled
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

    fn interrupt_handle(&self) -> crate::vm::InterruptHandle {
        todo!()
    }

    fn translate_gva(&self, gva: u64) -> Result<u64> {
        todo!()
    }

    fn set_debug(&mut self, enabled: bool) -> Result<()> {
        todo!()
    }

    fn set_single_step(&mut self, enable: bool) -> Result<()> {
        todo!()
    }

    fn add_sw_breakpoint(
        &mut self,
        addr: u64,
        dbg_mem_access_fn: std::sync::Arc<std::sync::Mutex<dyn DbgMemAccessHandlerCaller>>,
    ) -> Result<()> {
        todo!()
    }

    fn remove_sw_breakpoint(
        &mut self,
        addr: u64,
        dbg_mem_access_fn: std::sync::Arc<std::sync::Mutex<dyn DbgMemAccessHandlerCaller>>,
    ) -> Result<()> {
        todo!()
    }

    fn add_hw_breakpoint(&mut self, addr: u64) -> Result<()> {
        todo!()
    }

    fn remove_hw_breakpoint(&mut self, addr: u64) -> Result<()> {
        todo!()
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

    // #[test]
    // fn create_driver() {
    //     if !super::is_hypervisor_present() {
    //         return;
    //     }
    //     const MEM_SIZE: usize = 0x3000;
    //     let gm = shared_mem_with_code(CODE.as_slice(), MEM_SIZE, 0).unwrap();
    //     let rsp_ptr = GuestPtr::try_from(0).unwrap();
    //     let pml4_ptr = GuestPtr::try_from(0).unwrap();
    //     let entrypoint_ptr = GuestPtr::try_from(0).unwrap();
    //     let mut regions = MemoryRegionVecBuilder::new(0, gm.base_addr());
    //     regions.push_page_aligned(
    //         MEM_SIZE,
    //         MemoryRegionFlags::READ | MemoryRegionFlags::WRITE | MemoryRegionFlags::EXECUTE,
    //         crate::mem::memory_region::MemoryRegionType::Code,
    //     );
    //     super::MshvVm::new(
    //         regions.build(),
    //         entrypoint_ptr,
    //         rsp_ptr,
    //         pml4_ptr,
    //         #[cfg(gdb)]
    //         None,
    //     )
    //     .unwrap();
    // }
}
