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
use mshv_bindings::{
    hv_intercept_parameters, hv_intercept_type_HV_INTERCEPT_TYPE_EXCEPTION,
    hv_message_type_HVMSG_X64_EXCEPTION_INTERCEPT, mshv_install_intercept,
    HV_INTERCEPT_ACCESS_MASK_EXECUTE,
};
use mshv_bindings::{
    hv_message_type, hv_message_type_HVMSG_GPA_INTERCEPT, hv_message_type_HVMSG_UNMAPPED_GPA,
    hv_message_type_HVMSG_X64_HALT, hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT,
};
#[cfg(mshv3)]
use mshv_bindings::{
    hv_partition_property_code_HV_PARTITION_PROPERTY_SYNTHETIC_PROC_FEATURES,
    hv_partition_synthetic_processor_features,
};
use mshv_bindings2::{hv_register_assoc, hv_register_name_HV_X64_REGISTER_RIP, hv_register_value};
use mshv_ioctls::{Mshv, VcpuFd, VmFd};
use tracing::{instrument, Span};

#[cfg(gdb)]
use super::gdb::{DebugCommChannel, DebugMsg, DebugResponse, GuestDebug, MshvDebug};
#[cfg(gdb)]
use super::handlers::DbgMemAccessHandlerWrapper;
use super::HyperlightExit;
use crate::fpuregs::CommonFpu;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::regs::CommonRegisters;
use crate::sregs::CommonSpecialRegisters;
use crate::vm::Vm;
#[cfg(gdb)]
use crate::HyperlightError;
use crate::{log_then_return, HyperlightError, Result};

#[cfg(gdb)]
mod debug {
    use std::sync::{Arc, Mutex};

    use super::{HypervLinuxDriver, *};
    use crate::hypervisor::gdb::{DebugMsg, DebugResponse, VcpuStopReason, X86_64Regs};
    use crate::hypervisor::handlers::DbgMemAccessHandlerCaller;
    use crate::{new_error, Result};

    impl MshvVm {
        /// Resets the debug information to disable debugging
        fn disable_debug(&mut self) -> Result<()> {
            let mut debug = MshvDebug::default();

            debug.set_single_step(&self.vcpu_fd, false)?;

            self.debug = Some(debug);

            Ok(())
        }

        /// Get the reason the vCPU has stopped
        pub(crate) fn get_stop_reason(&mut self) -> Result<VcpuStopReason> {
            let debug = self
                .debug
                .as_mut()
                .ok_or_else(|| new_error!("Debug is not enabled"))?;

            debug.get_stop_reason(&self.vcpu_fd, self.entrypoint)
        }

        pub(crate) fn process_dbg_request(
            &mut self,
            req: DebugMsg,
            dbg_mem_access_fn: Arc<Mutex<dyn DbgMemAccessHandlerCaller>>,
        ) -> Result<DebugResponse> {
            if let Some(debug) = self.debug.as_mut() {
                match req {
                    DebugMsg::AddHwBreakpoint(addr) => Ok(DebugResponse::AddHwBreakpoint(
                        debug
                            .add_hw_breakpoint(&self.vcpu_fd, addr)
                            .map_err(|e| {
                                log::error!("Failed to add hw breakpoint: {:?}", e);

                                e
                            })
                            .is_ok(),
                    )),
                    DebugMsg::AddSwBreakpoint(addr) => Ok(DebugResponse::AddSwBreakpoint(
                        debug
                            .add_sw_breakpoint(&self.vcpu_fd, addr, dbg_mem_access_fn)
                            .map_err(|e| {
                                log::error!("Failed to add sw breakpoint: {:?}", e);

                                e
                            })
                            .is_ok(),
                    )),
                    DebugMsg::Continue => {
                        debug.set_single_step(&self.vcpu_fd, false).map_err(|e| {
                            log::error!("Failed to continue execution: {:?}", e);

                            e
                        })?;

                        Ok(DebugResponse::Continue)
                    }
                    DebugMsg::DisableDebug => {
                        self.disable_debug().map_err(|e| {
                            log::error!("Failed to disable debugging: {:?}", e);

                            e
                        })?;

                        Ok(DebugResponse::DisableDebug)
                    }
                    DebugMsg::GetCodeSectionOffset => {
                        let offset = dbg_mem_access_fn
                            .try_lock()
                            .map_err(|e| {
                                new_error!("Error locking at {}:{}: {}", file!(), line!(), e)
                            })?
                            .get_code_offset()
                            .map_err(|e| {
                                log::error!("Failed to get code offset: {:?}", e);

                                e
                            })?;

                        Ok(DebugResponse::GetCodeSectionOffset(offset as u64))
                    }
                    DebugMsg::ReadAddr(addr, len) => {
                        let mut data = vec![0u8; len];

                        debug
                            .read_addrs(&self.vcpu_fd, addr, &mut data, dbg_mem_access_fn)
                            .map_err(|e| {
                                log::error!("Failed to read from address: {:?}", e);

                                e
                            })?;

                        Ok(DebugResponse::ReadAddr(data))
                    }
                    DebugMsg::ReadRegisters => {
                        let mut regs = X86_64Regs::default();

                        debug
                            .read_regs(&self.vcpu_fd, &mut regs)
                            .map_err(|e| {
                                log::error!("Failed to read registers: {:?}", e);

                                e
                            })
                            .map(|_| DebugResponse::ReadRegisters(regs))
                    }
                    DebugMsg::RemoveHwBreakpoint(addr) => Ok(DebugResponse::RemoveHwBreakpoint(
                        debug
                            .remove_hw_breakpoint(&self.vcpu_fd, addr)
                            .map_err(|e| {
                                log::error!("Failed to remove hw breakpoint: {:?}", e);

                                e
                            })
                            .is_ok(),
                    )),
                    DebugMsg::RemoveSwBreakpoint(addr) => Ok(DebugResponse::RemoveSwBreakpoint(
                        debug
                            .remove_sw_breakpoint(&self.vcpu_fd, addr, dbg_mem_access_fn)
                            .map_err(|e| {
                                log::error!("Failed to remove sw breakpoint: {:?}", e);

                                e
                            })
                            .is_ok(),
                    )),
                    DebugMsg::Step => {
                        debug.set_single_step(&self.vcpu_fd, true).map_err(|e| {
                            log::error!("Failed to enable step instruction: {:?}", e);

                            e
                        })?;

                        Ok(DebugResponse::Step)
                    }
                    DebugMsg::WriteAddr(addr, data) => {
                        debug
                            .write_addrs(&self.vcpu_fd, addr, &data, dbg_mem_access_fn)
                            .map_err(|e| {
                                log::error!("Failed to write to address: {:?}", e);

                                e
                            })?;

                        Ok(DebugResponse::WriteAddr)
                    }
                    DebugMsg::WriteRegisters(regs) => debug
                        .write_regs(&self.vcpu_fd, &regs)
                        .map_err(|e| {
                            log::error!("Failed to write registers: {:?}", e);

                            e
                        })
                        .map(|_| DebugResponse::WriteRegisters),
                }
            } else {
                Err(new_error!("Debugging is not enabled"))
            }
        }

        pub(crate) fn recv_dbg_msg(&mut self) -> Result<DebugMsg> {
            let gdb_conn = self
                .gdb_conn
                .as_mut()
                .ok_or_else(|| new_error!("Debug is not enabled"))?;

            gdb_conn.recv().map_err(|e| {
                new_error!(
                    "Got an error while waiting to receive a
                    message: {:?}",
                    e
                )
            })
        }

        pub(crate) fn send_dbg_msg(&mut self, cmd: DebugResponse) -> Result<()> {
            log::debug!("Sending {:?}", cmd);

            let gdb_conn = self
                .gdb_conn
                .as_mut()
                .ok_or_else(|| new_error!("Debug is not enabled"))?;

            gdb_conn
                .send(cmd)
                .map_err(|e| new_error!("Got an error while sending a response message {:?}", e))
        }
    }
}

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

    // #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    // fn setup_initial_sregs(vcpu: &mut VcpuFd, pml4_addr: u64) -> Result<()> {
    //     let sregs = SpecialRegisters {
    //         cr0: CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_AM | CR0_PG | CR0_WP,
    //         cr4: CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT,
    //         cr3: pml4_addr,
    //         efer: EFER_LME | EFER_LMA | EFER_SCE | EFER_NX,
    //         cs: SegmentRegister {
    //             type_: 11,
    //             present: 1,
    //             s: 1,
    //             l: 1,
    //             ..Default::default()
    //         },
    //         tr: SegmentRegister {
    //             limit: 65535,
    //             type_: 11,
    //             present: 1,
    //             ..Default::default()
    //         },
    //         ..Default::default()
    //     };
    //     vcpu.set_sregs(&sregs)?;
    //     Ok(())
    // }
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
                EXCEPTION_INTERCEPT => match self.get_stop_reason() {
                    Ok(reason) => HyperlightExit::Debug(reason),
                    Err(e) => {
                        log_then_return!("Error getting stop reason: {:?}", e);
                    }
                },
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
