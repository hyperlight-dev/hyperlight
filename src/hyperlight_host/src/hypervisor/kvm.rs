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

use kvm_bindings::{kvm_userspace_memory_region, KVM_MEM_READONLY};
use kvm_ioctls::Cap::UserMemory;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use tracing::{instrument, Span};

use super::HyperlightExit;
use crate::fpuregs::CommonFpu;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::regs::CommonRegisters;
use crate::sregs::CommonSpecialRegisters;
use crate::vm::Vm;
use crate::{log_then_return, Result};

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

#[cfg(gdb)]
mod debug {
    use std::sync::{Arc, Mutex};

    use kvm_bindings::kvm_debug_exit_arch;

    use super::KVMDriver;
    use crate::hypervisor::gdb::{
        DebugMsg, DebugResponse, GuestDebug, KvmDebug, VcpuStopReason, X86_64Regs,
    };
    use crate::hypervisor::handlers::DbgMemAccessHandlerCaller;
    use crate::{new_error, Result};

    impl KvmVm {
        /// Resets the debug information to disable debugging
        fn disable_debug(&mut self) -> Result<()> {
            let mut debug = KvmDebug::default();

            debug.set_single_step(&self.vcpu_fd, false)?;

            self.debug = Some(debug);

            Ok(())
        }

        /// Get the reason the vCPU has stopped
        pub(crate) fn get_stop_reason(
            &mut self,
            debug_exit: kvm_debug_exit_arch,
        ) -> Result<VcpuStopReason> {
            let debug = self
                .debug
                .as_mut()
                .ok_or_else(|| new_error!("Debug is not enabled"))?;

            debug.get_stop_reason(&self.vcpu_fd, debug_exit, self.entrypoint)
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
                    "Got an error while waiting to receive a message from the gdb thread: {:?}",
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

            gdb_conn.send(cmd).map_err(|e| {
                new_error!(
                    "Got an error while sending a response message to the gdb thread: {:?}",
                    e
                )
            })
        }
    }
}

/// A KVM implementation of a single-vcpu VM
#[derive(Debug)]
pub(super) struct KvmVm {
    kvm_fd: Kvm,
    vm_fd: VmFd,
    vcpu_fd: VcpuFd,
}

impl KvmVm {
    /// Create a new instance of a `KvmVm`
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(super) fn new() -> Result<Self> {
        let kvm_fd = Kvm::new()?;
        let vm_fd = kvm_fd.create_vm_with_type(0)?;
        let vcpu_fd = vm_fd.create_vcpu(0)?;

        Ok(Self {
            kvm_fd,
            vm_fd,
            vcpu_fd,
        })
    }
}

impl Vm for KvmVm {
    fn get_regs(&self) -> Result<CommonRegisters> {
        let kvm_regs = self.vcpu_fd.get_regs()?;
        Ok(kvm_regs.into())
    }

    fn set_regs(&self, regs: &CommonRegisters) -> Result<()> {
        let kvm_regs = regs.clone().into();
        Ok(self.vcpu_fd.set_regs(&kvm_regs)?)
    }

    fn get_sregs(&self) -> Result<CommonSpecialRegisters> {
        Ok(self.vcpu_fd.get_sregs()?.into())
    }

    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> Result<()> {
        Ok(self.vcpu_fd.set_sregs(&sregs.clone().into())?)
    }

    fn get_fpu(&self) -> Result<CommonFpu> {
        Ok(self.vcpu_fd.get_fpu()?.into())
    }

    fn set_fpu(&self, fpu: &CommonFpu) -> Result<()> {
        Ok(self.vcpu_fd.set_fpu(&fpu.clone().into())?)
    }

    unsafe fn map_memory(&self, regions: &[MemoryRegion]) -> Result<()> {
        regions.iter().enumerate().try_for_each(|(i, region)| {
            let kvm_region = kvm_userspace_memory_region {
                slot: i as u32,
                guest_phys_addr: region.guest_region.start as u64,
                memory_size: (region.guest_region.end - region.guest_region.start) as u64,
                userspace_addr: region.host_region.start as u64,
                flags: match region.flags {
                    MemoryRegionFlags::READ => KVM_MEM_READONLY,
                    _ => 0, // normal, RWX
                },
            };
            unsafe { self.vm_fd.set_user_memory_region(kvm_region) }
        })?;
        Ok(())
    }

    fn run_vcpu(&mut self) -> Result<HyperlightExit> {
        match self.vcpu_fd.run() {
            Ok(VcpuExit::Hlt) => Ok(HyperlightExit::Halt()),
            Ok(VcpuExit::IoOut(port, data)) => Ok(HyperlightExit::IoOut(port, data.to_vec())),
            Ok(VcpuExit::MmioRead(addr, _)) => Ok(HyperlightExit::MmioRead(addr)),
            Ok(VcpuExit::MmioWrite(addr, _)) => Ok(HyperlightExit::MmioWrite(addr)),
            #[cfg(gdb)]
            // KVM provides architecture specific information about the vCPU state when exiting
            Ok(VcpuExit::Debug(debug_exit)) => match self.get_stop_reason(debug_exit) {
                Ok(reason) => VcpuExit::Debug(reason),
                Err(e) => {
                    log_then_return!("Error getting stop reason: {:?}", e);
                }
            },
            Err(e) => match e.errno() {
                // In case of the gdb feature, the timeout is not enabled, this
                // exit is because of a signal sent from the gdb thread to the
                // hypervisor thread to cancel execution
                #[cfg(gdb)]
                libc::EINTR => VcpuExit::Debug(VcpuStopReason::Interrupt),
                // we send a signal to the thread to cancel execution this results in EINTR being returned by KVM so we return Cancelled
                #[cfg(not(gdb))]
                libc::EINTR => Ok(HyperlightExit::Cancelled()),
                libc::EAGAIN => Ok(HyperlightExit::Retry()),
                _ => {
                    crate::debug!("KVM Error -Details: Address: {} \n {:#?}", e, &self);
                    log_then_return!("Error running VCPU {:?}", e);
                }
            },
            Ok(other) => {
                let err_msg = format!("Unexpected KVM Exit {:?}", other);
                crate::debug!("KVM Other Exit Details: {:#?}", &self);
                Ok(HyperlightExit::Unknown(err_msg))
            }
        }
    }

    fn interrupt_handle(&self) -> crate::vm::InterruptHandle {
        todo!()
    }
}
