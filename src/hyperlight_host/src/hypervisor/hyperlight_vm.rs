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
use crate::HyperlightError::ExecutionCanceledByHost;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
#[cfg(gdb)]
use std::sync::{Arc, Mutex};

use kvm_bindings::{kvm_fpu, kvm_regs, kvm_userspace_memory_region, KVM_MEM_READONLY};
use kvm_ioctls::Cap::UserMemory;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use log::LevelFilter;
use tracing::{instrument, Span};

use super::fpu::{FP_CONTROL_WORD_DEFAULT, FP_TAG_WORD_DEFAULT, MXCSR_DEFAULT};
#[cfg(gdb)]
use super::gdb::{DebugCommChannel, DebugMsg, DebugResponse, GuestDebug, KvmDebug, VcpuStopReason};
#[cfg(gdb)]
use super::handlers::DbgMemAccessHandlerWrapper;
use super::handlers::{
    MemAccessHandlerCaller, MemAccessHandlerWrapper, OutBHandlerCaller, OutBHandlerWrapper,
};
use super::kvm::KvmVm;
use super::{
    HyperlightExit, HyperlightVm, CR0_AM, CR0_ET, CR0_MP, CR0_NE, CR0_PE, CR0_PG, CR0_WP,
    CR4_OSFXSR, CR4_OSXMMEXCPT, CR4_PAE, EFER_LMA, EFER_LME, EFER_NX, EFER_SCE,
};
use crate::hypervisor::hypervisor_handler::HypervisorHandler;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::mem::ptr::{GuestPtr, RawPtr};
use crate::metrics::METRIC_GUEST_CANCELLATION;
use crate::regs::Registers;
use crate::vm::Vm;
#[cfg(gdb)]
use crate::HyperlightError;
use crate::{log_then_return, new_error, HyperlightError, Result};

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

    impl HyperlightSandbox {
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

/// A Hypervisor driver for KVM on Linux
#[derive(Debug)]
pub(super) struct HyperlightSandbox {
    vm: Box<dyn Vm>,
    entrypoint: u64,
    orig_rsp: GuestPtr,
    mem_regions: Vec<MemoryRegion>,

    #[cfg(gdb)]
    debug: Option<KvmDebug>,
    #[cfg(gdb)]
    gdb_conn: Option<DebugCommChannel<DebugResponse, DebugMsg>>,
}

impl HyperlightSandbox {
    /// Create a new instance of a `KVMDriver`, with only control registers
    /// set. Standard registers will not be set, and `initialise` must
    /// be called to do so.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(super) fn new(
        mem_regions: Vec<MemoryRegion>,
        pml4_addr: u64,
        entrypoint: u64,
        rsp: u64,
        #[cfg(gdb)] gdb_conn: Option<DebugCommChannel<DebugResponse, DebugMsg>>,
    ) -> Result<Self> {
        let kvm_vm = KvmVm::new()?;

        let perm_flags =
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE | MemoryRegionFlags::EXECUTE;

        mem_regions.iter().enumerate().try_for_each(|(i, region)| {
            let perm_flags = perm_flags.intersection(region.flags);
            let kvm_region = kvm_userspace_memory_region {
                slot: i as u32,
                guest_phys_addr: region.guest_region.start as u64,
                memory_size: (region.guest_region.end - region.guest_region.start) as u64,
                userspace_addr: region.host_region.start as u64,
                flags: match perm_flags {
                    MemoryRegionFlags::READ => KVM_MEM_READONLY,
                    _ => 0, // normal, RWX
                },
            };
            unsafe { kvm_vm.map_memory_kvm(kvm_region) }
        })?;

        let mut sregs = kvm_vm.sregs_kvm()?;
        sregs.cr3 = pml4_addr;
        sregs.cr4 = CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT;
        sregs.cr0 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_AM | CR0_PG | CR0_WP;
        sregs.efer = EFER_LME | EFER_LMA | EFER_SCE | EFER_NX;
        sregs.cs.l = 1; // required for 64-bit mode
        kvm_vm.set_sregs_kvm(&sregs)?;

        #[cfg(gdb)]
        let (debug, gdb_conn) = if let Some(gdb_conn) = gdb_conn {
            let mut debug = KvmDebug::new();
            // Add breakpoint to the entry point address
            debug.add_hw_breakpoint(&vcpu_fd, entrypoint)?;

            (Some(debug), Some(gdb_conn))
        } else {
            (None, None)
        };

        let rsp_gp = GuestPtr::try_from(RawPtr::from(rsp))?;

        let ret = Self {
            vm: Box::new(kvm_vm),
            entrypoint,
            orig_rsp: rsp_gp,
            mem_regions: mem_regions,

            #[cfg(gdb)]
            debug,
            #[cfg(gdb)]
            gdb_conn,
        };

        Ok(ret)
    }
}

impl HyperlightVm for HyperlightSandbox {
    /// Implementation of initialise for Hypervisor trait.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn initialise(
        &mut self,
        peb_addr: RawPtr,
        seed: u64,
        page_size: u32,
        outb_hdl: OutBHandlerWrapper,
        mem_access_hdl: MemAccessHandlerWrapper,
        hv_handler: Option<HypervisorHandler>,
        max_guest_log_level: Option<LevelFilter>,
        #[cfg(gdb)] dbg_mem_access_fn: DbgMemAccessHandlerWrapper,
    ) -> Result<()> {
        let max_guest_log_level: u64 = match max_guest_log_level {
            Some(level) => level as u64,
            None => self.get_max_log_level().into(),
        };

        let regs = Registers {
            rip: self.entrypoint,
            rsp: self.orig_rsp.absolute()?,

            // function args
            rcx: peb_addr.into(),
            rdx: seed,
            r8: page_size.into(),
            r9: max_guest_log_level,

            ..Default::default()
        };
        self.vm.set_regs(&regs)?;

        self.run(
            hv_handler,
            outb_hdl,
            mem_access_hdl,
            #[cfg(gdb)]
            dbg_mem_access_fn,
        )?;

        Ok(())
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn dispatch_call_from_host(
        &mut self,
        dispatch_func_addr: RawPtr,
        outb_handle_fn: OutBHandlerWrapper,
        mem_access_fn: MemAccessHandlerWrapper,
        hv_handler: Option<HypervisorHandler>,
        #[cfg(gdb)] dbg_mem_access_fn: DbgMemAccessHandlerWrapper,
    ) -> Result<()> {
        // Reset general purpose registers, then set RIP and RSP
        let regs = Registers {
            rip: dispatch_func_addr.into(),
            rsp: self.orig_rsp.absolute()?,
            ..Default::default()
        };
        self.vm.set_regs(&regs)?;

        // reset fpu state
        let fpu = kvm_fpu {
            fcw: FP_CONTROL_WORD_DEFAULT,
            ftwx: FP_TAG_WORD_DEFAULT,
            mxcsr: MXCSR_DEFAULT,
            ..Default::default() // zero out the rest
        };
        self.vm.set_fpu_regs(&fpu)?;

        // run
        self.run(
            hv_handler,
            outb_handle_fn,
            mem_access_fn,
            #[cfg(gdb)]
            dbg_mem_access_fn,
        )?;

        Ok(())
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn handle_io(
        &mut self,
        port: u16,
        data: Vec<u8>,
        _rip: u64,
        _instruction_length: u64,
        outb_handle_fn: OutBHandlerWrapper,
    ) -> Result<()> {
        // KVM does not need RIP or instruction length, as it automatically sets the RIP

        // The payload param for the outb_handle_fn is the first byte
        // of the data array cast to an u64. Thus, we need to make sure
        // the data array has at least one u8, then convert that to an u64
        if data.is_empty() {
            log_then_return!("no data was given in IO interrupt");
        } else {
            let payload_u64 = u64::from(data[0]);
            outb_handle_fn
                .try_lock()
                .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
                .call(port, payload_u64)?;
        }

        Ok(())
    }

    fn run(
        &mut self,
        hv_handler: Option<HypervisorHandler>,
        outb_handle_fn: Arc<Mutex<dyn OutBHandlerCaller>>,
        mem_access_fn: Arc<Mutex<dyn MemAccessHandlerCaller>>,
    ) -> Result<()> {
        loop {
            match self.vm.run_vcpu() {
                #[cfg(gdb)]
                Ok(HyperlightExit::Debug(stop_reason)) => {
                    if let Err(e) = hv.handle_debug(dbg_mem_access_fn.clone(), stop_reason) {
                        log_then_return!(e);
                    }
                }

                Ok(HyperlightExit::Halt()) => {
                    break;
                }
                Ok(HyperlightExit::IoOut(port, data, rip, instruction_length)) => {
                    self.handle_io(port, data, rip, instruction_length, outb_handle_fn.clone())?
                }
                Ok(HyperlightExit::MmioRead(addr)) => {
                    match get_memory_access_violation(
                        addr as usize,
                        MemoryRegionFlags::READ,
                        &self.mem_regions,
                    ) {
                        Some(MemoryAccess::StackGuardPageViolation) => {
                            #[cfg(crashdump)]
                            crashdump::crashdump_to_tempfile(hv)?;

                            return Err(HyperlightError::StackOverflow());
                        }
                        Some(MemoryAccess::AccessViolation(region_flags)) => {
                            #[cfg(crashdump)]
                            crashdump::crashdump_to_tempfile(hv)?;

                            log_then_return!(HyperlightError::MemoryAccessViolation(
                                addr,
                                MemoryRegionFlags::READ,
                                region_flags
                            ));
                        }
                        None => {
                            #[cfg(crashdump)]
                            crashdump::crashdump_to_tempfile(hv)?;

                            mem_access_fn
                                .clone()
                                .try_lock()
                                .map_err(|e| {
                                    new_error!("Error locking at {}:{}: {}", file!(), line!(), e)
                                })?
                                .call()?;

                            log_then_return!("MMIO access address {:#x}", addr);
                        }
                    }
                }
                Ok(HyperlightExit::MmioWrite(addr)) => {
                    #[cfg(crashdump)]
                    crashdump::crashdump_to_tempfile(hv)?;

                    match get_memory_access_violation(
                        addr as usize,
                        MemoryRegionFlags::WRITE,
                        &self.mem_regions,
                    ) {
                        Some(MemoryAccess::StackGuardPageViolation) => {
                            return Err(HyperlightError::StackOverflow());
                        }
                        Some(MemoryAccess::AccessViolation(region_flags)) => {
                            log_then_return!(HyperlightError::MemoryAccessViolation(
                                addr,
                                MemoryRegionFlags::WRITE,
                                region_flags
                            ));
                        }
                        None => {
                            mem_access_fn
                                .clone()
                                .try_lock()
                                .map_err(|e| {
                                    new_error!("Error locking at {}:{}: {}", file!(), line!(), e)
                                })?
                                .call()?;

                            log_then_return!("MMIO access address {:#x}", addr);
                        }
                    }
                }

                Ok(HyperlightExit::Cancelled()) => {
                    // Shutdown is returned when the host has cancelled execution
                    // After termination, the main thread will re-initialize the VM
                    if let Some(hvh) = hv_handler {
                        // If hvh is None, then we are running from the C API, which doesn't use
                        // the HypervisorHandler
                        hvh.set_running(false);
                        #[cfg(target_os = "linux")]
                        hvh.set_run_cancelled(true);
                    }
                    metrics::counter!(METRIC_GUEST_CANCELLATION).increment(1);
                    log_then_return!(ExecutionCanceledByHost());
                }
                Ok(HyperlightExit::Unknown(reason)) => {
                    #[cfg(crashdump)]
                    crashdump::crashdump_to_tempfile(hv)?;

                    log_then_return!("Unexpected VM Exit {:?}", reason);
                }
                Ok(HyperlightExit::Retry()) => continue,
                Err(e) => {
                    #[cfg(crashdump)]
                    crashdump::crashdump_to_tempfile(hv)?;

                    return Err(e);
                }
            }
        }

        Ok(())
    }

    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    fn as_mut_hypervisor(&mut self) -> &mut dyn HyperlightVm {
        self as &mut dyn HyperlightVm
    }

    #[cfg(crashdump)]
    fn get_memory_regions(&self) -> &[MemoryRegion] {
        &self.mem_regions
    }

    #[cfg(gdb)]
    fn handle_debug(
        &mut self,
        dbg_mem_access_fn: Arc<Mutex<dyn super::handlers::DbgMemAccessHandlerCaller>>,
        stop_reason: VcpuStopReason,
    ) -> Result<()> {
        self.send_dbg_msg(DebugResponse::VcpuStopped(stop_reason))
            .map_err(|e| new_error!("Couldn't signal vCPU stopped event to GDB thread: {:?}", e))?;

        loop {
            log::debug!("Debug wait for event to resume vCPU");
            // Wait for a message from gdb
            let req = self.recv_dbg_msg()?;

            let result = self.process_dbg_request(req, dbg_mem_access_fn.clone());

            let response = match result {
                Ok(response) => response,
                // Treat non fatal errors separately so the guest doesn't fail
                Err(HyperlightError::TranslateGuestAddress(_)) => DebugResponse::ErrorOccurred,
                Err(e) => {
                    return Err(e);
                }
            };

            // If the command was either step or continue, we need to run the vcpu
            let cont = matches!(
                response,
                DebugResponse::Step | DebugResponse::Continue | DebugResponse::DisableDebug
            );

            self.send_dbg_msg(response)
                .map_err(|e| new_error!("Couldn't send response to gdb: {:?}", e))?;

            if cont {
                break;
            }
        }

        Ok(())
    }
}

/// The vCPU tried to access the given addr, b
enum MemoryAccess {
    /// The accessed region has the given flags
    AccessViolation(MemoryRegionFlags),
    /// The accessed region is a stack guard page
    StackGuardPageViolation,
}

/// Determines if a memory access violation occurred at the given address with the given action type.
fn get_memory_access_violation(
    gpa: usize,
    tried: MemoryRegionFlags,
    mem_regions: &[MemoryRegion],
) -> Option<MemoryAccess> {
    // find the region containing the given gpa
    let region = mem_regions
        .iter()
        .find(|region| region.guest_region.contains(&gpa));

    if let Some(region) = region {
        if region.flags.contains(MemoryRegionFlags::STACK_GUARD) {
            return Some(MemoryAccess::StackGuardPageViolation);
        } else if !region.flags.contains(tried) {
            return Some(MemoryAccess::AccessViolation(region.flags));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    #[cfg(gdb)]
    use crate::hypervisor::handlers::DbgMemAccessHandlerCaller;
    use crate::hypervisor::handlers::{MemAccessHandler, OutBHandler};
    use crate::hypervisor::tests::test_initialise;
    use crate::Result;

    #[cfg(gdb)]
    struct DbgMemAccessHandler {}

    #[cfg(gdb)]
    impl DbgMemAccessHandlerCaller for DbgMemAccessHandler {
        fn read(&mut self, _offset: usize, _data: &mut [u8]) -> Result<()> {
            Ok(())
        }

        fn write(&mut self, _offset: usize, _data: &[u8]) -> Result<()> {
            Ok(())
        }

        fn get_code_offset(&mut self) -> Result<usize> {
            Ok(0)
        }
    }

    #[test]
    fn test_init() {
        let outb_handler: Arc<Mutex<OutBHandler>> = {
            let func: Box<dyn FnMut(u16, u64) -> Result<()> + Send> =
                Box::new(|_, _| -> Result<()> { Ok(()) });
            Arc::new(Mutex::new(OutBHandler::from(func)))
        };
        let mem_access_handler = {
            let func: Box<dyn FnMut() -> Result<()> + Send> = Box::new(|| -> Result<()> { Ok(()) });
            Arc::new(Mutex::new(MemAccessHandler::from(func)))
        };
        #[cfg(gdb)]
        let dbg_mem_access_handler = Arc::new(Mutex::new(DbgMemAccessHandler {}));

        test_initialise(
            outb_handler,
            mem_access_handler,
            #[cfg(gdb)]
            dbg_mem_access_handler,
        )
        .unwrap();
    }
}
