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

use std::convert::TryFrom;
use std::fmt::Debug;
#[cfg(crashdump)]
use std::path::Path;
#[cfg(gdb)]
use std::sync::{Arc, Mutex};

use kvm_bindings::{kvm_fpu, kvm_regs, kvm_userspace_memory_region, KVM_MEM_READONLY};
use kvm_ioctls::Cap::UserMemory;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use log::LevelFilter;
use tracing::{instrument, Span};

#[cfg(crashdump)]
use super::crashdump;
use super::fpu::{FP_CONTROL_WORD_DEFAULT, FP_TAG_WORD_DEFAULT, MXCSR_DEFAULT};
#[cfg(gdb)]
use super::gdb::{DebugCommChannel, DebugMsg, DebugResponse, GuestDebug, KvmDebug, VcpuStopReason};
#[cfg(gdb)]
use super::handlers::DbgMemAccessHandlerWrapper;
use super::handlers::{MemAccessHandlerWrapper, OutBHandlerWrapper};
use super::{
    HyperlightExit, Hypervisor, VirtualCPU, CR0_AM, CR0_ET, CR0_MP, CR0_NE, CR0_PE, CR0_PG, CR0_WP,
    CR4_OSFXSR, CR4_OSXMMEXCPT, CR4_PAE, EFER_LMA, EFER_LME, EFER_NX, EFER_SCE,
};
use crate::hypervisor::hypervisor_handler::HypervisorHandler;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::mem::ptr::{GuestPtr, RawPtr};
use crate::sandbox::uninitialized::SandboxMetadata;
#[cfg(gdb)]
use crate::HyperlightError;
use crate::{log_then_return, new_error, Result};

/// Return `true` if the KVM API is available, version 12, and has UserMemory capability, or `false` otherwise
#[instrument(skip_all, parent = Span::current(), level = "Trace")]
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
        log::info!("Error creating KVM object");
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

    impl KVMDriver {
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
pub(super) struct KVMDriver {
    _kvm: Kvm,
    _vm_fd: VmFd,
    vcpu_fd: VcpuFd,
    entrypoint: u64,
    orig_rsp: GuestPtr,
    mem_regions: Vec<MemoryRegion>,

    #[cfg(gdb)]
    debug: Option<KvmDebug>,
    #[cfg(gdb)]
    gdb_conn: Option<DebugCommChannel<DebugResponse, DebugMsg>>,
    #[allow(dead_code)]
    metadata: SandboxMetadata,
}

impl KVMDriver {
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
        metadata: SandboxMetadata,
    ) -> Result<Self> {
        let kvm = Kvm::new()?;

        let vm_fd = kvm.create_vm_with_type(0)?;

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
            unsafe { vm_fd.set_user_memory_region(kvm_region) }
        })?;

        let mut vcpu_fd = vm_fd.create_vcpu(0)?;
        Self::setup_initial_sregs(&mut vcpu_fd, pml4_addr)?;

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
            _kvm: kvm,
            _vm_fd: vm_fd,
            vcpu_fd,
            entrypoint,
            orig_rsp: rsp_gp,
            mem_regions,

            #[cfg(gdb)]
            debug,
            #[cfg(gdb)]
            gdb_conn,
            metadata,
        };

        Ok(ret)
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn setup_initial_sregs(vcpu_fd: &mut VcpuFd, pml4_addr: u64) -> Result<()> {
        // setup paging and IA-32e (64-bit) mode
        let mut sregs = vcpu_fd.get_sregs()?;
        sregs.cr3 = pml4_addr;
        sregs.cr4 = CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT;
        sregs.cr0 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_AM | CR0_PG | CR0_WP;
        sregs.efer = EFER_LME | EFER_LMA | EFER_SCE | EFER_NX;
        sregs.cs.l = 1; // required for 64-bit mode
        vcpu_fd.set_sregs(&sregs)?;
        Ok(())
    }
}

impl Debug for KVMDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_struct("KVM Driver");
        // Output each memory region

        for region in &self.mem_regions {
            f.field("Memory Region", &region);
        }
        let regs = self.vcpu_fd.get_regs();
        // check that regs is OK and then set field in debug struct

        if let Ok(regs) = regs {
            f.field("Registers", &regs);
        }

        let sregs = self.vcpu_fd.get_sregs();

        // check that sregs is OK and then set field in debug struct

        if let Ok(sregs) = sregs {
            f.field("Special Registers", &sregs);
        }

        f.finish()
    }
}

impl Hypervisor for KVMDriver {
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

        let regs = kvm_regs {
            rip: self.entrypoint,
            rsp: self.orig_rsp.absolute()?,

            // function args
            rcx: peb_addr.into(),
            rdx: seed,
            r8: page_size.into(),
            r9: max_guest_log_level,

            ..Default::default()
        };
        self.vcpu_fd.set_regs(&regs)?;

        VirtualCPU::run(
            self.as_mut_hypervisor(),
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
        let regs = kvm_regs {
            rip: dispatch_func_addr.into(),
            rsp: self.orig_rsp.absolute()?,
            ..Default::default()
        };
        self.vcpu_fd.set_regs(&regs)?;

        // reset fpu state
        let fpu = kvm_fpu {
            fcw: FP_CONTROL_WORD_DEFAULT,
            ftwx: FP_TAG_WORD_DEFAULT,
            mxcsr: MXCSR_DEFAULT,
            ..Default::default() // zero out the rest
        };
        self.vcpu_fd.set_fpu(&fpu)?;

        // run
        VirtualCPU::run(
            self.as_mut_hypervisor(),
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

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn run(&mut self) -> Result<HyperlightExit> {
        let exit_reason = self.vcpu_fd.run();
        let result = match exit_reason {
            Ok(VcpuExit::Hlt) => {
                crate::debug!("KVM - Halt Details : {:#?}", &self);
                HyperlightExit::Halt()
            }
            Ok(VcpuExit::IoOut(port, data)) => {
                // because vcpufd.run() mutably borrows self we cannot pass self to crate::debug! macro here
                crate::debug!("KVM IO Details : \nPort : {}\nData : {:?}", port, data);
                // KVM does not need to set RIP or instruction length so these are set to 0
                HyperlightExit::IoOut(port, data.to_vec(), 0, 0)
            }
            Ok(VcpuExit::MmioRead(addr, _)) => {
                crate::debug!("KVM MMIO Read -Details: Address: {} \n {:#?}", addr, &self);

                match self.get_memory_access_violation(
                    addr as usize,
                    &self.mem_regions,
                    MemoryRegionFlags::READ,
                ) {
                    Some(access_violation_exit) => access_violation_exit,
                    None => HyperlightExit::Mmio(addr),
                }
            }
            Ok(VcpuExit::MmioWrite(addr, _)) => {
                crate::debug!("KVM MMIO Write -Details: Address: {} \n {:#?}", addr, &self);

                match self.get_memory_access_violation(
                    addr as usize,
                    &self.mem_regions,
                    MemoryRegionFlags::WRITE,
                ) {
                    Some(access_violation_exit) => access_violation_exit,
                    None => HyperlightExit::Mmio(addr),
                }
            }
            #[cfg(gdb)]
            // KVM provides architecture specific information about the vCPU state when exiting
            Ok(VcpuExit::Debug(debug_exit)) => match self.get_stop_reason(debug_exit) {
                Ok(reason) => HyperlightExit::Debug(reason),
                Err(e) => {
                    log_then_return!("Error getting stop reason: {:?}", e);
                }
            },
            Err(e) => match e.errno() {
                // In case of the gdb feature, the timeout is not enabled, this
                // exit is because of a signal sent from the gdb thread to the
                // hypervisor thread to cancel execution
                #[cfg(gdb)]
                libc::EINTR => HyperlightExit::Debug(VcpuStopReason::Interrupt),
                // we send a signal to the thread to cancel execution this results in EINTR being returned by KVM so we return Cancelled
                #[cfg(not(gdb))]
                libc::EINTR => HyperlightExit::Cancelled(),
                libc::EAGAIN => HyperlightExit::Retry(),
                _ => {
                    crate::debug!("KVM Error -Details: Address: {} \n {:#?}", e, &self);
                    log_then_return!("Error running VCPU {:?}", e);
                }
            },
            Ok(other) => {
                crate::debug!("KVM Other Exit {:?}", other);
                HyperlightExit::Unknown(format!("Unexpected KVM Exit {:?}", other))
            }
        };
        Ok(result)
    }

    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    fn as_mut_hypervisor(&mut self) -> &mut dyn Hypervisor {
        self as &mut dyn Hypervisor
    }

    #[cfg(crashdump)]
    fn get_crashdump_context(&self) -> Result<crashdump::CrashDumpContext> {
        let mut regs = [0; 27];

        let vcpu_regs = self.vcpu_fd.get_regs()?;
        let sregs = self.vcpu_fd.get_sregs()?;
        let xsave = self.vcpu_fd.get_xsave()?;

        regs[0] = vcpu_regs.r15; // r15
        regs[1] = vcpu_regs.r14; // r14
        regs[2] = vcpu_regs.r13; // r13
        regs[3] = vcpu_regs.r12; // r12
        regs[4] = vcpu_regs.rbp; // rbp
        regs[5] = vcpu_regs.rbx; // rbx
        regs[6] = vcpu_regs.r11; // r11
        regs[7] = vcpu_regs.r10; // r10
        regs[8] = vcpu_regs.r9; // r9
        regs[9] = vcpu_regs.r8; // r8
        regs[10] = vcpu_regs.rax; // rax
        regs[11] = vcpu_regs.rcx; // rcx
        regs[12] = vcpu_regs.rdx; // rdx
        regs[13] = vcpu_regs.rsi; // rsi
        regs[14] = vcpu_regs.rdi; // rdi
        regs[15] = 0; // orig rax
        regs[16] = vcpu_regs.rip; // rip
        regs[17] = sregs.cs.selector as u64; // cs
        regs[18] = vcpu_regs.rflags; // eflags
        regs[19] = vcpu_regs.rsp; // rsp
        regs[20] = sregs.ss.selector as u64; // ss
        regs[21] = sregs.fs.base; // fs_base
        regs[22] = sregs.gs.base; // gs_base
        regs[23] = sregs.ds.selector as u64; // ds
        regs[24] = sregs.es.selector as u64; // es
        regs[25] = sregs.fs.selector as u64; // fs
        regs[26] = sregs.gs.selector as u64; // gs

        let filename = self.metadata.binary_path.clone().map(|path| {
            Path::new(&path)
                .file_name()
                .map(|name| name.to_os_string().into_string().unwrap())
                .unwrap()
        });

        Ok(crashdump::CrashDumpContext::new(
            &self.mem_regions,
            regs,
            xsave.region.into_iter().fold(vec![], |mut acc, item| {
                let bytes = item.to_le_bytes();
                acc.append(&mut bytes.to_vec());

                acc
            }),
            self.entrypoint,
            self.metadata.binary_path.clone(),
            filename,
        ))
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
        if !super::is_hypervisor_present() {
            return;
        }

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
