use crate::fpuregs::CommonFpu;
use crate::sandbox::hypervisor::HypervisorType;
use crate::sregs::{CommonSegmentRegister, CommonSpecialRegisters};
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

use log::LevelFilter;
use tracing::{instrument, Span};

use super::fpu::{FP_CONTROL_WORD_DEFAULT, FP_TAG_WORD_DEFAULT, MXCSR_DEFAULT};
#[cfg(gdb)]
use super::gdb::{DebugCommChannel, DebugMsg, DebugResponse, VcpuStopReason};
#[cfg(gdb)]
use super::handlers::DbgMemAccessHandlerWrapper;
use super::handlers::{
    MemAccessHandlerCaller, MemAccessHandlerWrapper, OutBHandlerCaller, OutBHandlerWrapper,
};
use super::hyperv_linux::MshvVm;
use super::kvm::KvmVm;
use super::{
    HyperlightExit, HyperlightVm, CR0_AM, CR0_ET, CR0_MP, CR0_NE, CR0_PE, CR0_PG, CR0_WP,
    CR4_OSFXSR, CR4_OSXMMEXCPT, CR4_PAE, EFER_LMA, EFER_LME, EFER_NX, EFER_SCE,
};
use crate::hypervisor::hypervisor_handler::HypervisorHandler;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::mem::ptr::{GuestPtr, RawPtr};
use crate::metrics::METRIC_GUEST_CANCELLATION;
use crate::regs::CommonRegisters;
use crate::vm::Vm;
use crate::HyperlightError;
use crate::{log_then_return, new_error, Result};

// Described in Table 6-1. Exceptions and Interrupts at Page 6-13 Vol. 1
// of Intel 64 and IA-32 Architectures Software Developer's Manual
/// Exception id for #DB
const DB_EX_ID: u32 = 1;
/// Exception id for #BP - triggered by the INT3 instruction
const BP_EX_ID: u32 = 3;

/// Software Breakpoint size in memory
pub(crate) const SW_BP_SIZE: usize = 1;
/// Software Breakpoint opcode - INT3
/// Check page 7-28 Vol. 3A of Intel 64 and IA-32
/// Architectures Software Developer's Manual
pub(crate) const SW_BP_OP: u8 = 0xCC;
/// Software Breakpoint written to memory
pub(crate) const SW_BP: [u8; SW_BP_SIZE] = [SW_BP_OP];
/// Maximum number of supported hardware breakpoints
pub(crate) const MAX_NO_OF_HW_BP: usize = 4;

/// Check page 19-4 Vol. 3B of Intel 64 and IA-32
/// Architectures Software Developer's Manual
/// Bit position of BS flag in DR6 debug register
pub(crate) const DR6_BS_FLAG_POS: usize = 14;
/// Bit mask of BS flag in DR6 debug register
pub(crate) const DR6_BS_FLAG_MASK: u64 = 1 << DR6_BS_FLAG_POS;
/// Bit position of HW breakpoints status in DR6 debug register
pub(crate) const DR6_HW_BP_FLAGS_POS: usize = 0;
/// Bit mask of HW breakpoints status in DR6 debug register
pub(crate) const DR6_HW_BP_FLAGS_MASK: u64 = 0x0F << DR6_HW_BP_FLAGS_POS;

#[cfg(gdb)]
mod debug {
    use std::sync::{Arc, Mutex};

    use hyperlight_common::mem::PAGE_SIZE;

    use super::HyperlightSandbox;
    use crate::hypervisor::gdb::{DebugMsg, DebugResponse};
    use crate::hypervisor::handlers::DbgMemAccessHandlerCaller;
    use crate::mem::layout::SandboxMemoryLayout;
    use crate::{new_error, HyperlightError, Result};

    impl HyperlightSandbox {
        pub(crate) fn process_dbg_request(
            &mut self,
            req: DebugMsg,
            dbg_mem_access_fn: Arc<Mutex<dyn DbgMemAccessHandlerCaller>>,
        ) -> Result<DebugResponse> {
            if let Some(debug) = self.gdb_conn.as_mut() {
                match req {
                    DebugMsg::AddHwBreakpoint(addr) => Ok(DebugResponse::AddHwBreakpoint(
                        self.vm
                            .add_hw_breakpoint(addr)
                            .map_err(|e| {
                                log::error!("Failed to add hw breakpoint: {:?}", e);

                                e
                            })
                            .is_ok(),
                    )),
                    DebugMsg::AddSwBreakpoint(addr) => Ok(DebugResponse::AddSwBreakpoint(
                        self.vm
                            .add_sw_breakpoint(addr, dbg_mem_access_fn)
                            .map_err(|e| {
                                log::error!("Failed to add sw breakpoint: {:?}", e);

                                e
                            })
                            .is_ok(),
                    )),
                    DebugMsg::Continue => {
                        self.vm.set_single_step(false).map_err(|e| {
                            log::error!("Failed to continue execution: {:?}", e);

                            e
                        })?;

                        Ok(DebugResponse::Continue)
                    }
                    DebugMsg::DisableDebug => {
                        self.vm.set_debug(false).map_err(|e| {
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

                        self.read_addrs(addr, &mut data, dbg_mem_access_fn)
                            .map_err(|e| {
                                log::error!("Failed to read from address: {:?}", e);

                                e
                            })?;

                        Ok(DebugResponse::ReadAddr(data))
                    }
                    DebugMsg::ReadRegisters => self
                        .vm
                        .get_regs()
                        .map_err(|e| {
                            log::error!("Failed to read registers: {:?}", e);

                            e
                        })
                        .map(|regs| DebugResponse::ReadRegisters(regs)),
                    DebugMsg::RemoveHwBreakpoint(addr) => Ok(DebugResponse::RemoveHwBreakpoint(
                        self.vm
                            .remove_hw_breakpoint(addr)
                            .map_err(|e| {
                                log::error!("Failed to remove hw breakpoint: {:?}", e);

                                e
                            })
                            .is_ok(),
                    )),
                    DebugMsg::RemoveSwBreakpoint(addr) => Ok(DebugResponse::RemoveSwBreakpoint(
                        self.vm
                            .remove_sw_breakpoint(addr, dbg_mem_access_fn)
                            .map_err(|e| {
                                log::error!("Failed to remove sw breakpoint: {:?}", e);

                                e
                            })
                            .is_ok(),
                    )),
                    DebugMsg::Step => {
                        self.vm.set_single_step(true).map_err(|e| {
                            log::error!("Failed to enable step instruction: {:?}", e);

                            e
                        })?;

                        Ok(DebugResponse::Step)
                    }
                    DebugMsg::WriteAddr(addr, data) => {
                        self.write_addrs(addr, &data, dbg_mem_access_fn)
                            .map_err(|e| {
                                log::error!("Failed to write to address: {:?}", e);

                                e
                            })?;

                        Ok(DebugResponse::WriteAddr)
                    }
                    DebugMsg::WriteRegisters(regs) => self
                        .vm
                        .set_regs(&regs)
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

        fn read_addrs(
            &mut self,
            mut gva: u64,
            mut data: &mut [u8],
            dbg_mem_access_fn: Arc<Mutex<dyn DbgMemAccessHandlerCaller>>,
        ) -> crate::Result<()> {
            let data_len = data.len();
            log::debug!("Read addr: {:X} len: {:X}", gva, data_len);

            while !data.is_empty() {
                let gpa = self.vm.translate_gva(gva)?;

                let read_len = std::cmp::min(
                    data.len(),
                    (PAGE_SIZE - (gpa & (PAGE_SIZE - 1))).try_into().unwrap(),
                );
                let offset = (gpa as usize)
                    .checked_sub(SandboxMemoryLayout::BASE_ADDRESS)
                    .ok_or_else(|| {
                        log::warn!(
                            "gva=0x{:#X} causes subtract with underflow: \"gpa - BASE_ADDRESS={:#X}-{:#X}\"",
                            gva, gpa, SandboxMemoryLayout::BASE_ADDRESS);
                        HyperlightError::TranslateGuestAddress(gva)
                    })?;

                dbg_mem_access_fn
                    .try_lock()
                    .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
                    .read(offset, &mut data[..read_len])?;

                data = &mut data[read_len..];
                gva += read_len as u64;
            }

            Ok(())
        }

        /// Copies the data from the provided slice to the guest memory address
        /// The address is checked to be a valid guest address
        fn write_addrs(
            &mut self,
            mut gva: u64,
            mut data: &[u8],
            dbg_mem_access_fn: Arc<Mutex<dyn DbgMemAccessHandlerCaller>>,
        ) -> crate::Result<()> {
            let data_len = data.len();
            log::debug!("Write addr: {:X} len: {:X}", gva, data_len);

            while !data.is_empty() {
                let gpa = self.vm.translate_gva(gva)?;

                let write_len = std::cmp::min(
                    data.len(),
                    (PAGE_SIZE - (gpa & (PAGE_SIZE - 1))).try_into().unwrap(),
                );
                let offset = (gpa as usize)
                .checked_sub(SandboxMemoryLayout::BASE_ADDRESS)
                .ok_or_else(|| {
                    log::warn!(
                        "gva=0x{:#X} causes subtract with underflow: \"gpa - BASE_ADDRESS={:#X}-{:#X}\"",
                        gva, gpa, SandboxMemoryLayout::BASE_ADDRESS);
                    HyperlightError::TranslateGuestAddress(gva)
                })?;

                dbg_mem_access_fn
                    .try_lock()
                    .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
                    .write(offset, data)?;

                data = &data[write_len..];
                gva += write_len as u64;
            }

            Ok(())
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
    gdb_conn: Option<DebugCommChannel<DebugResponse, DebugMsg>>,
}

impl HyperlightSandbox {
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(super) fn new(
        hv: &HypervisorType,
        mem_regions: Vec<MemoryRegion>,
        pml4_addr: u64,
        entrypoint: u64,
        rsp: u64,
        #[cfg(gdb)] gdb_conn: Option<DebugCommChannel<DebugResponse, DebugMsg>>,
    ) -> Result<Self> {
        let mut vm: Box<dyn Vm> = match hv {
            HypervisorType::Kvm => Box::new(KvmVm::new()?),
            HypervisorType::Mshv => Box::new(MshvVm::new()?),
            _ => {
                return Err(new_error!("Unsupported hypervisor type"));
            }
        };

        // Safety: We haven't called this before and the regions are valid
        unsafe {
            vm.map_memory(&mem_regions)?;
        }

        let mut sregs = vm.get_sregs()?;
        sregs.cr3 = pml4_addr;
        sregs.cr4 = CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT;
        sregs.cr0 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_AM | CR0_PG | CR0_WP;
        sregs.efer = EFER_LME | EFER_LMA | EFER_SCE | EFER_NX;
        sregs.cs.l = 1; // required for 64-bit mode
        vm.set_sregs(&sregs)?;

        #[cfg(gdb)]
        let gdb_conn = if let Some(gdb_conn) = gdb_conn {
            // Add breakpoint to the entry point address
            vm.set_debug(true)?;
            vm.add_hw_breakpoint(entrypoint)?;

            Some(gdb_conn)
        } else {
            None
        };

        let rsp_gp = GuestPtr::try_from(RawPtr::from(rsp))?;

        let ret = Self {
            vm,
            entrypoint,
            orig_rsp: rsp_gp,
            mem_regions: mem_regions,

            #[cfg(gdb)]
            gdb_conn,
        };

        Ok(ret)
    }

    /// Determine the reason the vCPU stopped
    /// This is done by checking the DR6 register and the exception id
    /// NOTE: Additional checks are done for the entrypoint, stored hw_breakpoints
    /// and sw_breakpoints to ensure the stop reason is valid with internal state
    pub(crate) fn vcpu_stop_reason(&mut self, dr6: u64, exception: u32) -> Result<VcpuStopReason> {
        let CommonRegisters { rip, .. } = self.vm.get_regs()?;
        if DB_EX_ID == exception {
            // If the BS flag in DR6 register is set, it means a single step
            // instruction triggered the exit
            // Check page 19-4 Vol. 3B of Intel 64 and IA-32
            // Architectures Software Developer's Manual
            if dr6 & DR6_BS_FLAG_MASK != 0 {
                log::info!("Done Step stop reason");
                return Ok(VcpuStopReason::DoneStep);
            }

            // If any of the B0-B3 flags in DR6 register is set, it means a
            // hardware breakpoint triggered the exit
            // Check page 19-4 Vol. 3B of Intel 64 and IA-32
            // Architectures Software Developer's Manual
            if DR6_HW_BP_FLAGS_MASK & dr6 != 0 {
                if rip == self.entrypoint {
                    log::info!("EntryPoint stop reason");
                    self.vm.remove_hw_breakpoint(self.entrypoint)?;
                    return Ok(VcpuStopReason::EntryPointBp);
                }
                log::info!("Hardware breakpoint stop reason");
                return Ok(VcpuStopReason::HwBp);
            }
        }

        if BP_EX_ID == exception {
            log::info!("Software breakpoint stop reason");
            return Ok(VcpuStopReason::SwBp);
        }

        // Log an error and provide internal debugging info
        log::error!(
            r"The vCPU exited because of an unknown reason:
        rip: {:?}
        dr6: {:?}
        entrypoint: {:?}
        exception: {:?}

        ",
            rip,
            dr6,
            self.entrypoint,
            exception,
        );

        Ok(VcpuStopReason::Unknown)
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

        let regs = CommonRegisters {
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
        let regs = CommonRegisters {
            rip: dispatch_func_addr.into(),
            rsp: self.orig_rsp.absolute()?,
            rflags: 2,
            ..Default::default()
        };
        self.vm.set_regs(&regs)?;

        // reset fpu state
        let fpu = CommonFpu {
            fcw: FP_CONTROL_WORD_DEFAULT,
            ftwx: FP_TAG_WORD_DEFAULT,
            mxcsr: MXCSR_DEFAULT,
            ..Default::default() // zero out the rest
        };
        self.vm.set_fpu(&fpu)?;

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
        #[cfg(gdb)] dbg_mem_access_fn: DbgMemAccessHandlerWrapper,
    ) -> Result<()> {
        loop {
            match self.vm.run_vcpu() {
                #[cfg(gdb)]
                Ok(HyperlightExit::Debug { dr6, exception }) => {
                    let stop_reason = self.vcpu_stop_reason(dr6, exception)?;
                    if let Err(e) = self.handle_debug(dbg_mem_access_fn.clone(), stop_reason) {
                        log_then_return!(e);
                    }
                }

                Ok(HyperlightExit::Halt()) => {
                    break;
                }
                Ok(HyperlightExit::IoOut(port, data)) => {
                    self.handle_io(port, data, outb_handle_fn.clone())?
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
            log::info!("GDB request: {:?}", req);

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
