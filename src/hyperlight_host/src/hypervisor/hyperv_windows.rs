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

use std::ffi::c_void;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::string::String;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex};

use log::LevelFilter;
use tracing::{Span, instrument};
use windows::Win32::System::Hypervisor::{
    WHV_MEMORY_ACCESS_TYPE, WHV_REGISTER_VALUE, WHV_RUN_VP_EXIT_CONTEXT, WHV_RUN_VP_EXIT_REASON,
    WHvRunVirtualProcessor, WHvRunVpExitReasonCanceled, WHvRunVpExitReasonMemoryAccess,
    WHvRunVpExitReasonX64Halt, WHvRunVpExitReasonX64IoPortAccess, WHvX64RegisterRip,
};
#[cfg(crashdump)]
use {super::crashdump, std::path::Path};
#[cfg(gdb)]
use {
    super::gdb::{
        DebugCommChannel, DebugMemoryAccess, DebugMsg, DebugResponse, GuestDebug, HypervDebug,
        VcpuStopReason,
    },
    crate::HyperlightError,
    crate::new_error,
    windows::Win32::System::Hypervisor::WHvGetVirtualProcessorRegisters,
    windows::Win32::System::Hypervisor::WHvRunVpExitReasonException,
    windows::Win32::System::Hypervisor::WHvX64RegisterDr6,
};

use super::regs::CommonSpecialRegisters;
use super::surrogate_process::SurrogateProcess;
use super::surrogate_process_manager::*;
use super::windows_hypervisor_platform::{VMPartition, VMProcessor};
use super::wrappers::HandleWrapper;
use super::{Hypervisor, InterruptHandle};
use crate::hypervisor::regs::{Align16, CommonFpu, CommonRegisters};
use crate::hypervisor::{InterruptHandleImpl, VmExit, WindowsInterruptHandle};
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::ptr::{GuestPtr, RawPtr};
use crate::mem::shared_mem::HostSharedMemory;
use crate::sandbox::host_funcs::FunctionRegistry;
#[cfg(feature = "mem_profile")]
use crate::sandbox::trace::MemTraceInfo;
#[cfg(crashdump)]
use crate::sandbox::uninitialized::SandboxRuntimeConfig;
use crate::{Result, log_then_return};

#[cfg(gdb)]
mod debug {

    use super::{HypervWindowsDriver, *};
    use crate::Result;
    use crate::hypervisor::gdb::{DebugMemoryAccess, DebugMsg, DebugResponse};

    impl HypervWindowsDriver {
        /// Resets the debug information to disable debugging
        fn disable_debug(&mut self) -> Result<()> {
            let mut debug = HypervDebug::default();

            debug.set_single_step(&self.processor, false)?;

            self.debug = Some(debug);

            Ok(())
        }

        pub(crate) fn process_dbg_request(
            &mut self,
            req: DebugMsg,
            mem_access: &DebugMemoryAccess,
        ) -> Result<DebugResponse> {
            if let Some(debug) = self.debug.as_mut() {
                match req {
                    DebugMsg::AddHwBreakpoint(addr) => Ok(DebugResponse::AddHwBreakpoint(
                        debug
                            .add_hw_breakpoint(&self.processor, addr)
                            .map_err(|e| {
                                log::error!("Failed to add hw breakpoint: {:?}", e);

                                e
                            })
                            .is_ok(),
                    )),
                    DebugMsg::AddSwBreakpoint(addr) => Ok(DebugResponse::AddSwBreakpoint(
                        debug
                            .add_sw_breakpoint(&self.processor, addr, mem_access)
                            .map_err(|e| {
                                log::error!("Failed to add sw breakpoint: {:?}", e);

                                e
                            })
                            .is_ok(),
                    )),
                    DebugMsg::Continue => {
                        debug.set_single_step(&self.processor, false).map_err(|e| {
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
                        let offset = mem_access
                            .dbg_mem_access_fn
                            .try_lock()
                            .map_err(|e| {
                                new_error!("Error locking at {}:{}: {}", file!(), line!(), e)
                            })?
                            .layout
                            .get_guest_code_address();

                        Ok(DebugResponse::GetCodeSectionOffset(offset as u64))
                    }
                    DebugMsg::ReadAddr(addr, len) => {
                        let mut data = vec![0u8; len];

                        debug
                            .read_addrs(&self.processor, addr, &mut data, mem_access)
                            .map_err(|e| {
                                log::error!("Failed to read from address: {:?}", e);

                                e
                            })?;

                        Ok(DebugResponse::ReadAddr(data))
                    }
                    DebugMsg::ReadRegisters => debug
                        .read_regs(&self.processor)
                        .map_err(|e| {
                            log::error!("Failed to read registers: {:?}", e);

                            e
                        })
                        .map(|(regs, fpu)| DebugResponse::ReadRegisters(Box::new((regs, fpu)))),
                    DebugMsg::RemoveHwBreakpoint(addr) => Ok(DebugResponse::RemoveHwBreakpoint(
                        debug
                            .remove_hw_breakpoint(&self.processor, addr)
                            .map_err(|e| {
                                log::error!("Failed to remove hw breakpoint: {:?}", e);

                                e
                            })
                            .is_ok(),
                    )),
                    DebugMsg::RemoveSwBreakpoint(addr) => Ok(DebugResponse::RemoveSwBreakpoint(
                        debug
                            .remove_sw_breakpoint(&self.processor, addr, mem_access)
                            .map_err(|e| {
                                log::error!("Failed to remove sw breakpoint: {:?}", e);

                                e
                            })
                            .is_ok(),
                    )),
                    DebugMsg::Step => {
                        debug.set_single_step(&self.processor, true).map_err(|e| {
                            log::error!("Failed to enable step instruction: {:?}", e);

                            e
                        })?;

                        Ok(DebugResponse::Step)
                    }
                    DebugMsg::WriteAddr(addr, data) => {
                        debug
                            .write_addrs(&self.processor, addr, &data, mem_access)
                            .map_err(|e| {
                                log::error!("Failed to write to address: {:?}", e);

                                e
                            })?;

                        Ok(DebugResponse::WriteAddr)
                    }
                    DebugMsg::WriteRegisters(boxed_regs) => {
                        let (regs, fpu) = boxed_regs.as_ref();
                        debug
                            .write_regs(&self.processor, regs, fpu)
                            .map_err(|e| {
                                log::error!("Failed to write registers: {:?}", e);

                                e
                            })
                            .map(|_| DebugResponse::WriteRegisters)
                    }
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

/// A Hypervisor driver for HyperV-on-Windows.
pub(crate) struct HypervWindowsDriver {
    processor: VMProcessor,
    _surrogate_process: SurrogateProcess, // we need to keep a reference to the SurrogateProcess for the duration of the driver since otherwise it will dropped and the memory mapping will be unmapped and the surrogate process will be returned to the pool
    entrypoint: u64,
    orig_rsp: GuestPtr,
    interrupt_handle: Arc<dyn InterruptHandleImpl>,

    sandbox_regions: Vec<MemoryRegion>, // Initially mapped regions when sandbox is created
    mmap_regions: Vec<MemoryRegion>,    // Later mapped regions

    #[cfg(gdb)]
    debug: Option<HypervDebug>,
    #[cfg(gdb)]
    gdb_conn: Option<DebugCommChannel<DebugResponse, DebugMsg>>,
    #[cfg(crashdump)]
    rt_cfg: SandboxRuntimeConfig,
    #[cfg(feature = "mem_profile")]
    trace_info: MemTraceInfo,
}
/* This does not automatically impl Send because the host
 * address of the shared memory region is a raw pointer, which are
 * marked as !Send (and !Sync). However, the access patterns used
 * here are safe.
 */
unsafe impl Send for HypervWindowsDriver {}

impl HypervWindowsDriver {
    #[allow(clippy::too_many_arguments)]
    // TODO: refactor this function to take fewer arguments. Add trace_info to rt_cfg
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn new(
        mem_regions: Vec<MemoryRegion>,
        raw_size: usize,
        pml4_address: u64,
        entrypoint: u64,
        rsp: u64,
        mmap_file_handle: HandleWrapper,
        #[cfg(gdb)] gdb_conn: Option<DebugCommChannel<DebugResponse, DebugMsg>>,
        #[cfg(crashdump)] rt_cfg: SandboxRuntimeConfig,
        #[cfg(feature = "mem_profile")] trace_info: MemTraceInfo,
    ) -> Result<Self> {
        // create and setup hypervisor partition
        let mut partition = VMPartition::new(1)?;

        // get a surrogate process with preallocated memory of size SharedMemory::raw_mem_size()
        // with guard pages setup
        let surrogate_process = {
            let mgr = get_surrogate_process_manager()?;
            mgr.get_surrogate_process(raw_size, mmap_file_handle)
        }?;

        partition.map_gpa_range(&mem_regions, &surrogate_process)?;

        let proc = VMProcessor::new(partition)?;
        let partition_handle = proc.get_partition_hdl();

        #[cfg(gdb)]
        let (debug, gdb_conn) = if let Some(gdb_conn) = gdb_conn {
            let mut debug = HypervDebug::new();
            debug.add_hw_breakpoint(&proc, entrypoint)?;

            (Some(debug), Some(gdb_conn))
        } else {
            (None, None)
        };

        let interrupt_handle: Arc<dyn InterruptHandleImpl> = Arc::new(WindowsInterruptHandle {
            state: AtomicU64::new(0),
            #[cfg(gdb)]
            debug_interrupt: AtomicBool::new(false),
            partition_handle,
            dropped: AtomicBool::new(false),
        });

        let mut hv = Self {
            processor: proc,
            _surrogate_process: surrogate_process,
            entrypoint,
            orig_rsp: GuestPtr::try_from(RawPtr::from(rsp))?,
            interrupt_handle: interrupt_handle.clone(),
            sandbox_regions: mem_regions,
            mmap_regions: Vec::new(),
            #[cfg(gdb)]
            debug,
            #[cfg(gdb)]
            gdb_conn,
            #[cfg(crashdump)]
            rt_cfg,
            #[cfg(feature = "mem_profile")]
            trace_info,
        };

        hv.setup_initial_sregs(pml4_address)?;

        // Send the interrupt handle to the GDB thread if debugging is enabled
        // This is used to allow the GDB thread to stop the vCPU
        #[cfg(gdb)]
        if hv.debug.is_some() {
            hv.send_dbg_msg(DebugResponse::InterruptHandle(interrupt_handle))?;
        }

        Ok(hv)
    }
}

impl Debug for HypervWindowsDriver {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut fs = f.debug_struct("HyperV Driver");

        fs.field("Entrypoint", &self.entrypoint)
            .field("Original RSP", &self.orig_rsp);

        for region in &self.sandbox_regions {
            fs.field("Sandbox Memory Region", &region);
        }
        for region in &self.mmap_regions {
            fs.field("Mapped Memory Region", &region);
        }

        // Get the registers
        if let Ok(regs) = self.processor.regs() {
            fs.field("Registers", &regs);
        }

        // Get the special registers
        if let Ok(special_regs) = self.processor.sregs() {
            fs.field("SpecialRegisters", &special_regs);
        }

        fs.finish()
    }
}

impl Hypervisor for HypervWindowsDriver {
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn initialise(
        &mut self,
        peb_address: RawPtr,
        seed: u64,
        page_size: u32,
        mut mem_mgr: SandboxMemoryManager<HostSharedMemory>,
        host_funcs: Arc<Mutex<FunctionRegistry>>,
        max_guest_log_level: Option<LevelFilter>,
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    ) -> Result<()> {
        let max_guest_log_level: u64 = match max_guest_log_level {
            Some(level) => level as u64,
            None => self.get_max_log_level().into(),
        };

        let regs = CommonRegisters {
            rip: self.entrypoint,
            rsp: self.orig_rsp.absolute()?,

            // function args
            rdi: peb_address.into(),
            rsi: seed,
            rdx: page_size.into(),
            rcx: max_guest_log_level,
            rflags: 1 << 1, // eflags bit index 1 is reserved and always needs to be 1

            ..Default::default()
        };
        self.set_regs(&regs)?;

        self.run(
            self.entrypoint,
            self.interrupt_handle.clone(),
            &self.sandbox_regions.clone(),
            &self.mmap_regions.clone(),
            &mut mem_mgr,
            host_funcs.clone(),
            #[cfg(gdb)]
            dbg_mem_access_fn,
            #[cfg(crashdump)]
            &self.rt_cfg.clone(),
        )
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    unsafe fn map_region(&mut self, _region: &MemoryRegion) -> Result<()> {
        log_then_return!("Mapping host memory into the guest not yet supported on this platform");
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    unsafe fn unmap_region(&mut self, _region: &MemoryRegion) -> Result<()> {
        log_then_return!("Mapping host memory into the guest not yet supported on this platform");
    }

    fn get_mapped_regions(&self) -> Box<dyn ExactSizeIterator<Item = &MemoryRegion> + '_> {
        Box::new(self.mmap_regions.iter())
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn dispatch_call_from_host(
        &mut self,
        dispatch_func_addr: RawPtr,
        mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
        host_funcs: Arc<Mutex<FunctionRegistry>>,
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    ) -> Result<()> {
        // Reset general purpose registers, then set RIP and RSP
        let regs = CommonRegisters {
            rip: dispatch_func_addr.into(),
            rsp: self.orig_rsp.absolute()?,
            rflags: 1 << 1, // eflags bit index 1 is reserved and always needs to be 1
            ..Default::default()
        };
        self.processor.set_regs(&regs)?;

        // reset fpu state
        self.processor.set_fpu(&CommonFpu::default())?;

        self.run(
            self.entrypoint,
            self.interrupt_handle.clone(),
            &self.sandbox_regions.clone(),
            &self.mmap_regions.clone(),
            mem_mgr,
            host_funcs.clone(),
            #[cfg(gdb)]
            dbg_mem_access_fn,
            #[cfg(crashdump)]
            &self.rt_cfg.clone(),
        )
    }

    // Note, this function should not be instrumented with a span as it is called after setting up guest trace span
    #[expect(non_upper_case_globals, reason = "Windows API constant are lower case")]
    fn run_vcpu(&mut self) -> Result<VmExit> {
        let mut exit_context: WHV_RUN_VP_EXIT_CONTEXT = Default::default();

        unsafe {
            WHvRunVirtualProcessor(
                self.processor.get_partition_hdl(),
                0,
                &mut exit_context as *mut _ as *mut c_void,
                std::mem::size_of::<WHV_RUN_VP_EXIT_CONTEXT>() as u32,
            )?;
        }

        let result = match exit_context.ExitReason {
            WHvRunVpExitReasonX64IoPortAccess => unsafe {
                let instruction_length = exit_context.VpContext._bitfield & 0xF;
                let rip = exit_context.VpContext.Rip + instruction_length as u64;
                self.processor.set_registers(&[(
                    WHvX64RegisterRip,
                    Align16(WHV_REGISTER_VALUE { Reg64: rip }),
                )])?;
                VmExit::IoOut(
                    exit_context.Anonymous.IoPortAccess.PortNumber,
                    exit_context
                        .Anonymous
                        .IoPortAccess
                        .Rax
                        .to_le_bytes()
                        .to_vec(),
                )
            },
            WHvRunVpExitReasonX64Halt => VmExit::Halt(),
            WHvRunVpExitReasonMemoryAccess => {
                let gpa = unsafe { exit_context.Anonymous.MemoryAccess.Gpa };
                let access_info = unsafe {
                    WHV_MEMORY_ACCESS_TYPE(
                        // 2 first bits are the access type, see https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/memoryaccess#syntax
                        (exit_context.Anonymous.MemoryAccess.AccessInfo.AsUINT32 & 0b11) as i32,
                    )
                };
                let access_info = MemoryRegionFlags::try_from(access_info)?;
                match access_info {
                    MemoryRegionFlags::READ => VmExit::MmioRead(gpa),
                    MemoryRegionFlags::WRITE => VmExit::MmioWrite(gpa),
                    _ => VmExit::Unknown("Unknown memory access type".to_string()),
                }
            }
            // Execution was cancelled by the host.
            WHvRunVpExitReasonCanceled => VmExit::Cancelled(),
            #[cfg(gdb)]
            WHvRunVpExitReasonException => {
                let exception = unsafe { exit_context.Anonymous.VpException };

                // Get the DR6 register to see which breakpoint was hit
                let dr6 = {
                    let names = [WHvX64RegisterDr6];
                    let mut out: [Align16<WHV_REGISTER_VALUE>; 1] = unsafe { std::mem::zeroed() };
                    unsafe {
                        WHvGetVirtualProcessorRegisters(
                            self.processor.get_partition_hdl(),
                            0,
                            names.as_ptr(),
                            out.len() as u32,
                            out.as_mut_ptr() as *mut WHV_REGISTER_VALUE,
                        )?;
                    }
                    unsafe { out[0].0.Reg64 }
                };

                VmExit::Debug {
                    dr6,
                    exception: exception.ExceptionType as u32,
                }
            }
            WHV_RUN_VP_EXIT_REASON(_) => VmExit::Unknown(format!(
                "Unknown exit reason '{}'",
                exit_context.ExitReason.0
            )),
        };
        Ok(result)
    }

    /// Get regs
    #[allow(dead_code)]
    fn regs(&self) -> Result<CommonRegisters> {
        self.processor.regs()
    }
    /// Set regs
    fn set_regs(&mut self, regs: &CommonRegisters) -> Result<()> {
        self.processor.set_regs(regs)
    }
    /// Get fpu regs
    #[allow(dead_code)]
    fn fpu(&self) -> Result<CommonFpu> {
        self.processor.fpu()
    }
    /// Set fpu regs
    fn set_fpu(&mut self, fpu: &CommonFpu) -> Result<()> {
        self.processor.set_fpu(fpu)
    }
    /// Get special regs
    #[allow(dead_code)]
    fn sregs(&self) -> Result<CommonSpecialRegisters> {
        self.processor.sregs()
    }
    /// Set special regs
    #[allow(dead_code)]
    fn set_sregs(&mut self, sregs: &CommonSpecialRegisters) -> Result<()> {
        self.processor.set_sregs(sregs)
    }

    fn interrupt_handle(&self) -> Arc<dyn InterruptHandle> {
        self.interrupt_handle.clone()
    }

    #[cfg(crashdump)]
    fn crashdump_context(&self) -> Result<Option<crashdump::CrashDumpContext>> {
        if self.rt_cfg.guest_core_dump {
            let mut regs = [0; 27];

            let vcpu_regs = self.processor.regs()?;
            let sregs = self.processor.sregs()?;
            let xsave = self.processor.get_xsave()?;

            // Set the registers in the order expected by the crashdump context
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

            // Get the filename from the config
            let filename = self.rt_cfg.binary_path.clone().and_then(|path| {
                Path::new(&path)
                    .file_name()
                    .and_then(|name| name.to_os_string().into_string().ok())
            });

            // Include both initial sandbox regions and dynamically mapped regions
            let mut regions: Vec<MemoryRegion> = self.sandbox_regions.clone();
            regions.extend(self.mmap_regions.iter().cloned());
            Ok(Some(crashdump::CrashDumpContext::new(
                regions,
                regs,
                xsave,
                self.entrypoint,
                self.rt_cfg.binary_path.clone(),
                filename,
            )))
        } else {
            Ok(None)
        }
    }

    #[cfg(gdb)]
    fn handle_debug(
        &mut self,
        dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
        stop_reason: super::gdb::VcpuStopReason,
    ) -> Result<()> {
        if self.debug.is_none() {
            return Err(new_error!("Debugging is not enabled"));
        }

        let mem_access = DebugMemoryAccess {
            dbg_mem_access_fn,
            guest_mmap_regions: self.mmap_regions.to_vec(),
        };

        match stop_reason {
            // If the vCPU stopped because of a crash, we need to handle it differently
            // We do not want to allow resuming execution or placing breakpoints
            // because the guest has crashed.
            // We only allow reading registers and memory
            VcpuStopReason::Crash => {
                self.send_dbg_msg(DebugResponse::VcpuStopped(stop_reason))
                    .map_err(|e| {
                        new_error!("Couldn't signal vCPU stopped event to GDB thread: {:?}", e)
                    })?;

                loop {
                    log::debug!("Debug wait for event to resume vCPU");
                    // Wait for a message from gdb
                    let req = self.recv_dbg_msg()?;

                    // Flag to store if we should deny continue or step requests
                    let mut deny_continue = false;
                    // Flag to store if we should detach from the gdb session
                    let mut detach = false;

                    let response = match req {
                        // Allow the detach request to disable debugging by continuing resuming
                        // hypervisor crash error reporting
                        DebugMsg::DisableDebug => {
                            detach = true;
                            DebugResponse::DisableDebug
                        }
                        // Do not allow continue or step requests
                        DebugMsg::Continue | DebugMsg::Step => {
                            deny_continue = true;
                            DebugResponse::NotAllowed
                        }
                        // Do not allow adding/removing breakpoints and writing to memory or registers
                        DebugMsg::AddHwBreakpoint(_)
                        | DebugMsg::AddSwBreakpoint(_)
                        | DebugMsg::RemoveHwBreakpoint(_)
                        | DebugMsg::RemoveSwBreakpoint(_)
                        | DebugMsg::WriteAddr(_, _)
                        | DebugMsg::WriteRegisters(_) => DebugResponse::NotAllowed,

                        // For all other requests, we will process them normally
                        _ => {
                            let result = self.process_dbg_request(req, &mem_access);
                            match result {
                                Ok(response) => response,
                                Err(HyperlightError::TranslateGuestAddress(_)) => {
                                    // Treat non fatal errors separately so the guest doesn't fail
                                    DebugResponse::ErrorOccurred
                                }
                                Err(e) => {
                                    log::error!("Error processing debug request: {:?}", e);
                                    return Err(e);
                                }
                            }
                        }
                    };

                    // Send the response to the request back to gdb
                    self.send_dbg_msg(response)
                        .map_err(|e| new_error!("Couldn't send response to gdb: {:?}", e))?;

                    // If we are denying continue or step requests, the debugger assumes the
                    // execution started so we need to report a stop reason as a crash and let
                    // it request to read registers/memory to figure out what happened
                    if deny_continue {
                        self.send_dbg_msg(DebugResponse::VcpuStopped(VcpuStopReason::Crash))
                            .map_err(|e| new_error!("Couldn't send response to gdb: {:?}", e))?;
                    }

                    // If we are detaching, we will break the loop and the Hypervisor will continue
                    // to handle the Crash reason
                    if detach {
                        break;
                    }
                }
            }

            // If the vCPU stopped because of any other reason except a crash, we can handle it
            // normally
            _ => {
                // Temporary spot to remove hw breakpoints on exit
                // TODO: remove in future PR
                if stop_reason == VcpuStopReason::EntryPointBp {
                    #[allow(clippy::unwrap_used)] // we checked this above
                    self.debug
                        .as_mut()
                        .unwrap()
                        .remove_hw_breakpoint(&self.processor, self.entrypoint)?;
                }

                self.send_dbg_msg(DebugResponse::VcpuStopped(stop_reason))
                    .map_err(|e| {
                        new_error!("Couldn't signal vCPU stopped event to GDB thread: {:?}", e)
                    })?;

                loop {
                    log::debug!("Debug wait for event to resume vCPU");

                    // Wait for a message from gdb
                    let req = self.recv_dbg_msg()?;

                    let result = self.process_dbg_request(req, &mem_access);

                    let response = match result {
                        Ok(response) => response,
                        // Treat non fatal errors separately so the guest doesn't fail
                        Err(HyperlightError::TranslateGuestAddress(_)) => {
                            DebugResponse::ErrorOccurred
                        }
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
            }
        }

        Ok(())
    }

    #[cfg(gdb)]
    fn gdb_connection(&self) -> Option<&DebugCommChannel<DebugResponse, DebugMsg>> {
        self.gdb_conn.as_ref()
    }

    #[cfg(gdb)]
    fn translate_gva(&self, gva: u64) -> Result<u64> {
        use windows::Win32::System::Hypervisor::{
            WHV_TRANSLATE_GVA_RESULT, WHvTranslateGva, WHvTranslateGvaFlagValidateRead,
        };

        let partition_handle = self.processor.get_partition_hdl();
        let mut gpa = 0;
        let mut result = WHV_TRANSLATE_GVA_RESULT::default();

        unsafe {
            WHvTranslateGva(
                partition_handle,
                0,
                gva,
                // Only validate read access because the write access is handled through the
                // host memory mapping
                WHvTranslateGvaFlagValidateRead,
                &mut result,
                &mut gpa,
            )?;
        }

        Ok(gpa)
    }

    #[cfg(feature = "trace_guest")]
    fn handle_trace(
        &mut self,
        tc: &mut crate::sandbox::trace::TraceContext,
        mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
    ) -> Result<()> {
        let regs = self.regs()?;
        tc.handle_trace(&regs, mem_mgr)
    }

    #[cfg(feature = "mem_profile")]
    fn trace_info_mut(&mut self) -> &mut MemTraceInfo {
        &mut self.trace_info
    }
}

impl Drop for HypervWindowsDriver {
    fn drop(&mut self) {
        self.interrupt_handle.set_dropped();
    }
}
