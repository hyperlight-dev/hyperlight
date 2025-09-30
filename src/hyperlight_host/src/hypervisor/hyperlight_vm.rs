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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use log::LevelFilter;
use tracing::{Span, instrument};

#[cfg(gdb)]
use super::gdb::{DebugCommChannel, DebugMsg, DebugResponse, VcpuStopReason, arch};
use super::regs::{CommonFpu, CommonRegisters};
use super::{LinuxInterruptHandle, get_max_log_level};
use crate::HyperlightError::{ExecutionCanceledByHost, NoHypervisorFound};
#[cfg(crashdump)]
use crate::hypervisor::crashdump;
#[cfg(mshv)]
use crate::hypervisor::hyperv_linux::MshvVm;
#[cfg(kvm)]
use crate::hypervisor::kvm::KvmVm;
use crate::hypervisor::regs::CommonSpecialRegisters;
#[cfg(gdb)]
use crate::hypervisor::vm::DebugExit;
use crate::hypervisor::vm::{Vm, VmExit};
#[cfg(target_os = "windows")]
use crate::hypervisor::whp::WhpVm;
#[cfg(target_os = "windows")]
use crate::hypervisor::wrappers::HandleWrapper;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags, MemoryRegionType};
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::ptr::{GuestPtr, RawPtr};
use crate::mem::shared_mem::HostSharedMemory;
use crate::metrics::METRIC_GUEST_CANCELLATION;
use crate::sandbox::SandboxConfiguration;
#[cfg(feature = "trace_guest")]
use crate::sandbox::TraceInfo;
use crate::sandbox::host_funcs::FunctionRegistry;
use crate::sandbox::hypervisor::{HypervisorType, get_available_hypervisor};
use crate::sandbox::outb::handle_outb;
#[cfg(crashdump)]
use crate::sandbox::uninitialized::SandboxRuntimeConfig;
use crate::{HyperlightError, Result, log_then_return, new_error};

pub(crate) struct HyperlightVm {
    vm: Box<dyn Vm>,
    page_size: usize,
    entrypoint: u64,
    orig_rsp: GuestPtr,
    interrupt_handle: Arc<LinuxInterruptHandle>,
    mem_mgr: Option<SandboxMemoryManager<HostSharedMemory>>,
    host_funcs: Option<Arc<Mutex<FunctionRegistry>>>,

    sandbox_regions: Vec<MemoryRegion>, // Initially mapped regions when sandbox is created
    mmap_regions: Vec<(u32, MemoryRegion)>, // Later mapped regions (slot number, region)
    next_slot: u32,                     // Monotonically increasing slot number
    freed_slots: Vec<u32>,              // Reusable slots from unmapped regions

    #[cfg(gdb)]
    gdb_conn: Option<DebugCommChannel<DebugResponse, DebugMsg>>,
    #[cfg(feature = "trace_guest")]
    trace_info: TraceInfo,
    #[cfg(crashdump)]
    rt_cfg: SandboxRuntimeConfig,
}

impl HyperlightVm {
    /// Create a new HyperlightVm instance (will not run vm until calling `initialise`)
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        mem_regions: Vec<MemoryRegion>,
        pml4_addr: u64,
        entrypoint: u64,
        rsp: u64,
        config: &SandboxConfiguration,
        #[cfg(target_os = "windows")] handle: HandleWrapper,
        #[cfg(gdb)] gdb_conn: Option<DebugCommChannel<DebugResponse, DebugMsg>>,
        #[cfg(crashdump)] rt_cfg: SandboxRuntimeConfig,
        #[cfg(feature = "trace_guest")] trace_info: TraceInfo,
    ) -> Result<Self> {
        #[allow(unused_mut)] // needs to be mutable when gdb is enabled
        let mut vm: Box<dyn Vm> = match get_available_hypervisor() {
            #[cfg(kvm)]
            Some(HypervisorType::Kvm) => Box::new(KvmVm::new()?),
            #[cfg(mshv)]
            Some(HypervisorType::Mshv) => Box::new(MshvVm::new()?),
            #[cfg(target_os = "windows")]
            Some(HypervisorType::Whp) => Box::new(WhpVm::new(handle)?),
            None => return Err(NoHypervisorFound()),
        };

        for (i, region) in mem_regions.iter().enumerate() {
            // Safety: slots are unique and region points to valid memory since we created the regions
            unsafe { vm.map_memory((i as u32, region))? };
        }

        vm.set_sregs(&CommonSpecialRegisters {
            cr3: pml4_addr,
            ..Default::default()
        })?;

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
        let interrupt_handle = Arc::new(LinuxInterruptHandle {
            running: AtomicU64::new(0),
            cancel_requested: AtomicBool::new(false),
            #[cfg(gdb)]
            debug_interrupt: AtomicBool::new(false),
            #[cfg(all(
                target_arch = "x86_64",
                target_vendor = "unknown",
                target_os = "linux",
                target_env = "musl"
            ))]
            tid: AtomicU64::new(unsafe { libc::pthread_self() as u64 }),
            #[cfg(not(all(
                target_arch = "x86_64",
                target_vendor = "unknown",
                target_os = "linux",
                target_env = "musl"
            )))]
            tid: AtomicU64::new(unsafe { libc::pthread_self() }),
            retry_delay: config.get_interrupt_retry_delay(),
            sig_rt_min_offset: config.get_interrupt_vcpu_sigrtmin_offset(),
            dropped: AtomicBool::new(false),
        });

        #[allow(unused_mut)] // needs to be mutable when gdb is enabled
        let mut ret = Self {
            vm,
            entrypoint,
            orig_rsp: rsp_gp,
            interrupt_handle,
            page_size: 0, // Will be set in `initialise`
            mem_mgr: None,
            host_funcs: None,

            next_slot: mem_regions.len() as u32,
            sandbox_regions: mem_regions,
            mmap_regions: Vec::new(),
            freed_slots: Vec::new(),

            #[cfg(gdb)]
            gdb_conn,
            #[cfg(feature = "trace_guest")]
            trace_info,
            #[cfg(crashdump)]
            rt_cfg,
        };

        // Send the interrupt handle to the GDB thread if debugging is enabled
        // This is used to allow the GDB thread to stop the vCPU
        #[cfg(gdb)]
        if ret.gdb_conn.is_some() {
            ret.send_dbg_msg(DebugResponse::InterruptHandle(ret.interrupt_handle.clone()))?;
        }

        Ok(ret)
    }

    /// Initialise the HyperlightVm (will run vm).
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn initialise(
        &mut self,
        peb_addr: RawPtr,
        seed: u64,
        page_size: u32,
        mem_mgr: SandboxMemoryManager<HostSharedMemory>,
        host_funcs: Arc<Mutex<FunctionRegistry>>,
        max_guest_log_level: Option<LevelFilter>,
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    ) -> Result<()> {
        self.mem_mgr = Some(mem_mgr);
        self.host_funcs = Some(host_funcs);
        self.page_size = page_size as usize;

        let max_guest_log_level: u64 = match max_guest_log_level {
            Some(level) => level as u64,
            None => get_max_log_level().into(),
        };

        let regs = CommonRegisters {
            rip: self.entrypoint,
            rsp: self.orig_rsp.absolute()?,

            // function args
            rdi: peb_addr.into(),
            rsi: seed,
            rdx: page_size.into(),
            rcx: max_guest_log_level,
            rflags: 1 << 1,

            ..Default::default()
        };
        self.vm.set_regs(&regs)?;

        self.run(
            #[cfg(gdb)]
            dbg_mem_access_fn,
        )?;

        Ok(())
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn dispatch_call_from_host(
        &mut self,
        dispatch_func_addr: RawPtr,
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    ) -> Result<()> {
        // set RIP and RSP, reset others
        let regs = CommonRegisters {
            rip: dispatch_func_addr.into(),
            rsp: self.orig_rsp.absolute()?,
            rflags: 1 << 1,
            ..Default::default()
        };
        self.vm.set_regs(&regs)?;

        // reset fpu
        self.vm.set_fpu(&CommonFpu::default())?;

        self.run(
            #[cfg(gdb)]
            dbg_mem_access_fn,
        )?;

        Ok(())
    }

    // Safety: The caller must ensure that the memory region is valid and points to valid memory,
    pub(crate) unsafe fn map_region(&mut self, region: &MemoryRegion) -> Result<()> {
        // Try to reuse a freed slot first, otherwise use next_slot
        let slot = if let Some(freed_slot) = self.freed_slots.pop() {
            freed_slot
        } else {
            let slot = self.next_slot;
            self.next_slot += 1;
            slot
        };

        // Safety: slots are unique. It's up to caller to ensure that the region is valid
        unsafe { self.vm.map_memory((slot, region))? };
        self.mmap_regions.push((slot, region.clone()));
        Ok(())
    }

    pub(crate) fn unmap_region(&mut self, region: &MemoryRegion) -> Result<()> {
        if let Some(pos) = self.mmap_regions.iter().position(|(_, r)| r == region) {
            let (slot, _) = self.mmap_regions.remove(pos);
            self.freed_slots.push(slot);
            self.vm.unmap_memory((slot, region))?;
        } else {
            return Err(new_error!("Region not found in mapped regions"));
        }

        Ok(())
    }

    pub(crate) fn get_mapped_regions(&self) -> &[(u32, MemoryRegion)] {
        &self.mmap_regions
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn handle_io(&mut self, port: u16, data: Vec<u8>) -> Result<()> {
        if data.is_empty() {
            log_then_return!("no data was given in IO interrupt");
        }

        #[allow(clippy::get_first)]
        let val = u32::from_le_bytes([
            data.get(0).copied().unwrap_or(0),
            data.get(1).copied().unwrap_or(0),
            data.get(2).copied().unwrap_or(0),
            data.get(3).copied().unwrap_or(0),
        ]);

        #[cfg(feature = "trace_guest")]
        {
            // We need to handle the borrow checker issue where we need both:
            // - &mut MemMgrWrapper (from self.mem_mgr.as_mut())
            // - &mut dyn Hypervisor (from self)
            // We'll use a temporary approach to extract the mem_mgr temporarily
            let mem_mgr_option = self.mem_mgr.take();
            let mut mem_mgr =
                mem_mgr_option.ok_or_else(|| new_error!("mem_mgr not initialized"))?;
            let host_funcs = self
                .host_funcs
                .as_ref()
                .ok_or_else(|| new_error!("host_funcs not initialized"))?
                .clone();

            handle_outb(&mut mem_mgr, host_funcs, self, port, val)?;

            // Put the mem_mgr back
            self.mem_mgr = Some(mem_mgr);
        }

        #[cfg(not(feature = "trace_guest"))]
        {
            let mem_mgr = self
                .mem_mgr
                .as_mut()
                .ok_or_else(|| new_error!("mem_mgr not initialized"))?;
            let host_funcs = self
                .host_funcs
                .as_ref()
                .ok_or_else(|| new_error!("host_funcs not initialized"))?
                .clone();

            handle_outb(mem_mgr, host_funcs, port, val)?;
        }

        Ok(())
    }

    fn run(
        &mut self,
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    ) -> Result<()> {
        let result = loop {
            self.interrupt_handle
                .tid
                .store(unsafe { libc::pthread_self() as u64 }, Ordering::Relaxed);
            // Note: if a `InterruptHandle::kill()` called while this thread is **here**
            // Then this is fine since `cancel_requested` is set to true, so we will skip the `VcpuFd::run()` call
            self.interrupt_handle
                .set_running_and_increment_generation()
                .map_err(|e| {
                    new_error!(
                        "Error setting running state and incrementing generation: {}",
                        e
                    )
                })?;

            // Don't run the vcpu if `cancel_requested` is true
            //
            // Note: if a `InterruptHandle::kill()` called while this thread is **here**
            // Then this is fine since `cancel_requested` is set to true, so we will skip the `VcpuFd::run()` call
            let exit_reason = if self
                .interrupt_handle
                .cancel_requested
                .load(Ordering::Relaxed)
            {
                Ok(VmExit::Cancelled())
            } else {
                self.vm.run_vcpu()
            };
            // Note: if a `InterruptHandle::kill()` called while this thread is **here**
            // Then signals will be sent to this thread until `running` is set to false.
            // This is fine since the signal handler is a no-op.
            let cancel_requested = self
                .interrupt_handle
                .cancel_requested
                .load(Ordering::Relaxed);
            // Note: if a `InterruptHandle::kill()` called while this thread is **here**
            // Then `cancel_requested` will be set to true again, which will cancel the **next vcpu run**.
            // Additionally signals will be sent to this thread until `running` is set to false.
            // This is fine since the signal handler is a no-op.
            self.interrupt_handle.clear_running_bit();
            // At this point, `running` is `false` so no more signals will be sent to this thread,
            // but we may still receive async signals that were sent before this point.
            // To prevent those signals from interrupting subsequent calls to `run()` (on other vms!),
            // we make sure to check `cancel_requested` before cancelling (see `libc::EINTR` match-arm below).
            match exit_reason {
                #[cfg(gdb)]
                Ok(VmExit::Debug(debug_exit)) => {
                    match debug_exit {
                        DebugExit::Debug { dr6, exception } => {
                            // Handle debug event (breakpoints)
                            let stop_reason = arch::vcpu_stop_reason(
                                self.vm.as_mut(),
                                self.entrypoint,
                                dr6,
                                exception,
                            )?;
                            if let Err(e) =
                                self.handle_debug(dbg_mem_access_fn.clone(), stop_reason)
                            {
                                break Err(e);
                            }
                        }
                        DebugExit::Interrupt => {
                            if let Err(e) = self
                                .handle_debug(dbg_mem_access_fn.clone(), VcpuStopReason::Interrupt)
                            {
                                break Err(e);
                            }
                        }
                    }
                }

                Ok(VmExit::Halt()) => {
                    break Ok(());
                }
                Ok(VmExit::IoOut(port, data)) => self.handle_io(port, data)?,
                Ok(VmExit::MmioRead(addr)) => {
                    let all_regions = self
                        .sandbox_regions
                        .iter()
                        .chain(self.mmap_regions.iter().map(|(_, r)| r));
                    match get_memory_access_violation(
                        addr as usize,
                        MemoryRegionFlags::WRITE,
                        all_regions,
                    ) {
                        Some(MemoryAccess::StackGuardPageViolation) => {
                            break Err(HyperlightError::StackOverflow());
                        }
                        Some(MemoryAccess::AccessViolation(region_flags)) => {
                            break Err(HyperlightError::MemoryAccessViolation(
                                addr,
                                MemoryRegionFlags::READ,
                                region_flags,
                            ));
                        }
                        None => {
                            match &self.mem_mgr {
                                Some(mem_mgr) => {
                                    if !mem_mgr.check_stack_guard()? {
                                        break Err(HyperlightError::StackOverflow());
                                    }
                                }
                                None => {
                                    break Err(new_error!("Memory manager not initialized"));
                                }
                            }

                            break Err(new_error!("MMIO READ access address {:#x}", addr));
                        }
                    }
                }
                Ok(VmExit::MmioWrite(addr)) => {
                    let all_regions = self
                        .sandbox_regions
                        .iter()
                        .chain(self.mmap_regions.iter().map(|(_, r)| r));
                    match get_memory_access_violation(
                        addr as usize,
                        MemoryRegionFlags::WRITE,
                        all_regions,
                    ) {
                        Some(MemoryAccess::StackGuardPageViolation) => {
                            break Err(HyperlightError::StackOverflow());
                        }
                        Some(MemoryAccess::AccessViolation(region_flags)) => {
                            break Err(HyperlightError::MemoryAccessViolation(
                                addr,
                                MemoryRegionFlags::WRITE,
                                region_flags,
                            ));
                        }
                        None => {
                            match &self.mem_mgr {
                                Some(mem_mgr) => {
                                    if !mem_mgr.check_stack_guard()? {
                                        break Err(HyperlightError::StackOverflow());
                                    }
                                }
                                None => {
                                    break Err(new_error!("Memory manager not initialized"));
                                }
                            }

                            break Err(new_error!("MMIO WRITE access address {:#x}", addr));
                        }
                    }
                }
                Ok(VmExit::Cancelled()) => {
                    // If cancellation was not requested for this specific vm, the vcpu was interrupted because of debug interrupt or
                    // a stale signal that meant to be delivered to a previous/other vcpu on this same thread, so let's ignore it
                    if cancel_requested {
                        self.interrupt_handle
                            .cancel_requested
                            .store(false, Ordering::Relaxed);
                        metrics::counter!(METRIC_GUEST_CANCELLATION).increment(1);
                        break Err(ExecutionCanceledByHost());
                    } else {
                        // treat this the same as a VmExit::Retry, the cancel was not meant for this vcpu
                        continue;
                    }
                }
                Ok(VmExit::Unknown(reason)) => {
                    break Err(new_error!("Unexpected VM Exit: {:?}", reason));
                }
                Ok(VmExit::Retry()) => continue,
                Err(e) => {
                    break Err(e);
                }
            }
        };

        match result {
            Ok(_) => Ok(()),
            Err(HyperlightError::ExecutionCanceledByHost()) => {
                // no need to crashdump this
                Err(HyperlightError::ExecutionCanceledByHost())
            }
            Err(e) => {
                #[cfg(crashdump)]
                if self.rt_cfg.guest_core_dump {
                    crashdump::generate_crashdump(self)?;
                }

                // If GDB is enabled, we handle the debug memory access
                // Disregard return value as we want to return the error
                #[cfg(gdb)]
                self.handle_debug(dbg_mem_access_fn.clone(), VcpuStopReason::Crash)?;

                log_then_return!(e);
            }
        }
    }

    pub(crate) fn interrupt_handle(&self) -> Arc<LinuxInterruptHandle> {
        self.interrupt_handle.clone()
    }

    #[cfg(gdb)]
    fn handle_debug(
        &mut self,
        dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
        stop_reason: VcpuStopReason,
    ) -> Result<()> {
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
                            let result = self.process_dbg_request(req, dbg_mem_access_fn.clone());
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
                // Send the stop reason to the gdb thread
                self.send_dbg_msg(DebugResponse::VcpuStopped(stop_reason))
                    .map_err(|e| {
                        new_error!("Couldn't signal vCPU stopped event to GDB thread: {:?}", e)
                    })?;

                loop {
                    log::debug!("Debug wait for event to resume vCPU");
                    // Wait for a message from gdb
                    let req = self.recv_dbg_msg()?;

                    let result = self.process_dbg_request(req, dbg_mem_access_fn.clone());

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

                    let cont = matches!(
                        response,
                        DebugResponse::Continue | DebugResponse::Step | DebugResponse::DisableDebug
                    );

                    self.send_dbg_msg(response)
                        .map_err(|e| new_error!("Couldn't send response to gdb: {:?}", e))?;

                    // Check if we should continue execution
                    // We continue if the response is one of the following: Step, Continue, or DisableDebug
                    if cont {
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn get_partition_handle(&self) -> windows::Win32::System::Hypervisor::WHV_PARTITION_HANDLE {
        self.vm.get_partition_handle()
    }

    // --------------------------
    // --- CRASHDUMP BELOW ------
    // --------------------------

    #[cfg(crashdump)]
    pub(super) fn crashdump_context(&self) -> Result<super::crashdump::CrashDumpContext<'_>> {
        use crate::hypervisor::crashdump;

        let mut regs = [0; 27];

        let vcpu_regs = self.vm.regs()?;
        let sregs = self.vm.sregs()?;
        let xsave = self.vm.xsave()?;

        // Set up the registers for the crash dump
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

        // Get the filename from the binary path
        let filename = self.rt_cfg.binary_path.clone().and_then(|path| {
            use std::path::Path;

            Path::new(&path)
                .file_name()
                .and_then(|name| name.to_os_string().into_string().ok())
        });

        Ok(crashdump::CrashDumpContext::new(
            &self.sandbox_regions,
            regs,
            xsave,
            self.entrypoint,
            self.rt_cfg.binary_path.clone(),
            filename,
        ))
    }

    #[cfg(feature = "trace_guest")]
    pub(crate) fn vm_regs(&self) -> Result<CommonRegisters> {
        self.vm.regs()
    }

    #[cfg(feature = "trace_guest")]
    pub(crate) fn trace_info(&self) -> &TraceInfo {
        &self.trace_info
    }

    #[cfg(feature = "trace_guest")]
    pub(crate) fn trace_info_as_mut(&mut self) -> &mut TraceInfo {
        &mut self.trace_info
    }
}

impl Drop for HyperlightVm {
    fn drop(&mut self) {
        self.interrupt_handle.dropped.store(true, Ordering::Relaxed);
    }
}

/// The vCPU tried to access the given addr
enum MemoryAccess {
    /// The accessed region has the given flags
    AccessViolation(MemoryRegionFlags),
    /// The accessed region is a stack guard page
    StackGuardPageViolation,
}

/// Determines if a memory access violation occurred at the given address with the given action type.
fn get_memory_access_violation<'a>(
    gpa: usize,
    tried: MemoryRegionFlags,
    mut mem_regions: impl Iterator<Item = &'a MemoryRegion>,
) -> Option<MemoryAccess> {
    // find the region containing the given gpa
    let region = mem_regions.find(|region| region.guest_region.contains(&gpa));

    if let Some(region) = region {
        if region.region_type == MemoryRegionType::GuardPage {
            return Some(MemoryAccess::StackGuardPageViolation);
        } else if !region.flags.contains(tried) {
            return Some(MemoryAccess::AccessViolation(region.flags));
        }
    }
    None
}

#[cfg(gdb)]
mod debug {
    use std::sync::{Arc, Mutex};

    use hyperlight_common::mem::PAGE_SIZE;

    use super::HyperlightVm;
    use crate::hypervisor::gdb::{DebugMsg, DebugResponse};
    use crate::mem::layout::SandboxMemoryLayout;
    use crate::mem::mgr::SandboxMemoryManager;
    use crate::mem::shared_mem::HostSharedMemory;
    use crate::{HyperlightError, Result, new_error};

    impl HyperlightVm {
        pub(crate) fn process_dbg_request(
            &mut self,
            req: DebugMsg,
            dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
        ) -> Result<DebugResponse> {
            if self.gdb_conn.is_some() {
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
                            .layout
                            .get_guest_code_address();

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
                        .regs()
                        .map_err(|e| {
                            log::error!("Failed to read registers: {:?}", e);

                            e
                        })
                        .map(DebugResponse::ReadRegisters),
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
            dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
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
                    .get_shared_mem_mut()
                    .copy_to_slice(&mut data[..read_len], offset)?;

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
            dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
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
                    .get_shared_mem_mut()
                    .copy_from_slice(&data[..write_len], offset)?;

                data = &data[write_len..];
                gva += write_len as u64;
            }

            Ok(())
        }
    }
}
