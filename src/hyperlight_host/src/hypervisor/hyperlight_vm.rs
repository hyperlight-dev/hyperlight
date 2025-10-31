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
#[cfg(gdb)]
use std::collections::HashMap;
use std::convert::TryFrom;
#[cfg(crashdump)]
use std::path::Path;
#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicBool, AtomicU64};
#[cfg(any(kvm, mshv3))]
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex};

use log::LevelFilter;
use tracing::{Span, instrument};
#[cfg(feature = "trace_guest")]
use tracing_opentelemetry::OpenTelemetrySpanExt;

#[cfg(any(kvm, mshv3))]
use super::LinuxInterruptHandle;
#[cfg(target_os = "windows")]
use super::WindowsInterruptHandle;
#[cfg(gdb)]
use super::gdb::{DebugCommChannel, DebugMsg, DebugResponse, VcpuStopReason, arch};
use super::regs::{CommonFpu, CommonRegisters};
use super::{InterruptHandle, InterruptHandleImpl, get_max_log_level};
use crate::HyperlightError::{ExecutionCanceledByHost, NoHypervisorFound};
#[cfg(crashdump)]
use crate::hypervisor::crashdump;
#[cfg(mshv3)]
use crate::hypervisor::hyperv_linux::MshvVm;
#[cfg(target_os = "windows")]
use crate::hypervisor::hyperv_windows::WhpVm;
#[cfg(kvm)]
use crate::hypervisor::kvm::KvmVm;
use crate::hypervisor::regs::{CommonDebugRegs, CommonSpecialRegisters};
use crate::hypervisor::vm::{Vm, VmExit};
#[cfg(target_os = "windows")]
use crate::hypervisor::wrappers::HandleWrapper;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags, MemoryRegionType};
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::ptr::{GuestPtr, RawPtr};
use crate::mem::shared_mem::HostSharedMemory;
use crate::metrics::METRIC_GUEST_CANCELLATION;
use crate::sandbox::SandboxConfiguration;
use crate::sandbox::host_funcs::FunctionRegistry;
use crate::sandbox::hypervisor::{HypervisorType, get_available_hypervisor};
use crate::sandbox::outb::handle_outb;
#[cfg(feature = "mem_profile")]
use crate::sandbox::trace::MemTraceInfo;
#[cfg(crashdump)]
use crate::sandbox::uninitialized::SandboxRuntimeConfig;
use crate::{HyperlightError, Result, log_then_return, new_error};

pub(crate) struct HyperlightVm {
    vm: Box<dyn Vm>,
    page_size: usize,
    entrypoint: u64,
    orig_rsp: GuestPtr,
    interrupt_handle: Arc<dyn InterruptHandleImpl>,
    mem_mgr: Option<SandboxMemoryManager<HostSharedMemory>>,
    host_funcs: Option<Arc<Mutex<FunctionRegistry>>>,

    sandbox_regions: Vec<MemoryRegion>, // Initially mapped regions when sandbox is created
    mmap_regions: Vec<(u32, MemoryRegion)>, // Later mapped regions (slot number, region)
    next_slot: u32,                     // Monotonically increasing slot number
    freed_slots: Vec<u32>,              // Reusable slots from unmapped regions

    #[cfg(gdb)]
    gdb_conn: Option<DebugCommChannel<DebugResponse, DebugMsg>>,
    #[cfg(gdb)]
    sw_breakpoints: HashMap<u64, u8>, // addr -> original instruction
    #[cfg(feature = "mem_profile")]
    trace_info: MemTraceInfo,
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
        #[cfg_attr(not(any(kvm, mshv3)), allow(unused_variables))] config: &SandboxConfiguration,
        #[cfg(target_os = "windows")] handle: HandleWrapper,
        #[cfg(target_os = "windows")] raw_size: usize,
        #[cfg(gdb)] gdb_conn: Option<DebugCommChannel<DebugResponse, DebugMsg>>,
        #[cfg(crashdump)] rt_cfg: SandboxRuntimeConfig,
        #[cfg(feature = "mem_profile")] trace_info: MemTraceInfo,
    ) -> Result<Self> {
        #[allow(unused_mut)] // needs to be mutable when gdb is enabled
        let mut vm: Box<dyn Vm> = match get_available_hypervisor() {
            #[cfg(kvm)]
            Some(HypervisorType::Kvm) => Box::new(KvmVm::new()?),
            #[cfg(mshv3)]
            Some(HypervisorType::Mshv) => Box::new(MshvVm::new()?),
            #[cfg(target_os = "windows")]
            Some(HypervisorType::Whp) => Box::new(WhpVm::new(handle, raw_size)?),
            None => return Err(NoHypervisorFound()),
        };

        vm.enable_msr_intercept()?;

        for (i, region) in mem_regions.iter().enumerate() {
            // Safety: slots are unique and region points to valid memory since we created the regions
            unsafe { vm.map_memory((i as u32, region))? };
        }

        // Mark initial setup as complete for Windows - subsequent map_memory calls will fail
        #[cfg(target_os = "windows")]
        vm.complete_initial_memory_setup();

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

        #[cfg(any(kvm, mshv3))]
        let interrupt_handle: Arc<dyn InterruptHandleImpl> = Arc::new(LinuxInterruptHandle {
            running: AtomicU64::new(0),
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

        #[cfg(target_os = "windows")]
        let interrupt_handle: Arc<dyn InterruptHandleImpl> = Arc::new(WindowsInterruptHandle {
            state: AtomicU64::new(0),
            #[cfg(gdb)]
            debug_interrupt: AtomicBool::new(false),
            partition_handle: vm.partition_handle(),
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
            #[cfg(gdb)]
            sw_breakpoints: HashMap::new(),
            #[cfg(feature = "mem_profile")]
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

        #[cfg(feature = "mem_profile")]
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

            handle_outb(&mut mem_mgr, host_funcs, port, val, self)?;

            // Put the mem_mgr back
            self.mem_mgr = Some(mem_mgr);
        }

        #[cfg(not(feature = "mem_profile"))]
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
        // ===== KILL() TIMING POINT 1: Between guest function calls =====
        // Clear any stale cancellation from a previous guest function call or if kill() was called too early.
        // This ensures that kill() called BETWEEN different guest function calls doesn't affect the next call.
        //
        // If kill() was called and ran to completion BEFORE this line executes:
        //    - kill() has NO effect on this guest function call because CANCEL_BIT is cleared here.
        //    - NOTE: stale signals can still be delivered, but they will be ignored.
        self.interrupt_handle.clear_cancel();

        // Keeps the trace context and open spans
        #[cfg(feature = "trace_guest")]
        let mut tc = crate::sandbox::trace::TraceContext::new();

        let result = loop {
            // ===== KILL() TIMING POINT 2: Before set_tid() =====
            // If kill() is called and ran to completion BEFORE this line executes:
            //    - CANCEL_BIT will be set and we will return an early VmExit::Cancelled()
            self.interrupt_handle.set_tid();
            self.interrupt_handle.set_running();

            let exit_reason = if self.interrupt_handle.is_cancelled()
                || self.interrupt_handle.is_debug_interrupted()
            {
                Ok(VmExit::Cancelled())
            } else {
                #[cfg(feature = "trace_guest")]
                tc.setup_guest_trace(Span::current().context());

                // ===== KILL() TIMING POINT 3: Before calling run_vcpu() =====
                // If kill() is called and ran to completion BEFORE this line executes:
                //    - CANCEL_BIT will be set, but it's too late to prevent entering the guest this iteration
                //    - Signals will interrupt the guest (RUNNING_BIT=true), causing VmExit::Cancelled()
                //    - If the guest completes before any signals arrive, kill() may have no effect
                //      - If there are more iterations to do (IO/host func, etc.), the next iteration will be cancelled
                let exit_reason = self.vm.run_vcpu();

                // End current host trace by closing the current span that captures traces
                // happening when a guest exits and re-enters.
                #[cfg(feature = "trace_guest")]
                tc.end_host_trace();

                // Handle the guest trace data if any
                #[cfg(feature = "trace_guest")]
                if let Err(e) = self.handle_trace(&mut tc) {
                    // If no trace data is available, we just log a message and continue
                    // Is this the right thing to do?
                    log::debug!("Error handling guest trace: {:?}", e);
                }
                exit_reason
            };

            // ===== KILL() TIMING POINT 4: Before capturing cancel_requested =====
            // If kill() is called and ran to completion BEFORE this line executes:
            //    - CANCEL_BIT will be set
            //    - Signals may still be sent (RUNNING_BIT=true) but are harmless no-ops
            //    - kill() will have no effect on this iteration, but CANCEL_BIT will persist
            //    - If the loop continues (e.g., for a host call), the next iteration will be cancelled
            //    - Stale signals from before clear_running() may arrive and kick future iterations,
            //      but will be filtered out by the cancel_requested check below (and retried).
            let cancel_requested = self.interrupt_handle.is_cancelled();
            let debug_interrupted = self.interrupt_handle.is_debug_interrupted();

            // ===== KILL() TIMING POINT 5: Before calling clear_running() =====
            // Same as point 4.
            self.interrupt_handle.clear_running();

            // ===== KILL() TIMING POINT 6: After calling clear_running() =====
            // If kill() is called and ran to completion BEFORE this line executes:
            //    - CANCEL_BIT will be set but won't affect this iteration, it is never read below this comment
            //      and cleared at next run() start
            //    - RUNNING_BIT=false, so no new signals will be sent
            //    - Stale signals from before clear_running() may arrive and kick future iterations,
            //      but will be filtered out by the cancel_requested check below (and retried).
            match exit_reason {
                #[cfg(gdb)]
                Ok(VmExit::Debug { dr6, exception }) => {
                    // Handle debug event (breakpoints)
                    let stop_reason =
                        arch::vcpu_stop_reason(self.vm.as_mut(), self.entrypoint, dr6, exception)?;
                    if let Err(e) = self.handle_debug(dbg_mem_access_fn.clone(), stop_reason) {
                        break Err(e);
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
                Ok(VmExit::MsrRead(msr_index)) => {
                    break Err(HyperlightError::MsrReadViolation(msr_index));
                }
                Ok(VmExit::MsrWrite { msr_index, value }) => {
                    break Err(HyperlightError::MsrWriteViolation(msr_index, value));
                }
                Ok(VmExit::Cancelled()) => {
                    // If cancellation was not requested for this specific guest function call,
                    // the vcpu was interrupted by a stale cancellation from a previous call
                    if !cancel_requested && !debug_interrupted {
                        // treat this the same as a VmExit::Retry, the cancel was not meant for this call
                        continue;
                    }

                    #[cfg(gdb)]
                    if debug_interrupted {
                        // If the vcpu was interrupted by a debugger, we need to handle it
                        self.interrupt_handle.clear_debug_interrupt();
                        if let Err(e) =
                            self.handle_debug(dbg_mem_access_fn.clone(), VcpuStopReason::Interrupt)
                        {
                            break Err(e);
                        }
                    }

                    metrics::counter!(METRIC_GUEST_CANCELLATION).increment(1);
                    break Err(ExecutionCanceledByHost());
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
                if self.gdb_conn.is_some() {
                    self.handle_debug(dbg_mem_access_fn.clone(), VcpuStopReason::Crash)?;
                }

                log_then_return!(e);
            }
        }
    }

    pub(crate) fn interrupt_handle(&self) -> Arc<dyn InterruptHandle> {
        self.interrupt_handle.clone()
    }

    pub(crate) fn reset_vcpu(&self) -> Result<()> {
        self.vm.set_regs(&CommonRegisters::default())?;
        self.vm.set_sregs(&CommonSpecialRegisters::default())?;
        self.vm.set_fpu(&CommonFpu::default())?;
        self.vm.set_xsave(&[0; 1024])?;
        self.vm.set_debug_regs(&CommonDebugRegs::default())?;
        // TODO reset MSRs
        Ok(())
    }

    #[cfg(gdb)]
    fn handle_debug(
        &mut self,
        dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
        stop_reason: VcpuStopReason,
    ) -> Result<()> {
        use crate::hypervisor::gdb::DebugMemoryAccess;

        if self.gdb_conn.is_none() {
            return Err(new_error!("Debugging is not enabled"));
        }

        let mem_access = DebugMemoryAccess {
            dbg_mem_access_fn,
            guest_mmap_regions: self.mmap_regions.iter().map(|(_, r)| r.clone()).collect(),
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
                // Send the stop reason to the gdb thread
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

    // --------------------------
    // --- CRASHDUMP BELOW ------
    // --------------------------

    #[cfg(crashdump)]
    pub(crate) fn crashdump_context(&self) -> Result<super::crashdump::CrashDumpContext> {
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
            Path::new(&path)
                .file_name()
                .and_then(|name| name.to_os_string().into_string().ok())
        });

        // Include both initial sandbox regions and dynamically mapped regions
        let mut regions: Vec<MemoryRegion> = self.sandbox_regions.clone();
        regions.extend(self.mmap_regions.iter().map(|(_, r)| r).cloned());
        Ok(crashdump::CrashDumpContext::new(
            regions,
            regs,
            xsave.to_vec(),
            self.entrypoint,
            self.rt_cfg.binary_path.clone(),
            filename,
        ))
    }

    #[cfg(feature = "mem_profile")]
    pub(crate) fn vm_regs(&self) -> Result<CommonRegisters> {
        self.vm.regs()
    }

    #[cfg(feature = "trace_guest")]
    fn handle_trace(&mut self, tc: &mut crate::sandbox::trace::TraceContext) -> Result<()> {
        let regs = self.vm.regs()?;
        tc.handle_trace(
            &regs,
            self.mem_mgr.as_ref().ok_or_else(|| {
                new_error!("Memory manager is not initialized before handling trace")
            })?,
        )
    }

    #[cfg(feature = "mem_profile")]
    pub(crate) fn trace_info_mut(&mut self) -> &mut MemTraceInfo {
        &mut self.trace_info
    }
}

impl Drop for HyperlightVm {
    fn drop(&mut self) {
        self.interrupt_handle.set_dropped();
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
    use hyperlight_common::mem::PAGE_SIZE;

    use super::HyperlightVm;
    use crate::hypervisor::gdb::arch::{SW_BP, SW_BP_SIZE};
    use crate::hypervisor::gdb::{DebugMemoryAccess, DebugMsg, DebugResponse};
    use crate::{Result, new_error};

    impl HyperlightVm {
        pub(crate) fn process_dbg_request(
            &mut self,
            req: DebugMsg,
            mem_access: &DebugMemoryAccess,
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
                        self.add_sw_breakpoint(addr, mem_access)
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

                        self.read_addrs(addr, &mut data, mem_access).map_err(|e| {
                            log::error!("Failed to read from address: {:?}", e);

                            e
                        })?;

                        Ok(DebugResponse::ReadAddr(data))
                    }
                    DebugMsg::ReadRegisters => {
                        let regs = self.vm.regs()?;
                        let fpu = self.vm.fpu()?;
                        Ok(DebugResponse::ReadRegisters(Box::new((regs, fpu))))
                    }
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
                        self.remove_sw_breakpoint(addr, mem_access)
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
                        self.write_addrs(addr, &data, mem_access).map_err(|e| {
                            log::error!("Failed to write to address: {:?}", e);

                            e
                        })?;

                        Ok(DebugResponse::WriteAddr)
                    }
                    DebugMsg::WriteRegisters(boxed_regs) => {
                        let (regs, fpu) = boxed_regs.as_ref();
                        self.vm.set_regs(regs)?;
                        self.vm.set_fpu(fpu)?;

                        Ok(DebugResponse::WriteRegisters)
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
            mem_access: &DebugMemoryAccess,
        ) -> crate::Result<()> {
            let data_len = data.len();
            log::debug!("Read addr: {:X} len: {:X}", gva, data_len);

            while !data.is_empty() {
                let gpa = self.vm.translate_gva(gva)?;

                let read_len = std::cmp::min(
                    data.len(),
                    (PAGE_SIZE - (gpa & (PAGE_SIZE - 1))).try_into().unwrap(),
                );

                mem_access.read(&mut data[..read_len], gpa)?;

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
            mem_access: &DebugMemoryAccess,
        ) -> crate::Result<()> {
            let data_len = data.len();
            log::debug!("Write addr: {:X} len: {:X}", gva, data_len);

            while !data.is_empty() {
                let gpa = self.vm.translate_gva(gva)?;

                let write_len = std::cmp::min(
                    data.len(),
                    (PAGE_SIZE - (gpa & (PAGE_SIZE - 1))).try_into().unwrap(),
                );

                // Use the memory access to write to guest memory
                mem_access.write(&data[..write_len], gpa)?;

                data = &data[write_len..];
                gva += write_len as u64;
            }

            Ok(())
        }

        // Must be idempotent!
        fn add_sw_breakpoint(
            &mut self,
            addr: u64,
            mem_access: &DebugMemoryAccess,
        ) -> crate::Result<()> {
            let addr = self.vm.translate_gva(addr)?;

            // Check if breakpoint already exists
            if self.sw_breakpoints.contains_key(&addr) {
                return Ok(());
            }

            // Write breakpoint OP code to write to guest memory
            let mut save_data = [0; SW_BP_SIZE];
            self.read_addrs(addr, &mut save_data[..], mem_access)?;
            self.write_addrs(addr, &SW_BP, mem_access)?;

            // Save guest memory to restore when breakpoint is removed
            self.sw_breakpoints.insert(addr, save_data[0]);

            Ok(())
        }

        fn remove_sw_breakpoint(
            &mut self,
            addr: u64,
            mem_access: &DebugMemoryAccess,
        ) -> crate::Result<()> {
            let addr = self.vm.translate_gva(addr)?;

            if let Some(saved_data) = self.sw_breakpoints.remove(&addr) {
                // Restore saved data to the guest's memory
                self.write_addrs(addr, &[saved_data], mem_access)?;

                Ok(())
            } else {
                Err(new_error!("The address: {:?} is not a sw breakpoint", addr))
            }
        }
    }
}
