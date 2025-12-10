/*
Copyright 2025 The Hyperlight Authors.

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
#[cfg(crashdump)]
use std::path::Path;
#[cfg(any(kvm, mshv3))]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU8;
#[cfg(any(kvm, mshv3))]
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use log::LevelFilter;
use tracing::{Span, instrument};
#[cfg(feature = "trace_guest")]
use tracing_opentelemetry::OpenTelemetrySpanExt;

#[cfg(gdb)]
use super::gdb::{DebugCommChannel, DebugMsg, DebugResponse, DebuggableVm, VcpuStopReason, arch};
use super::regs::{CommonFpu, CommonRegisters};
#[cfg(target_os = "windows")]
use super::{PartitionState, WindowsInterruptHandle};
use crate::HyperlightError::{ExecutionCanceledByHost, NoHypervisorFound};
#[cfg(not(gdb))]
use crate::hypervisor::Hypervisor;
#[cfg(any(kvm, mshv3))]
use crate::hypervisor::LinuxInterruptHandle;
#[cfg(crashdump)]
use crate::hypervisor::crashdump;
#[cfg(mshv3)]
use crate::hypervisor::hyperv_linux::MshvVm;
#[cfg(target_os = "windows")]
use crate::hypervisor::hyperv_windows::WhpVm;
#[cfg(kvm)]
use crate::hypervisor::kvm::KvmVm;
use crate::hypervisor::regs::CommonSpecialRegisters;
#[cfg(target_os = "windows")]
use crate::hypervisor::wrappers::HandleWrapper;
use crate::hypervisor::{HyperlightExit, InterruptHandle, InterruptHandleImpl, get_max_log_level};
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags, MemoryRegionType};
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::ptr::{GuestPtr, RawPtr};
use crate::mem::shared_mem::HostSharedMemory;
use crate::metrics::{METRIC_ERRONEOUS_VCPU_KICKS, METRIC_GUEST_CANCELLATION};
use crate::sandbox::SandboxConfiguration;
use crate::sandbox::host_funcs::FunctionRegistry;
use crate::sandbox::hypervisor::{HypervisorType, get_available_hypervisor};
use crate::sandbox::outb::handle_outb;
#[cfg(feature = "mem_profile")]
use crate::sandbox::trace::MemTraceInfo;
#[cfg(crashdump)]
use crate::sandbox::uninitialized::SandboxRuntimeConfig;
use crate::{HyperlightError, Result, log_then_return, new_error};

/// Represents a Hyperlight Virtual Machine instance.
///
/// This struct manages the lifecycle of the VM, including:
/// - The underlying hypervisor implementation (e.g., KVM, MSHV, WHP).
/// - Memory management, including initial sandbox regions and dynamic mappings.
/// - The vCPU execution loop and handling of VM exits (I/O, MMIO, interrupts).
pub(crate) struct HyperlightVm {
    #[cfg(gdb)]
    vm: Box<dyn DebuggableVm>,
    #[cfg(not(gdb))]
    vm: Box<dyn Hypervisor>,
    page_size: usize,
    entrypoint: u64,
    orig_rsp: GuestPtr,
    interrupt_handle: Arc<dyn InterruptHandleImpl>,

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
        _pml4_addr: u64,
        entrypoint: u64,
        rsp: u64,
        #[cfg_attr(target_os = "windows", allow(unused_variables))] config: &SandboxConfiguration,
        #[cfg(target_os = "windows")] handle: HandleWrapper,
        #[cfg(target_os = "windows")] raw_size: usize,
        #[cfg(gdb)] gdb_conn: Option<DebugCommChannel<DebugResponse, DebugMsg>>,
        #[cfg(crashdump)] rt_cfg: SandboxRuntimeConfig,
        #[cfg(feature = "mem_profile")] trace_info: MemTraceInfo,
    ) -> Result<Self> {
        #[cfg(gdb)]
        type VmType = Box<dyn DebuggableVm>;
        #[cfg(not(gdb))]
        type VmType = Box<dyn Hypervisor>;

        #[cfg_attr(not(gdb), allow(unused_mut))]
        let mut vm: VmType = match get_available_hypervisor() {
            #[cfg(kvm)]
            Some(HypervisorType::Kvm) => Box::new(KvmVm::new()?),
            #[cfg(mshv3)]
            Some(HypervisorType::Mshv) => Box::new(MshvVm::new()?),
            #[cfg(target_os = "windows")]
            Some(HypervisorType::Whp) => Box::new(WhpVm::new(handle, raw_size)?),
            None => return Err(NoHypervisorFound()),
        };

        for (i, region) in mem_regions.iter().enumerate() {
            // Safety: slots are unique and region points to valid memory since we created the regions
            unsafe { vm.map_memory((i as u32, region))? };
        }

        // Mark initial setup as complete for Windows - subsequent map_memory calls will fail
        #[cfg(target_os = "windows")]
        vm.complete_initial_memory_setup();

        #[cfg(feature = "init-paging")]
        vm.set_sregs(&CommonSpecialRegisters::standard_64bit_defaults(_pml4_addr))?;
        #[cfg(not(feature = "init-paging"))]
        vm.set_sregs(&CommonSpecialRegisters::standard_real_mode_defaults())?;
        let rsp_gp = GuestPtr::try_from(RawPtr::from(rsp))?;

        #[cfg(any(kvm, mshv3))]
        let interrupt_handle: Arc<dyn InterruptHandleImpl> = Arc::new(LinuxInterruptHandle {
            state: AtomicU8::new(0),
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
            state: AtomicU8::new(0),
            partition_state: std::sync::RwLock::new(PartitionState {
                handle: vm.partition_handle(),
                dropped: false,
            }),
        });

        #[cfg_attr(not(gdb), allow(unused_mut))]
        let mut ret = Self {
            vm,
            entrypoint,
            orig_rsp: rsp_gp,
            interrupt_handle,
            page_size: 0, // Will be set in `initialise`

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
            // Add breakpoint to the entry point address
            ret.vm.set_debug(true)?;
            ret.vm.add_hw_breakpoint(entrypoint)?;
        }

        Ok(ret)
    }

    /// Initialise the internally stored vCPU with the given PEB address and
    /// random number seed, then run it until a HLT instruction.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn initialise(
        &mut self,
        peb_addr: RawPtr,
        seed: u64,
        page_size: u32,
        mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
        host_funcs: &Arc<Mutex<FunctionRegistry>>,
        guest_max_log_level: Option<LevelFilter>,
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    ) -> Result<()> {
        self.page_size = page_size as usize;

        let guest_max_log_level: u64 = match guest_max_log_level {
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
            rcx: guest_max_log_level,
            rflags: 1 << 1,

            ..Default::default()
        };
        self.vm.set_regs(&regs)?;

        self.run(
            mem_mgr,
            host_funcs,
            #[cfg(gdb)]
            dbg_mem_access_fn,
        )
    }

    /// Map a region of host memory into the sandbox.
    ///
    /// Safety: The caller must ensure that the region points to valid memory and
    /// that the memory is valid for the duration of Self's lifetime.
    /// Depending on the host platform, there are likely alignment
    /// requirements of at least one page for base and len.
    pub(crate) unsafe fn map_region(&mut self, region: &MemoryRegion) -> Result<()> {
        if [
            region.guest_region.start,
            region.guest_region.end,
            region.host_region.start,
            region.host_region.end,
        ]
        .iter()
        .any(|x| x % self.page_size != 0)
        {
            log_then_return!(
                "region is not page-aligned {:x}, {region:?}",
                self.page_size
            );
        }

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

    /// Unmap a memory region from the sandbox
    pub(crate) fn unmap_region(&mut self, region: &MemoryRegion) -> Result<()> {
        let pos = self
            .mmap_regions
            .iter()
            .position(|(_, r)| r == region)
            .ok_or_else(|| new_error!("Region not found in mapped regions"))?;

        let (slot, _) = self.mmap_regions.remove(pos);
        self.freed_slots.push(slot);
        self.vm.unmap_memory((slot, region))?;
        Ok(())
    }

    /// Get the currently mapped dynamic memory regions (not including initial sandbox region)
    pub(crate) fn get_mapped_regions(&self) -> impl Iterator<Item = &MemoryRegion> {
        self.mmap_regions.iter().map(|(_, region)| region)
    }

    /// Dispatch a call from the host to the guest using the given pointer
    /// to the dispatch function _in the guest's address space_.
    ///
    /// Do this by setting the instruction pointer to `dispatch_func_addr`
    /// and then running the execution loop until a halt instruction.
    ///
    /// Returns `Ok` if the call succeeded, and an `Err` if it failed
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn dispatch_call_from_host(
        &mut self,
        dispatch_func_addr: RawPtr,
        mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
        host_funcs: &Arc<Mutex<FunctionRegistry>>,
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
            mem_mgr,
            host_funcs,
            #[cfg(gdb)]
            dbg_mem_access_fn,
        )
    }

    pub(crate) fn interrupt_handle(&self) -> Arc<dyn InterruptHandle> {
        self.interrupt_handle.clone()
    }

    pub(crate) fn clear_cancel(&self) {
        self.interrupt_handle.clear_cancel();
    }

    fn run(
        &mut self,
        mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
        host_funcs: &Arc<Mutex<FunctionRegistry>>,
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    ) -> Result<()> {
        // Keeps the trace context and open spans
        #[cfg(feature = "trace_guest")]
        let mut tc = crate::sandbox::trace::TraceContext::new();

        let result = loop {
            // ===== KILL() TIMING POINT 2: Before set_tid() =====
            // If kill() is called and ran to completion BEFORE this line executes:
            //    - CANCEL_BIT will be set and we will return an early HyperlightExit::Cancelled()
            //      without sending any signals/WHV api calls
            #[cfg(any(kvm, mshv3))]
            self.interrupt_handle.set_tid();
            self.interrupt_handle.set_running();
            // NOTE: `set_running()`` must be called before checking `is_cancelled()`
            // otherwise we risk missing a call to `kill()` because the vcpu would not be marked as running yet so signals won't be sent

            let exit_reason = if self.interrupt_handle.is_cancelled()
                || self.interrupt_handle.is_debug_interrupted()
            {
                Ok(HyperlightExit::Cancelled())
            } else {
                #[cfg(feature = "trace_guest")]
                tc.setup_guest_trace(Span::current().context());

                // ==== KILL() TIMING POINT 3: Before calling run() ====
                // If kill() is called and ran to completion BEFORE this line executes:
                //    - Will still do a VM entry, but signals will be sent until VM exits
                let result = self.vm.run_vcpu();

                // End current host trace by closing the current span that captures traces
                // happening when a guest exits and re-enters.
                #[cfg(feature = "trace_guest")]
                {
                    tc.end_host_trace();
                    // Handle the guest trace data if any
                    let regs = self.vm.regs()?;
                    if let Err(e) = tc.handle_trace(&regs, mem_mgr) {
                        // If no trace data is available, we just log a message and continue
                        // Is this the right thing to do?
                        log::debug!("Error handling guest trace: {:?}", e);
                    }
                }
                result
            };

            // ===== KILL() TIMING POINT 4: Before clear_running() =====
            // If kill() is called and ran to completion BEFORE this line executes:
            //    - CANCEL_BIT will be set. Cancellation is deferred to the next iteration.
            //    - Signals will be sent until `clear_running()` is called, which is ok
            self.interrupt_handle.clear_running();

            // ===== KILL() TIMING POINT 5: Before capturing cancel_requested =====
            // If kill() is called and ran to completion BEFORE this line executes:
            //    - CANCEL_BIT will be set. Cancellation is deferred to the next iteration.
            //    - Signals will not be sent
            let cancel_requested = self.interrupt_handle.is_cancelled();
            let debug_interrupted = self.interrupt_handle.is_debug_interrupted();

            // ===== KILL() TIMING POINT 6: Before checking exit_reason =====
            // If kill() is called and ran to completion BEFORE this line executes:
            //    - CANCEL_BIT will be set. Cancellation is deferred to the next iteration.
            //    - Signals will not be sent
            match exit_reason {
                #[cfg(gdb)]
                Ok(HyperlightExit::Debug { dr6, exception }) => {
                    // Handle debug event (breakpoints)
                    let stop_reason =
                        arch::vcpu_stop_reason(self.vm.as_mut(), dr6, self.entrypoint, exception)?;
                    if let Err(e) = self.handle_debug(dbg_mem_access_fn.clone(), stop_reason) {
                        break Err(e);
                    }
                }

                Ok(HyperlightExit::Halt()) => {
                    break Ok(());
                }
                Ok(HyperlightExit::IoOut(port, data)) => {
                    self.handle_io(mem_mgr, host_funcs, port, data)?
                }
                Ok(HyperlightExit::MmioRead(addr)) => {
                    let all_regions = self.sandbox_regions.iter().chain(self.get_mapped_regions());
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
                            if !mem_mgr.check_stack_guard()? {
                                break Err(HyperlightError::StackOverflow());
                            }

                            break Err(new_error!("MMIO READ access address {:#x}", addr));
                        }
                    }
                }
                Ok(HyperlightExit::MmioWrite(addr)) => {
                    let all_regions = self.sandbox_regions.iter().chain(self.get_mapped_regions());
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
                            if !mem_mgr.check_stack_guard()? {
                                break Err(HyperlightError::StackOverflow());
                            }

                            break Err(new_error!("MMIO WRITE access address {:#x}", addr));
                        }
                    }
                }
                Ok(HyperlightExit::Cancelled()) => {
                    // If cancellation was not requested for this specific guest function call,
                    // the vcpu was interrupted by a stale cancellation. This can occur when:
                    // - Linux: A signal from a previous call arrives late
                    // - Windows: WHvCancelRunVirtualProcessor called right after vcpu exits but RUNNING_BIT is still true
                    if !cancel_requested && !debug_interrupted {
                        // Track that an erroneous vCPU kick occurred
                        metrics::counter!(METRIC_ERRONEOUS_VCPU_KICKS).increment(1);
                        // treat this the same as a HyperlightExit::Retry, the cancel was not meant for this call
                        continue;
                    }

                    // If the vcpu was interrupted by a debugger, we need to handle it
                    #[cfg(gdb)]
                    {
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
                Ok(HyperlightExit::Unknown(reason)) => {
                    break Err(new_error!("Unexpected VM Exit: {:?}", reason));
                }
                Ok(HyperlightExit::Retry()) => continue,
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

    /// Handle an IO exit
    fn handle_io(
        &mut self,
        mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
        host_funcs: &Arc<Mutex<FunctionRegistry>>,
        port: u16,
        data: Vec<u8>,
    ) -> Result<()> {
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
            let regs = self.vm.regs()?;
            handle_outb(mem_mgr, host_funcs, port, val, &regs, &mut self.trace_info)?;
        }

        #[cfg(not(feature = "mem_profile"))]
        {
            handle_outb(mem_mgr, host_funcs, port, val)?;
        }

        Ok(())
    }

    // Handle a debug exit
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
            guest_mmap_regions: self.get_mapped_regions().cloned().collect(),
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

    #[cfg(crashdump)]
    pub(crate) fn crashdump_context(&self) -> Result<Option<super::crashdump::CrashDumpContext>> {
        if self.rt_cfg.guest_core_dump {
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
            regions.extend(self.get_mapped_regions().cloned());
            Ok(Some(crashdump::CrashDumpContext::new(
                regions,
                regs,
                xsave.to_vec(),
                self.entrypoint,
                self.rt_cfg.binary_path.clone(),
                filename,
            )))
        } else {
            Ok(None)
        }
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

/// Determines if a known memory access violation occurred at the given address with the given action type.
/// Returns Some(reason) if violation reason could be determined, or None if violation occurred but in unmapped region.
fn get_memory_access_violation<'a>(
    gpa: usize,
    tried: MemoryRegionFlags,
    mut mem_regions: impl Iterator<Item = &'a MemoryRegion>,
) -> Option<MemoryAccess> {
    let region = mem_regions.find(|region| region.guest_region.contains(&gpa))?;
    if region.region_type == MemoryRegionType::GuardPage {
        return Some(MemoryAccess::StackGuardPageViolation);
    }
    if !region.flags.contains(tried) {
        return Some(MemoryAccess::AccessViolation(region.flags));
    }
    // gpa is in `region`, and region allows the tried access, but we got here anyway.
    // Treat as a generic access violation for now, unsure if this is reachable.
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
