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
#[cfg(any(kvm, mshv3))]
use crate::hypervisor::LinuxInterruptHandle;
#[cfg(crashdump)]
use crate::hypervisor::crashdump;
use crate::hypervisor::regs::{CommonDebugRegs, CommonSpecialRegisters};
#[cfg(not(gdb))]
use crate::hypervisor::virtual_machine::VirtualMachine;
#[cfg(kvm)]
use crate::hypervisor::virtual_machine::kvm::KvmVm;
#[cfg(mshv3)]
use crate::hypervisor::virtual_machine::mshv::MshvVm;
#[cfg(target_os = "windows")]
use crate::hypervisor::virtual_machine::whp::WhpVm;
use crate::hypervisor::virtual_machine::{HypervisorType, VmExit, get_available_hypervisor};
#[cfg(target_os = "windows")]
use crate::hypervisor::wrappers::HandleWrapper;
use crate::hypervisor::{InterruptHandle, InterruptHandleImpl, get_max_log_level};
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags, MemoryRegionType};
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::ptr::{GuestPtr, RawPtr};
use crate::mem::shared_mem::HostSharedMemory;
use crate::metrics::{METRIC_ERRONEOUS_VCPU_KICKS, METRIC_GUEST_CANCELLATION};
use crate::sandbox::SandboxConfiguration;
use crate::sandbox::host_funcs::FunctionRegistry;
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
    vm: Box<dyn VirtualMachine>,
    page_size: usize,
    entrypoint: u64,
    orig_rsp: GuestPtr,
    interrupt_handle: Arc<dyn InterruptHandleImpl>,

    sandbox_regions: Vec<MemoryRegion>, // Initially mapped regions when sandbox is created
    mmap_regions: Vec<(u32, MemoryRegion)>, // Later mapped regions (slot number, region)
    next_slot: u32,                     // Monotonically increasing slot number
    freed_slots: Vec<u32>,              // Reusable slots from unmapped regions

    // pml4 saved to be able to restore it if needed
    #[cfg(feature = "init-paging")]
    pml4_addr: u64,
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
        type VmType = Box<dyn VirtualMachine>;

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

            #[cfg(feature = "init-paging")]
            pml4_addr: _pml4_addr,
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
            //    - CANCEL_BIT will be set and we will return an early VmExit::Cancelled()
            //      without sending any signals/WHV api calls
            #[cfg(any(kvm, mshv3))]
            self.interrupt_handle.set_tid();
            self.interrupt_handle.set_running();
            // NOTE: `set_running()`` must be called before checking `is_cancelled()`
            // otherwise we risk missing a call to `kill()` because the vcpu would not be marked as running yet so signals won't be sent

            let exit_reason = if self.interrupt_handle.is_cancelled()
                || self.interrupt_handle.is_debug_interrupted()
            {
                Ok(VmExit::Cancelled())
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
                Ok(VmExit::Debug { dr6, exception }) => {
                    // Handle debug event (breakpoints)
                    let stop_reason =
                        arch::vcpu_stop_reason(self.vm.as_mut(), dr6, self.entrypoint, exception)?;
                    if let Err(e) = self.handle_debug(dbg_mem_access_fn.clone(), stop_reason) {
                        break Err(e);
                    }
                }

                Ok(VmExit::Halt()) => {
                    break Ok(());
                }
                Ok(VmExit::IoOut(port, data)) => self.handle_io(mem_mgr, host_funcs, port, data)?,
                Ok(VmExit::MmioRead(addr)) => {
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
                Ok(VmExit::MmioWrite(addr)) => {
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
                Ok(VmExit::Cancelled()) => {
                    // If cancellation was not requested for this specific guest function call,
                    // the vcpu was interrupted by a stale cancellation. This can occur when:
                    // - Linux: A signal from a previous call arrives late
                    // - Windows: WHvCancelRunVirtualProcessor called right after vcpu exits but RUNNING_BIT is still true
                    if !cancel_requested && !debug_interrupted {
                        // Track that an erroneous vCPU kick occurred
                        metrics::counter!(METRIC_ERRONEOUS_VCPU_KICKS).increment(1);
                        // treat this the same as a VmExit::Retry, the cancel was not meant for this call
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

    // Resets the following vCPU state:
    // - General purpose registers
    // - Debug registers
    // - XSAVE (overlaps with FPU)
    // - FPU registers (to set default FPU state)
    // - Special registers (with saved PML4 if feature enabled)
    // TODO: check if we can't avoid calling set_fpu and only use reset_xsave
    // TODO: check if other state needs to be reset
    pub(crate) fn reset_vcpu(&self) -> Result<()> {
        self.vm.set_regs(&CommonRegisters {
            rflags: 1 << 1, // Reserved bit always set
            ..Default::default()
        })?;
        self.vm.set_debug_regs(&CommonDebugRegs::default())?;
        // Note: On KVM this ignores MXCSR so it's being set as part of reset_xsave.
        // See https://github.com/torvalds/linux/blob/d358e5254674b70f34c847715ca509e46eb81e6f/arch/x86/kvm/x86.c#L12554-L12599
        self.vm.set_fpu(&CommonFpu::default())?;
        self.vm.reset_xsave()?;
        #[cfg(feature = "init-paging")]
        self.vm
            .set_sregs(&CommonSpecialRegisters::standard_64bit_defaults(
                self.pml4_addr,
            ))?;
        #[cfg(not(feature = "init-paging"))]
        self.vm
            .set_sregs(&CommonSpecialRegisters::standard_real_mode_defaults())?;

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

#[cfg(test)]
#[cfg(feature = "init-paging")]
#[allow(clippy::needless_range_loop)]
mod tests {
    use std::sync::{Arc, Mutex};

    use rand::Rng;

    use super::*;
    #[cfg(kvm)]
    use crate::hypervisor::regs::FP_CONTROL_WORD_DEFAULT;
    use crate::hypervisor::regs::{CommonSegmentRegister, CommonTableRegister, MXCSR_DEFAULT};
    #[cfg(target_os = "windows")]
    use crate::hypervisor::wrappers::HandleWrapper;
    use crate::mem::exe::LoadInfo;
    use crate::mem::layout::SandboxMemoryLayout;
    use crate::mem::mgr::SandboxMemoryManager;
    use crate::mem::ptr::RawPtr;
    use crate::mem::ptr_offset::Offset;
    use crate::mem::shared_mem::ExclusiveSharedMemory;
    use crate::sandbox::SandboxConfiguration;
    use crate::sandbox::host_funcs::FunctionRegistry;
    #[cfg(crashdump)]
    use crate::sandbox::uninitialized::SandboxRuntimeConfig;
    use crate::sandbox::uninitialized_evolve::set_up_hypervisor_partition;

    /// Build dirty general purpose registers for testing reset_vcpu.
    fn dirty_regs() -> CommonRegisters {
        CommonRegisters {
            rax: 0x1111111111111111,
            rbx: 0x2222222222222222,
            rcx: 0x3333333333333333,
            rdx: 0x4444444444444444,
            rsi: 0x5555555555555555,
            rdi: 0x6666666666666666,
            rsp: 0x7777777777777777,
            rbp: 0x8888888888888888,
            r8: 0x9999999999999999,
            r9: 0xAAAAAAAAAAAAAAAA,
            r10: 0xBBBBBBBBBBBBBBBB,
            r11: 0xCCCCCCCCCCCCCCCC,
            r12: 0xDDDDDDDDDDDDDDDD,
            r13: 0xEEEEEEEEEEEEEEEE,
            r14: 0xFFFFFFFFFFFFFFFF,
            r15: 0x0123456789ABCDEF,
            rip: 0xFEDCBA9876543210,
            rflags: 0x202, // IF + reserved bit 1
        }
    }

    /// Build dirty FPU state for testing reset_vcpu.
    fn dirty_fpu() -> CommonFpu {
        CommonFpu {
            fpr: [[0xAB; 16]; 8],
            fcw: 0x0F7F, // Different from default 0x037F
            fsw: 0x1234,
            ftwx: 0xAB,
            last_opcode: 0x0123,
            last_ip: 0xDEADBEEF00000000,
            last_dp: 0xCAFEBABE00000000,
            xmm: [[0xCD; 16]; 16],
            mxcsr: 0x3F80, // Different from default 0x1F80
        }
    }

    /// Build dirty special registers for testing reset_vcpu.
    /// Must be consistent for 64-bit long mode (CR0/CR4/EFER).
    fn dirty_sregs(_pml4_addr: u64) -> CommonSpecialRegisters {
        let segment = CommonSegmentRegister {
            base: 0x1000,
            limit: 0xFFFF,
            selector: 0x10,
            type_: 3, // data segment, read/write, accessed
            present: 1,
            dpl: 0,
            db: 1,
            s: 1,
            l: 0,
            g: 1,
            avl: 1,
            unusable: 0,
            padding: 0,
        };
        // CS segment - 64-bit code segment
        let cs_segment = CommonSegmentRegister {
            base: 0,
            limit: 0xFFFF,
            selector: 0x08,
            type_: 0b1011, // code segment, execute/read, accessed
            present: 1,
            dpl: 0,
            db: 0, // must be 0 in 64-bit mode
            s: 1,
            l: 1, // 64-bit mode
            g: 1,
            avl: 0,
            unusable: 0,
            padding: 0,
        };
        let table = CommonTableRegister {
            base: 0xDEAD0000,
            limit: 0xFFFF,
        };
        CommonSpecialRegisters {
            cs: cs_segment,
            ds: segment,
            es: segment,
            fs: segment,
            gs: segment,
            ss: segment,
            tr: CommonSegmentRegister {
                type_: 0b1011, // busy TSS
                present: 1,
                ..segment
            },
            ldt: segment,
            gdt: table,
            idt: table,
            cr0: 0x80000011, // PE + ET + PG
            cr2: 0xBADC0DE,
            // MSHV validates cr3 and rejects bogus values; use valid _pml4_addr for MSHV
            cr3: match get_available_hypervisor() {
                #[cfg(mshv3)]
                Some(HypervisorType::Mshv) => _pml4_addr,
                _ => 0x12345000,
            },
            cr4: 0x20, // PAE
            cr8: 0x5,
            efer: 0x500, // LME + LMA
            apic_base: 0xFEE00900,
            // interrupt_bitmap: [0xFFFFFFFF; 4],
            interrupt_bitmap: [0; 4], // fails if non-zero on MSHV
        }
    }

    /// Build dirty debug registers for testing reset_vcpu.
    ///
    /// DR6 bit layout (Intel SDM / AMD APM):
    ///   Bits 0-3 (B0-B3): Breakpoint condition detected - software writable/clearable
    ///   Bits 4-10: Reserved, read as 1s on modern processors (read-only)
    ///   Bit 11 (BLD): Bus Lock Trap - cleared by processor, read-only on older CPUs
    ///   Bit 12: Reserved, always 0
    ///   Bit 13 (BD): Debug Register Access Detected - software clearable
    ///   Bit 14 (BS): Single-Step - software clearable
    ///   Bit 15 (BT): Task Switch breakpoint - software clearable
    ///   Bit 16 (RTM): TSX-related, read-only (1 if no TSX)
    ///   Bits 17-31: Reserved, read as 1s on modern processors (read-only)
    ///   Bits 32-63: Reserved, must be 0
    ///
    /// Writable bits: 0-3, 13, 14, 15 = mask 0xE00F
    /// Reserved 1s: 4-10, 11 (if no BLD), 16 (if no TSX), 17-31 = ~0xE00F on lower 32 bits
    const DR6_WRITABLE_MASK: u64 = 0xE00F; // B0-B3, BD, BS, BT

    /// DR7 bit layout:
    ///   Bits 0-7 (L0-L3, G0-G3): Local/global breakpoint enables - writable
    ///   Bits 8-9 (LE, GE): Local/Global Exact (386 only, ignored on modern) - writable
    ///   Bit 10: Reserved, must be 1 (read-only)
    ///   Bits 11-12: Reserved (RTM/TSX on some CPUs), must be 0 (read-only)
    ///   Bit 13 (GD): General Detect Enable - writable
    ///   Bits 14-15: Reserved, must be 0 (read-only)
    ///   Bits 16-31 (R/W0-3, LEN0-3): Breakpoint conditions and lengths - writable
    ///   Bits 32-63: Reserved, must be 0 (read-only)
    ///
    /// Writable bits: 0-9, 13, 16-31 = mask 0xFFFF23FF
    const DR7_WRITABLE_MASK: u64 = 0xFFFF_23FF;

    fn dirty_debug_regs() -> CommonDebugRegs {
        CommonDebugRegs {
            dr0: 0xDEADBEEF00001000,
            dr1: 0xDEADBEEF00002000,
            dr2: 0xDEADBEEF00003000,
            dr3: 0xDEADBEEF00004000,
            // Set all writable bits: B0-B3 (0-3), BD (13), BS (14), BT (15)
            dr6: DR6_WRITABLE_MASK,
            // Set writable bits: L0-L3, G0-G3 (0-7), LE/GE (8-9), GD (13), conditions (16-31)
            dr7: DR7_WRITABLE_MASK,
        }
    }

    /// Query CPUID.0DH.n for XSAVE component info.
    /// Returns (size, offset, align_64) for the given component:
    /// - size: CPUID.0DH.n:EAX - size in bytes
    /// - offset: CPUID.0DH.n:EBX - offset from XSAVE base (standard format only)
    /// - align_64: CPUID.0DH.n:ECX bit 1 - true if 64-byte aligned (compacted format)
    fn xsave_component_info(comp_id: u32) -> (usize, usize, bool) {
        let result = unsafe { std::arch::x86_64::__cpuid_count(0xD, comp_id) };
        let size = result.eax as usize;
        let offset = result.ebx as usize;
        let align_64 = (result.ecx & 0b10) != 0;
        (size, offset, align_64)
    }

    /// Query CPUID.0DH.00H for the bitmap of supported user state components.
    /// EDX:EAX forms a 64-bit bitmap where bit i indicates support for component i.
    fn xsave_supported_components() -> u64 {
        let result = unsafe { std::arch::x86_64::__cpuid_count(0xD, 0) };
        (result.edx as u64) << 32 | (result.eax as u64)
    }

    /// Dirty extended state components using compacted XSAVE format (MSHV/WHP).
    /// Components are stored contiguously starting at byte 576, with alignment
    /// requirements from CPUID.0DH.n:ECX[1].
    /// Returns a bitmask of components that were actually dirtied.
    fn dirty_xsave_extended_compacted(
        xsave: &mut [u32],
        xcomp_bv: u64,
        supported_components: u64,
    ) -> u64 {
        let mut dirtied_mask = 0u64;
        let mut offset = 576usize;

        for comp_id in 2..63u32 {
            // Skip if component not supported by CPU or not enabled in XCOMP_BV
            if (supported_components & (1u64 << comp_id)) == 0 {
                continue;
            }
            if (xcomp_bv & (1u64 << comp_id)) == 0 {
                continue;
            }

            let (size, _, align_64) = xsave_component_info(comp_id);

            // ECX[1]=1 means 64-byte aligned; ECX[1]=0 means immediately after previous
            if align_64 {
                offset = offset.next_multiple_of(64);
            }

            // Dirty this component's data area (only if it fits in the buffer)
            let start_idx = offset / 4;
            let end_idx = (offset + size) / 4;
            if end_idx <= xsave.len() {
                for i in start_idx..end_idx {
                    xsave[i] = 0x12345678 ^ comp_id.wrapping_mul(0x11111111);
                }
                dirtied_mask |= 1u64 << comp_id;
            }

            offset += size;
        }

        dirtied_mask
    }

    /// Dirty extended state components using standard XSAVE format (KVM).
    /// Components are at fixed offsets from CPUID.0DH.n:EBX.
    /// Returns a bitmask of components that were actually dirtied.
    fn dirty_xsave_extended_standard(xsave: &mut [u32], supported_components: u64) -> u64 {
        let mut dirtied_mask = 0u64;

        for comp_id in 2..63u32 {
            // Skip if component not supported by CPU
            if (supported_components & (1u64 << comp_id)) == 0 {
                continue;
            }

            let (size, fixed_offset, _) = xsave_component_info(comp_id);

            let start_idx = fixed_offset / 4;
            let end_idx = (fixed_offset + size) / 4;
            if end_idx <= xsave.len() {
                for i in start_idx..end_idx {
                    xsave[i] = 0x12345678 ^ comp_id.wrapping_mul(0x11111111);
                }
                dirtied_mask |= 1u64 << comp_id;
            }
        }

        dirtied_mask
    }

    /// Dirty the legacy XSAVE region (bytes 0-511) for testing reset_vcpu.
    /// This includes FPU/x87 state, SSE state, and reserved areas.
    ///
    /// Layout (from Intel SDM Table 13-1):
    ///   Bytes 0-1: FCW, 2-3: FSW, 4: FTW, 5: reserved, 6-7: FOP
    ///   Bytes 8-15: FIP, 16-23: FDP
    ///   Bytes 24-27: MXCSR, 28-31: MXCSR_MASK (preserve - hardware defined)
    ///   Bytes 32-159: ST0-ST7/MM0-MM7 (8 regs × 16 bytes)
    ///   Bytes 160-415: XMM0-XMM15 (16 regs × 16 bytes)
    ///   Bytes 416-511: Reserved
    fn dirty_xsave_legacy(xsave: &mut [u32], current_xsave: &[u8]) {
        // FCW (bytes 0-1) + FSW (bytes 2-3) - pack into xsave[0]
        // FCW = 0x0F7F (different from default 0x037F), FSW = 0x1234
        xsave[0] = 0x0F7F | (0x1234 << 16);
        // FTW (byte 4) + reserved (byte 5) + FOP (bytes 6-7) - pack into xsave[1]
        // FTW = 0xAB, FOP = 0x0123
        xsave[1] = 0xAB | (0x0123 << 16);
        // FIP (bytes 8-15) - xsave[2] and xsave[3]
        xsave[2] = 0xDEAD0001;
        xsave[3] = 0xBEEF0002;
        // FDP (bytes 16-23) - xsave[4] and xsave[5]
        xsave[4] = 0xCAFE0003;
        xsave[5] = 0xBABE0004;
        // MXCSR (bytes 24-27) - xsave[6], use valid value different from default
        xsave[6] = 0x3F80;
        // xsave[7] is MXCSR_MASK - preserve from current (hardware defined, read-only)
        if current_xsave.len() >= 32 {
            xsave[7] = u32::from_le_bytes(current_xsave[28..32].try_into().unwrap());
        }

        // ST0-ST7/MM0-MM7 (bytes 32-159, indices 8-39)
        for i in 8..40 {
            xsave[i] = 0xCAFEBABE;
        }
        // XMM0-XMM15 (bytes 160-415, indices 40-103)
        for i in 40..104 {
            xsave[i] = 0xDEADBEEF;
        }

        // Reserved area (bytes 416-511, indices 104-127)
        for i in 104..128 {
            xsave[i] = 0xABCDEF12;
        }
    }

    /// Preserve XSAVE header (bytes 512-575) from current state.
    /// This includes XSTATE_BV and XCOMP_BV which hypervisors require.
    fn preserve_xsave_header(xsave: &mut [u32], current_xsave: &[u8]) {
        for i in 128..144 {
            let byte_offset = i * 4;
            xsave[i] = u32::from_le_bytes(
                current_xsave[byte_offset..byte_offset + 4]
                    .try_into()
                    .unwrap(),
            );
        }
    }

    fn dirty_xsave(current_xsave: &[u8]) -> Vec<u32> {
        let mut xsave = vec![0u32; current_xsave.len() / 4];

        dirty_xsave_legacy(&mut xsave, current_xsave);
        preserve_xsave_header(&mut xsave, current_xsave);

        let xcomp_bv = u64::from_le_bytes(current_xsave[520..528].try_into().unwrap());
        let supported_components = xsave_supported_components();

        // Dirty extended components and get mask of what was actually dirtied
        let extended_mask = if (xcomp_bv & (1u64 << 63)) != 0 {
            // Compacted format (MSHV/WHP)
            dirty_xsave_extended_compacted(&mut xsave, xcomp_bv, supported_components)
        } else {
            // Standard format (KVM)
            dirty_xsave_extended_standard(&mut xsave, supported_components)
        };

        // UPDATE XSTATE_BV to indicate dirtied components have valid data.
        // WHP validates consistency between XSTATE_BV and actual data in the buffer.
        // Bits 0,1 = legacy x87/SSE (always set after dirty_xsave_legacy)
        // Bits 2+ = extended components that we actually dirtied
        let xstate_bv = 0x3 | extended_mask;

        // Write XSTATE_BV to bytes 512-519 (u32 indices 128-129)
        xsave[128] = (xstate_bv & 0xFFFFFFFF) as u32;
        xsave[129] = (xstate_bv >> 32) as u32;

        xsave
    }

    fn hyperlight_vm(code: &[u8]) -> Result<HyperlightVm> {
        let config: SandboxConfiguration = Default::default();
        #[cfg(crashdump)]
        let rt_cfg: SandboxRuntimeConfig = Default::default();

        let layout = SandboxMemoryLayout::new(config, code.len(), 4096, 0, 0, None)?;

        let mem_size = layout.get_memory_size()?;
        let eshm = ExclusiveSharedMemory::new(mem_size)?;

        let stack_cookie = [0u8; 16];
        let mem_mgr = SandboxMemoryManager::new(
            layout,
            eshm,
            RawPtr::from(0),
            Some(Offset::from(0)),
            stack_cookie,
        );

        let (mut hshm, mut gshm) = mem_mgr.build();

        let mut vm = set_up_hypervisor_partition(
            &mut gshm,
            &config,
            #[cfg(any(crashdump, gdb))]
            &rt_cfg,
            LoadInfo::dummy(),
        )?;

        // Write code
        let code_offset = layout.get_guest_code_offset();
        hshm.shared_mem.copy_from_slice(code, code_offset)?;

        let seed = {
            let mut rng = rand::rng();
            rng.random::<u64>()
        };
        let peb_addr = {
            let peb_u64 = u64::try_from(gshm.layout.peb_address)?;
            RawPtr::from(peb_u64)
        };

        let page_size = u32::try_from(page_size::get())?;

        #[cfg(gdb)]
        let dbg_mem_access_hdl = Arc::new(Mutex::new(hshm.clone()));

        let host_funcs = Arc::new(Mutex::new(FunctionRegistry::default()));

        // Run the VM
        vm.initialise(
            peb_addr,
            seed,
            page_size,
            &mut hshm,
            &host_funcs,
            None,
            #[cfg(gdb)]
            dbg_mem_access_hdl.clone(),
        )?;
        Ok(vm)
    }

    #[test]
    fn reset_vcpu_simple() {
        const CODE: [u8; 1] = [0xf4]; // hlt
        let hyperlight_vm = hyperlight_vm(&CODE).unwrap();
        let available_hv = *get_available_hypervisor().as_ref().unwrap();

        // Set all vCPU state to dirty values
        let regs = dirty_regs();
        let fpu = dirty_fpu();
        let sregs = dirty_sregs(hyperlight_vm.pml4_addr);
        let current_xsave = hyperlight_vm.vm.xsave().unwrap();
        let xsave = dirty_xsave(&current_xsave);
        let debug_regs = dirty_debug_regs();

        hyperlight_vm.vm.set_xsave(&xsave).unwrap();
        hyperlight_vm.vm.set_regs(&regs).unwrap();
        hyperlight_vm.vm.set_fpu(&fpu).unwrap();
        hyperlight_vm.vm.set_sregs(&sregs).unwrap();
        hyperlight_vm.vm.set_debug_regs(&debug_regs).unwrap();

        // Verify state was set
        assert_eq!(hyperlight_vm.vm.regs().unwrap(), regs);
        #[cfg_attr(not(kvm), allow(unused_mut))]
        let mut got_fpu = hyperlight_vm.vm.fpu().unwrap();
        let mut expected_fpu = fpu;
        // KVM doesn't preserve mxcsr via set_fpu/fpu()
        #[cfg(kvm)]
        if available_hv == HypervisorType::Kvm {
            got_fpu.mxcsr = fpu.mxcsr;
        }
        // fpr only uses 80 bits per register. Normalize upper bits for comparison.
        for i in 0..8 {
            expected_fpu.fpr[i][10..16].copy_from_slice(&got_fpu.fpr[i][10..16]);
        }
        assert_eq!(got_fpu, expected_fpu);

        // Verify debug regs
        let got_debug_regs = hyperlight_vm.vm.debug_regs().unwrap();
        let mut expected_debug_regs = debug_regs;
        // DR6: writable bits are B0-B3 (0-3), BD (13), BS (14), BT (15) = 0xE00F
        // Reserved bits (4-12, 16-31) are read-only and set by CPU, copy from actual
        expected_debug_regs.dr6 =
            (debug_regs.dr6 & DR6_WRITABLE_MASK) | (got_debug_regs.dr6 & !DR6_WRITABLE_MASK);
        // DR7: writable bits are 0-9, 13, 16-31 = 0xFFFF23FF
        // Reserved bits (10-12, 14-15) have fixed values, copy from actual
        expected_debug_regs.dr7 =
            (debug_regs.dr7 & DR7_WRITABLE_MASK) | (got_debug_regs.dr7 & !DR7_WRITABLE_MASK);
        assert_eq!(got_debug_regs, expected_debug_regs);

        // Verify sregs were set
        let got_sregs = hyperlight_vm.vm.sregs().unwrap();
        let mut expected_sregs = sregs;
        // ss.db (stack segment default size) may differ by hypervisor; ignored in 64-bit mode
        expected_sregs.ss.db = got_sregs.ss.db;
        // unusable and g are hypervisor implementation details (see comment below for details)
        expected_sregs.cs.unusable = got_sregs.cs.unusable;
        expected_sregs.cs.g = got_sregs.cs.g;
        expected_sregs.ds.unusable = got_sregs.ds.unusable;
        expected_sregs.ds.g = got_sregs.ds.g;
        expected_sregs.es.unusable = got_sregs.es.unusable;
        expected_sregs.es.g = got_sregs.es.g;
        expected_sregs.fs.unusable = got_sregs.fs.unusable;
        expected_sregs.fs.g = got_sregs.fs.g;
        expected_sregs.gs.unusable = got_sregs.gs.unusable;
        expected_sregs.gs.g = got_sregs.gs.g;
        expected_sregs.ss.unusable = got_sregs.ss.unusable;
        expected_sregs.ss.g = got_sregs.ss.g;
        expected_sregs.tr.unusable = got_sregs.tr.unusable;
        expected_sregs.tr.g = got_sregs.tr.g;
        expected_sregs.ldt.unusable = got_sregs.ldt.unusable;
        expected_sregs.ldt.g = got_sregs.ldt.g;
        assert_eq!(got_sregs, expected_sregs);

        // Reset the vCPU
        hyperlight_vm.reset_vcpu().unwrap();

        // Verify the fpu was reset to defaults
        assert_eq!(
            hyperlight_vm.vm.regs().unwrap(),
            CommonRegisters {
                rflags: 1 << 1, // Reserved bit 1 is always set
                ..Default::default()
            }
        );

        #[cfg_attr(not(kvm), allow(unused_mut))]
        let mut reset_fpu = hyperlight_vm.vm.fpu().unwrap();
        // KVM ignores mxcsr in its set_fpu/fpu()
        #[cfg(kvm)]
        if available_hv == HypervisorType::Kvm {
            reset_fpu.mxcsr = MXCSR_DEFAULT;
        }
        assert_eq!(reset_fpu, CommonFpu::default());

        // Verify debug registers are reset to defaults
        // Reserved bits in DR6/DR7 are read-only (set by CPU), copy from actual
        // Writable bits should be cleared to 0 after reset
        let reset_debug_regs = hyperlight_vm.vm.debug_regs().unwrap();
        let expected_reset_debug_regs = CommonDebugRegs {
            dr6: reset_debug_regs.dr6 & !DR6_WRITABLE_MASK,
            dr7: reset_debug_regs.dr7 & !DR7_WRITABLE_MASK,
            ..Default::default()
        };
        assert_eq!(reset_debug_regs, expected_reset_debug_regs);

        // Verify xsave is reset - should be zeroed except for hypervisor-specific fields
        let reset_xsave = hyperlight_vm.vm.xsave().unwrap();
        // Build expected xsave: all zeros with fpu specific defaults. Then copy hypervisor-specific fields from actual
        let mut expected_xsave = vec![0u8; reset_xsave.len()];
        #[cfg(mshv3)]
        if available_hv == HypervisorType::Mshv {
            // FCW (offset 0-1): When XSTATE_BV.LegacyX87 = 0 (init state), the hypervisor
            // skips copying the FPU legacy region entirely, leaving zeros in the buffer.
            // The actual guest FCW register is 0x037F (verified via fpu() assertion above),
            // but xsave() doesn't report it because XSTATE_BV=0 means "init state, buffer
            // contents undefined." We copy from actual to handle this.
            expected_xsave[0..2].copy_from_slice(&reset_xsave[0..2]);
        }
        #[cfg(target_os = "windows")]
        if available_hv == HypervisorType::Whp {
            // FCW (offset 0-1): When XSTATE_BV.LegacyX87 = 0 (init state), the hypervisor
            // skips copying the FPU legacy region entirely, leaving zeros in the buffer.
            // The actual guest FCW register is 0x037F (verified via fpu() assertion above),
            // but xsave() doesn't report it because XSTATE_BV=0 means "init state, buffer
            // contents undefined." We copy from actual to handle this.
            expected_xsave[0..2].copy_from_slice(&reset_xsave[0..2]);
        }
        #[cfg(kvm)]
        if available_hv == HypervisorType::Kvm {
            expected_xsave[0..2].copy_from_slice(&FP_CONTROL_WORD_DEFAULT.to_le_bytes());
        }

        // - MXCSR at offset 24-27: default FPU state set by hypervisor
        expected_xsave[24..28].copy_from_slice(&MXCSR_DEFAULT.to_le_bytes());
        // - MXCSR_MASK at offset 28-31: hardware-defined, read-only
        expected_xsave[28..32].copy_from_slice(&reset_xsave[28..32]);
        // - Reserved bytes at offset 464-511: These are in the reserved/padding area of the legacy
        //   FXSAVE region (after XMM registers which end at byte 416). On KVM/Intel, these bytes
        //   may contain hypervisor-specific metadata that isn't cleared during vCPU reset.
        //   Since this is not guest-visible computational state, we copy from actual to expected.
        expected_xsave[464..512].copy_from_slice(&reset_xsave[464..512]);
        // - XSAVE header at offset 512-575: contains XSTATE_BV and XCOMP_BV (hypervisor-managed)
        //   XSTATE_BV (512-519): Bitmap indicating which state components have valid data in the
        //   buffer. When a bit is 0, the hypervisor uses the architectural init value for that
        //   component. After reset, xsave() may still return non-zero XSTATE_BV since the
        //   hypervisor reports which components it manages, not which have been modified.
        //   XCOMP_BV (520-527): Compaction bitmap. Bit 63 indicates compacted format (used by MSHV/WHP).
        //   When set, the XSAVE area uses a compact layout where only enabled components are stored
        //   contiguously. This is a format indicator, not state data, so it's preserved across reset.
        //   Both fields are managed by the hypervisor to describe the XSAVE area format and capabilities,
        //   not guest-visible computational state, so they don't need to be zeroed on reset.
        if reset_xsave.len() >= 576 {
            expected_xsave[512..576].copy_from_slice(&reset_xsave[512..576]);
        }
        assert_eq!(
            reset_xsave, expected_xsave,
            "xsave should be zeroed except for hypervisor-specific fields"
        );

        // Verify sregs are reset to defaults
        let defaults = CommonSpecialRegisters::standard_64bit_defaults(hyperlight_vm.pml4_addr);
        let reset_sregs = hyperlight_vm.vm.sregs().unwrap();
        let mut expected_reset_sregs = defaults;
        // ss.db (stack segment default size) may differ by hypervisor; ignored in 64-bit mode
        expected_reset_sregs.ss.db = reset_sregs.ss.db;
        // unusable, type_, and g (granularity) for segments are hypervisor implementation details.
        // These fields are part of the hidden descriptor cache. While guests can write them
        // indirectly (by loading segments from a crafted GDT), guests cannot read them back
        // (e.g., `mov ax, ds` only returns the selector, not the hidden cache).
        // KVM and MSHV reset to different default values, but both properly reset so there's
        // no information leakage between tenants. g=0 means byte granularity, g=1 means 4KB pages.
        expected_reset_sregs.cs.unusable = reset_sregs.cs.unusable;
        expected_reset_sregs.cs.g = reset_sregs.cs.g;
        expected_reset_sregs.ds.unusable = reset_sregs.ds.unusable;
        expected_reset_sregs.ds.type_ = reset_sregs.ds.type_;
        expected_reset_sregs.ds.g = reset_sregs.ds.g;
        expected_reset_sregs.es.unusable = reset_sregs.es.unusable;
        expected_reset_sregs.es.type_ = reset_sregs.es.type_;
        expected_reset_sregs.es.g = reset_sregs.es.g;
        expected_reset_sregs.fs.unusable = reset_sregs.fs.unusable;
        expected_reset_sregs.fs.type_ = reset_sregs.fs.type_;
        expected_reset_sregs.fs.g = reset_sregs.fs.g;
        expected_reset_sregs.gs.unusable = reset_sregs.gs.unusable;
        expected_reset_sregs.gs.type_ = reset_sregs.gs.type_;
        expected_reset_sregs.gs.g = reset_sregs.gs.g;
        expected_reset_sregs.ss.unusable = reset_sregs.ss.unusable;
        expected_reset_sregs.ss.type_ = reset_sregs.ss.type_;
        expected_reset_sregs.ss.g = reset_sregs.ss.g;
        expected_reset_sregs.tr.unusable = reset_sregs.tr.unusable;
        expected_reset_sregs.tr.g = reset_sregs.tr.g;
        expected_reset_sregs.ldt.unusable = reset_sregs.ldt.unusable;
        expected_reset_sregs.ldt.g = reset_sregs.ldt.g;
        assert_eq!(reset_sregs, expected_reset_sregs);
    }

    /// Tests that actually runs code, as opposed to just setting vCPU state.
    mod run_tests {
        use super::*;

        #[test]
        fn reset_vcpu_regs() {
            #[rustfmt::skip]
            const CODE: [u8; 151] = [
                0x48, 0xb8, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, // mov rax, 0x1111111111111111
                0x48, 0xbb, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, // mov rbx, 0x2222222222222222
                0x48, 0xb9, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, // mov rcx, 0x3333333333333333
                0x48, 0xba, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, // mov rdx, 0x4444444444444444
                0x48, 0xbe, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, // mov rsi, 0x5555555555555555
                0x48, 0xbf, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, // mov rdi, 0x6666666666666666
                0x48, 0xbd, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, // mov rbp, 0x7777777777777777
                0x49, 0xb8, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, // mov r8,  0x8888888888888888
                0x49, 0xb9, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, // mov r9,  0x9999999999999999
                0x49, 0xba, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, // mov r10, 0xAAAAAAAAAAAAAAAA
                0x49, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, // mov r11, 0xBBBBBBBBBBBBBBBB
                0x49, 0xbc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // mov r12, 0xCCCCCCCCCCCCCCCC
                0x49, 0xbd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, // mov r13, 0xDDDDDDDDDDDDDDDD
                0x49, 0xbe, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, // mov r14, 0xEEEEEEEEEEEEEEEE
                0x49, 0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // mov r15, 0xFFFFFFFFFFFFFFFF
                0xf4, // hlt
            ];

            let hyperlight_vm = hyperlight_vm(&CODE).unwrap();

            // After run, check registers match expected dirty state
            let regs = hyperlight_vm.vm.regs().unwrap();
            let mut expected_dirty = CommonRegisters {
                rax: 0x1111111111111111,
                rbx: 0x2222222222222222,
                rcx: 0x3333333333333333,
                rdx: 0x4444444444444444,
                rsi: 0x5555555555555555,
                rdi: 0x6666666666666666,
                rsp: 0,
                rbp: 0x7777777777777777,
                r8: 0x8888888888888888,
                r9: 0x9999999999999999,
                r10: 0xAAAAAAAAAAAAAAAA,
                r11: 0xBBBBBBBBBBBBBBBB,
                r12: 0xCCCCCCCCCCCCCCCC,
                r13: 0xDDDDDDDDDDDDDDDD,
                r14: 0xEEEEEEEEEEEEEEEE,
                r15: 0xFFFFFFFFFFFFFFFF,
                rip: 0,
                rflags: 0,
            };
            // rip, rsp, and rflags are set by the CPU, we don't expect those to match our expected values
            expected_dirty.rip = regs.rip;
            expected_dirty.rsp = regs.rsp;
            expected_dirty.rflags = regs.rflags;
            assert_eq!(regs, expected_dirty);

            // Reset vcpu
            hyperlight_vm.reset_vcpu().unwrap();

            // Check registers are reset to defaults
            let regs = hyperlight_vm.vm.regs().unwrap();
            let expected_reset = CommonRegisters {
                rax: 0,
                rbx: 0,
                rcx: 0,
                rdx: 0,
                rsi: 0,
                rdi: 0,
                rsp: 0,
                rbp: 0,
                r8: 0,
                r9: 0,
                r10: 0,
                r11: 0,
                r12: 0,
                r13: 0,
                r14: 0,
                r15: 0,
                rip: 0,
                rflags: 1 << 1, // Reserved bit 1 is always set
            };
            assert_eq!(regs, expected_reset);
        }

        #[test]
        fn reset_vcpu_fpu() {
            #[cfg(kvm)]
            use crate::hypervisor::regs::MXCSR_DEFAULT;

            #[cfg(kvm)]
            let available_hv = *get_available_hypervisor().as_ref().unwrap();

            #[rustfmt::skip]
            const CODE: [u8; 289] = [
                // xmm0-xmm7: use movd + pshufd to fill with pattern
                0xb8, 0x11, 0x11, 0x11, 0x11,       // mov eax, 0x11111111
                0x66, 0x0f, 0x6e, 0xc0,             // movd xmm0, eax
                0x66, 0x0f, 0x70, 0xc0, 0x00,       // pshufd xmm0, xmm0, 0
                0xb8, 0x22, 0x22, 0x22, 0x22,       // mov eax, 0x22222222
                0x66, 0x0f, 0x6e, 0xc8,             // movd xmm1, eax
                0x66, 0x0f, 0x70, 0xc9, 0x00,       // pshufd xmm1, xmm1, 0
                0xb8, 0x33, 0x33, 0x33, 0x33,       // mov eax, 0x33333333
                0x66, 0x0f, 0x6e, 0xd0,             // movd xmm2, eax
                0x66, 0x0f, 0x70, 0xd2, 0x00,       // pshufd xmm2, xmm2, 0
                0xb8, 0x44, 0x44, 0x44, 0x44,       // mov eax, 0x44444444
                0x66, 0x0f, 0x6e, 0xd8,             // movd xmm3, eax
                0x66, 0x0f, 0x70, 0xdb, 0x00,       // pshufd xmm3, xmm3, 0
                0xb8, 0x55, 0x55, 0x55, 0x55,       // mov eax, 0x55555555
                0x66, 0x0f, 0x6e, 0xe0,             // movd xmm4, eax
                0x66, 0x0f, 0x70, 0xe4, 0x00,       // pshufd xmm4, xmm4, 0
                0xb8, 0x66, 0x66, 0x66, 0x66,       // mov eax, 0x66666666
                0x66, 0x0f, 0x6e, 0xe8,             // movd xmm5, eax
                0x66, 0x0f, 0x70, 0xed, 0x00,       // pshufd xmm5, xmm5, 0
                0xb8, 0x77, 0x77, 0x77, 0x77,       // mov eax, 0x77777777
                0x66, 0x0f, 0x6e, 0xf0,             // movd xmm6, eax
                0x66, 0x0f, 0x70, 0xf6, 0x00,       // pshufd xmm6, xmm6, 0
                0xb8, 0x88, 0x88, 0x88, 0x88,       // mov eax, 0x88888888
                0x66, 0x0f, 0x6e, 0xf8,             // movd xmm7, eax
                0x66, 0x0f, 0x70, 0xff, 0x00,       // pshufd xmm7, xmm7, 0
                // xmm8-xmm15: REX prefix versions
                0xb8, 0x99, 0x99, 0x99, 0x99,       // mov eax, 0x99999999
                0x66, 0x44, 0x0f, 0x6e, 0xc0,       // movd xmm8, eax
                0x66, 0x45, 0x0f, 0x70, 0xc0, 0x00, // pshufd xmm8, xmm8, 0
                0xb8, 0xaa, 0xaa, 0xaa, 0xaa,       // mov eax, 0xAAAAAAAA
                0x66, 0x44, 0x0f, 0x6e, 0xc8,       // movd xmm9, eax
                0x66, 0x45, 0x0f, 0x70, 0xc9, 0x00, // pshufd xmm9, xmm9, 0
                0xb8, 0xbb, 0xbb, 0xbb, 0xbb,       // mov eax, 0xBBBBBBBB
                0x66, 0x44, 0x0f, 0x6e, 0xd0,       // movd xmm10, eax
                0x66, 0x45, 0x0f, 0x70, 0xd2, 0x00, // pshufd xmm10, xmm10, 0
                0xb8, 0xcc, 0xcc, 0xcc, 0xcc,       // mov eax, 0xCCCCCCCC
                0x66, 0x44, 0x0f, 0x6e, 0xd8,       // movd xmm11, eax
                0x66, 0x45, 0x0f, 0x70, 0xdb, 0x00, // pshufd xmm11, xmm11, 0
                0xb8, 0xdd, 0xdd, 0xdd, 0xdd,       // mov eax, 0xDDDDDDDD
                0x66, 0x44, 0x0f, 0x6e, 0xe0,       // movd xmm12, eax
                0x66, 0x45, 0x0f, 0x70, 0xe4, 0x00, // pshufd xmm12, xmm12, 0
                0xb8, 0xee, 0xee, 0xee, 0xee,       // mov eax, 0xEEEEEEEE
                0x66, 0x44, 0x0f, 0x6e, 0xe8,       // movd xmm13, eax
                0x66, 0x45, 0x0f, 0x70, 0xed, 0x00, // pshufd xmm13, xmm13, 0
                0xb8, 0xff, 0xff, 0xff, 0xff,       // mov eax, 0xFFFFFFFF
                0x66, 0x44, 0x0f, 0x6e, 0xf0,       // movd xmm14, eax
                0x66, 0x45, 0x0f, 0x70, 0xf6, 0x00, // pshufd xmm14, xmm14, 0
                0xb8, 0x78, 0x56, 0x34, 0x12,       // mov eax, 0x12345678
                0x66, 0x44, 0x0f, 0x6e, 0xf8,       // movd xmm15, eax
                0x66, 0x45, 0x0f, 0x70, 0xff, 0x00, // pshufd xmm15, xmm15, 0

                // Use 7 FLDs so TOP=1 after execution, different from default TOP=0.
                // This ensures reset properly clears TOP, not just register contents.
                0xd9, 0xee,                         // fldz   (0.0)
                0xd9, 0xea,                         // fldl2e (log2(e))
                0xd9, 0xe9,                         // fldl2t (log2(10))
                0xd9, 0xec,                         // fldlg2 (log10(2))
                0xd9, 0xed,                         // fldln2 (ln(2))
                0xd9, 0xeb,                         // fldpi  (pi)
                // Push a memory value to also dirty last_dp
                0x48, 0xb8, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00, // mov rax, 0xDEADBEEF
                0x50,                               // push rax
                0xdd, 0x04, 0x24,                   // fld qword [rsp] - dirties last_dp
                0x58,                               // pop rax

                // Dirty FCW (0x0F7F, different from default 0x037F)
                0xb8, 0x7f, 0x0f, 0x00, 0x00,       // mov eax, 0x0F7F
                0x50,                               // push rax
                0xd9, 0x2c, 0x24,                   // fldcw [rsp]
                0x58,                               // pop rax

                // Dirty MXCSR (0x3F80, different from default 0x1F80)
                0xb8, 0x80, 0x3f, 0x00, 0x00,       // mov eax, 0x3F80
                0x50,                               // push rax
                0x0f, 0xae, 0x14, 0x24,             // ldmxcsr [rsp]
                0x58,                               // pop rax

                0xf4, // hlt
            ];

            let hyperlight_vm = hyperlight_vm(&CODE).unwrap();

            // After run, check FPU state matches expected dirty values
            let fpu = hyperlight_vm.vm.fpu().unwrap();

            #[cfg_attr(not(kvm), allow(unused_mut))]
            let mut expected_dirty = CommonFpu {
                fcw: 0x0F7F,
                ftwx: 0xFE, // 7 registers valid (bit 0 empty after 7 pushes with TOP=1)
                xmm: [
                    0x11111111111111111111111111111111_u128.to_le_bytes(),
                    0x22222222222222222222222222222222_u128.to_le_bytes(),
                    0x33333333333333333333333333333333_u128.to_le_bytes(),
                    0x44444444444444444444444444444444_u128.to_le_bytes(),
                    0x55555555555555555555555555555555_u128.to_le_bytes(),
                    0x66666666666666666666666666666666_u128.to_le_bytes(),
                    0x77777777777777777777777777777777_u128.to_le_bytes(),
                    0x88888888888888888888888888888888_u128.to_le_bytes(),
                    0x99999999999999999999999999999999_u128.to_le_bytes(),
                    0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA_u128.to_le_bytes(),
                    0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB_u128.to_le_bytes(),
                    0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC_u128.to_le_bytes(),
                    0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD_u128.to_le_bytes(),
                    0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE_u128.to_le_bytes(),
                    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_u128.to_le_bytes(),
                    0x12345678123456781234567812345678_u128.to_le_bytes(),
                ],
                mxcsr: 0x3F80,
                fsw: 0x0802, // TOP=1 after 7 pushes (bits 11-13), DE flag from denormal load
                // fpr: 80-bit values with 6 bytes padding; may vary between CPU vendors
                fpr: fpu.fpr,
                // last_opcode: FPU Opcode update varies by CPU (may only update on unmasked exceptions)
                last_opcode: fpu.last_opcode,
                // last_ip: code is loaded at runtime-determined address
                last_ip: fpu.last_ip,
                // last_dp: points to stack (rsp) which is runtime-determined
                last_dp: fpu.last_dp,
            };
            // KVM doesn't preserve mxcsr via fpu()
            #[cfg(kvm)]
            if available_hv == HypervisorType::Kvm {
                expected_dirty.mxcsr = fpu.mxcsr;
            }
            assert_eq!(fpu, expected_dirty);

            // Verify MXCSR via xsave on KVM (since fpu() doesn't return it)
            #[cfg(kvm)]
            if available_hv == HypervisorType::Kvm {
                let xsave = hyperlight_vm.vm.xsave().unwrap();
                let mxcsr = u32::from_le_bytes(xsave[24..28].try_into().unwrap());
                assert_eq!(mxcsr, 0x3F80, "MXCSR in XSAVE should be dirty");
            }

            // Reset vcpu
            hyperlight_vm.reset_vcpu().unwrap();

            // Check FPU is reset to defaults
            #[cfg_attr(not(kvm), allow(unused_mut))]
            let mut fpu = hyperlight_vm.vm.fpu().unwrap();
            // KVM doesn't preserve mxcsr via fpu(), set to expected default
            #[cfg(kvm)]
            if available_hv == HypervisorType::Kvm {
                fpu.mxcsr = MXCSR_DEFAULT;
            }
            assert_eq!(fpu, CommonFpu::default());

            // Verify MXCSR via xsave on KVM
            #[cfg(kvm)]
            if available_hv == HypervisorType::Kvm {
                let xsave = hyperlight_vm.vm.xsave().unwrap();
                let mxcsr = u32::from_le_bytes(xsave[24..28].try_into().unwrap());
                assert_eq!(mxcsr, MXCSR_DEFAULT, "MXCSR in XSAVE should be reset");
            }
        }

        #[test]
        fn reset_vcpu_debug_regs() {
            // Code that sets debug registers and halts
            // In real mode (ring 0), we can access debug registers directly
            #[rustfmt::skip]
            let code: &[u8] = &[
                0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, // mov rax, 0xDEADBEEF00000000
                0x0f, 0x23, 0xc0,                                           // mov dr0, rax
                0x48, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, // mov rax, 0xDEADBEEF00000001
                0x0f, 0x23, 0xc8,                                           // mov dr1, rax
                0x48, 0xb8, 0x02, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, // mov rax, 0xDEADBEEF00000002
                0x0f, 0x23, 0xd0,                                           // mov dr2, rax
                0x48, 0xb8, 0x03, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, // mov rax, 0xDEADBEEF00000003
                0x0f, 0x23, 0xd8,                                           // mov dr3, rax
                0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,                   // mov rax, 1
                0x0f, 0x23, 0xf0,                                           // mov dr6, rax
                0x48, 0xc7, 0xc0, 0xff, 0x00, 0x00, 0x00,                   // mov rax, 0xFF
                0x0f, 0x23, 0xf8,                                           // mov dr7, rax
                0xf4,                                                       // hlt
            ];

            let hyperlight_vm = hyperlight_vm(code).unwrap();

            // Verify debug registers are dirty
            let debug_regs = hyperlight_vm.vm.debug_regs().unwrap();
            let expected_dirty = CommonDebugRegs {
                dr0: 0xDEAD_BEEF_0000_0000,
                dr1: 0xDEAD_BEEF_0000_0001,
                dr2: 0xDEAD_BEEF_0000_0002,
                dr3: 0xDEAD_BEEF_0000_0003,
                // dr6: guest set B0 (bit 0) = 1, reserved bits vary by CPU
                dr6: (debug_regs.dr6 & !DR6_WRITABLE_MASK) | 0x1,
                // dr7: guest set lower byte = 0xFF, reserved bits vary by CPU
                dr7: (debug_regs.dr7 & !DR7_WRITABLE_MASK) | 0xFF,
            };
            assert_eq!(debug_regs, expected_dirty);

            // Reset vcpu
            hyperlight_vm.reset_vcpu().unwrap();

            // Check debug registers are reset to default values
            let debug_regs = hyperlight_vm.vm.debug_regs().unwrap();
            let expected_reset = CommonDebugRegs {
                dr0: 0,
                dr1: 0,
                dr2: 0,
                dr3: 0,
                // dr6: reserved bits preserved, writable bits (B0-B3, BD, BS, BT) cleared
                dr6: debug_regs.dr6 & !DR6_WRITABLE_MASK,
                // dr7: reserved bits preserved, writable bits cleared
                dr7: debug_regs.dr7 & !DR7_WRITABLE_MASK,
            };
            assert_eq!(debug_regs, expected_reset);
        }

        #[test]
        fn reset_vcpu_sregs() {
            // Code that modifies special registers and halts
            // We can modify CR0.WP, CR2, CR4.TSD, and CR8 from guest code in ring 0
            #[rustfmt::skip]
            let code: &[u8] = &[
                // Set CR0.WP (Write Protect, bit 16)
                0x0f, 0x20, 0xc0,                                           // mov rax, cr0
                0x48, 0x0d, 0x00, 0x00, 0x01, 0x00,                         // or rax, 0x10000
                0x0f, 0x22, 0xc0,                                           // mov cr0, rax
                // Set CR2
                0x48, 0xb8, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00, // mov rax, 0xDEADBEEF
                0x0f, 0x22, 0xd0,                                           // mov cr2, rax
                // Set CR4.TSD (Time Stamp Disable, bit 2)
                0x0f, 0x20, 0xe0,                                           // mov rax, cr4
                0x48, 0x83, 0xc8, 0x04,                                     // or rax, 0x4
                0x0f, 0x22, 0xe0,                                           // mov cr4, rax
                // Set CR8
                0x48, 0xc7, 0xc0, 0x05, 0x00, 0x00, 0x00,                   // mov rax, 5
                0x44, 0x0f, 0x22, 0xc0,                                     // mov cr8, rax
                0xf4,                                                       // hlt
            ];

            let hyperlight_vm = hyperlight_vm(code).unwrap();

            // Get the expected defaults
            let defaults = CommonSpecialRegisters::standard_64bit_defaults(hyperlight_vm.pml4_addr);

            // Verify registers are dirty (CR0.WP, CR2, CR4.TSD and CR8 modified by our code)
            let sregs = hyperlight_vm.vm.sregs().unwrap();
            let mut expected_dirty = CommonSpecialRegisters {
                cr0: defaults.cr0 | 0x10000, // WP bit set
                cr2: 0xDEADBEEF,
                cr4: defaults.cr4 | 0x4, // TSD bit set
                cr8: 0x5,
                ..defaults
            };
            // ss.db (stack segment default size) may differ by hypervisor; ignored in 64-bit mode
            expected_dirty.ss.db = sregs.ss.db;
            // unusable and type_ for non-present segments are hypervisor implementation details
            // KVM returns type_=1, WHP returns type_=0 for non-present segments
            expected_dirty.cs.unusable = sregs.cs.unusable;
            expected_dirty.ds.unusable = sregs.ds.unusable;
            expected_dirty.ds.type_ = sregs.ds.type_;
            expected_dirty.es.unusable = sregs.es.unusable;
            expected_dirty.es.type_ = sregs.es.type_;
            expected_dirty.fs.unusable = sregs.fs.unusable;
            expected_dirty.fs.type_ = sregs.fs.type_;
            expected_dirty.gs.unusable = sregs.gs.unusable;
            expected_dirty.gs.type_ = sregs.gs.type_;
            expected_dirty.ss.unusable = sregs.ss.unusable;
            expected_dirty.ss.type_ = sregs.ss.type_;
            expected_dirty.tr.unusable = sregs.tr.unusable;
            expected_dirty.ldt.unusable = sregs.ldt.unusable;
            assert_eq!(sregs, expected_dirty);

            // Reset vcpu
            hyperlight_vm.reset_vcpu().unwrap();

            // Check registers are reset to defaults
            let sregs = hyperlight_vm.vm.sregs().unwrap();
            let mut expected_reset = defaults;
            // ss.db (stack segment default size) may differ by hypervisor; ignored in 64-bit mode
            expected_reset.ss.db = sregs.ss.db;
            // unusable and type_ for non-present segments are hypervisor implementation details
            // KVM returns type_=1, WHP returns type_=0 for non-present segments
            expected_reset.cs.unusable = sregs.cs.unusable;
            expected_reset.ds.unusable = sregs.ds.unusable;
            expected_reset.ds.type_ = sregs.ds.type_;
            expected_reset.es.unusable = sregs.es.unusable;
            expected_reset.es.type_ = sregs.es.type_;
            expected_reset.fs.unusable = sregs.fs.unusable;
            expected_reset.fs.type_ = sregs.fs.type_;
            expected_reset.gs.unusable = sregs.gs.unusable;
            expected_reset.gs.type_ = sregs.gs.type_;
            expected_reset.ss.unusable = sregs.ss.unusable;
            expected_reset.ss.type_ = sregs.ss.type_;
            expected_reset.tr.unusable = sregs.tr.unusable;
            expected_reset.ldt.unusable = sregs.ldt.unusable;
            assert_eq!(sregs, expected_reset);
        }
    }
}
