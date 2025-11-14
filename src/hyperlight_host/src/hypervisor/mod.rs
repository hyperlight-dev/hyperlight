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

use log::LevelFilter;

use crate::error::HyperlightError::ExecutionCanceledByHost;
#[cfg(gdb)]
use crate::hypervisor::gdb::{DebugCommChannel, DebugMsg, DebugResponse, arch};
use crate::hypervisor::regs::{
    CommonFpu, CommonRegisters, CommonSegmentRegister, CommonSpecialRegisters,
};
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags, MemoryRegionType};
use crate::metrics::METRIC_GUEST_CANCELLATION;
use crate::sandbox::outb::handle_outb;
#[cfg(feature = "mem_profile")]
use crate::sandbox::trace::MemTraceInfo;
#[cfg(crashdump)]
use crate::sandbox::uninitialized::SandboxRuntimeConfig;
use crate::{HyperlightError, Result, log_then_return, new_error};

/// HyperV-on-linux functionality
#[cfg(mshv3)]
pub mod hyperv_linux;
#[cfg(target_os = "windows")]
/// Hyperv-on-windows functionality
pub(crate) mod hyperv_windows;

/// GDB debugging support
#[cfg(gdb)]
pub(crate) mod gdb;

/// Abstracts over different hypervisor register representations
pub(crate) mod regs;

#[cfg(kvm)]
/// Functionality to manipulate KVM-based virtual machines
pub mod kvm;
#[cfg(target_os = "windows")]
/// Hyperlight Surrogate Process
pub(crate) mod surrogate_process;
#[cfg(target_os = "windows")]
/// Hyperlight Surrogate Process
pub(crate) mod surrogate_process_manager;
/// WindowsHypervisorPlatform utilities
#[cfg(target_os = "windows")]
pub(crate) mod windows_hypervisor_platform;
/// Safe wrappers around windows types like `PSTR`
#[cfg(target_os = "windows")]
pub(crate) mod wrappers;

#[cfg(crashdump)]
pub(crate) mod crashdump;

use std::fmt::Debug;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(any(kvm, mshv3))]
use std::time::Duration;

#[cfg(gdb)]
use gdb::VcpuStopReason;

use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::ptr::RawPtr;
use crate::mem::shared_mem::HostSharedMemory;
use crate::sandbox::host_funcs::FunctionRegistry;

cfg_if::cfg_if! {
    if #[cfg(feature = "init-paging")] {
        pub(crate) const CR4_PAE: u64 = 1 << 5;
        pub(crate) const CR4_OSFXSR: u64 = 1 << 9;
        pub(crate) const CR4_OSXMMEXCPT: u64 = 1 << 10;
        pub(crate) const CR0_PE: u64 = 1;
        pub(crate) const CR0_MP: u64 = 1 << 1;
        pub(crate) const CR0_ET: u64 = 1 << 4;
        pub(crate) const CR0_NE: u64 = 1 << 5;
        pub(crate) const CR0_WP: u64 = 1 << 16;
        pub(crate) const CR0_AM: u64 = 1 << 18;
        pub(crate) const CR0_PG: u64 = 1 << 31;
        pub(crate) const EFER_LME: u64 = 1 << 8;
        pub(crate) const EFER_LMA: u64 = 1 << 10;
        pub(crate) const EFER_SCE: u64 = 1;
        pub(crate) const EFER_NX: u64 = 1 << 11;
    }
}

/// These are the generic exit reasons that we can handle from a Hypervisor the Hypervisors run method is responsible for mapping from
/// the hypervisor specific exit reasons to these generic ones
pub(crate) enum VmExit {
    /// The vCPU has halted
    Halt(),
    /// The vCPU has issued a write to the given port with the given value
    IoOut(u16, Vec<u8>),
    /// The vCPU tried to read from the given (unmapped) addr
    MmioRead(u64),
    /// The vCPU tried to write to the given (unmapped) addr
    MmioWrite(u64),
    /// The vCPU execution has been cancelled
    Cancelled(),
    /// The vCPU has exited for a reason that is not handled by Hyperlight
    Unknown(String),
    /// The operation should be retried, for example this can happen on Linux where a call to run the CPU can return EAGAIN
    #[cfg_attr(
        target_os = "windows",
        expect(
            dead_code,
            reason = "Retry() is never constructed on Windows, but it is still matched on (which dead_code lint ignores)"
        )
    )]
    Retry(),
    #[cfg(gdb)]
    /// The vCPU has exited due to a debug event (usually breakpoint)
    Debug { dr6: u64, exception: u32 },
}

/// A common set of hypervisor functionality
pub(crate) trait Hypervisor: Debug + Send {
    /// Initialise the internally stored vCPU with the given PEB address and
    /// random number seed, then run it until a HLT instruction.
    #[allow(clippy::too_many_arguments)]
    fn initialise(
        &mut self,
        peb_addr: RawPtr,
        seed: u64,
        page_size: u32,
        mem_mgr: SandboxMemoryManager<HostSharedMemory>,
        host_funcs: Arc<Mutex<FunctionRegistry>>,
        guest_max_log_level: Option<LevelFilter>,
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    ) -> Result<()>;

    /// Map a region of host memory into the sandbox.
    ///
    /// Depending on the host platform, there are likely alignment
    /// requirements of at least one page for base and len.
    unsafe fn map_region(&mut self, rgn: &MemoryRegion) -> Result<()>;

    /// Unmap a memory region from the sandbox
    unsafe fn unmap_region(&mut self, rgn: &MemoryRegion) -> Result<()>;

    /// Get the currently mapped dynamic memory regions (not including sandbox regions)
    ///
    /// Note: Box needed for trait to be object-safe :(
    fn get_mapped_regions(&self) -> Box<dyn ExactSizeIterator<Item = &MemoryRegion> + '_>;

    /// Dispatch a call from the host to the guest using the given pointer
    /// to the dispatch function _in the guest's address space_.
    ///
    /// Do this by setting the instruction pointer to `dispatch_func_addr`
    /// and then running the execution loop until a halt instruction.
    ///
    /// Returns `Ok` if the call succeeded, and an `Err` if it failed
    fn dispatch_call_from_host(
        &mut self,
        dispatch_func_addr: RawPtr,
        mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
        host_funcs: Arc<Mutex<FunctionRegistry>>,
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    ) -> Result<()>;

    // Run the vCPU "one step until it exits"
    fn run_vcpu(&mut self) -> Result<VmExit>;

    /// Run the vCPU while handling potential exists. Returns when the vCPU halts or an error occurs.
    #[allow(clippy::too_many_arguments)]
    fn run(
        &mut self,
        _entrypoint: u64,
        interrupt_handle: Arc<dyn InterruptHandleImpl>,
        sandbox_regions: &[MemoryRegion],
        mmap_regions: &[MemoryRegion],
        mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
        host_funcs: Arc<Mutex<FunctionRegistry>>,
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
        #[cfg(crashdump)] rt_cfg: &SandboxRuntimeConfig,
    ) -> Result<()> {
        // ===== KILL() TIMING POINT 1: Between guest function calls =====
        // Clear any stale cancellation from a previous guest function call or if kill() was called too early.
        // This ensures that kill() called BETWEEN different guest function calls doesn't affect the next call.
        //
        // If kill() was called and ran to completion BEFORE this line executes:
        //    - kill() has NO effect on this guest function call because CANCEL_BIT is cleared here.
        //    - NOTE: stale signals can still be delivered, but they will be ignored.
        interrupt_handle.clear_cancel();

        // Keeps the trace context and open spans
        #[cfg(feature = "trace_guest")]
        let mut tc = crate::sandbox::trace::TraceContext::new();

        let result = loop {
            // ===== KILL() TIMING POINT 2: Before set_tid() =====
            // If kill() is called and ran to completion BEFORE this line executes:
            //    - CANCEL_BIT will be set and we will return an early VmExit::Cancelled()
            interrupt_handle.set_tid();
            interrupt_handle.set_running();

            let exit_reason =
                if interrupt_handle.is_cancelled() || interrupt_handle.is_debug_interrupted() {
                    Ok(VmExit::Cancelled())
                } else {
                    #[cfg(feature = "trace_guest")]
                    tc.setup_guest_trace(tracing_opentelemetry::OpenTelemetrySpanExt::context(
                        &tracing::Span::current(),
                    ));

                    // ===== KILL() TIMING POINT 3: Before calling run_vcpu() =====
                    // If kill() is called and ran to completion BEFORE this line executes:
                    //    - CANCEL_BIT will be set, but it's too late to prevent entering the guest this iteration
                    //    - Signals will interrupt the guest (RUNNING_BIT=true), causing VmExit::Cancelled()
                    //    - If the guest completes before any signals arrive, kill() may have no effect
                    //      - If there are more iterations to do (IO/host func, etc.), the next iteration will be cancelled
                    let exit_reason = self.run_vcpu(); // Note, this function must not create any spans as it is called after setting up guest trace span

                    // End current host trace by closing the current span that captures traces
                    // happening when a guest exits and re-enters.
                    #[cfg(feature = "trace_guest")]
                    tc.end_host_trace();

                    // Handle the guest trace data if any
                    #[cfg(feature = "trace_guest")]
                    if let Err(e) = self.handle_trace(&mut tc, mem_mgr) {
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
            let cancel_requested = interrupt_handle.is_cancelled();
            let debug_interrupted = interrupt_handle.is_debug_interrupted();

            // ===== KILL() TIMING POINT 5: Before calling clear_running() =====
            // Same as point 4.
            interrupt_handle.clear_running();

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
                    let regs = self.regs()?;
                    let rip_gva = self.translate_gva(regs.rip)?;
                    // Handle debug event (breakpoints)
                    let stop_reason = arch::vcpu_stop_reason(rip_gva, _entrypoint, dr6, exception);

                    if stop_reason == VcpuStopReason::EntryPointBp {
                        // TODO in next PR: make sure to remove hw breakpoint here
                        // In case the hw breakpoint is the entry point, remove it to
                        // avoid hanging here as gdb does not remove breakpoints it
                        // has not set.
                        // Gdb expects the target to be stopped when connected.
                        // self.remove_hw_breakpoint(vcpu_fd, entrypoint)?;
                    }
                    if let Err(e) = self.handle_debug(dbg_mem_access_fn.clone(), stop_reason) {
                        break Err(e);
                    }
                }

                Ok(VmExit::Halt()) => {
                    break Ok(());
                }
                Ok(VmExit::IoOut(port, data)) => {
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

                    let regs = self.regs()?;

                    #[cfg(feature = "mem_profile")]
                    {
                        let trace_info = self.trace_info_mut();
                        handle_outb(mem_mgr, host_funcs.clone(), &regs, port, val, trace_info)?;
                    }

                    #[cfg(not(feature = "mem_profile"))]
                    {
                        handle_outb(mem_mgr, host_funcs.clone(), &regs, port, val)?;
                    }
                }
                Ok(VmExit::MmioRead(addr)) => {
                    let all_regions = sandbox_regions.iter().chain(mmap_regions.iter());
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
                    let all_regions = sandbox_regions.iter().chain(mmap_regions.iter());
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
                    // the vcpu was interrupted by a stale cancellation from a previous call
                    if !cancel_requested && !debug_interrupted {
                        // treat this the same as a VmExit::Retry, the cancel was not meant for this call
                        continue;
                    }

                    #[cfg(gdb)]
                    if debug_interrupted {
                        // If the vcpu was interrupted by a debugger, we need to handle it
                        interrupt_handle.clear_debug_interrupt();
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
                if rt_cfg.guest_core_dump {
                    let ctx = self
                        .crashdump_context()
                        .map_err(|e| new_error!("Failed to get crashdump context: {:?}", e))?;
                    crashdump::generate_crashdump(ctx)?;
                }

                // If GDB is enabled, we handle the debug memory access
                // Disregard return value as we want to return the error
                #[cfg(gdb)]
                if self.gdb_connection().is_some() {
                    self.handle_debug(dbg_mem_access_fn.clone(), VcpuStopReason::Crash)?;
                }

                log_then_return!(e);
            }
        }
    }

    /// Get InterruptHandle to underlying VM
    fn interrupt_handle(&self) -> Arc<dyn InterruptHandle>;

    /// Get regs
    #[allow(dead_code)]
    fn regs(&self) -> Result<CommonRegisters>;
    /// Set regs
    #[allow(dead_code)]
    fn set_regs(&mut self, regs: &CommonRegisters) -> Result<()>;
    /// Get fpu regs
    #[allow(dead_code)]
    fn fpu(&self) -> Result<CommonFpu>;
    /// Set fpu regs
    #[allow(dead_code)]
    fn set_fpu(&mut self, fpu: &CommonFpu) -> Result<()>;
    /// Get special regs
    #[allow(dead_code)]
    fn sregs(&self) -> Result<CommonSpecialRegisters>;
    /// Set special regs
    #[allow(dead_code)]
    fn set_sregs(&mut self, sregs: &CommonSpecialRegisters) -> Result<()>;

    /// Setup initial special registers for the hypervisor
    /// This is a default implementation that works for all hypervisors
    fn setup_initial_sregs(&mut self, _pml4_addr: u64) -> Result<()> {
        #[cfg(feature = "init-paging")]
        let sregs = CommonSpecialRegisters {
            cr0: CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_AM | CR0_PG | CR0_WP,
            cr4: CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT,
            cr3: _pml4_addr,
            efer: EFER_LME | EFER_LMA | EFER_SCE | EFER_NX,
            cs: CommonSegmentRegister {
                type_: 11,
                present: 1,
                s: 1,
                l: 1,
                ..Default::default()
            },
            tr: CommonSegmentRegister {
                limit: 65535,
                type_: 11,
                present: 1,
                s: 0,
                ..Default::default()
            },
            ..Default::default()
        };

        #[cfg(not(feature = "init-paging"))]
        let sregs = CommonSpecialRegisters {
            cs: CommonSegmentRegister {
                base: 0,
                selector: 0,
                limit: 0xFFFF,
                type_: 11,
                present: 1,
                s: 1,
                ..Default::default()
            },
            ds: CommonSegmentRegister {
                base: 0,
                selector: 0,
                limit: 0xFFFF,
                type_: 3,
                present: 1,
                s: 1,
                ..Default::default()
            },
            tr: CommonSegmentRegister {
                base: 0,
                selector: 0,
                limit: 0xFFFF,
                type_: 11,
                present: 1,
                s: 0,
                ..Default::default()
            },
            ..Default::default()
        };

        self.set_sregs(&sregs)?;
        Ok(())
    }

    /// Get the logging level to pass to the guest entrypoint
    fn get_max_log_level(&self) -> u32 {
        // Check to see if the RUST_LOG environment variable is set
        // and if so, parse it to get the log_level for hyperlight_guest
        // if that is not set get the log level for the hyperlight_host

        // This is done as the guest will produce logs based on the log level returned here
        // producing those logs is expensive and we don't want to do it if the host is not
        // going to process them

        let val = std::env::var("RUST_LOG").unwrap_or_default();

        let level = if val.contains("hyperlight_guest") {
            val.split(',')
                .find(|s| s.contains("hyperlight_guest"))
                .unwrap_or("")
                .split('=')
                .nth(1)
                .unwrap_or("")
        } else if val.contains("hyperlight_host") {
            val.split(',')
                .find(|s| s.contains("hyperlight_host"))
                .unwrap_or("")
                .split('=')
                .nth(1)
                .unwrap_or("")
        } else {
            // look for a value string that does not contain "="
            val.split(',').find(|s| !s.contains("=")).unwrap_or("")
        };

        log::info!("Determined guest log level: {}", level);
        // Convert the log level string to a LevelFilter
        // If no value is found, default to Error
        LevelFilter::from_str(level).unwrap_or(LevelFilter::Error) as u32
    }

    #[cfg(crashdump)]
    fn crashdump_context(&self) -> Result<Option<crashdump::CrashDumpContext>>;

    #[cfg(gdb)]
    /// handles the cases when the vCPU stops due to a Debug event
    fn handle_debug(
        &mut self,
        _dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
        _stop_reason: VcpuStopReason,
    ) -> Result<()> {
        unimplemented!()
    }

    #[cfg(gdb)]
    fn gdb_connection(&self) -> Option<&DebugCommChannel<DebugResponse, DebugMsg>>;

    /// Translates the guest virtual address to physical address
    #[cfg(gdb)]
    fn translate_gva(&self, gva: u64) -> crate::Result<u64>;

    #[cfg(feature = "trace_guest")]
    fn handle_trace(
        &mut self,
        tc: &mut crate::sandbox::trace::TraceContext,
        mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
    ) -> Result<()>;

    /// Get a mutable reference of the trace info for the guest
    #[cfg(feature = "mem_profile")]
    fn trace_info_mut(&mut self) -> &mut MemTraceInfo;
}

/// The vCPU tried to access the given addr
pub(crate) enum MemoryAccess {
    /// The accessed region has the given flags
    AccessViolation(MemoryRegionFlags),
    /// The accessed region is a stack guard page
    StackGuardPageViolation,
}

/// Returns a Some(HyperlightExit::AccessViolation(..)) if the given gpa doesn't have
/// access its corresponding region. Returns None otherwise, or if the region is not found.
pub(crate) fn get_memory_access_violation<'a>(
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

/// A trait for platform-specific interrupt handle implementation details
pub(crate) trait InterruptHandleImpl: InterruptHandle {
    /// Set the thread ID for the vcpu thread (no-op on Windows)
    fn set_tid(&self);

    /// Set the running state and increment generation if needed
    /// Returns Ok(generation) on success, Err(generation) if generation wrapped
    fn set_running(&self);

    /// Clear the running state
    /// On Windows, this also clears cancel_requested and debug_interrupt
    /// On Linux, this only clears the running bit
    fn clear_running(&self);

    /// Mark the handle as dropped
    fn set_dropped(&self);

    /// Check if cancellation was requested
    fn is_cancelled(&self) -> bool;

    /// Clear the cancellation request flag
    fn clear_cancel(&self);

    /// Check if debug interrupt was requested (always returns false when gdb feature is disabled)
    fn is_debug_interrupted(&self) -> bool;

    // Clear the debug interrupt request flag
    #[cfg(gdb)]
    fn clear_debug_interrupt(&self);
}

/// A trait for handling interrupts to a sandbox's vcpu
pub trait InterruptHandle: Send + Sync + Debug {
    /// Interrupt the corresponding sandbox from running.
    ///
    /// - If this is called while the the sandbox currently executing a guest function call, it will interrupt the sandbox and return `true`.
    /// - If this is called while the sandbox is not running (for example before or after calling a guest function), it will do nothing and return `false`.
    ///
    /// # Note
    /// This function will block for the duration of the time it takes for the vcpu thread to be interrupted.
    fn kill(&self) -> bool;

    /// Used by a debugger to interrupt the corresponding sandbox from running.
    ///
    /// - If this is called while the vcpu is running, then it will interrupt the vcpu and return `true`.
    /// - If this is called while the vcpu is not running, (for example during a host call), the
    ///   vcpu will not immediately be interrupted, but will prevent the vcpu from running **the next time**
    ///   it's scheduled, and returns `false`.
    ///
    /// # Note
    /// This function will block for the duration of the time it takes for the vcpu thread to be interrupted.
    #[cfg(gdb)]
    fn kill_from_debugger(&self) -> bool;

    /// Returns true if the corresponding sandbox has been dropped
    fn dropped(&self) -> bool;
}

#[cfg(any(kvm, mshv3))]
#[derive(Debug)]
pub(super) struct LinuxInterruptHandle {
    /// Atomic value packing vcpu execution state.
    ///
    /// Bit layout:
    /// - Bit 63: RUNNING_BIT - set when vcpu is actively running
    /// - Bit 62: CANCEL_BIT - set when cancellation has been requested
    /// - Bits 61-0: generation counter - tracks vcpu run iterations to prevent ABA problem
    ///
    /// CANCEL_BIT persists across vcpu exits/re-entries within a single `HyperlightVm::run()` call
    /// (e.g., during host function calls), but is cleared at the start of each new `HyperlightVm::run()` call.
    running: AtomicU64,

    /// Thread ID where the vcpu is running.
    ///
    /// Note: Multiple VMs may have the same `tid` (same thread runs multiple sandboxes sequentially),
    /// but at most one VM will have RUNNING_BIT set at any given time.
    tid: AtomicU64,

    /// Debugger interrupt flag (gdb feature only).
    /// Set when `kill_from_debugger()` is called, cleared when vcpu stops running.
    #[cfg(gdb)]
    debug_interrupt: AtomicBool,

    /// Whether the corresponding VM has been dropped.
    dropped: AtomicBool,

    /// Delay between retry attempts when sending signals to interrupt the vcpu.
    retry_delay: Duration,

    /// Offset from SIGRTMIN for the signal used to interrupt the vcpu thread.
    sig_rt_min_offset: u8,
}

#[cfg(any(kvm, mshv3))]
impl LinuxInterruptHandle {
    const RUNNING_BIT: u64 = 1 << 63;
    const CANCEL_BIT: u64 = 1 << 62;
    const MAX_GENERATION: u64 = (1 << 62) - 1;

    /// Sets the RUNNING_BIT and increments the generation counter.
    ///
    /// # Preserves
    /// - CANCEL_BIT: The current value of CANCEL_BIT is preserved
    ///
    /// # Invariants Maintained
    /// - Generation increments by 1 (wraps to 0 at MAX_GENERATION)
    /// - RUNNING_BIT is set
    /// - CANCEL_BIT remains unchanged
    ///
    /// # Memory Ordering
    /// Uses `Release` ordering to ensure that the `tid` store (which uses `Release`)
    /// is visible to any thread that observes RUNNING_BIT=true via `Acquire` ordering.
    /// This prevents the interrupt thread from reading a stale `tid` value.
    #[expect(clippy::expect_used)]
    fn set_running_and_increment_generation(&self) -> u64 {
        self.running
            .fetch_update(Ordering::Release, Ordering::Relaxed, |raw| {
                let cancel_bit = raw & Self::CANCEL_BIT; // Preserve CANCEL_BIT
                let generation = raw & Self::MAX_GENERATION;
                let new_generation = if generation == Self::MAX_GENERATION {
                    // restart generation from 0
                    0
                } else {
                    generation + 1
                };
                // Set RUNNING_BIT, preserve CANCEL_BIT, increment generation
                Some(Self::RUNNING_BIT | cancel_bit | new_generation)
            })
            .expect("Should never fail since we always return Some")
    }

    /// Get the running and cancel bits, return the previous value.
    ///
    /// # Memory Ordering
    /// Uses `Acquire` ordering to synchronize with the `Release` in `set_running_and_increment_generation()`.
    /// This ensures that when we observe RUNNING_BIT=true, we also see the correct `tid` value.
    fn get_running_cancel_and_generation(&self) -> (bool, bool, u64) {
        let raw = self.running.load(Ordering::Acquire);
        let running = raw & Self::RUNNING_BIT != 0;
        let cancel = raw & Self::CANCEL_BIT != 0;
        let generation = raw & Self::MAX_GENERATION;
        (running, cancel, generation)
    }

    fn send_signal(&self) -> bool {
        let signal_number = libc::SIGRTMIN() + self.sig_rt_min_offset as libc::c_int;
        let mut sent_signal = false;
        let mut target_generation: Option<u64> = None;

        loop {
            let (running, cancel, generation) = self.get_running_cancel_and_generation();

            // Check if we should continue sending signals
            // Exit if not running OR if neither cancel nor debug_interrupt is set
            #[cfg(gdb)]
            let should_continue =
                running && (cancel || self.debug_interrupt.load(Ordering::Relaxed));
            #[cfg(not(gdb))]
            let should_continue = running && cancel;

            if !should_continue {
                break;
            }

            match target_generation {
                None => target_generation = Some(generation),
                // prevent ABA problem
                Some(expected) if expected != generation => break,
                _ => {}
            }

            log::info!("Sending signal to kill vcpu thread...");
            sent_signal = true;
            // Acquire ordering to synchronize with the Release store in set_tid()
            // This ensures we see the correct tid value for the currently running vcpu
            unsafe {
                libc::pthread_kill(self.tid.load(Ordering::Acquire) as _, signal_number);
            }
            std::thread::sleep(self.retry_delay);
        }

        sent_signal
    }
}

#[cfg(any(kvm, mshv3))]
impl InterruptHandleImpl for LinuxInterruptHandle {
    fn set_tid(&self) {
        // Release ordering to synchronize with the Acquire load of `running` in send_signal()
        // This ensures that when send_signal() observes RUNNING_BIT=true (via Acquire),
        // it also sees the correct tid value stored here
        self.tid
            .store(unsafe { libc::pthread_self() as u64 }, Ordering::Release);
    }

    fn set_running(&self) {
        self.set_running_and_increment_generation();
    }

    fn is_cancelled(&self) -> bool {
        // Acquire ordering to synchronize with the Release in kill()
        // This ensures we see the CANCEL_BIT set by the interrupt thread
        self.running.load(Ordering::Acquire) & Self::CANCEL_BIT != 0
    }

    fn clear_cancel(&self) {
        // Relaxed is sufficient here - we're the only thread that clears this bit
        // at the start of run(), and there's no data race on the clear operation itself
        self.running.fetch_and(!Self::CANCEL_BIT, Ordering::Relaxed);
    }

    fn clear_running(&self) {
        // Release ordering to ensure all vcpu operations are visible before clearing RUNNING_BIT
        self.running
            .fetch_and(!Self::RUNNING_BIT, Ordering::Release);
    }

    fn is_debug_interrupted(&self) -> bool {
        #[cfg(gdb)]
        {
            self.debug_interrupt.load(Ordering::Relaxed)
        }
        #[cfg(not(gdb))]
        {
            false
        }
    }

    #[cfg(gdb)]
    fn clear_debug_interrupt(&self) {
        self.debug_interrupt.store(false, Ordering::Relaxed);
    }

    fn set_dropped(&self) {
        self.dropped.store(true, Ordering::Relaxed);
    }
}

#[cfg(any(kvm, mshv3))]
impl InterruptHandle for LinuxInterruptHandle {
    fn kill(&self) -> bool {
        // Release ordering ensures that any writes before kill() are visible to the vcpu thread
        // when it checks is_cancelled() with Acquire ordering
        self.running.fetch_or(Self::CANCEL_BIT, Ordering::Release);

        // Send signals to interrupt the vcpu if it's currently running
        self.send_signal()
    }

    #[cfg(gdb)]
    fn kill_from_debugger(&self) -> bool {
        self.debug_interrupt.store(true, Ordering::Relaxed);
        self.send_signal()
    }
    fn dropped(&self) -> bool {
        self.dropped.load(Ordering::Relaxed)
    }
}

#[cfg(target_os = "windows")]
#[derive(Debug)]
pub(super) struct WindowsInterruptHandle {
    /// Atomic value packing vcpu execution state.
    ///
    /// Bit layout:
    /// - Bit 1: RUNNING_BIT - set when vcpu is actively running
    /// - Bit 0: CANCEL_BIT - set when cancellation has been requested
    ///
    /// `WHvCancelRunVirtualProcessor()` will return Ok even if the vcpu is not running,
    /// which is why we need the RUNNING_BIT.
    ///
    /// CANCEL_BIT persists across vcpu exits/re-entries within a single `HyperlightVm::run()` call
    /// (e.g., during host function calls), but is cleared at the start of each new `HyperlightVm::run()` call.
    state: AtomicU64,

    // This is used to signal the GDB thread to stop the vCPU
    #[cfg(gdb)]
    debug_interrupt: AtomicBool,
    partition_handle: windows::Win32::System::Hypervisor::WHV_PARTITION_HANDLE,
    dropped: AtomicBool,
}

#[cfg(target_os = "windows")]
impl WindowsInterruptHandle {
    const RUNNING_BIT: u64 = 1 << 1;
    const CANCEL_BIT: u64 = 1 << 0;
}

#[cfg(target_os = "windows")]
impl InterruptHandleImpl for WindowsInterruptHandle {
    fn set_tid(&self) {
        // No-op on Windows - we don't need to track thread ID
    }

    fn set_running(&self) {
        // Release ordering to ensure prior memory operations are visible when another thread observes running=true
        self.state.fetch_or(Self::RUNNING_BIT, Ordering::Release);
    }

    fn is_cancelled(&self) -> bool {
        // Acquire ordering to synchronize with the Release in kill()
        // This ensures we see the CANCEL_BIT set by the interrupt thread
        self.state.load(Ordering::Acquire) & Self::CANCEL_BIT != 0
    }

    fn clear_cancel(&self) {
        // Relaxed is sufficient here - we're the only thread that clears this bit
        // at the start of run(), and there's no data race on the clear operation itself
        self.state.fetch_and(!Self::CANCEL_BIT, Ordering::Relaxed);
    }

    fn clear_running(&self) {
        // Release ordering to ensure all vcpu operations are visible before clearing running
        self.state.fetch_and(!Self::RUNNING_BIT, Ordering::Release);
        #[cfg(gdb)]
        self.debug_interrupt.store(false, Ordering::Relaxed);
    }

    fn is_debug_interrupted(&self) -> bool {
        #[cfg(gdb)]
        {
            self.debug_interrupt.load(Ordering::Relaxed)
        }
        #[cfg(not(gdb))]
        {
            false
        }
    }

    #[cfg(gdb)]
    fn clear_debug_interrupt(&self) {
        #[cfg(gdb)]
        self.debug_interrupt.store(false, Ordering::Relaxed);
    }

    fn set_dropped(&self) {
        self.dropped.store(true, Ordering::Relaxed);
    }
}

#[cfg(target_os = "windows")]
impl InterruptHandle for WindowsInterruptHandle {
    fn kill(&self) -> bool {
        use windows::Win32::System::Hypervisor::WHvCancelRunVirtualProcessor;

        // Release ordering ensures that any writes before kill() are visible to the vcpu thread
        // when it checks is_cancelled() with Acquire ordering
        self.state.fetch_or(Self::CANCEL_BIT, Ordering::Release);

        // Acquire ordering to synchronize with the Release in set_running()
        // This ensures we see the running state set by the vcpu thread
        let state = self.state.load(Ordering::Acquire);
        (state & Self::RUNNING_BIT != 0)
            && unsafe { WHvCancelRunVirtualProcessor(self.partition_handle, 0, 0).is_ok() }
    }
    #[cfg(gdb)]
    fn kill_from_debugger(&self) -> bool {
        use windows::Win32::System::Hypervisor::WHvCancelRunVirtualProcessor;

        self.debug_interrupt.store(true, Ordering::Relaxed);
        // Acquire ordering to synchronize with the Release in set_running()
        let state = self.state.load(Ordering::Acquire);
        (state & Self::RUNNING_BIT != 0)
            && unsafe { WHvCancelRunVirtualProcessor(self.partition_handle, 0, 0).is_ok() }
    }

    fn dropped(&self) -> bool {
        self.dropped.load(Ordering::Relaxed)
    }
}

#[cfg(all(test, any(target_os = "windows", kvm)))]
pub(crate) mod tests {
    use std::sync::{Arc, Mutex};

    use hyperlight_testing::dummy_guest_as_string;

    use crate::sandbox::uninitialized::GuestBinary;
    #[cfg(any(crashdump, gdb))]
    use crate::sandbox::uninitialized::SandboxRuntimeConfig;
    use crate::sandbox::uninitialized_evolve::set_up_hypervisor_partition;
    use crate::sandbox::{SandboxConfiguration, UninitializedSandbox};
    use crate::{Result, is_hypervisor_present, new_error};

    #[test]
    fn test_initialise() -> Result<()> {
        if !is_hypervisor_present() {
            return Ok(());
        }

        use crate::mem::ptr::RawPtr;
        use crate::sandbox::host_funcs::FunctionRegistry;

        let filename = dummy_guest_as_string().map_err(|e| new_error!("{}", e))?;

        let config: SandboxConfiguration = Default::default();
        #[cfg(any(crashdump, gdb))]
        let rt_cfg: SandboxRuntimeConfig = Default::default();
        let sandbox =
            UninitializedSandbox::new(GuestBinary::FilePath(filename.clone()), Some(config))?;
        let (mem_mgr, mut gshm) = sandbox.mgr.build();
        let mut vm = set_up_hypervisor_partition(
            &mut gshm,
            &config,
            #[cfg(any(crashdump, gdb))]
            &rt_cfg,
            sandbox.load_info,
        )?;

        // Set up required parameters for initialise
        let peb_addr = RawPtr::from(0x1000u64); // Dummy PEB address
        let seed = 12345u64; // Random seed
        let page_size = 4096u32; // Standard page size
        let host_funcs = Arc::new(Mutex::new(FunctionRegistry::default()));
        let guest_max_log_level = Some(log::LevelFilter::Error);

        #[cfg(gdb)]
        let dbg_mem_access_fn = Arc::new(Mutex::new(mem_mgr.clone()));

        // Test the initialise method
        vm.initialise(
            peb_addr,
            seed,
            page_size,
            mem_mgr,
            host_funcs,
            guest_max_log_level,
            #[cfg(gdb)]
            dbg_mem_access_fn,
        )?;

        Ok(())
    }
}
