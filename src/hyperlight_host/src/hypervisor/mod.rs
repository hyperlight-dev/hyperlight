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

use log::{LevelFilter, debug};
use tracing::{Span, instrument};

use crate::HyperlightError::StackOverflow;
use crate::error::HyperlightError::ExecutionCanceledByHost;
use crate::hypervisor::regs::{
    CommonFpu, CommonRegisters, CommonSegmentRegister, CommonSpecialRegisters,
};
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::metrics::METRIC_GUEST_CANCELLATION;
#[cfg(feature = "mem_profile")]
use crate::sandbox::trace::MemTraceInfo;
use crate::{HyperlightError, Result, log_then_return};

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
pub enum HyperlightExit {
    #[cfg(gdb)]
    /// The vCPU has exited due to a debug event
    Debug(VcpuStopReason),
    /// The vCPU has halted
    Halt(),
    /// The vCPU has issued a write to the given port with the given value
    IoOut(u16, Vec<u8>, u64, u64),
    /// The vCPU has attempted to read or write from an unmapped address
    Mmio(u64),
    /// The vCPU tried to access memory but was missing the required permissions
    AccessViolation(u64, MemoryRegionFlags, MemoryRegionFlags),
    /// The vCPU execution has been cancelled
    Cancelled(),
    /// The vCPU has exited for a reason that is not handled by Hyperlight
    Unknown(String),
    /// The operation should be retried
    /// On Linux this can happen where a call to run the CPU can return EAGAIN
    /// On Windows the platform could cause a cancelation of the VM run
    Retry(),
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
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    ) -> Result<()>;

    /// Handle an IO exit from the internally stored vCPU.
    fn handle_io(
        &mut self,
        port: u16,
        data: Vec<u8>,
        rip: u64,
        instruction_length: u64,
    ) -> Result<()>;

    /// Run the vCPU
    fn run(
        &mut self,
        #[cfg(feature = "trace_guest")] tc: &mut crate::sandbox::trace::TraceContext,
    ) -> Result<HyperlightExit>;

    /// Get InterruptHandle to underlying VM (returns internal trait)
    fn interrupt_handle(&self) -> Arc<dyn InterruptHandleInternal>;

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

    /// get a mutable trait object from self
    fn as_mut_hypervisor(&mut self) -> &mut dyn Hypervisor;

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

    /// Check stack guard to see if the stack is still valid
    fn check_stack_guard(&self) -> Result<bool>;

    #[cfg(feature = "trace_guest")]
    fn handle_trace(&mut self, tc: &mut crate::sandbox::trace::TraceContext) -> Result<()>;

    /// Get a mutable reference of the trace info for the guest
    #[cfg(feature = "mem_profile")]
    fn trace_info_mut(&mut self) -> &mut MemTraceInfo;
}

/// Returns a Some(HyperlightExit::AccessViolation(..)) if the given gpa doesn't have
/// access its corresponding region. Returns None otherwise, or if the region is not found.
pub(crate) fn get_memory_access_violation<'a>(
    gpa: usize,
    mut mem_regions: impl Iterator<Item = &'a MemoryRegion>,
    access_info: MemoryRegionFlags,
) -> Option<HyperlightExit> {
    // find the region containing the given gpa
    let region = mem_regions.find(|region| region.guest_region.contains(&gpa));

    if let Some(region) = region
        && (!region.flags.contains(access_info)
            || region.flags.contains(MemoryRegionFlags::STACK_GUARD))
    {
        return Some(HyperlightExit::AccessViolation(
            gpa as u64,
            access_info,
            region.flags,
        ));
    }
    None
}

/// A virtual CPU that can be run until an exit occurs
pub struct VirtualCPU {}

impl VirtualCPU {
    /// Run the given hypervisor until a halt instruction is reached
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn run(
        hv: &mut dyn Hypervisor,
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    ) -> Result<()> {
        // Keeps the trace context and open spans
        #[cfg(feature = "trace_guest")]
        let mut tc = crate::sandbox::trace::TraceContext::new();

        loop {
            #[cfg(feature = "trace_guest")]
            let result = {
                let result = hv.run(&mut tc);
                // End current host trace by closing the current span that captures traces
                // happening when a guest exits and re-enters.
                tc.end_host_trace();

                // Handle the guest trace data if any
                if let Err(e) = hv.handle_trace(&mut tc) {
                    // If no trace data is available, we just log a message and continue
                    // Is this the right thing to do?
                    log::debug!("Error handling guest trace: {:?}", e);
                }

                result
            };
            #[cfg(not(feature = "trace_guest"))]
            let result = hv.run();

            match result {
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
                    hv.handle_io(port, data, rip, instruction_length)?
                }
                Ok(HyperlightExit::Mmio(addr)) => {
                    #[cfg(crashdump)]
                    crashdump::generate_crashdump(hv)?;

                    if !hv.check_stack_guard()? {
                        log_then_return!(StackOverflow());
                    }

                    log_then_return!("MMIO access address {:#x}", addr);
                }
                Ok(HyperlightExit::AccessViolation(addr, tried, region_permission)) => {
                    #[cfg(crashdump)]
                    crashdump::generate_crashdump(hv)?;

                    // If GDB is enabled, we handle the debug memory access
                    // Disregard return value as we want to return the error
                    #[cfg(gdb)]
                    let _ = hv.handle_debug(dbg_mem_access_fn.clone(), VcpuStopReason::Crash);

                    if region_permission.intersects(MemoryRegionFlags::STACK_GUARD) {
                        return Err(HyperlightError::StackOverflow());
                    }
                    log_then_return!(HyperlightError::MemoryAccessViolation(
                        addr,
                        tried,
                        region_permission
                    ));
                }
                Ok(HyperlightExit::Cancelled()) => {
                    // Shutdown is returned when the host has cancelled execution
                    // After termination, the main thread will re-initialize the VM
                    metrics::counter!(METRIC_GUEST_CANCELLATION).increment(1);
                    log_then_return!(ExecutionCanceledByHost());
                }
                Ok(HyperlightExit::Unknown(reason)) => {
                    #[cfg(crashdump)]
                    crashdump::generate_crashdump(hv)?;
                    // If GDB is enabled, we handle the debug memory access
                    // Disregard return value as we want to return the error
                    #[cfg(gdb)]
                    let _ = hv.handle_debug(dbg_mem_access_fn.clone(), VcpuStopReason::Crash);

                    log_then_return!("Unexpected VM Exit {:?}", reason);
                }
                Ok(HyperlightExit::Retry()) => {
                    debug!("[VCPU] Retry - continuing VM run loop");
                    continue;
                }
                Err(e) => {
                    #[cfg(crashdump)]
                    crashdump::generate_crashdump(hv)?;
                    // If GDB is enabled, we handle the debug memory access
                    // Disregard return value as we want to return the error
                    #[cfg(gdb)]
                    let _ = hv.handle_debug(dbg_mem_access_fn.clone(), VcpuStopReason::Crash);

                    return Err(e);
                }
            }
        }

        Ok(())
    }
}

/// A trait for handling interrupts to a sandbox's vcpu (public API)
pub trait InterruptHandle: Debug + Send + Sync {
    /// Interrupt the corresponding sandbox from running.
    ///
    /// This method attempts to cancel a currently executing guest function call by sending
    /// a signal to the VCPU thread. It uses generation tracking and call_active flag to
    /// ensure the interruption is safe and precise.
    ///
    /// # Behavior
    ///
    /// - **Guest function running**: If called while a guest function is executing (VCPU running
    ///   or in a host function call), this stamps the current generation into cancel_requested
    ///   and sends a signal to interrupt the VCPU. Returns `true`.
    ///
    /// - **No active call**: If called when no guest function call is in progress (call_active=false),
    ///   this has no effect and returns `false`. This prevents "kill-in-advance" where kill()
    ///   is called before a guest function starts.
    ///
    /// - **During host function**: If the guest call is currently executing a host function
    ///   (VCPU not running but call_active=true), this stamps cancel_requested. When the
    ///   host function returns and attempts to re-enter the guest, the cancellation will
    ///   be detected and the call will abort. Returns `true`.
    ///
    /// # Generation Tracking
    ///
    /// The method stamps the current generation number along with the cancellation request.
    /// This ensures that:
    /// - Stale signals from previous calls are ignored (generation mismatch)
    /// - Only the intended guest function call is affected
    /// - Multiple rapid kill() calls on the same generation are idempotent
    ///
    /// # Blocking Behavior
    ///
    /// This function will block while attempting to deliver the signal to the VCPU thread,
    /// retrying until either:
    /// - The signal is successfully delivered (VCPU transitions from running to not running)
    /// - The VCPU stops running for another reason (e.g., call completes normally)
    ///
    /// # Returns
    ///
    /// - `true`: Cancellation request was stamped (kill will take effect)
    /// - `false`: No active call, cancellation request was not stamped (no effect)
    ///
    /// # Note
    ///
    /// To reliably interrupt a guest call, ensure `kill()` is called while the guest
    /// function is actually executing. Calling kill() before call_guest_function() will
    /// have no effect.
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

    /// Check if the corresponding VM has been dropped.
    fn dropped(&self) -> bool;
}

/// Internal trait for interrupt handle implementation details (private, cross-platform).
///
/// This trait contains all the internal atomics access methods and helper functions
/// that are shared between Linux and Windows implementations. It extends InterruptHandle
/// to inherit the public API.
///
/// This trait should NOT be used outside of hypervisor implementations.
pub(crate) trait InterruptHandleInternal: InterruptHandle {
    /// Returns the call_active atomic bool reference for internal implementations.
    fn get_call_active(&self) -> &AtomicBool;

    /// Returns the running atomic u64 reference for internal implementations.
    fn get_running(&self) -> &AtomicU64;

    /// Returns the cancel_requested atomic u64 reference for internal implementations.
    fn get_cancel_requested(&self) -> &AtomicU64;

    /// Set call_active - increments generation and sets flag.
    ///
    /// Increments the generation counter and sets the call_active flag to true,
    /// indicating that a guest function call is now in progress. This allows
    /// kill() to stamp cancel_requested with the correct generation.
    ///
    /// Must be called at the start of call_guest_function_by_name_no_reset(),
    /// before any VCPU execution begins.
    ///
    /// Returns true if call_active was already set (indicating a guard already exists),
    /// false otherwise.
    fn set_call_active(&self) -> bool {
        self.increment_generation();
        self.get_call_active().swap(true, Ordering::AcqRel)
    }

    /// Clear call_active - clears the call_active flag.
    ///
    /// Clears the call_active flag, indicating that no guest function call is
    /// in progress. After this, kill() will have no effect and will return false.
    ///
    /// Must be called at the end of call_guest_function_by_name_no_reset(),
    /// after the guest call has fully completed (whether successfully or with error).
    fn clear_call_active(&self) {
        self.get_call_active().store(false, Ordering::Release)
    }

    /// Set cancel_requested to true with the given generation.
    ///
    /// This stamps the cancellation request with the current generation number,
    /// ensuring that only the VCPU running with this exact generation will honor
    /// the cancellation.
    fn set_cancel_requested(&self, generation: u64) {
        const CANCEL_REQUESTED_BIT: u64 = 1 << 63;
        const MAX_GENERATION: u64 = CANCEL_REQUESTED_BIT - 1;
        let value = CANCEL_REQUESTED_BIT | (generation & MAX_GENERATION);
        self.get_cancel_requested().store(value, Ordering::Release);
    }

    /// Clear cancel_requested (reset to no cancellation).
    ///
    /// This is called after a cancellation has been processed to reset the
    /// cancellation flag for the next guest call.
    fn clear_cancel_requested(&self) {
        self.get_cancel_requested().store(0, Ordering::Release);
    }

    /// Check if cancel_requested is set for the given generation.
    ///
    /// Returns true only if BOTH:
    /// - The cancellation flag is set
    /// - The stored generation matches the provided generation
    ///
    /// This prevents stale cancellations from affecting new guest calls.
    fn is_cancel_requested_for_generation(&self, generation: u64) -> bool {
        const CANCEL_REQUESTED_BIT: u64 = 1 << 63;
        const MAX_GENERATION: u64 = CANCEL_REQUESTED_BIT - 1;
        let raw = self.get_cancel_requested().load(Ordering::Acquire);
        let is_set = raw & CANCEL_REQUESTED_BIT != 0;
        let stored_generation = raw & MAX_GENERATION;
        is_set && stored_generation == generation
    }

    /// Set running bit to true, return current generation.
    ///
    /// This is called when the VCPU is about to enter guest mode. It atomically
    /// sets the running flag while preserving the generation counter.
    fn set_running_bit(&self) -> u64 {
        const RUNNING_BIT: u64 = 1 << 63;
        self.get_running()
            .fetch_update(Ordering::Release, Ordering::Acquire, |raw| {
                Some(raw | RUNNING_BIT)
            })
            .map(|raw| raw & !RUNNING_BIT) // Return the current generation
            .unwrap_or(0)
    }

    /// Increment the generation for a new guest function call.
    ///
    /// The generation counter wraps around at MAX_GENERATION (2^63 - 1).
    /// This is called at the start of each new guest function call to provide
    /// a unique identifier that prevents ABA problems with stale cancellations.
    ///
    /// Returns the NEW generation number (after incrementing).
    fn increment_generation(&self) -> u64 {
        const RUNNING_BIT: u64 = 1 << 63;
        const MAX_GENERATION: u64 = RUNNING_BIT - 1;
        self.get_running()
            .fetch_update(Ordering::Release, Ordering::Acquire, |raw| {
                let current_generation = raw & !RUNNING_BIT;
                let running_bit = raw & RUNNING_BIT;
                if current_generation == MAX_GENERATION {
                    // Restart generation from 0
                    return Some(running_bit);
                }
                Some((current_generation + 1) | running_bit)
            })
            .map(|raw| (raw & !RUNNING_BIT) + 1) // Return the NEW generation
            .unwrap_or(1) // If wrapped, return 1
    }

    /// Get the current running state and generation counter.
    ///
    /// Returns a tuple of (running, generation) where:
    /// - running: true if VCPU is currently in guest mode
    /// - generation: current generation counter value
    fn get_running_and_generation(&self) -> (bool, u64) {
        const RUNNING_BIT: u64 = 1 << 63;
        let raw = self.get_running().load(Ordering::Acquire);
        let running = raw & RUNNING_BIT != 0;
        let generation = raw & !RUNNING_BIT;
        (running, generation)
    }

    /// Clear the running bit and return the old value.
    ///
    /// This is called when the VCPU exits from guest mode back to host mode.
    /// The return value (which includes the generation and the old running bit)
    /// is currently unused by all callers.
    fn clear_running_bit(&self) -> u64 {
        const RUNNING_BIT: u64 = 1 << 63;
        self.get_running()
            .fetch_and(!RUNNING_BIT, Ordering::Release)
    }
}

#[cfg(any(kvm, mshv3))]
#[derive(Debug)]
pub(super) struct LinuxInterruptHandle {
    /// Atomic flag combining running state and generation counter.
    ///
    /// **Bit 63**: VCPU running state (1 = running, 0 = not running)
    /// **Bits 0-62**: Generation counter (incremented once per guest function call)
    ///
    /// # Generation Tracking
    ///
    /// The generation counter is incremented once at the start of each guest function call
    /// and remains constant throughout that call, even if the VCPU is run multiple times
    /// (due to host function calls, retries, etc.). This design solves the race condition
    /// where a kill() from a previous call could spuriously cancel a new call.
    ///
    /// ## Why Generations Are Needed
    ///
    /// Consider this scenario WITHOUT generation tracking:
    /// 1. Thread A starts guest call 1, VCPU runs
    /// 2. Thread B calls kill(), sends signal to Thread A
    /// 3. Guest call 1 completes before signal arrives
    /// 4. Thread A starts guest call 2, VCPU runs again
    /// 5. Stale signal from step 2 arrives and incorrectly cancels call 2
    ///
    /// WITH generation tracking:
    /// 1. Thread A starts guest call 1 (generation N), VCPU runs
    /// 2. Thread B calls kill(), stamps cancel_requested with generation N
    /// 3. Guest call 1 completes, signal may or may not have arrived yet
    /// 4. Thread A starts guest call 2 (generation N+1), VCPU runs again
    /// 5. If stale signal arrives, signal handler checks: cancel_requested.generation (N) != current generation (N+1)
    /// 6. Stale signal is ignored, call 2 continues normally
    ///
    /// ## Per-Call vs Per-Run Generation
    ///
    /// It's critical that generation is incremented per GUEST FUNCTION CALL, not per vcpu.run():
    /// - A single guest function call may invoke vcpu.run() multiple times (host calls, retries)
    /// - All run() calls within the same guest call must share the same generation
    /// - This ensures kill() affects the entire guest function call atomically
    ///
    /// # Invariants
    ///
    /// - If VCPU is running: bit 63 is set (neither converse nor inverse holds)
    /// - If VCPU is running: bits 0-62 match the current guest call's generation
    running: AtomicU64,

    /// Thread ID where the VCPU is currently running.
    ///
    /// # Invariants
    ///
    /// - If VCPU is running: tid contains the thread ID of the executing thread
    /// - Multiple VMs may share the same tid, but at most one will have running=true
    tid: AtomicU64,

    /// Generation-aware cancellation request flag.
    ///
    /// **Bit 63**: Cancellation requested flag (1 = kill requested, 0 = no kill)
    /// **Bits 0-62**: Generation number when cancellation was requested
    ///
    /// # Purpose
    ///
    /// This flag serves three critical functions:
    ///
    /// 1. **Prevent stale signals**: A VCPU may only be interrupted if cancel_requested
    ///    is set AND the generation matches the current call's generation
    ///
    /// 2. **Handle host function calls**: If kill() is called while a host function is
    ///    executing (VCPU not running but call is active), cancel_requested is stamped
    ///    with the current generation. When the host function returns and the VCPU
    ///    attempts to re-enter the guest, it will see the cancellation and abort.
    ///
    /// 3. **Detect stale kills**: If cancel_requested.generation doesn't match the
    ///    current generation, it's from a previous call and should be ignored
    ///
    /// # States and Transitions
    ///
    /// - **No cancellation**: cancel_requested = 0 (bit 63 clear)
    /// - **Cancellation for generation N**: cancel_requested = (1 << 63) | N
    /// - Signal handler checks: (cancel_requested & 0x7FFFFFFFFFFFFFFF) == current_generation
    cancel_requested: AtomicU64,

    /// Flag indicating whether a guest function call is currently in progress.
    ///
    /// **true**: A guest function call is active (between call start and completion)
    /// **false**: No guest function call is active
    ///
    /// # Purpose
    ///
    /// This flag prevents kill() from having any effect when called outside of a
    /// guest function call. This solves the "kill-in-advance" problem where kill()
    /// could be called before a guest function starts and would incorrectly cancel it.
    ///
    /// # Behavior
    ///
    /// - Set to true at the start of call_guest_function_by_name_no_reset()
    /// - Cleared at the end of call_guest_function_by_name_no_reset()
    /// - kill() only stamps cancel_requested if call_active is true
    /// - If kill() is called when call_active=false, it returns false and has no effect
    ///
    /// # Why AtomicBool is Safe
    ///
    /// Although there's a theoretical race where:
    /// 1. Thread A checks call_active (false)
    /// 2. Thread B sets call_active (true) and starts guest call
    /// 3. Thread A's kill() returns false (no effect)
    ///
    /// This is acceptable because the generation tracking provides an additional
    /// safety layer. Even if a stale kill somehow stamped cancel_requested, the
    /// generation mismatch would cause it to be ignored.
    call_active: AtomicBool,

    /// Debugger interrupt request flag (GDB only).
    ///
    /// Set when kill_from_debugger() is called, cleared when VCPU stops running.
    /// Used to distinguish debugger interrupts from normal kill() interrupts.
    #[cfg(gdb)]
    debug_interrupt: AtomicBool,

    /// Whether the corresponding VM has been dropped.
    dropped: AtomicBool,

    /// Delay between retry attempts when sending signals to the VCPU thread.
    retry_delay: Duration,

    /// Offset from SIGRTMIN for the signal used to interrupt the VCPU thread.
    sig_rt_min_offset: u8,
}

#[cfg(any(kvm, mshv3))]
impl LinuxInterruptHandle {
    fn send_signal(&self, stamp_generation: bool) -> bool {
        let signal_number = libc::SIGRTMIN() + self.sig_rt_min_offset as libc::c_int;
        let mut sent_signal = false;
        let mut target_generation: Option<u64> = None;

        loop {
            if !self.call_active.load(Ordering::Acquire) {
                // No active call, so no need to send signal
                break;
            }

            let (running, generation) = self.get_running_and_generation();

            // Stamp generation into cancel_requested if requested and this is the first iteration
            // We stamp even when running=false to support killing during host function calls
            // The generation tracking will prevent stale kills from affecting new calls
            // Only stamp if a call is actually active (call_active=true)
            if stamp_generation
                && target_generation.is_none()
                && self.call_active.load(Ordering::Acquire)
            {
                self.set_cancel_requested(generation);
                target_generation = Some(generation);
            }

            // If not running, we've stamped the generation (if requested), so we're done
            // This handles the host function call scenario
            if !running {
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
            unsafe {
                libc::pthread_kill(self.tid.load(Ordering::Acquire) as _, signal_number);
            }
            std::thread::sleep(self.retry_delay);
        }

        sent_signal
    }
}

#[cfg(any(kvm, mshv3))]
impl InterruptHandle for LinuxInterruptHandle {
    fn kill(&self) -> bool {
        if !(self.call_active.load(Ordering::Acquire)) {
            // No active call, so no effect
            return false;
        }

        // send_signal will stamp the generation into cancel_requested
        // right before sending each signal, ensuring they're always in sync
        self.send_signal(true)
    }

    #[cfg(gdb)]
    fn kill_from_debugger(&self) -> bool {
        self.debug_interrupt.store(true, Ordering::Relaxed);
        self.send_signal(false)
    }

    fn dropped(&self) -> bool {
        self.dropped.load(Ordering::Relaxed)
    }
}

#[cfg(any(kvm, mshv3))]
impl InterruptHandleInternal for LinuxInterruptHandle {
    fn get_call_active(&self) -> &AtomicBool {
        &self.call_active
    }

    fn get_running(&self) -> &AtomicU64 {
        &self.running
    }

    fn get_cancel_requested(&self) -> &AtomicU64 {
        &self.cancel_requested
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
