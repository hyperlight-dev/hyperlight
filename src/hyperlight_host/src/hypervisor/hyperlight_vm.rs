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

use crate::Result;

use crate::hypervisor::{Hypervisor, InterruptHandle};
use crate::mem::memory_region::MemoryRegion;
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::ptr::RawPtr;
use crate::mem::shared_mem::HostSharedMemory;
use crate::sandbox::host_funcs::FunctionRegistry;

use log::LevelFilter;
use std::sync::{Arc, Mutex};

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
    pub(crate) fn new(inner: Box<dyn Hypervisor>) -> Self {
        Self { vm: inner }
    }

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
        self.vm.initialise(
            peb_addr,
            seed,
            page_size,
            mem_mgr,
            host_funcs,
            guest_max_log_level,
            #[cfg(gdb)]
            dbg_mem_access_fn,
        )
    }

    pub(crate) unsafe fn map_region(&mut self, rgn: &MemoryRegion) -> Result<()> {
        unsafe { self.vm.map_region(rgn) }
    }

    pub(crate) unsafe fn unmap_region(&mut self, rgn: &MemoryRegion) -> Result<()> {
        unsafe { self.vm.unmap_region(rgn) }
    }

    pub(crate) fn get_mapped_regions(
        &self,
    ) -> Box<dyn ExactSizeIterator<Item = &MemoryRegion> + '_> {
        self.vm.get_mapped_regions()
    }

    pub(crate) fn dispatch_call_from_host(
        &mut self,
        dispatch_func_addr: RawPtr,
        mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
        host_funcs: &Arc<Mutex<FunctionRegistry>>,
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    ) -> Result<()> {
        self.vm.dispatch_call_from_host(
            dispatch_func_addr,
            mem_mgr,
            host_funcs,
            #[cfg(gdb)]
            dbg_mem_access_fn,
        )
    }

    pub(crate) fn interrupt_handle(&self) -> Arc<dyn InterruptHandle> {
        self.vm.interrupt_handle()
    }

    pub(crate) fn clear_cancel(&self) {
        self.vm.clear_cancel()
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
                            if !mem_mgr.check_stack_guard()? {
                                break Err(HyperlightError::StackOverflow());
                            }

                            break Err(new_error!("MMIO READ access address {:#x}", addr));
                        }
                    }
                }
                Ok(HyperlightExit::MmioWrite(addr)) => {
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