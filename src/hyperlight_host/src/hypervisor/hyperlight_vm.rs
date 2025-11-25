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

use crate::metrics::{METRIC_ERRONEOUS_VCPU_KICKS, METRIC_GUEST_CANCELLATION};
use crate::{HyperlightError, Result, log_then_return, new_error};

#[cfg(any(kvm, mshv3))]
use crate::hypervisor::LinuxInterruptHandle;
use crate::hypervisor::{
    HyperlightExit, Hypervisor, InterruptHandle, InterruptHandleImpl, MemoryAccess,
    get_memory_access_violation,
};
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::ptr::RawPtr;
use crate::mem::shared_mem::HostSharedMemory;
use crate::sandbox::SandboxConfiguration;
use crate::sandbox::host_funcs::FunctionRegistry;
use crate::sandbox::outb::handle_outb;

use log::LevelFilter;
#[cfg(any(kvm, mshv3))]
#[cfg(not(all(
    target_arch = "x86_64",
    target_vendor = "unknown",
    target_os = "linux",
    target_env = "musl"
)))]
use std::sync::atomic::AtomicU64;
#[cfg(any(kvm, mshv3))]
use std::sync::atomic::{AtomicBool, AtomicU8};
use std::sync::{Arc, Mutex};
use tracing::{Span, instrument};

#[derive(Debug)]
pub(crate) struct HyperlightVm {
    pub(crate) vm: Box<dyn Hypervisor>,
    interrupt_handle: Arc<dyn InterruptHandleImpl>,

    sandbox_regions: Vec<MemoryRegion>, // Initially mapped regions when sandbox is created
    mmap_regions: Vec<(u32, MemoryRegion)>, // Later mapped regions (slot number, region)
    next_slot: u32,                     // Monotonically increasing slot number
    freed_slots: Vec<u32>,              // Reusable slots from unmapped regions
}

impl HyperlightVm {
    pub(crate) fn new(
        mut vm: Box<dyn Hypervisor>,
        mem_regions: Vec<MemoryRegion>,
        config: &SandboxConfiguration,
    ) -> Result<Self> {
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
            partition_handle: vm.partition_handle(),
            dropped: AtomicBool::new(false),
        });

        for (i, region) in mem_regions.iter().enumerate() {
            // Safety: slots are unique and region points to valid memory since we created the regions
            unsafe { vm.map_memory((i as u32, region))? };
        }

        Ok(Self {
            vm,
            interrupt_handle,
            next_slot: mem_regions.len() as u32,
            sandbox_regions: mem_regions,
            mmap_regions: Vec::new(),
            freed_slots: Vec::new(),
        })
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
        )?;
        self.run(mem_mgr, host_funcs)
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

    pub(crate) fn get_mapped_regions(&self) -> impl Iterator<Item = &MemoryRegion> {
        self.mmap_regions.iter().map(|(_, region)| region)
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
        )?;
        self.run(mem_mgr, host_funcs)
    }

    pub(crate) fn interrupt_handle(&self) -> Arc<dyn InterruptHandle> {
        self.vm.interrupt_handle()
    }

    pub(crate) fn clear_cancel(&self) {
        self.vm.clear_cancel()
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
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
                tc.end_host_trace();

                // Handle the guest trace data if any
                #[cfg(feature = "trace_guest")]
                {
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
                    break Err(HyperlightError::ExecutionCanceledByHost());
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
