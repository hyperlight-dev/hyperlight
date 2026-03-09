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

#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(gdb)]
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

#[cfg(target_arch = "aarch64")]
pub(crate) use aarch64::*;
use hyperlight_common::log_level::GuestLogFilter;
use tracing_core::LevelFilter;

use crate::HyperlightError;
#[cfg(gdb)]
use crate::hypervisor::gdb::DebuggableVm;
#[cfg(gdb)]
use crate::hypervisor::gdb::arch::VcpuStopReasonError;
#[cfg(gdb)]
use crate::hypervisor::gdb::{
    DebugCommChannel, DebugError, DebugMsg, DebugResponse, GdbTargetError, VcpuStopReason,
};
#[cfg(gdb)]
use crate::hypervisor::hyperlight_vm::x86_64::debug::ProcessDebugRequestError;
#[cfg(not(gdb))]
use crate::hypervisor::virtual_machine::VirtualMachine;
use crate::hypervisor::virtual_machine::{
    MapMemoryError, RegisterError, RunVcpuError, UnmapMemoryError, VmError, VmExit,
};
use crate::hypervisor::{InterruptHandle, InterruptHandleImpl};
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags, MemoryRegionType};
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::shared_mem::{GuestSharedMemory, HostSharedMemory, SharedMemory};
use crate::metrics::{METRIC_ERRONEOUS_VCPU_KICKS, METRIC_GUEST_CANCELLATION};
use crate::sandbox::host_funcs::FunctionRegistry;
use crate::sandbox::outb::{HandleOutbError, handle_outb};
use crate::sandbox::snapshot::NextAction;
#[cfg(feature = "mem_profile")]
use crate::sandbox::trace::MemTraceInfo;
#[cfg(crashdump)]
use crate::sandbox::uninitialized::SandboxRuntimeConfig;

/// Get the logging level filter to pass to the guest entrypoint
///
/// The guest entrypoint uses this to determine the maximum log level to enable for the guest.
/// The `RUST_LOG` environment variable is expected to be in the format of comma-separated
/// key-value pairs, where the key is a log target (e.g., "hyperlight_guest_bin") and the value is
/// a log level (e.g., "debug").
///
/// NOTE: This prioritizes the log level for the targets containing "hyperlight_guest" string, then
/// "hyperlight_host", and then general log level. If none of these targets are found, it
/// defaults to "error".
fn get_max_log_level_filter(rust_log: String) -> LevelFilter {
    // This is done as the guest will produce logs based on the log level returned here
    // producing those logs is expensive and we don't want to do it if the host is not
    // going to process them
    let level_str = rust_log
        .split(',')
        // Prioritize targets containing "hyperlight_guest"
        .find_map(|part| {
            let mut kv = part.splitn(2, '=');
            match (kv.next(), kv.next()) {
                (Some(k), Some(v)) if k.trim().contains("hyperlight_guest") => Some(v.trim()),
                _ => None,
            }
        })
        // Then check for "hyperlight_host"
        .or_else(|| {
            rust_log.split(',').find_map(|part| {
                let mut kv = part.splitn(2, '=');
                match (kv.next(), kv.next()) {
                    (Some(k), Some(v)) if k.trim().contains("hyperlight_host") => Some(v.trim()),
                    _ => None,
                }
            })
        })
        // Finally, check for general log level
        .or_else(|| {
            rust_log.split(',').find_map(|part| {
                if part.contains("=") {
                    None
                } else {
                    Some(part.trim())
                }
            })
        })
        .unwrap_or("");

    tracing::info!("Determined guest log level: {}", level_str);

    // If no value is found, default to Error
    LevelFilter::from_str(level_str).unwrap_or(LevelFilter::ERROR)
}

/// Converts a given [`Option<LevelFilter>`] to a `u64` value to be passed to the guest entrypoint
/// If the provided filter is `None`, it uses the `RUST_LOG` environment variable to determine the
/// maximum log level filter for the guest and converts it to a `u64` value.
pub(super) fn get_guest_log_filter(guest_max_log_level: Option<LevelFilter>) -> u64 {
    let guest_log_level_filter = match guest_max_log_level {
        Some(level) => level,
        None => get_max_log_level_filter(std::env::var("RUST_LOG").unwrap_or_default()),
    };
    GuestLogFilter::from(guest_log_level_filter).into()
}

/// Represents a Hyperlight Virtual Machine instance.
///
/// This struct manages the lifecycle of the VM, including:
/// - The underlying hypervisor implementation (e.g., KVM, MSHV, WHP).
/// - Memory management, including initial sandbox regions and dynamic mappings.
/// - The vCPU execution loop and handling of VM exits (I/O, MMIO, interrupts).
pub(crate) struct HyperlightVm {
    #[cfg(gdb)]
    pub(super) vm: Box<dyn DebuggableVm>,
    #[cfg(not(gdb))]
    pub(super) vm: Box<dyn VirtualMachine>,
    pub(super) page_size: usize,
    pub(super) entrypoint: NextAction, // only present if this vm has not yet been initialised
    pub(super) rsp_gva: u64,
    pub(super) interrupt_handle: Arc<dyn InterruptHandleImpl>,

    pub(super) next_slot: u32, // Monotonically increasing slot number
    pub(super) freed_slots: Vec<u32>, // Reusable slots from unmapped regions

    pub(super) snapshot_slot: u32,
    // The current snapshot region, used to keep it alive as long as
    // it is used & when unmapping
    pub(super) snapshot_memory: Option<GuestSharedMemory>,
    pub(super) scratch_slot: u32, // The slot number used for the scratch region
    // The current scratch region, used to keep it alive as long as it
    // is used & when unmapping
    pub(super) scratch_memory: Option<GuestSharedMemory>,

    pub(super) mmap_regions: Vec<(u32, MemoryRegion)>, // Later mapped regions (slot number, region)

    pub(super) pending_tlb_flush: bool,

    #[cfg(gdb)]
    pub(super) gdb_conn: Option<DebugCommChannel<DebugResponse, DebugMsg>>,
    #[cfg(gdb)]
    pub(super) sw_breakpoints: HashMap<u64, u8>, // addr -> original instruction
    #[cfg(feature = "mem_profile")]
    pub(super) trace_info: MemTraceInfo,
    #[cfg(crashdump)]
    pub(super) rt_cfg: SandboxRuntimeConfig,
}


/// DispatchGuestCall error
#[derive(Debug, thiserror::Error)]
pub enum DispatchGuestCallError {
    #[error("Failed to run vm: {0}")]
    Run(#[from] RunVmError),
    #[error("Failed to setup registers: {0}")]
    SetupRegs(RegisterError),
    #[error("VM was uninitialized")]
    Uninitialized,
}

impl DispatchGuestCallError {
    /// Returns true if this error should poison the sandbox
    pub(crate) fn is_poison_error(&self) -> bool {
        match self {
            // These errors poison the sandbox because they can leave it in an inconsistent state
            // by returning before the guest can unwind properly
            DispatchGuestCallError::Run(_) => true,
            DispatchGuestCallError::SetupRegs(_) | DispatchGuestCallError::Uninitialized => false,
        }
    }

    /// Converts a `DispatchGuestCallError` to a `HyperlightError`. Used for backwards compatibility.
    /// Also determines if the sandbox should be poisoned.
    ///
    /// Returns a tuple of (error, should_poison) where should_poison indicates whether
    /// the sandbox should be marked as poisoned due to incomplete guest execution.
    pub(crate) fn promote(self) -> (HyperlightError, bool) {
        let should_poison = self.is_poison_error();
        let promoted_error = match self {
            DispatchGuestCallError::Run(RunVmError::ExecutionCancelledByHost) => {
                HyperlightError::ExecutionCanceledByHost()
            }

            DispatchGuestCallError::Run(RunVmError::HandleIo(HandleIoError::Outb(
                HandleOutbError::GuestAborted { code, message },
            ))) => HyperlightError::GuestAborted(code, message),

            DispatchGuestCallError::Run(RunVmError::MemoryAccessViolation {
                addr,
                access_type,
                region_flags,
            }) => HyperlightError::MemoryAccessViolation(addr, access_type, region_flags),

            // Leave others as is
            other => HyperlightVmError::DispatchGuestCall(other).into(),
        };
        (promoted_error, should_poison)
    }
}

/// Initialize error
#[derive(Debug, thiserror::Error)]
pub enum InitializeError {
    #[error("Failed to convert pointer: {0}")]
    ConvertPointer(String),
    #[error("Failed to run vm: {0}")]
    Run(#[from] RunVmError),
    #[error("Failed to setup registers: {0}")]
    SetupRegs(#[from] RegisterError),
    #[error("Guest initialised stack pointer to architecturally invalid value: {0}")]
    InvalidStackPointer(u64),
}

/// Errors that can occur during VM execution in the run loop
#[derive(Debug, thiserror::Error)]
pub enum RunVmError {
    #[cfg(crashdump)]
    #[error("Crashdump generation error: {0}")]
    CrashdumpGeneration(Box<HyperlightError>),
    #[cfg(gdb)]
    #[error("Debug handler error: {0}")]
    DebugHandler(#[from] HandleDebugError),
    #[error("Execution was cancelled by the host")]
    ExecutionCancelledByHost,
    #[error("Failed to access page: {0}")]
    PageTableAccess(AccessPageTableError),
    #[cfg(feature = "trace_guest")]
    #[error("Failed to get registers: {0}")]
    GetRegs(RegisterError),
    #[error("IO handling error: {0}")]
    HandleIo(#[from] HandleIoError),
    #[error(
        "Memory access violation at address {addr:#x}: {access_type} access, but memory is marked as {region_flags}"
    )]
    MemoryAccessViolation {
        addr: u64,
        access_type: MemoryRegionFlags,
        region_flags: MemoryRegionFlags,
    },
    #[error("MMIO READ access to unmapped address {0:#x}")]
    MmioReadUnmapped(u64),
    #[error("MMIO WRITE access to unmapped address {0:#x}")]
    MmioWriteUnmapped(u64),
    #[error("vCPU run failed: {0}")]
    RunVcpu(#[from] RunVcpuError),
    #[error("Unexpected VM exit: {0}")]
    UnexpectedVmExit(String),
    #[cfg(gdb)]
    #[error("vCPU stop reason error: {0}")]
    VcpuStopReason(#[from] VcpuStopReasonError),
}

/// Errors that can occur during IO (outb) handling
#[derive(Debug, thiserror::Error)]
pub enum HandleIoError {
    #[cfg(feature = "mem_profile")]
    #[error("Failed to get registers: {0}")]
    GetRegs(RegisterError),
    #[error("No data was given in IO interrupt")]
    NoData,
    #[error("{0}")]
    Outb(#[from] HandleOutbError),
}

/// Errors that can occur when mapping a memory region
#[derive(Debug, thiserror::Error)]
pub enum MapRegionError {
    #[error("VM map memory error: {0}")]
    MapMemory(#[from] MapMemoryError),
    #[error("Region is not page-aligned (page size: {0:#x})")]
    NotPageAligned(usize),
}

/// Errors that can occur when unmapping a memory region
#[derive(Debug, thiserror::Error)]
pub enum UnmapRegionError {
    #[error("Region not found in mapped regions")]
    RegionNotFound,
    #[error("VM unmap memory error: {0}")]
    UnmapMemory(#[from] UnmapMemoryError),
}

/// Errors that can occur when updating the scratch mapping
#[derive(Debug, thiserror::Error)]
pub enum UpdateRegionError {
    #[error("VM map memory error: {0}")]
    MapMemory(#[from] MapMemoryError),
    #[error("VM unmap memory error: {0}")]
    UnmapMemory(#[from] UnmapMemoryError),
}

/// Errors that can occur when accessing the root page table state
#[derive(Debug, thiserror::Error)]
pub enum AccessPageTableError {
    #[error("Failed to get/set registers: {0}")]
    AccessRegs(#[from] RegisterError),
}

#[cfg(crashdump)]
#[derive(Debug, thiserror::Error)]
pub enum CrashDumpError {
    #[error("Failed to generate crashdump because of a register error: {0}")]
    GetRegs(#[from] RegisterError),
    #[error("Failed to get root PT during crashdump generation: {0}")]
    GetRootPt(#[from] AccessPageTableError),
    #[error("Failed to get guest memory mapping during crashdump generation: {0}")]
    AccessPageTable(Box<HyperlightError>),
}

/// Errors that can occur during HyperlightVm creation
#[derive(Debug, thiserror::Error)]
pub enum CreateHyperlightVmError {
    #[cfg(gdb)]
    #[error("Failed to add hardware breakpoint: {0}")]
    AddHwBreakpoint(DebugError),
    #[error("No hypervisor was found")]
    NoHypervisorFound,
    #[cfg(gdb)]
    #[error("Failed to send debug message: {0}")]
    SendDbgMsg(#[from] SendDbgMsgError),
    #[error("VM operation error: {0}")]
    Vm(#[from] VmError),
    #[error("Set scratch error: {0}")]
    UpdateRegion(#[from] UpdateRegionError),
}

/// Errors that can occur during debug exit handling
#[cfg(gdb)]
#[derive(Debug, thiserror::Error)]
pub enum HandleDebugError {
    #[error("Debug is not enabled")]
    DebugNotEnabled,
    #[error("Error processing debug request: {0}")]
    ProcessRequest(#[from] ProcessDebugRequestError),
    #[error("Failed to receive message from GDB thread: {0}")]
    ReceiveMessage(#[from] RecvDbgMsgError),
    #[error("Failed to send message to GDB thread: {0}")]
    SendMessage(#[from] SendDbgMsgError),
}

/// Errors that can occur when sending a debug message
#[cfg(gdb)]
#[derive(Debug, thiserror::Error)]
pub enum SendDbgMsgError {
    #[error("Debug is not enabled")]
    DebugNotEnabled,
    #[error("Failed to send message: {0}")]
    SendFailed(#[from] GdbTargetError),
}

/// Errors that can occur when receiving a debug message
#[cfg(gdb)]
#[derive(Debug, thiserror::Error)]
pub enum RecvDbgMsgError {
    #[error("Debug is not enabled")]
    DebugNotEnabled,
    #[error("Failed to receive message: {0}")]
    RecvFailed(#[from] GdbTargetError),
}

/// Unified error type for all HyperlightVm operations
#[derive(Debug, thiserror::Error)]
pub enum HyperlightVmError {
    #[error("Create VM error: {0}")]
    Create(#[from] CreateHyperlightVmError),
    #[error("Dispatch guest call error: {0}")]
    DispatchGuestCall(#[from] DispatchGuestCallError),
    #[error("Initialize error: {0}")]
    Initialize(#[from] InitializeError),
    #[error("Map region error: {0}")]
    MapRegion(#[from] MapRegionError),
    #[error("Restore VM (vcpu) error: {0}")]
    Restore(#[from] RegisterError),
    #[error("Unmap region error: {0}")]
    UnmapRegion(#[from] UnmapRegionError),
    #[error("Update region error: {0}")]
    UpdateRegion(#[from] UpdateRegionError),
    #[error("Access page table error: {0}")]
    AccessPageTable(#[from] AccessPageTableError),
}
impl HyperlightVm {
    /// Map a region of host memory into the sandbox.
    ///
    /// Safety: The caller must ensure that the region points to valid memory and
    /// that the memory is valid for the duration of Self's lifetime.
    /// Depending on the host platform, there are likely alignment
    /// requirements of at least one page for base and len.
    pub(crate) unsafe fn map_region(
        &mut self,
        region: &MemoryRegion,
    ) -> std::result::Result<(), MapRegionError> {
        if [
            region.guest_region.start,
            region.guest_region.end,
            #[allow(clippy::useless_conversion)]
            region.host_region.start.into(),
            #[allow(clippy::useless_conversion)]
            region.host_region.end.into(),
        ]
        .iter()
        .any(|x| x % self.page_size != 0)
        {
            return Err(MapRegionError::NotPageAligned(self.page_size));
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
    pub(crate) fn unmap_region(
        &mut self,
        region: &MemoryRegion,
    ) -> std::result::Result<(), UnmapRegionError> {
        let pos = self
            .mmap_regions
            .iter()
            .position(|(_, r)| r == region)
            .ok_or(UnmapRegionError::RegionNotFound)?;

        let (slot, _) = self.mmap_regions.remove(pos);
        self.freed_slots.push(slot);
        self.vm.unmap_memory((slot, region))?;
        Ok(())
    }

    /// Get the currently mapped dynamic memory regions (not including initial sandbox region)
    pub(crate) fn get_mapped_regions(&self) -> impl Iterator<Item = &MemoryRegion> {
        self.mmap_regions.iter().map(|(_, region)| region)
    }

    /// Update the snapshot mapping to point to a new GuestSharedMemory
    pub(crate) fn update_snapshot_mapping(
        &mut self,
        snapshot: GuestSharedMemory,
    ) -> Result<(), UpdateRegionError> {
        let guest_base = crate::mem::layout::SandboxMemoryLayout::BASE_ADDRESS as u64;
        let rgn = snapshot.mapping_at(guest_base, MemoryRegionType::Snapshot);

        if let Some(old_snapshot) = self.snapshot_memory.replace(snapshot) {
            let old_rgn = old_snapshot.mapping_at(guest_base, MemoryRegionType::Snapshot);
            self.vm.unmap_memory((self.snapshot_slot, &old_rgn))?;
        }
        unsafe { self.vm.map_memory((self.snapshot_slot, &rgn))? };

        Ok(())
    }

    /// Update the scratch mapping to point to a new GuestSharedMemory
    pub(crate) fn update_scratch_mapping(
        &mut self,
        scratch: GuestSharedMemory,
    ) -> Result<(), UpdateRegionError> {
        let guest_base = hyperlight_common::layout::scratch_base_gpa(scratch.mem_size());
        let rgn = scratch.mapping_at(guest_base, MemoryRegionType::Scratch);

        if let Some(old_scratch) = self.scratch_memory.replace(scratch) {
            let old_base = hyperlight_common::layout::scratch_base_gpa(old_scratch.mem_size());
            let old_rgn = old_scratch.mapping_at(old_base, MemoryRegionType::Scratch);
            self.vm.unmap_memory((self.scratch_slot, &old_rgn))?;
        }
        unsafe { self.vm.map_memory((self.scratch_slot, &rgn))? };

        Ok(())
    }

    /// Get the current stack top virtual address
    pub(crate) fn get_stack_top(&mut self) -> u64 {
        self.rsp_gva
    }

    /// Set the current stack top virtual address
    pub(crate) fn set_stack_top(&mut self, gva: u64) {
        self.rsp_gva = gva;
    }

    /// Get the current entrypoint action
    pub(crate) fn get_entrypoint(&self) -> NextAction {
        self.entrypoint
    }

    /// Set the current entrypoint action
    pub(crate) fn set_entrypoint(&mut self, entrypoint: NextAction) {
        self.entrypoint = entrypoint
    }

    pub(crate) fn interrupt_handle(&self) -> Arc<dyn InterruptHandle> {
        self.interrupt_handle.clone()
    }

    pub(crate) fn clear_cancel(&self) {
        self.interrupt_handle.clear_cancel();
    }

    pub(super) fn run(
        &mut self,
        mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
        host_funcs: &Arc<Mutex<FunctionRegistry>>,
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    ) -> std::result::Result<(), RunVmError> {
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
                // ==== KILL() TIMING POINT 3: Before calling run() ====
                // If kill() is called and ran to completion BEFORE this line executes:
                //    - Will still do a VM entry, but signals will be sent until VM exits
                let result = self.vm.run_vcpu(
                    #[cfg(feature = "trace_guest")]
                    &mut tc,
                );

                // End current host trace by closing the current span that captures traces
                // happening when a guest exits and re-enters.
                #[cfg(feature = "trace_guest")]
                {
                    tc.end_host_trace();
                    // Handle the guest trace data if any
                    let regs = self.vm.regs().map_err(RunVmError::GetRegs)?;

                    // Only parse the trace if it has reported
                    if tc.has_trace_data(&regs) {
                        let root_pt = self.get_root_pt().map_err(RunVmError::PageTableAccess)?;

                        // If something goes wrong with parsing the trace data, we log the error and
                        // continue execution instead of returning an error since this is not critical
                        // to correct execution of the guest
                        tc.handle_trace(&regs, mem_mgr, root_pt)
                            .unwrap_or_else(|e| {
                                tracing::error!("Cannot handle trace data: {}", e);
                            });
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
                    let initialise = match self.entrypoint {
                        NextAction::Initialise(initialise) => initialise,
                        _ => 0,
                    };
                    // Handle debug event (breakpoints)
                    let stop_reason = crate::hypervisor::gdb::arch::vcpu_stop_reason(
                        self.vm.as_mut(),
                        dr6,
                        initialise,
                        exception,
                    )?;
                    if let Err(e) = self.handle_debug(dbg_mem_access_fn.clone(), stop_reason) {
                        break Err(e.into());
                    }
                }

                Ok(VmExit::Halt()) => {
                    break Ok(());
                }
                Ok(VmExit::IoOut(port, data)) => {
                    self.handle_io(mem_mgr, host_funcs, port, data)?;
                }
                Ok(VmExit::MmioRead(addr)) => {
                    let all_regions = self.get_mapped_regions();
                    match get_memory_access_violation(
                        addr as usize,
                        MemoryRegionFlags::READ,
                        all_regions,
                    ) {
                        Some(MemoryAccess::AccessViolation(region_flags)) => {
                            break Err(RunVmError::MemoryAccessViolation {
                                addr,
                                access_type: MemoryRegionFlags::READ,
                                region_flags,
                            });
                        }
                        None => {
                            break Err(RunVmError::MmioReadUnmapped(addr));
                        }
                    }
                }
                Ok(VmExit::MmioWrite(addr)) => {
                    let all_regions = self.get_mapped_regions();
                    match get_memory_access_violation(
                        addr as usize,
                        MemoryRegionFlags::WRITE,
                        all_regions,
                    ) {
                        Some(MemoryAccess::AccessViolation(region_flags)) => {
                            break Err(RunVmError::MemoryAccessViolation {
                                addr,
                                access_type: MemoryRegionFlags::WRITE,
                                region_flags,
                            });
                        }
                        None => {
                            break Err(RunVmError::MmioWriteUnmapped(addr));
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
                            break Err(e.into());
                        }
                    }

                    metrics::counter!(METRIC_GUEST_CANCELLATION).increment(1);
                    break Err(RunVmError::ExecutionCancelledByHost);
                }
                Ok(VmExit::Unknown(reason)) => {
                    break Err(RunVmError::UnexpectedVmExit(reason));
                }
                Ok(VmExit::Retry()) => continue,
                Err(e) => {
                    break Err(RunVmError::RunVcpu(e));
                }
            }
        };

        match result {
            Ok(_) => Ok(()),
            Err(RunVmError::ExecutionCancelledByHost) => {
                // no need to crashdump this
                Err(RunVmError::ExecutionCancelledByHost)
            }
            Err(e) => {
                #[cfg(crashdump)]
                if self.rt_cfg.guest_core_dump {
                    crate::hypervisor::crashdump::generate_crashdump(self, mem_mgr, None)
                        .map_err(|e| RunVmError::CrashdumpGeneration(Box::new(e)))?;
                }

                // If GDB is enabled, we handle the debug memory access
                // Disregard return value as we want to return the error
                #[cfg(gdb)]
                if self.gdb_conn.is_some() {
                    self.handle_debug(dbg_mem_access_fn.clone(), VcpuStopReason::Crash)?
                }
                Err(e)
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
    ) -> std::result::Result<(), HandleIoError> {
        if data.is_empty() {
            return Err(HandleIoError::NoData);
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
            let regs = self.vm.regs().map_err(HandleIoError::GetRegs)?;
            handle_outb(mem_mgr, host_funcs, port, val, &regs, &mut self.trace_info)?;
        }

        #[cfg(not(feature = "mem_profile"))]
        {
            handle_outb(mem_mgr, host_funcs, port, val)?;
        }

        Ok(())
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
}

/// Determines if a known memory access violation occurred at the given address with the given action type.
/// Returns Some(reason) if violation reason could be determined, or None if violation occurred but in unmapped region.
fn get_memory_access_violation<'a>(
    gpa: usize,
    tried: MemoryRegionFlags,
    mut mem_regions: impl Iterator<Item = &'a MemoryRegion>,
) -> Option<MemoryAccess> {
    let region = mem_regions.find(|region| region.guest_region.contains(&gpa))?;
    if !region.flags.contains(tried) {
        return Some(MemoryAccess::AccessViolation(region.flags));
    }
    // gpa is in `region`, and region allows the tried access, but we got here anyway.
    // Treat as a generic access violation for now, unsure if this is reachable.
    None
}
