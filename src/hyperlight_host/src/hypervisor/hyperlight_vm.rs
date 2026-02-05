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

#[cfg(gdb)]
use super::gdb::arch::VcpuStopReasonError;
#[cfg(gdb)]
use super::gdb::{
    DebugCommChannel, DebugMsg, DebugResponse, DebuggableVm, GdbTargetError, VcpuStopReason, arch,
};
use super::regs::{CommonFpu, CommonRegisters};
#[cfg(target_os = "windows")]
use super::{PartitionState, WindowsInterruptHandle};
use crate::HyperlightError;
#[cfg(any(kvm, mshv3))]
use crate::hypervisor::LinuxInterruptHandle;
#[cfg(crashdump)]
use crate::hypervisor::crashdump;
#[cfg(gdb)]
use crate::hypervisor::gdb::{DebugError, DebugMemoryAccessError};
#[cfg(gdb)]
use crate::hypervisor::hyperlight_vm::debug::ProcessDebugRequestError;
use crate::hypervisor::regs::{CommonDebugRegs, CommonSpecialRegisters};
#[cfg(not(gdb))]
use crate::hypervisor::virtual_machine::VirtualMachine;
#[cfg(kvm)]
use crate::hypervisor::virtual_machine::kvm::KvmVm;
#[cfg(mshv3)]
use crate::hypervisor::virtual_machine::mshv::MshvVm;
#[cfg(target_os = "windows")]
use crate::hypervisor::virtual_machine::whp::WhpVm;
use crate::hypervisor::virtual_machine::{
    HypervisorType, MapMemoryError, RegisterError, RunVcpuError, UnmapMemoryError, VmError, VmExit,
    get_available_hypervisor,
};
use crate::hypervisor::{InterruptHandle, InterruptHandleImpl, get_max_log_level};
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags, MemoryRegionType};
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::ptr::RawPtr;
use crate::mem::shared_mem::{GuestSharedMemory, HostSharedMemory, SharedMemory};
use crate::metrics::{METRIC_ERRONEOUS_VCPU_KICKS, METRIC_GUEST_CANCELLATION};
use crate::sandbox::SandboxConfiguration;
use crate::sandbox::host_funcs::FunctionRegistry;
use crate::sandbox::outb::{HandleOutbError, handle_outb};
#[cfg(feature = "mem_profile")]
use crate::sandbox::trace::MemTraceInfo;
#[cfg(crashdump)]
use crate::sandbox::uninitialized::SandboxRuntimeConfig;

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
    entrypoint: Option<u64>, // only present if this vm has not yet been initialised
    rsp_gva: u64,
    interrupt_handle: Arc<dyn InterruptHandleImpl>,

    next_slot: u32,        // Monotonically increasing slot number
    freed_slots: Vec<u32>, // Reusable slots from unmapped regions

    snapshot_slot: u32,
    // The current snapshot region, used to keep it alive as long as
    // it is used & when unmapping
    snapshot_memory: Option<GuestSharedMemory>,
    scratch_slot: u32, // The slot number used for the scratch region
    // The current scratch region, used to keep it alive as long as it
    // is used & when unmapping
    scratch_memory: Option<GuestSharedMemory>,

    mmap_regions: Vec<(u32, MemoryRegion)>, // Later mapped regions (slot number, region)

    #[cfg(gdb)]
    gdb_conn: Option<DebugCommChannel<DebugResponse, DebugMsg>>,
    #[cfg(gdb)]
    sw_breakpoints: HashMap<u64, u8>, // addr -> original instruction
    #[cfg(feature = "mem_profile")]
    trace_info: MemTraceInfo,
    #[cfg(crashdump)]
    rt_cfg: SandboxRuntimeConfig,
}

/// DispatchGuestCall error
#[derive(Debug, thiserror::Error)]
pub enum DispatchGuestCallError {
    #[error("Failed to run vm: {0}")]
    Run(#[from] RunVmError),
    #[error("Failed to setup registers: {0}")]
    SetupRegs(RegisterError),
}

impl DispatchGuestCallError {
    /// Returns true if this error should poison the sandbox
    pub(crate) fn is_poison_error(&self) -> bool {
        match self {
            // These errors poison the sandbox because they can leave it in an inconsistent state
            // by returning before the guest can unwind properly
            DispatchGuestCallError::Run(_) => true,
            DispatchGuestCallError::SetupRegs(_) => false,
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
    /// Create a new HyperlightVm instance (will not run vm until calling `initialise`)
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        snapshot_mem: GuestSharedMemory,
        scratch_mem: GuestSharedMemory,
        _pml4_addr: u64,
        entrypoint: Option<u64>,
        rsp_gva: u64,
        #[cfg_attr(target_os = "windows", allow(unused_variables))] config: &SandboxConfiguration,
        #[cfg(gdb)] gdb_conn: Option<DebugCommChannel<DebugResponse, DebugMsg>>,
        #[cfg(crashdump)] rt_cfg: SandboxRuntimeConfig,
        #[cfg(feature = "mem_profile")] trace_info: MemTraceInfo,
    ) -> std::result::Result<Self, CreateHyperlightVmError> {
        #[cfg(gdb)]
        type VmType = Box<dyn DebuggableVm>;
        #[cfg(not(gdb))]
        type VmType = Box<dyn VirtualMachine>;

        let vm: VmType = match get_available_hypervisor() {
            #[cfg(kvm)]
            Some(HypervisorType::Kvm) => Box::new(KvmVm::new().map_err(VmError::CreateVm)?),
            #[cfg(mshv3)]
            Some(HypervisorType::Mshv) => Box::new(MshvVm::new().map_err(VmError::CreateVm)?),
            #[cfg(target_os = "windows")]
            Some(HypervisorType::Whp) => Box::new(WhpVm::new().map_err(VmError::CreateVm)?),
            None => return Err(CreateHyperlightVmError::NoHypervisorFound),
        };

        #[cfg(feature = "init-paging")]
        vm.set_sregs(&CommonSpecialRegisters::standard_64bit_defaults(_pml4_addr))
            .map_err(VmError::Register)?;
        #[cfg(not(feature = "init-paging"))]
        vm.set_sregs(&CommonSpecialRegisters::standard_real_mode_defaults())
            .map_err(VmError::Register)?;

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

        let snapshot_slot = 0u32;
        let scratch_slot = 1u32;
        #[cfg_attr(not(gdb), allow(unused_mut))]
        let mut ret = Self {
            vm,
            entrypoint,
            rsp_gva,
            interrupt_handle,
            page_size: 0, // Will be set in `initialise`

            next_slot: scratch_slot + 1,
            freed_slots: Vec::new(),

            snapshot_slot,
            snapshot_memory: None,
            scratch_slot,
            scratch_memory: None,

            mmap_regions: Vec::new(),

            #[cfg(gdb)]
            gdb_conn,
            #[cfg(gdb)]
            sw_breakpoints: HashMap::new(),
            #[cfg(feature = "mem_profile")]
            trace_info,
            #[cfg(crashdump)]
            rt_cfg,
        };

        ret.update_snapshot_mapping(snapshot_mem)?;
        ret.update_scratch_mapping(scratch_mem)?;

        // Send the interrupt handle to the GDB thread if debugging is enabled
        // This is used to allow the GDB thread to stop the vCPU
        #[cfg(gdb)]
        if ret.gdb_conn.is_some() {
            ret.send_dbg_msg(DebugResponse::InterruptHandle(ret.interrupt_handle.clone()))?;
            // Add breakpoint to the entry point address, if we are going to initialise
            ret.vm.set_debug(true).map_err(VmError::Debug)?;
            if let Some(entrypoint) = entrypoint {
                ret.vm
                    .add_hw_breakpoint(entrypoint)
                    .map_err(CreateHyperlightVmError::AddHwBreakpoint)?;
            }
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
    ) -> std::result::Result<(), InitializeError> {
        let Some(entrypoint) = self.entrypoint else {
            return Ok(());
        };

        self.page_size = page_size as usize;

        let guest_max_log_level: u64 = match guest_max_log_level {
            Some(level) => level as u64,
            None => get_max_log_level().into(),
        };

        let regs = CommonRegisters {
            rip: entrypoint,
            // We usually keep the top of the stack 16-byte
            // aligned. However, the ABI requirement is that the stack
            // be aligned _before a call instruction_, which means
            // that the stack needs to actually be ≡ 8 mod 16 at the
            // first instruction (since, on x64, a call instruction
            // automatically pushes a return address).
            rsp: self.rsp_gva - 8,

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
        .map_err(InitializeError::Run)?;

        let regs = self.vm.regs()?;
        // todo(portability): this is architecture-specific
        if !regs.rsp.is_multiple_of(16) {
            return Err(InitializeError::InvalidStackPointer(regs.rsp));
        }
        self.rsp_gva = regs.rsp;

        Ok(())
    }

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

    /// Get the current base page table physical address
    pub(crate) fn get_root_pt(&mut self) -> Result<u64, AccessPageTableError> {
        let sregs = self.vm.sregs()?;
        Ok(sregs.cr3)
    }

    /// Get the special registers that need to be stored in a snapshot.
    pub(crate) fn get_snapshot_sregs(
        &mut self,
    ) -> Result<CommonSpecialRegisters, AccessPageTableError> {
        Ok(self.vm.sregs()?)
    }

    /// Get the current stack top virtual address
    pub(crate) fn get_stack_top(&mut self) -> u64 {
        self.rsp_gva
    }

    /// Set the current stack top virtual address
    pub(crate) fn set_stack_top(&mut self, gva: u64) {
        self.rsp_gva = gva;
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
    ) -> std::result::Result<(), DispatchGuestCallError> {
        // set RIP and RSP, reset others
        let regs = CommonRegisters {
            rip: dispatch_func_addr.into(),
            // We usually keep the top of the stack 16-byte
            // aligned. However, the ABI requirement is that the stack
            // be aligned _before a call instruction_, which means
            // that the stack needs to actually be ≡ 8 mod 16 at the
            // first instruction (since, on x64, a call instruction
            // automatically pushes a return address).
            rsp: self.rsp_gva - 8,
            rflags: 1 << 1,
            ..Default::default()
        };
        self.vm
            .set_regs(&regs)
            .map_err(DispatchGuestCallError::SetupRegs)?;

        // reset fpu
        self.vm
            .set_fpu(&CommonFpu::default())
            .map_err(DispatchGuestCallError::SetupRegs)?;

        self.run(
            mem_mgr,
            host_funcs,
            #[cfg(gdb)]
            dbg_mem_access_fn,
        )
        .map_err(DispatchGuestCallError::Run)
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
                    let stop_reason = arch::vcpu_stop_reason(
                        self.vm.as_mut(),
                        dr6,
                        self.entrypoint.unwrap_or(0),
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
                        MemoryRegionFlags::WRITE,
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
                    crashdump::generate_crashdump(self)
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

    /// Resets the following vCPU state:
    /// - General purpose registers
    /// - Debug registers
    /// - XSAVE (includes FPU/SSE state with proper FCW and MXCSR defaults)
    /// - Special registers (restored from snapshot, with CR3 updated to new page table location)
    // TODO: check if other state needs to be reset
    pub(crate) fn reset_vcpu(
        &self,
        cr3: u64,
        sregs: &CommonSpecialRegisters,
    ) -> std::result::Result<(), RegisterError> {
        self.vm.set_regs(&CommonRegisters {
            rflags: 1 << 1, // Reserved bit always set
            ..Default::default()
        })?;
        self.vm.set_debug_regs(&CommonDebugRegs::default())?;
        self.vm.reset_xsave()?;

        #[cfg(feature = "init-paging")]
        {
            // Restore the full special registers from snapshot, but update CR3
            // to point to the new (relocated) page tables
            let mut sregs = *sregs;
            sregs.cr3 = cr3;
            self.vm.set_sregs(&sregs)?;
        }
        #[cfg(not(feature = "init-paging"))]
        {
            let _ = (cr3, sregs); // suppress unused warnings
            // TODO: This is probably not correct.
            // Let's deal with it when we clean up the init-paging feature
            self.vm
                .set_sregs(&CommonSpecialRegisters::standard_real_mode_defaults())?;
        }

        Ok(())
    }

    // Handle a debug exit
    #[cfg(gdb)]
    fn handle_debug(
        &mut self,
        dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
        stop_reason: VcpuStopReason,
    ) -> std::result::Result<(), HandleDebugError> {
        use crate::hypervisor::gdb::DebugMemoryAccess;
        use crate::hypervisor::hyperlight_vm::debug::ProcessDebugRequestError;

        if self.gdb_conn.is_none() {
            return Err(HandleDebugError::DebugNotEnabled);
        }

        let mem_access = DebugMemoryAccess {
            // TODO: dbg_mem_access_fn could be out of sync with the
            // actual snapshot/scratch regions, if a snapshot restore
            // has caused either of those to change.
            dbg_mem_access_fn,
            guest_mmap_regions: self.get_mapped_regions().cloned().collect(),
        };

        match stop_reason {
            // If the vCPU stopped because of a crash, we need to handle it differently
            // We do not want to allow resuming execution or placing breakpoints
            // because the guest has crashed.
            // We only allow reading registers and memory
            VcpuStopReason::Crash => {
                self.send_dbg_msg(DebugResponse::VcpuStopped(stop_reason))?;

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
                                // Treat non-fatal errors separately so the guest doesn't fail
                                Err(ProcessDebugRequestError::ReadMemory(
                                    DebugMemoryAccessError::TranslateGuestAddress(_),
                                ))
                                | Err(ProcessDebugRequestError::Debug(DebugError::TranslateGva(
                                    _,
                                ))) => DebugResponse::ErrorOccurred,
                                Err(e) => {
                                    log::error!("Error processing debug request: {:?}", e);
                                    return Err(HandleDebugError::ProcessRequest(e));
                                }
                            }
                        }
                    };

                    // Send the response to the request back to gdb
                    self.send_dbg_msg(response)?;

                    // If we are denying continue or step requests, the debugger assumes the
                    // execution started so we need to report a stop reason as a crash and let
                    // it request to read registers/memory to figure out what happened
                    if deny_continue {
                        self.send_dbg_msg(DebugResponse::VcpuStopped(VcpuStopReason::Crash))?;
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
                self.send_dbg_msg(DebugResponse::VcpuStopped(stop_reason))?;

                loop {
                    log::debug!("Debug wait for event to resume vCPU");
                    // Wait for a message from gdb
                    let req = self.recv_dbg_msg()?;

                    let result = self.process_dbg_request(req, &mem_access);

                    let response = match result {
                        Ok(response) => response,
                        // Treat non-fatal errors separately so the guest doesn't fail
                        Err(ProcessDebugRequestError::ReadMemory(
                            DebugMemoryAccessError::TranslateGuestAddress(_),
                        ))
                        | Err(ProcessDebugRequestError::Debug(DebugError::TranslateGva(_))) => {
                            DebugResponse::ErrorOccurred
                        }
                        Err(e) => {
                            return Err(HandleDebugError::ProcessRequest(e));
                        }
                    };

                    let cont = matches!(
                        response,
                        DebugResponse::Continue | DebugResponse::Step | DebugResponse::DisableDebug
                    );

                    self.send_dbg_msg(response)?;

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
    pub(crate) fn crashdump_context(
        &self,
    ) -> std::result::Result<Option<super::crashdump::CrashDumpContext>, RegisterError> {
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

            // Include dynamically mapped regions
            // TODO: include the snapshot and scratch regions
            let regions: Vec<MemoryRegion> = self.get_mapped_regions().cloned().collect();
            Ok(Some(crashdump::CrashDumpContext::new(
                regions,
                regs,
                xsave.to_vec(),
                self.entrypoint.unwrap_or(0),
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

#[cfg(gdb)]
mod debug {
    use hyperlight_common::mem::PAGE_SIZE;

    use super::HyperlightVm;
    use crate::hypervisor::gdb::arch::{SW_BP, SW_BP_SIZE};
    use crate::hypervisor::gdb::{
        DebugError, DebugMemoryAccess, DebugMemoryAccessError, DebugMsg, DebugResponse,
    };
    use crate::hypervisor::virtual_machine::VmError;

    /// Errors that can occur during GDB debug request processing
    #[derive(Debug, thiserror::Error)]
    pub enum ProcessDebugRequestError {
        #[error("Debug is not enabled")]
        DebugNotEnabled,
        #[error("Failed to acquire lock at {0}:{1}")]
        TryLockError(&'static str, u32),
        #[error("VM operation error: {0}")]
        Vm(#[from] VmError),
        #[error("Debug operation error: {0}")]
        Debug(#[from] DebugError),
        #[error("Address {0:#x} is not a software breakpoint")]
        SwBreakpointNotFound(u64),
        #[error("Failed to read memory: {0}")]
        ReadMemory(#[from] DebugMemoryAccessError),
        #[error("Failed to write memory: {0}")]
        WriteMemory(DebugMemoryAccessError),
    }

    impl HyperlightVm {
        pub(crate) fn process_dbg_request(
            &mut self,
            req: DebugMsg,
            mem_access: &DebugMemoryAccess,
        ) -> std::result::Result<DebugResponse, ProcessDebugRequestError> {
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
                            .map_err(|_| ProcessDebugRequestError::TryLockError(file!(), line!()))?
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
                        let regs = self.vm.regs().map_err(VmError::Register)?;
                        let fpu = self.vm.fpu().map_err(VmError::Register)?;
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
                        self.vm.set_regs(regs).map_err(VmError::Register)?;
                        self.vm.set_fpu(fpu).map_err(VmError::Register)?;

                        Ok(DebugResponse::WriteRegisters)
                    }
                }
            } else {
                Err(ProcessDebugRequestError::DebugNotEnabled)
            }
        }

        pub(crate) fn recv_dbg_msg(
            &mut self,
        ) -> std::result::Result<DebugMsg, super::RecvDbgMsgError> {
            use super::RecvDbgMsgError;

            let gdb_conn = self
                .gdb_conn
                .as_mut()
                .ok_or(RecvDbgMsgError::DebugNotEnabled)?;

            Ok(gdb_conn.recv()?)
        }

        pub(crate) fn send_dbg_msg(
            &mut self,
            cmd: DebugResponse,
        ) -> std::result::Result<(), super::SendDbgMsgError> {
            use super::SendDbgMsgError;

            log::debug!("Sending {:?}", cmd);

            let gdb_conn = self
                .gdb_conn
                .as_mut()
                .ok_or(SendDbgMsgError::DebugNotEnabled)?;

            Ok(gdb_conn.send(cmd)?)
        }

        fn read_addrs(
            &mut self,
            mut gva: u64,
            mut data: &mut [u8],
            mem_access: &DebugMemoryAccess,
        ) -> std::result::Result<(), ProcessDebugRequestError> {
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
        ) -> std::result::Result<(), ProcessDebugRequestError> {
            let data_len = data.len();
            log::debug!("Write addr: {:X} len: {:X}", gva, data_len);

            while !data.is_empty() {
                let gpa = self.vm.translate_gva(gva)?;

                let write_len = std::cmp::min(
                    data.len(),
                    (PAGE_SIZE - (gpa & (PAGE_SIZE - 1))).try_into().unwrap(),
                );

                // Use the memory access to write to guest memory
                mem_access
                    .write(&data[..write_len], gpa)
                    .map_err(ProcessDebugRequestError::WriteMemory)?;

                data = &data[write_len..];
                gva += write_len as u64;
            }

            Ok(())
        }

        // Must be idempotent!
        fn add_sw_breakpoint(
            &mut self,
            gva: u64,
            mem_access: &DebugMemoryAccess,
        ) -> std::result::Result<(), ProcessDebugRequestError> {
            // Check if breakpoint already exists
            if self.sw_breakpoints.contains_key(&gva) {
                return Ok(());
            }

            // Write breakpoint OP code to write to guest memory
            let mut save_data = [0; SW_BP_SIZE];
            self.read_addrs(gva, &mut save_data[..], mem_access)?;
            self.write_addrs(gva, &SW_BP, mem_access)?;

            // Save guest memory to restore when breakpoint is removed
            self.sw_breakpoints.insert(gva, save_data[0]);

            Ok(())
        }

        fn remove_sw_breakpoint(
            &mut self,
            gva: u64,
            mem_access: &DebugMemoryAccess,
        ) -> std::result::Result<(), ProcessDebugRequestError> {
            if let Some(saved_data) = self.sw_breakpoints.remove(&gva) {
                // Restore saved data to the guest's memory
                self.write_addrs(gva, &[saved_data], mem_access)?;

                Ok(())
            } else {
                Err(ProcessDebugRequestError::SwBreakpointNotFound(gva))
            }
        }
    }
}

#[cfg(test)]
#[cfg(feature = "init-paging")]
#[allow(clippy::needless_range_loop)]
mod tests {
    use std::sync::{Arc, Mutex};

    use hyperlight_common::vmem::{self, BasicMapping, Mapping, MappingKind};
    use rand::Rng;

    use super::*;
    #[cfg(kvm)]
    use crate::hypervisor::regs::FP_CONTROL_WORD_DEFAULT;
    use crate::hypervisor::regs::{CommonSegmentRegister, CommonTableRegister, MXCSR_DEFAULT};
    use crate::hypervisor::virtual_machine::VirtualMachine;
    use crate::mem::layout::SandboxMemoryLayout;
    use crate::mem::memory_region::{GuestMemoryRegion, MemoryRegionFlags};
    use crate::mem::mgr::{GuestPageTableBuffer, SandboxMemoryManager};
    use crate::mem::ptr::RawPtr;
    use crate::mem::ptr_offset::Offset;
    use crate::mem::shared_mem::ExclusiveSharedMemory;
    use crate::sandbox::SandboxConfiguration;
    use crate::sandbox::host_funcs::FunctionRegistry;
    #[cfg(any(crashdump, gdb))]
    use crate::sandbox::uninitialized::SandboxRuntimeConfig;
    use crate::sandbox::uninitialized_evolve::set_up_hypervisor_partition;

    /// Test context holding an initialized VM with memory manager.
    /// Used by tests that need to interact with guest memory after execution.
    struct TestVmContext {
        vm: HyperlightVm,
        hshm: SandboxMemoryManager<HostSharedMemory>,
        host_funcs: Arc<Mutex<FunctionRegistry>>,
        #[cfg(gdb)]
        dbg_mem_access_hdl: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    }

    // ==========================================================================
    // Dirty State Builders - Create non-default vCPU state for testing reset
    // ==========================================================================

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

    /// Returns default test values for reset_vcpu parameters.
    /// Uses standard 64-bit defaults since reset_vcpu now restores full sregs from snapshot.
    fn default_sregs() -> CommonSpecialRegisters {
        CommonSpecialRegisters::standard_64bit_defaults(0)
    }

    // ==========================================================================
    // Normalizers - Handle hypervisor-specific quirks when comparing vCPU state
    // ==========================================================================

    /// Normalize debug registers for comparison by applying writable masks.
    /// Reserved bits in DR6/DR7 are read-only (set by CPU), so we copy them from actual.
    fn normalize_debug_regs(expected: &mut CommonDebugRegs, actual: &CommonDebugRegs) {
        expected.dr6 = (expected.dr6 & DR6_WRITABLE_MASK) | (actual.dr6 & !DR6_WRITABLE_MASK);
        expected.dr7 = (expected.dr7 & DR7_WRITABLE_MASK) | (actual.dr7 & !DR7_WRITABLE_MASK);
    }

    /// Normalize segment hidden cache fields that hypervisors report differently.
    /// Applies to: unusable, granularity (g), and ss.db fields.
    /// Does NOT normalize type_ - use this when verifying explicitly-set dirty state.
    fn normalize_sregs_hidden_cache(
        expected: &mut CommonSpecialRegisters,
        actual: &CommonSpecialRegisters,
    ) {
        expected.ss.db = actual.ss.db;
        expected.cs.unusable = actual.cs.unusable;
        expected.cs.g = actual.cs.g;
        expected.ds.unusable = actual.ds.unusable;
        expected.ds.g = actual.ds.g;
        expected.es.unusable = actual.es.unusable;
        expected.es.g = actual.es.g;
        expected.fs.unusable = actual.fs.unusable;
        expected.fs.g = actual.fs.g;
        expected.gs.unusable = actual.gs.unusable;
        expected.gs.g = actual.gs.g;
        expected.ss.unusable = actual.ss.unusable;
        expected.ss.g = actual.ss.g;
        expected.tr.unusable = actual.tr.unusable;
        expected.tr.g = actual.tr.g;
        expected.ldt.unusable = actual.ldt.unusable;
        expected.ldt.g = actual.ldt.g;
    }

    /// Normalize sregs for verifying reset state.
    ///
    /// Handles hypervisor-specific differences in segment descriptor fields:
    /// - Hidden cache fields (unusable, granularity bits) vary between KVM/MSHV/WHP
    /// - For unusable segments (DS/ES/FS/GS/SS in 64-bit mode), the type_ field
    ///   is ignored by the CPU and varies between hypervisors
    fn normalize_sregs_for_reset(
        expected: &mut CommonSpecialRegisters,
        actual: &CommonSpecialRegisters,
    ) {
        normalize_sregs_hidden_cache(expected, actual);
        // type_ for unusable segments: hypervisors return different defaults
        // (KVM returns type_=1, WHP returns type_=0).
        expected.ds.type_ = actual.ds.type_;
        expected.es.type_ = actual.es.type_;
        expected.fs.type_ = actual.fs.type_;
        expected.gs.type_ = actual.gs.type_;
        expected.ss.type_ = actual.ss.type_;
    }

    /// Normalize sregs for tests that run actual guest code.
    ///
    /// Handles hypervisor-specific differences in segment descriptor fields:
    /// - Hidden cache fields (unusable, db) vary between KVM/MSHV/WHP
    /// - For unusable segments (DS/ES/FS/GS/SS in 64-bit mode), the type_ field
    ///   is ignored by the CPU and varies between hypervisors
    fn normalize_sregs_for_run_tests(
        expected: &mut CommonSpecialRegisters,
        actual: &CommonSpecialRegisters,
    ) {
        expected.ss.db = actual.ss.db;
        expected.cs.unusable = actual.cs.unusable;
        expected.ds.unusable = actual.ds.unusable;
        expected.ds.type_ = actual.ds.type_;
        expected.es.unusable = actual.es.unusable;
        expected.es.type_ = actual.es.type_;
        expected.fs.unusable = actual.fs.unusable;
        expected.fs.type_ = actual.fs.type_;
        expected.gs.unusable = actual.gs.unusable;
        expected.gs.type_ = actual.gs.type_;
        expected.ss.unusable = actual.ss.unusable;
        expected.ss.type_ = actual.ss.type_;
        expected.tr.unusable = actual.tr.unusable;
        expected.ldt.unusable = actual.ldt.unusable;
    }

    /// Normalize FPU MXCSR for KVM quirk.
    /// KVM doesn't preserve MXCSR via set_fpu/fpu(), so we need to set it manually
    /// when comparing FPU state.
    #[cfg_attr(not(kvm), allow(unused_variables))]
    fn normalize_fpu_mxcsr_for_kvm(fpu: &mut CommonFpu, expected_mxcsr: u32) {
        #[cfg(kvm)]
        if *get_available_hypervisor().as_ref().unwrap() == HypervisorType::Kvm {
            fpu.mxcsr = expected_mxcsr;
        }
    }

    /// Normalize FPU state for reset comparison.
    ///
    /// When ftwx == 0, all x87 FPU registers are marked empty. In this state:
    /// - `fpr`: Contents are architecturally undefined since registers are empty
    /// - `last_ip`, `last_dp`, `last_opcode`: Track the last FPU instruction location.
    ///   On WHP, the register read API may return stale values even after
    ///   reset_xsave() properly zeroes the XSAVE area. This is a WHP API quirk -
    ///   the guest-visible state (via FXSAVE/XSAVE instructions) IS properly reset.
    ///
    /// IMPORTANT: The `reset_vcpu_fpu_guest_visible_state` test verifies actual
    /// guest-visible FPU state by running real guest code with FXSAVE, providing
    /// defense-in-depth against hypervisor API quirks masking real issues.
    fn normalize_fpu_for_reset(expected: &mut CommonFpu, actual: &CommonFpu) {
        if actual.ftwx == 0 {
            expected.fpr = actual.fpr;
            expected.last_ip = actual.last_ip;
            expected.last_dp = actual.last_dp;
            expected.last_opcode = actual.last_opcode;
        }
    }

    // ==========================================================================
    // Assertion Helpers - Verify vCPU state after reset
    // ==========================================================================

    /// Assert that debug registers are in reset state.
    /// Reserved bits in DR6/DR7 are read-only (set by CPU), so we only check
    /// that writable bits are cleared to 0 and DR0-DR3 are zeroed.
    fn assert_debug_regs_reset(vm: &dyn VirtualMachine) {
        let debug_regs = vm.debug_regs().unwrap();
        let expected = CommonDebugRegs {
            dr0: 0,
            dr1: 0,
            dr2: 0,
            dr3: 0,
            dr6: debug_regs.dr6 & !DR6_WRITABLE_MASK,
            dr7: debug_regs.dr7 & !DR7_WRITABLE_MASK,
        };
        assert_eq!(debug_regs, expected);
    }

    /// Assert that general-purpose registers are in reset state.
    /// After reset, all registers should be zeroed except rflags which has
    /// reserved bit 1 always set.
    fn assert_regs_reset(vm: &dyn VirtualMachine) {
        assert_eq!(
            vm.regs().unwrap(),
            CommonRegisters {
                rflags: 1 << 1, // Reserved bit 1 is always set
                ..Default::default()
            }
        );
    }

    /// Assert that FPU state is in reset state.
    /// Handles hypervisor-specific quirks (KVM MXCSR, empty FPU registers).
    fn assert_fpu_reset(vm: &dyn VirtualMachine) {
        let fpu = vm.fpu().unwrap();
        let mut expected_fpu = CommonFpu::default();
        normalize_fpu_mxcsr_for_kvm(&mut expected_fpu, fpu.mxcsr);
        normalize_fpu_for_reset(&mut expected_fpu, &fpu);
        assert_eq!(fpu, expected_fpu);
    }

    /// Assert that special registers are in reset state.
    /// Handles hypervisor-specific differences in hidden descriptor cache fields.
    fn assert_sregs_reset(vm: &dyn VirtualMachine, pml4_addr: u64) {
        let defaults = CommonSpecialRegisters::standard_64bit_defaults(pml4_addr);
        let sregs = vm.sregs().unwrap();
        let mut expected_sregs = defaults;
        // Normalize hypervisor implementation-specific fields.
        // These are part of the hidden descriptor cache. While guests can write them
        // indirectly (by loading segments from a crafted GDT), guests cannot read them back
        // (e.g., `mov ax, ds` only returns the selector, not the hidden cache).
        // KVM and MSHV reset to different default values, but both properly reset so there's
        // no information leakage between tenants.
        normalize_sregs_for_reset(&mut expected_sregs, &sregs);
        assert_eq!(sregs, expected_sregs);
    }

    // ==========================================================================
    // XSAVE Helpers - Build dirty XSAVE state for testing extended CPU state
    // ==========================================================================

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

    // ==========================================================================
    // Test VM Setup
    // ==========================================================================

    /// Creates a test VM with the given code. This is the shared setup logic used by
    /// both `hyperlight_vm()` and `create_test_vm_context()`.
    fn create_test_vm_context(code: &[u8]) -> TestVmContext {
        let config: SandboxConfiguration = Default::default();
        #[cfg(any(crashdump, gdb))]
        let rt_cfg: SandboxRuntimeConfig = Default::default();

        let mut layout =
            SandboxMemoryLayout::new(config, code.len(), 4096, 4096, 0x3000, None).unwrap();

        let pt_base_gpa = SandboxMemoryLayout::BASE_ADDRESS + layout.get_pt_offset();
        let pt_buf = GuestPageTableBuffer::new(pt_base_gpa);

        for rgn in layout
            .get_memory_regions_::<GuestMemoryRegion>(())
            .unwrap()
            .iter()
        {
            let readable = rgn.flags.contains(MemoryRegionFlags::READ);
            let writable = rgn.flags.contains(MemoryRegionFlags::WRITE)
                || rgn.flags.contains(MemoryRegionFlags::STACK_GUARD);
            let executable = rgn.flags.contains(MemoryRegionFlags::EXECUTE);
            let mapping = Mapping {
                phys_base: rgn.guest_region.start as u64,
                virt_base: rgn.guest_region.start as u64,
                len: rgn.guest_region.len() as u64,
                kind: MappingKind::BasicMapping(BasicMapping {
                    readable,
                    writable,
                    executable,
                }),
            };
            unsafe { vmem::map(&pt_buf, mapping) };
        }

        let mut pt_size_mapped = 0;
        while pt_buf.size() > pt_size_mapped {
            let mapping = Mapping {
                phys_base: (pt_base_gpa + pt_size_mapped) as u64,
                virt_base: (hyperlight_common::layout::SNAPSHOT_PT_GVA_MIN + pt_size_mapped) as u64,
                len: (pt_buf.size() - pt_size_mapped) as u64,
                kind: MappingKind::BasicMapping(BasicMapping {
                    readable: true,
                    writable: true,
                    executable: false,
                }),
            };
            unsafe { vmem::map(&pt_buf, mapping) };
            pt_size_mapped = pt_buf.size();
        }

        // Map the scratch region at the top of the address space
        let scratch_size = config.get_scratch_size();
        let scratch_gpa = hyperlight_common::layout::scratch_base_gpa(scratch_size);
        let scratch_gva = hyperlight_common::layout::scratch_base_gva(scratch_size);
        let scratch_mapping = Mapping {
            phys_base: scratch_gpa,
            virt_base: scratch_gva,
            len: scratch_size as u64,
            kind: MappingKind::BasicMapping(BasicMapping {
                readable: true,
                writable: true,
                executable: true, // Match regular codepath (map_specials)
            }),
        };
        unsafe { vmem::map(&pt_buf, scratch_mapping) };

        // Re-map page tables if they grew from scratch mapping
        while pt_buf.size() > pt_size_mapped {
            let mapping = Mapping {
                phys_base: (pt_base_gpa + pt_size_mapped) as u64,
                virt_base: (hyperlight_common::layout::SNAPSHOT_PT_GVA_MIN + pt_size_mapped) as u64,
                len: (pt_buf.size() - pt_size_mapped) as u64,
                kind: MappingKind::BasicMapping(BasicMapping {
                    readable: true,
                    writable: true,
                    executable: false,
                }),
            };
            unsafe { vmem::map(&pt_buf, mapping) };
            pt_size_mapped = pt_buf.size();
        }

        let pt_bytes = pt_buf.into_bytes();
        layout.set_pt_size(pt_bytes.len());

        let mem_size = layout.get_memory_size().unwrap();
        let mut eshm = ExclusiveSharedMemory::new(mem_size).unwrap();
        eshm.copy_from_slice(&pt_bytes, layout.get_pt_offset())
            .unwrap();
        eshm.copy_from_slice(code, layout.get_guest_code_offset())
            .unwrap();

        let load_addr = RawPtr::from(layout.get_guest_code_address() as u64);
        let scratch_mem = ExclusiveSharedMemory::new(config.get_scratch_size()).unwrap();
        let mut mem_mgr = SandboxMemoryManager::new(
            layout,
            eshm,
            scratch_mem,
            load_addr,
            Some(Offset::from(0u64)),
        );
        mem_mgr.write_memory_layout().unwrap();

        let (mut hshm, gshm) = mem_mgr.build().unwrap();

        let peb_address = gshm.layout.peb_address;
        let stack_top_gva = hyperlight_common::layout::MAX_GVA as u64
            - hyperlight_common::layout::SCRATCH_TOP_EXN_STACK_OFFSET
            + 1;
        let mut vm = set_up_hypervisor_partition(
            gshm,
            &config,
            stack_top_gva,
            #[cfg(any(crashdump, gdb))]
            &rt_cfg,
            crate::mem::exe::LoadInfo::dummy(),
        )
        .unwrap();

        let seed = rand::rng().random::<u64>();
        let peb_addr = RawPtr::from(u64::try_from(peb_address).unwrap());
        let page_size = u32::try_from(page_size::get()).unwrap();

        #[cfg(gdb)]
        let dbg_mem_access_hdl = Arc::new(Mutex::new(hshm.clone()));

        let host_funcs = Arc::new(Mutex::new(FunctionRegistry::default()));

        vm.initialise(
            peb_addr,
            seed,
            page_size,
            &mut hshm,
            &host_funcs,
            None,
            #[cfg(gdb)]
            dbg_mem_access_hdl.clone(),
        )
        .unwrap();

        TestVmContext {
            vm,
            hshm,
            host_funcs,
            #[cfg(gdb)]
            dbg_mem_access_hdl,
        }
    }

    /// Simple helper that returns just the VM for tests that don't need memory access.
    fn hyperlight_vm(code: &[u8]) -> HyperlightVm {
        create_test_vm_context(code).vm
    }

    // ==========================================================================
    // Tests
    // ==========================================================================

    #[test]
    fn reset_vcpu_simple() {
        // push rax; hlt - aligns stack to 16 bytes
        const CODE: [u8; 2] = [0x50, 0xf4];
        let hyperlight_vm = hyperlight_vm(&CODE);
        let available_hv = *get_available_hypervisor().as_ref().unwrap();

        // Get the initial CR3 value before dirtying sregs
        let initial_cr3 = hyperlight_vm.vm.sregs().unwrap().cr3;

        // Set all vCPU state to dirty values
        let regs = dirty_regs();
        let fpu = dirty_fpu();
        let sregs = dirty_sregs(initial_cr3);
        let current_xsave = hyperlight_vm.vm.xsave().unwrap();
        let xsave = dirty_xsave(&current_xsave);
        let debug_regs = dirty_debug_regs();

        hyperlight_vm.vm.set_xsave(&xsave).unwrap();
        hyperlight_vm.vm.set_regs(&regs).unwrap();
        hyperlight_vm.vm.set_fpu(&fpu).unwrap();
        hyperlight_vm.vm.set_sregs(&sregs).unwrap();
        hyperlight_vm.vm.set_debug_regs(&debug_regs).unwrap();

        // Verify regs were set
        assert_eq!(hyperlight_vm.vm.regs().unwrap(), regs);

        // Verify fpu was set
        let mut got_fpu = hyperlight_vm.vm.fpu().unwrap();
        let mut expected_fpu = fpu;
        // KVM doesn't preserve mxcsr via set_fpu/fpu(), copy expected to got
        normalize_fpu_mxcsr_for_kvm(&mut got_fpu, fpu.mxcsr);
        // fpr only uses 80 bits per register. Normalize upper bits for comparison.
        for i in 0..8 {
            expected_fpu.fpr[i][10..16].copy_from_slice(&got_fpu.fpr[i][10..16]);
        }
        assert_eq!(got_fpu, expected_fpu);

        // Verify xsave was set by checking key dirty values in the legacy region.
        // Note: set_fpu() is called after set_xsave(), so XMM registers reflect fpu state (0xCD pattern).
        let got_xsave = hyperlight_vm.vm.xsave().unwrap();
        // FCW (bytes 0-1) should be 0x0F7F (set by both xsave and fpu)
        let got_fcw = u16::from_le_bytes(got_xsave[0..2].try_into().unwrap());
        assert_eq!(got_fcw, 0x0F7F, "xsave FCW should be dirty");
        // MXCSR (bytes 24-27) should be 0x3F80 (set by xsave; fpu doesn't update it on KVM)
        let got_mxcsr = u32::from_le_bytes(got_xsave[24..28].try_into().unwrap());
        assert_eq!(got_mxcsr, 0x3F80, "xsave MXCSR should be dirty");
        // XMM0-XMM15 (bytes 160-415): set_fpu overwrites with 0xCD pattern from dirty_fpu()
        for i in 0..16 {
            let offset = 160 + i * 16;
            let xmm_word = u32::from_le_bytes(got_xsave[offset..offset + 4].try_into().unwrap());
            assert_eq!(
                xmm_word, 0xCDCDCDCD,
                "xsave XMM{i} should match fpu dirty value"
            );
        }

        // Verify debug regs were set
        let got_debug_regs = hyperlight_vm.vm.debug_regs().unwrap();
        let mut expected_debug_regs = debug_regs;
        normalize_debug_regs(&mut expected_debug_regs, &got_debug_regs);
        assert_eq!(got_debug_regs, expected_debug_regs);

        // Verify sregs were set
        let got_sregs = hyperlight_vm.vm.sregs().unwrap();
        let mut expected_sregs = sregs;
        normalize_sregs_hidden_cache(&mut expected_sregs, &got_sregs);
        assert_eq!(got_sregs, expected_sregs);

        // Reset the vCPU
        hyperlight_vm.reset_vcpu(0, &default_sregs()).unwrap();

        // Verify registers are reset to defaults
        assert_regs_reset(hyperlight_vm.vm.as_ref());

        // Verify FPU is reset to defaults
        assert_fpu_reset(hyperlight_vm.vm.as_ref());

        // Verify debug registers are reset to defaults
        assert_debug_regs_reset(hyperlight_vm.vm.as_ref());

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

        // Verify sregs are reset to defaults (CR3 is 0 as passed to reset_vcpu)
        assert_sregs_reset(hyperlight_vm.vm.as_ref(), 0);
    }

    /// Tests that actually runs code, as opposed to just setting vCPU state.
    mod run_tests {
        use iced_x86::code_asm::*;

        use super::*;

        #[test]
        fn reset_vcpu_regs() {
            let mut a = CodeAssembler::new(64).unwrap();
            a.push(rax).unwrap(); // Align stack to 16 bytes
            a.mov(rax, 0x1111111111111111u64).unwrap();
            a.mov(rbx, 0x2222222222222222u64).unwrap();
            a.mov(rcx, 0x3333333333333333u64).unwrap();
            a.mov(rdx, 0x4444444444444444u64).unwrap();
            a.mov(rsi, 0x5555555555555555u64).unwrap();
            a.mov(rdi, 0x6666666666666666u64).unwrap();
            a.mov(rbp, 0x7777777777777777u64).unwrap();
            a.mov(r8, 0x8888888888888888u64).unwrap();
            a.mov(r9, 0x9999999999999999u64).unwrap();
            a.mov(r10, 0xAAAAAAAAAAAAAAAAu64).unwrap();
            a.mov(r11, 0xBBBBBBBBBBBBBBBBu64).unwrap();
            a.mov(r12, 0xCCCCCCCCCCCCCCCCu64).unwrap();
            a.mov(r13, 0xDDDDDDDDDDDDDDDDu64).unwrap();
            a.mov(r14, 0xEEEEEEEEEEEEEEEEu64).unwrap();
            a.mov(r15, 0xFFFFFFFFFFFFFFFFu64).unwrap();
            a.hlt().unwrap();
            let code = a.assemble(0).unwrap();

            let hyperlight_vm = hyperlight_vm(&code);

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
            hyperlight_vm.reset_vcpu(0, &default_sregs()).unwrap();

            // Check registers are reset to defaults
            assert_regs_reset(hyperlight_vm.vm.as_ref());
        }

        #[test]
        fn reset_vcpu_fpu() {
            #[cfg(kvm)]
            use crate::hypervisor::regs::MXCSR_DEFAULT;

            #[cfg(kvm)]
            let available_hv = *get_available_hypervisor().as_ref().unwrap();

            // Build code to dirty XMM registers, x87 FPU, and MXCSR
            let mut a = CodeAssembler::new(64).unwrap();
            a.push(rax).unwrap(); // Align stack to 16 bytes

            // xmm0-xmm7: use movd + pshufd to fill with pattern
            let xmm_regs_low = [xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7];
            let patterns_low: [u32; 8] = [
                0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777,
                0x88888888,
            ];
            for (xmm, pat) in xmm_regs_low.iter().zip(patterns_low.iter()) {
                a.mov(eax, *pat).unwrap();
                a.movd(*xmm, eax).unwrap();
                a.pshufd(*xmm, *xmm, 0).unwrap();
            }

            // xmm8-xmm15: upper XMM registers
            let xmm_regs_high = [xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15];
            let patterns_high: [u32; 8] = [
                0x99999999, 0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD, 0xEEEEEEEE, 0xFFFFFFFF,
                0x12345678,
            ];
            for (xmm, pat) in xmm_regs_high.iter().zip(patterns_high.iter()) {
                a.mov(eax, *pat).unwrap();
                a.movd(*xmm, eax).unwrap();
                a.pshufd(*xmm, *xmm, 0).unwrap();
            }

            // Use 7 FLDs so TOP=1 after execution, different from default TOP=0.
            // This ensures reset properly clears TOP, not just register contents.
            a.fldz().unwrap(); // 0.0
            a.fldl2e().unwrap(); // log2(e)
            a.fldl2t().unwrap(); // log2(10)
            a.fldlg2().unwrap(); // log10(2)
            a.fldln2().unwrap(); // ln(2)
            a.fldpi().unwrap(); // pi
            // Push a memory value to also dirty last_dp
            a.mov(rax, 0xDEADBEEFu64).unwrap();
            a.push(rax).unwrap();
            a.fld(qword_ptr(rsp)).unwrap(); // dirties last_dp
            a.pop(rax).unwrap();

            // Dirty FCW (0x0F7F, different from default 0x037F)
            a.mov(eax, 0x0F7Fu32).unwrap();
            a.push(rax).unwrap();
            a.fldcw(word_ptr(rsp)).unwrap();
            a.pop(rax).unwrap();

            // Dirty MXCSR (0x3F80, different from default 0x1F80)
            a.mov(eax, 0x3F80u32).unwrap();
            a.push(rax).unwrap();
            a.ldmxcsr(dword_ptr(rsp)).unwrap();
            a.pop(rax).unwrap();

            a.hlt().unwrap();
            let code = a.assemble(0).unwrap();

            let hyperlight_vm = hyperlight_vm(&code);

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
            // KVM doesn't preserve mxcsr via fpu(), copy from actual
            normalize_fpu_mxcsr_for_kvm(&mut expected_dirty, fpu.mxcsr);
            assert_eq!(fpu, expected_dirty);

            // KVM's get_fpu/set_fpu ioctls don't include MXCSR (it's in the SSE state,
            // not x87 FPU state). We must use xsave to verify MXCSR on KVM.
            #[cfg(kvm)]
            if available_hv == HypervisorType::Kvm {
                let xsave = hyperlight_vm.vm.xsave().unwrap();
                let mxcsr = u32::from_le_bytes(xsave[24..28].try_into().unwrap());
                assert_eq!(mxcsr, 0x3F80, "MXCSR in XSAVE should be dirty");
            }

            // Reset vcpu
            hyperlight_vm.reset_vcpu(0, &default_sregs()).unwrap();

            // Check FPU is reset to defaults
            assert_fpu_reset(hyperlight_vm.vm.as_ref());

            // Verify MXCSR via xsave on KVM (fpu() doesn't include it)
            #[cfg(kvm)]
            if available_hv == HypervisorType::Kvm {
                let xsave = hyperlight_vm.vm.xsave().unwrap();
                let mxcsr = u32::from_le_bytes(xsave[24..28].try_into().unwrap());
                assert_eq!(mxcsr, MXCSR_DEFAULT, "MXCSR in XSAVE should be reset");
            }
        }

        #[test]
        fn reset_vcpu_debug_regs() {
            let mut a = CodeAssembler::new(64).unwrap();
            a.push(rax).unwrap(); // Align stack to 16 bytes
            a.mov(rax, 0xDEAD_BEEF_0000_0000u64).unwrap();
            a.mov(dr0, rax).unwrap();
            a.mov(rax, 0xDEAD_BEEF_0000_0001u64).unwrap();
            a.mov(dr1, rax).unwrap();
            a.mov(rax, 0xDEAD_BEEF_0000_0002u64).unwrap();
            a.mov(dr2, rax).unwrap();
            a.mov(rax, 0xDEAD_BEEF_0000_0003u64).unwrap();
            a.mov(dr3, rax).unwrap();
            a.mov(rax, 1u64).unwrap();
            a.mov(dr6, rax).unwrap();
            a.mov(rax, 0xFFu64).unwrap();
            a.mov(dr7, rax).unwrap();
            a.hlt().unwrap();
            let code = a.assemble(0).unwrap();

            let hyperlight_vm = hyperlight_vm(&code);

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
            hyperlight_vm.reset_vcpu(0, &default_sregs()).unwrap();

            // Check debug registers are reset to default values
            assert_debug_regs_reset(hyperlight_vm.vm.as_ref());
        }

        #[test]
        fn reset_vcpu_sregs() {
            // Build code that modifies special registers and halts
            // We can modify CR0.WP, CR2, CR4.TSD, and CR8 from guest code in ring 0
            let mut a = CodeAssembler::new(64).unwrap();
            a.push(rax).unwrap(); // Align stack to 16 bytes
            // Set CR0.WP (Write Protect, bit 16)
            a.mov(rax, cr0).unwrap();
            a.or(rax, 0x10000i32).unwrap();
            a.mov(cr0, rax).unwrap();
            // Set CR2
            a.mov(rax, 0xDEADBEEFu64).unwrap();
            a.mov(cr2, rax).unwrap();
            // Set CR4.TSD (Time Stamp Disable, bit 2)
            a.mov(rax, cr4).unwrap();
            a.or(rax, 0x4i32).unwrap();
            a.mov(cr4, rax).unwrap();
            // Set CR8
            a.mov(rax, 5u64).unwrap();
            a.mov(cr8, rax).unwrap();
            a.hlt().unwrap();
            let code = a.assemble(0).unwrap();

            let hyperlight_vm = hyperlight_vm(&code);

            // Get the initial CR3 value and expected defaults
            let initial_cr3 = hyperlight_vm.vm.sregs().unwrap().cr3;
            let defaults = CommonSpecialRegisters::standard_64bit_defaults(initial_cr3);

            // Verify registers are dirty (CR0.WP, CR2, CR4.TSD and CR8 modified by our code)
            let sregs = hyperlight_vm.vm.sregs().unwrap();
            let mut expected_dirty = CommonSpecialRegisters {
                cr0: defaults.cr0 | 0x10000, // WP bit set
                cr2: 0xDEADBEEF,
                cr4: defaults.cr4 | 0x4, // TSD bit set
                cr8: 0x5,
                ..defaults
            };
            normalize_sregs_for_run_tests(&mut expected_dirty, &sregs);
            assert_eq!(sregs, expected_dirty);

            // Reset vcpu
            hyperlight_vm.reset_vcpu(0, &default_sregs()).unwrap();

            // Check registers are reset to defaults (CR3 is 0 as passed to reset_vcpu)
            let sregs = hyperlight_vm.vm.sregs().unwrap();
            let mut expected_reset = CommonSpecialRegisters::standard_64bit_defaults(0);
            normalize_sregs_for_run_tests(&mut expected_reset, &sregs);
            assert_eq!(sregs, expected_reset);
        }

        /// Verifies guest-visible FPU state (via FXSAVE) is properly reset.
        /// Unlike tests using hypervisor API, this runs actual guest code with FXSAVE.
        #[test]
        fn reset_vcpu_fpu_guest_visible_state() {
            let mut ctx = hyperlight_vm_with_mem_mgr_fxsave();

            // Verify FPU was dirtied after first run
            let fpu_before_reset = ctx.ctx.vm.vm.fpu().unwrap();
            assert_eq!(
                fpu_before_reset.fcw, 0x0F7F,
                "FCW should be dirty after first run"
            );
            assert_ne!(
                fpu_before_reset.ftwx, 0,
                "FTW should indicate valid registers after first run"
            );

            let fxsave_before = ctx.read_fxsave();
            let fcw_before = u16::from_le_bytes(fxsave_before[0..2].try_into().unwrap());
            assert_eq!(fcw_before, 0x0F7F, "Guest FXSAVE FCW should be dirty");
            let mxcsr_before = u32::from_le_bytes(fxsave_before[24..28].try_into().unwrap());
            assert_eq!(mxcsr_before, 0x3F80, "Guest FXSAVE MXCSR should be dirty");
            let xmm0_before = u32::from_le_bytes(fxsave_before[160..164].try_into().unwrap());
            assert_eq!(xmm0_before, 0x11111111, "Guest FXSAVE XMM0 should be dirty");

            let root_pt_addr = ctx.ctx.vm.get_root_pt().unwrap();
            let segment_state = ctx.ctx.vm.get_snapshot_sregs().unwrap();

            ctx.ctx.vm.reset_vcpu(root_pt_addr, &segment_state).unwrap();

            // Re-run from entrypoint (flag=1 means guest skips dirty phase, just does FXSAVE)
            // Use stack_top - 8 to match initialise()'s behavior (simulates call pushing return addr)
            let regs = CommonRegisters {
                rip: ctx.ctx.vm.entrypoint.expect("entrypoint should be set"),
                rsp: ctx.stack_top_gva() - 8,
                rflags: 1 << 1,
                ..Default::default()
            };
            ctx.ctx.vm.vm.set_regs(&regs).unwrap();
            ctx.run();

            // Verify guest-visible state is reset
            let fxsave_after = ctx.read_fxsave();
            let fcw_after = u16::from_le_bytes(fxsave_after[0..2].try_into().unwrap());
            assert_eq!(
                fcw_after, 0x037F,
                "Guest FXSAVE FCW should be reset to default 0x037F, got 0x{:04X}",
                fcw_after
            );

            let fsw_after = u16::from_le_bytes(fxsave_after[2..4].try_into().unwrap());
            assert_eq!(fsw_after, 0, "FSW should be reset");

            let ftw_after = fxsave_after[4];
            assert_eq!(ftw_after, 0, "FTW should be 0 (all empty)");

            let fop_after = u16::from_le_bytes(fxsave_after[6..8].try_into().unwrap());
            assert_eq!(fop_after, 0, "FOP should be 0");

            let fip_after = u64::from_le_bytes(fxsave_after[8..16].try_into().unwrap());
            assert_eq!(fip_after, 0, "FIP should be 0");

            let fdp_after = u64::from_le_bytes(fxsave_after[16..24].try_into().unwrap());
            assert_eq!(fdp_after, 0, "FDP should be 0");

            let mxcsr_after = u32::from_le_bytes(fxsave_after[24..28].try_into().unwrap());
            assert_eq!(
                mxcsr_after, MXCSR_DEFAULT,
                "Guest FXSAVE MXCSR should be reset to 0x{:08X}, got 0x{:08X}",
                MXCSR_DEFAULT, mxcsr_after
            );

            // ST0-ST7 should be zeroed
            for i in 0..8 {
                let offset = 32 + i * 16;
                let st_bytes = &fxsave_after[offset..offset + 10];
                assert!(st_bytes.iter().all(|&b| b == 0), "ST{} should be zeroed", i);
            }

            // XMM0-XMM15 should be zeroed
            for i in 0..16 {
                let offset = 160 + i * 16;
                let xmm_bytes = &fxsave_after[offset..offset + 16];
                assert!(
                    xmm_bytes.iter().all(|&b| b == 0),
                    "XMM{} should be zeroed",
                    i
                );
            }
        }

        /// Extended test context for FXSAVE tests that need to read memory at a specific offset.
        struct FxsaveTestContext {
            ctx: TestVmContext,
            /// Offset in shared memory where FXSAVE data is stored (output_data region)
            fxsave_offset: usize,
        }

        impl FxsaveTestContext {
            fn run(&mut self) {
                self.ctx
                    .vm
                    .run(
                        &mut self.ctx.hshm,
                        &self.ctx.host_funcs,
                        #[cfg(gdb)]
                        self.ctx.dbg_mem_access_hdl.clone(),
                    )
                    .unwrap();
            }

            fn read_fxsave(&self) -> [u8; 512] {
                let mut fxsave = [0u8; 512];
                self.ctx
                    .hshm
                    .shared_mem
                    .copy_to_slice(&mut fxsave, self.fxsave_offset)
                    .unwrap();
                fxsave
            }

            /// Get the stack top GVA, same as the regular codepath.
            fn stack_top_gva(&self) -> u64 {
                hyperlight_common::layout::MAX_GVA as u64
                    - hyperlight_common::layout::SCRATCH_TOP_EXN_STACK_OFFSET
                    + 1
            }
        }

        /// Creates VM with guest code that: dirtys FPU (if flag==0), does FXSAVE to buffer, sets flag=1.
        /// Uses output_data region for FXSAVE buffer (like regular guest output), scratch for stack.
        fn hyperlight_vm_with_mem_mgr_fxsave() -> FxsaveTestContext {
            use iced_x86::code_asm::*;

            // Compute fixed addresses for FXSAVE buffer and flag.
            // These are in the output_data region which starts at a known offset.
            // We use a default SandboxConfiguration to get the same layout as create_test_vm_context.
            let config: SandboxConfiguration = Default::default();
            let layout = SandboxMemoryLayout::new(config, 512, 4096, 4096, 0x3000, None).unwrap();
            let fxsave_offset = layout.get_output_data_offset();
            let fxsave_gva = (SandboxMemoryLayout::BASE_ADDRESS + fxsave_offset) as u64;
            let flag_gva = fxsave_gva + 512;

            let mut a = CodeAssembler::new(64).unwrap();
            a.push(rax).unwrap(); // Align stack to 16 bytes

            // Check flag at fixed address: if flag != 0, skip dirty phase
            a.mov(rax, flag_gva).unwrap();
            a.mov(al, byte_ptr(rax)).unwrap();
            a.test(al, al).unwrap();
            let mut skip_dirty = a.create_label();
            a.jnz(skip_dirty).unwrap();

            // Dirty x87 FPU (7 pushes so TOP=1)
            a.fldz().unwrap();
            a.fldl2e().unwrap();
            a.fldl2t().unwrap();
            a.fldlg2().unwrap();
            a.fldln2().unwrap();
            a.fldpi().unwrap();
            a.fld1().unwrap();

            // Dirty FCW (0x0F7F vs default 0x037F)
            a.sub(rsp, 16i32).unwrap();
            a.mov(dword_ptr(rsp), 0x0F7Fu32).unwrap();
            a.fldcw(word_ptr(rsp)).unwrap();
            a.add(rsp, 16i32).unwrap();

            // Dirty MXCSR (0x3F80 vs default 0x1F80)
            a.sub(rsp, 16i32).unwrap();
            a.mov(dword_ptr(rsp), 0x3F80u32).unwrap();
            a.ldmxcsr(dword_ptr(rsp)).unwrap();
            a.add(rsp, 16i32).unwrap();

            // Dirty XMM0-7
            let xmm_regs = [xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7];
            for (i, xmm) in xmm_regs.iter().enumerate() {
                a.mov(eax, 0x11111111u32 * (i as u32 + 1)).unwrap();
                a.movd(*xmm, eax).unwrap();
                a.pshufd(*xmm, *xmm, 0).unwrap();
            }

            // Set flag = 1 at fixed address
            a.mov(rax, flag_gva).unwrap();
            a.mov(byte_ptr(rax), 1u32).unwrap();

            // FXSAVE to buffer at fixed address (runs on both executions)
            a.set_label(&mut skip_dirty).unwrap();
            a.mov(rax, fxsave_gva).unwrap();
            a.fxsave(ptr(rax)).unwrap();

            a.hlt().unwrap();

            let code = a.assemble(0).unwrap();

            // Reuse common test setup - initialise() will run the code
            let ctx = create_test_vm_context(&code);

            FxsaveTestContext { ctx, fxsave_offset }
        }
    }
}
