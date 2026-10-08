// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

//! Windows Hypervisor Platform (WHP) backend for AArch64.
//!
//! This module provides the [`VirtualMachine`] trait implementation using the
//! WHP APIs on Windows ARM64 systems. Because the `windows` crate does not yet
//! expose ARM64 WHP structures, we define our own FFI bindings derived from
//! the Windows SDK header `WinHvPlatformDefs.h` (10.0.26100.0).

#[cfg(gdb)]
use std::collections::HashSet;
use std::os::raw::c_void;
use std::sync::atomic::Ordering;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use hyperlight_common::layout::{
    WHP_GICD_BASE_GPA, WHP_GICR_BASE_GPA, WHP_GITS_TRANSLATOR_BASE_GPA,
};
use hyperlight_common::outb::VmAction;
use windows::Win32::System::Hypervisor::*;
use windows::Win32::System::Threading::GetCurrentProcess;
use windows_result::HRESULT;

use super::release_file_mapping;
#[cfg(gdb)]
use crate::hypervisor::gdb::arch::SW_BP_IMMEDIATE;
#[cfg(gdb)]
use crate::hypervisor::gdb::{DebugError, DebuggableVm, VcpuStopReason};
use crate::hypervisor::regs::whp_reg::*;
use crate::hypervisor::regs::{
    CommonDebugRegs, CommonFpu, CommonRegisters, CommonSpecialRegisters,
};
use crate::hypervisor::surrogate_process::SurrogateProcess;
use crate::hypervisor::surrogate_process_manager::{
    MAX_WHP_PARTITIONS, get_surrogate_process_manager, surrogates_disabled,
};
use crate::hypervisor::virtual_machine::{
    CreateVmError, HypervisorError, MapMemoryError, RegisterError, ResetVcpuError, RunVcpuError,
    UnmapMemoryError, VirtualMachine, VmExit,
};
use crate::hypervisor::wrappers::HandleWrapper;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags, MemoryRegionType};
#[cfg(gdb)]
use crate::mem::shared_mem::{ExclusiveSharedMemory, GuestSharedMemory, HostSharedMemory};
#[cfg(feature = "trace_guest")]
use crate::sandbox::trace::TraceContext as SandboxTraceContext;

// ============================================================================
// ARM64 WHP FFI bindings
//
// These are manually translated from WinHvPlatformDefs.h (Windows SDK 10.0.26100.0)
// because the `windows` crate does not expose ARM64 WHP types.
// ============================================================================

const WHV_PARTITION_PROPERTY_CODE_ARM64_IC_PARAMETERS: WHV_PARTITION_PROPERTY_CODE =
    WHV_PARTITION_PROPERTY_CODE(0x00001012);

#[repr(C)]
struct Arm64IcGicV3Parameters {
    gicd_base_address: u64,
    gits_translator_base_address: u64,
    reserved: u32,
    gic_lpi_int_id_bits: u32,
    gic_ppi_overflow_interrupt_from_cntv: u32,
    gic_ppi_performance_monitors_interrupt: u32,
    reserved1: [u32; 6],
}

#[repr(C)]
struct Arm64IcParameters {
    emulation_mode: i32,
    reserved: u32,
    gic_v3_parameters: Arm64IcGicV3Parameters,
}

const _: () = {
    assert!(core::mem::size_of::<Arm64IcGicV3Parameters>() == 56);
    assert!(core::mem::align_of::<Arm64IcGicV3Parameters>() == 8);
    assert!(core::mem::size_of::<Arm64IcParameters>() == 64);
    assert!(core::mem::align_of::<Arm64IcParameters>() == 8);
};

const ARM64_IC_PARAMETERS: Arm64IcParameters = Arm64IcParameters {
    emulation_mode: 1,
    reserved: 0,
    gic_v3_parameters: Arm64IcGicV3Parameters {
        gicd_base_address: WHP_GICD_BASE_GPA,
        gits_translator_base_address: WHP_GITS_TRANSLATOR_BASE_GPA,
        reserved: 0,
        gic_lpi_int_id_bits: 1,
        gic_ppi_overflow_interrupt_from_cntv: 0x1b,
        gic_ppi_performance_monitors_interrupt: 0x17,
        reserved1: [0; 6],
    },
};

const PARTITION_WAIT_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(gdb)]
const EXTENDED_VM_EXIT_HYPERCALL: u64 = 1 << 5;
#[cfg(gdb)]
const DEBUG_CACHE_SYNC_GPA: u64 = 0x1000;
#[cfg(gdb)]
const DEBUG_CACHE_SYNC_IMMEDIATE: u16 = 0x4858;
#[cfg(gdb)]
const DEBUG_CACHE_SYNC_CODE: [u8; 20] = [
    0x9f, 0x3b, 0x03, 0xd5, // dsb ish
    0x1f, 0x75, 0x08, 0xd5, // ic iallu
    0x9f, 0x3b, 0x03, 0xd5, // dsb ish
    0xdf, 0x3f, 0x03, 0xd5, // isb
    0x02, 0x0b, 0x09, 0xd4, // hvc #0x4858
];

type WhvResetPartitionFn = unsafe extern "system" fn(WHV_PARTITION_HANDLE) -> HRESULT;

static WHP_PARTITION_COUNT: Mutex<usize> = Mutex::new(0);
static WHP_PARTITION_AVAILABLE: Condvar = Condvar::new();

#[derive(Debug)]
struct WhpPartitionPermit;

impl WhpPartitionPermit {
    fn acquire() -> Result<Self, CreateVmError> {
        let deadline = Instant::now() + PARTITION_WAIT_TIMEOUT;
        let mut count = WHP_PARTITION_COUNT
            .lock()
            .unwrap_or_else(|error| error.into_inner());

        while *count >= MAX_WHP_PARTITIONS {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(CreateVmError::WhpPartitionLimit);
            };
            let (next_count, result) = WHP_PARTITION_AVAILABLE
                .wait_timeout(count, remaining)
                .unwrap_or_else(|error| error.into_inner());
            count = next_count;
            if result.timed_out() && *count >= MAX_WHP_PARTITIONS {
                return Err(CreateVmError::WhpPartitionLimit);
            }
        }

        *count += 1;
        Ok(Self)
    }
}

impl Drop for WhpPartitionPermit {
    fn drop(&mut self) {
        let mut count = WHP_PARTITION_COUNT
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *count -= 1;
        WHP_PARTITION_AVAILABLE.notify_one();
    }
}

/// ARM64 WHP exit reasons (from the SDK header under `_ARM64_`).
#[allow(dead_code)]
mod arm64_exit_reasons {
    use windows::Win32::System::Hypervisor::WHV_RUN_VP_EXIT_REASON;

    pub const WHV_EXIT_REASON_NONE: WHV_RUN_VP_EXIT_REASON =
        WHV_RUN_VP_EXIT_REASON(0x00000000u32 as i32);
    pub const WHV_EXIT_REASON_UNMAPPED_GPA: WHV_RUN_VP_EXIT_REASON =
        WHV_RUN_VP_EXIT_REASON(0x80000000u32 as i32);
    pub const WHV_EXIT_REASON_GPA_INTERCEPT: WHV_RUN_VP_EXIT_REASON =
        WHV_RUN_VP_EXIT_REASON(0x80000001u32 as i32);
    pub const WHV_EXIT_REASON_UNRECOVERABLE: WHV_RUN_VP_EXIT_REASON =
        WHV_RUN_VP_EXIT_REASON(0x80000021u32 as i32);
    pub const WHV_EXIT_REASON_INVALID_VP_REGISTER: WHV_RUN_VP_EXIT_REASON =
        WHV_RUN_VP_EXIT_REASON(0x80000020u32 as i32);
    pub const WHV_EXIT_REASON_HYPERCALL: WHV_RUN_VP_EXIT_REASON =
        WHV_RUN_VP_EXIT_REASON(0x80000050u32 as i32);
    pub const WHV_EXIT_REASON_ARM64_RESET: WHV_RUN_VP_EXIT_REASON =
        WHV_RUN_VP_EXIT_REASON(0x8001000cu32 as i32);
    pub const WHV_EXIT_REASON_CANCELLED: WHV_RUN_VP_EXIT_REASON =
        WHV_RUN_VP_EXIT_REASON(0xFFFFFFFFu32 as i32);
}

/// ARM64 WHP exit context layout.
///
/// On ARM64, `WHV_RUN_VP_EXIT_CONTEXT` is:
/// ```c
/// struct { ExitReason: u32, Reserved: u32, Reserved1: u64, union { ... AsUINT64[32] } }
/// ```
/// Total size = 8 (header) + 8 (reserved1) + 256 (union) = 272 bytes.
///
/// The union's `MemoryAccess` variant starts with `WHV_INTERCEPT_MESSAGE_HEADER` (24 bytes):
/// ```c
/// struct { VpIndex: u32, InstructionLength: u8, InterceptAccessType: u8,
///          ExecutionState: u16, Pc: u64, Cpsr: u64 }
/// ```
/// Followed by memory-access-specific fields.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct Arm64ExitContext {
    exit_reason: WHV_RUN_VP_EXIT_REASON,
    reserved: u32,
    reserved1: u64,
    /// Raw payload — union of various context types. We interpret based on exit_reason.
    payload: [u64; 32],
}

const _: () = {
    assert!(core::mem::size_of::<Arm64ExitContext>() == 272);
    assert!(core::mem::align_of::<Arm64ExitContext>() == 16);
};

impl Default for Arm64ExitContext {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

/// Parsed fields from `WHV_INTERCEPT_MESSAGE_HEADER` (ARM64 version).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Arm64InterceptMessageHeader {
    #[allow(dead_code)]
    vp_index: u32,
    instruction_length: u8,
    intercept_access_type: u8,
    #[allow(dead_code)]
    execution_state: u16,
    pc: u64,
    #[allow(dead_code)]
    cpsr: u64,
}

impl Arm64ExitContext {
    /// Parse the intercept message header from the start of the payload.
    /// This is valid for memory access, unrecoverable, and register intercept exits.
    fn intercept_header(&self) -> Arm64InterceptMessageHeader {
        let bytes = unsafe { core::slice::from_raw_parts(self.payload.as_ptr() as *const u8, 24) };
        Arm64InterceptMessageHeader {
            vp_index: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            instruction_length: bytes[4],
            intercept_access_type: bytes[5],
            execution_state: u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
            pc: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            cpsr: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        }
    }

    /// For memory access exits: get the GPA from the payload.
    ///
    /// ARM64 `WHV_MEMORY_ACCESS_CONTEXT` layout after the 24-byte header:
    /// ```text
    /// offset 24: Reserved0 (u32)
    /// offset 28: InstructionByteCount (u8)
    /// offset 29: AccessInfo (u8 bitfield: GvaValid, GvaGpaValid, HypercallOutputPending)
    /// offset 30: Reserved1 (u16)
    /// offset 32: InstructionBytes[4] (u32)
    /// offset 36: Reserved2 (u32)
    /// offset 40: Gva (u64)
    /// offset 48: Gpa (u64)
    /// offset 56: Syndrome (u64)
    /// ```
    fn memory_access_gpa(&self) -> u64 {
        let bytes = unsafe { core::slice::from_raw_parts(self.payload.as_ptr() as *const u8, 64) };
        u64::from_le_bytes(bytes[48..56].try_into().unwrap())
    }

    fn memory_access_syndrome(&self) -> u64 {
        let bytes = unsafe { core::slice::from_raw_parts(self.payload.as_ptr() as *const u8, 64) };
        u64::from_le_bytes(bytes[56..64].try_into().unwrap())
    }

    #[cfg(gdb)]
    fn hypercall_context(&self) -> Arm64HypercallContext {
        // SAFETY: The exit payload is 256 bytes. The hypercall context occupies
        // its first 176 bytes and may be read without alignment assumptions.
        unsafe { core::ptr::read_unaligned(self.payload.as_ptr().cast()) }
    }
}

#[cfg(gdb)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Arm64HypercallContext {
    header: Arm64InterceptMessageHeader,
    immediate: u16,
    reserved1: u16,
    reserved2: u32,
    x: [u64; 18],
}

#[cfg(gdb)]
const _: [(); 24] = [(); core::mem::size_of::<Arm64InterceptMessageHeader>()];
#[cfg(gdb)]
const _: [(); 176] = [(); core::mem::size_of::<Arm64HypercallContext>()];

#[cfg(gdb)]
#[derive(Debug, PartialEq, Eq)]
enum Arm64HypercallClassification {
    SoftwareBreakpoint,
    Unknown { immediate: u16, pc: u64 },
}

#[cfg(gdb)]
fn classify_hypercall(
    context: &Arm64HypercallContext,
    debug_enabled: bool,
    software_breakpoints: &HashSet<u64>,
) -> Arm64HypercallClassification {
    if debug_enabled
        && context.immediate == SW_BP_IMMEDIATE
        && software_breakpoints.contains(&context.header.pc)
    {
        Arm64HypercallClassification::SoftwareBreakpoint
    } else {
        Arm64HypercallClassification::Unknown {
            immediate: context.immediate,
            pc: context.header.pc,
        }
    }
}

// ============================================================================
// Surrogate process guard (same as x86_64 version)
// ============================================================================

use std::sync::atomic::AtomicBool as StdAtomicBool;

/// RAII guard: when surrogates are disabled, only one no-surrogate WHP VM
/// can exist at a time. This flag prevents a second one from being created.
static NO_SURROGATE_VM_ACTIVE: StdAtomicBool = StdAtomicBool::new(false);

#[derive(Debug)]
struct NoSurrogateGuard;

impl NoSurrogateGuard {
    fn acquire() -> Result<Self, CreateVmError> {
        if NO_SURROGATE_VM_ACTIVE
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(CreateVmError::SurrogateProcess(
                "Another no-surrogate WHP VM is already active".to_string(),
            ));
        }
        Ok(NoSurrogateGuard)
    }
}

impl Drop for NoSurrogateGuard {
    fn drop(&mut self) {
        NO_SURROGATE_VM_ACTIVE.store(false, Ordering::SeqCst);
    }
}

// ============================================================================
// WhpVm implementation
// ============================================================================

/// Determine whether the WHP hypervisor API is available.
#[allow(dead_code)]
pub(crate) fn is_hypervisor_present() -> bool {
    const ARM64_SUPPORT_BIT: u64 = 1 << 11;

    let mut capability: WHV_CAPABILITY = Default::default();
    let hypervisor_present = match unsafe {
        WHvGetCapability(
            WHvCapabilityCodeHypervisorPresent,
            &mut capability as *mut _ as *mut c_void,
            std::mem::size_of::<WHV_CAPABILITY>() as u32,
            None,
        )
    } {
        Ok(_) => unsafe { capability.HypervisorPresent.as_bool() },
        Err(_) => {
            tracing::info!("Windows Hypervisor Platform is not available on this system");
            false
        }
    };
    if !hypervisor_present {
        return false;
    }

    match unsafe {
        WHvGetCapability(
            WHvCapabilityCodeFeatures,
            &mut capability as *mut _ as *mut c_void,
            std::mem::size_of::<WHV_CAPABILITY>() as u32,
            None,
        )
    } {
        Ok(_) => unsafe { capability.Features.AsUINT64 & ARM64_SUPPORT_BIT != 0 },
        Err(error) => {
            tracing::info!("Failed to query Windows Hypervisor Platform features: {error}");
            false
        }
    }
}

/// A WHP-backed single-vCPU VM on ARM64.
#[derive(Debug)]
pub(crate) struct WhpVm {
    partition: WHV_PARTITION_HANDLE,
    reset_partition: WhvResetPartitionFn,
    map_gpa_range2: WhvMapGpaRange2Fn,
    _partition_permit: WhpPartitionPermit,
    surrogate_process: Option<SurrogateProcess>,
    /// Tracks host-side file mappings for cleanup.
    file_mappings: Vec<(HandleWrapper, *mut c_void)>,
    _no_surrogate_guard: Option<NoSurrogateGuard>,
    #[cfg(gdb)]
    debug_enabled: bool,
    #[cfg(gdb)]
    software_breakpoints: HashSet<u64>,
    #[cfg(gdb)]
    _debug_cache_sync_host_memory: Option<HostSharedMemory>,
    #[cfg(gdb)]
    _debug_cache_sync_guest_memory: Option<GuestSharedMemory>,
}

// Safety: same reasoning as x86_64 WhpVm — raw pointers are kernel resource handles,
// not dereferenced, safe to transfer between threads.
unsafe impl Send for WhpVm {}

impl WhpVm {
    pub(crate) fn new() -> Result<Self, CreateVmError> {
        const NUM_CPU: u32 = 1;

        let reset_partition = unsafe { try_load_whv_reset_partition() }
            .map_err(|error| CreateVmError::InitializeVm(error.into()))?;
        let map_gpa_range2 = unsafe { try_load_whv_map_gpa_range2() }
            .map_err(|error| CreateVmError::InitializeVm(error.into()))?;
        let partition_permit = WhpPartitionPermit::acquire()?;
        let no_surrogate = surrogates_disabled();
        let no_surrogate_guard = if no_surrogate {
            Some(NoSurrogateGuard::acquire()?)
        } else {
            None
        };

        let partition = unsafe {
            let p = WHvCreatePartition().map_err(|e| CreateVmError::CreateVmFd(e.into()))?;
            let mut vcpu_created = false;
            let setup_result = (|| {
                WHvSetPartitionProperty(
                    p,
                    WHvPartitionPropertyCodeProcessorCount,
                    &NUM_CPU as *const _ as *const _,
                    std::mem::size_of_val(&NUM_CPU) as _,
                )
                .map_err(|e| CreateVmError::SetPartitionProperty(e.into()))?;

                WHvSetPartitionProperty(
                    p,
                    WHV_PARTITION_PROPERTY_CODE_ARM64_IC_PARAMETERS,
                    &ARM64_IC_PARAMETERS as *const _ as *const _,
                    std::mem::size_of_val(&ARM64_IC_PARAMETERS) as _,
                )
                .map_err(|e| CreateVmError::SetPartitionProperty(e.into()))?;

                #[cfg(gdb)]
                WHvSetPartitionProperty(
                    p,
                    WHvPartitionPropertyCodeExtendedVmExits,
                    &WHV_EXTENDED_VM_EXITS {
                        AsUINT64: EXTENDED_VM_EXIT_HYPERCALL,
                    } as *const _ as *const _,
                    std::mem::size_of::<WHV_EXTENDED_VM_EXITS>() as _,
                )
                .map_err(|e| CreateVmError::SetPartitionProperty(e.into()))?;

                WHvSetupPartition(p).map_err(|e| CreateVmError::InitializeVm(e.into()))?;
                WHvCreateVirtualProcessor(p, 0, 0)
                    .map_err(|e| CreateVmError::CreateVcpuFd(e.into()))?;
                vcpu_created = true;

                let names = [WHV_ARM64_REGISTER_GICR_BASE_GPA];
                let values = [Align16(WHV_REGISTER_VALUE {
                    Reg64: WHP_GICR_BASE_GPA,
                })];
                WHvSetVirtualProcessorRegisters(p, 0, names.as_ptr(), 1, values.as_ptr().cast())
                    .map_err(|e| CreateVmError::InitializeVm(e.into()))
            })();

            if let Err(error) = setup_result {
                if vcpu_created && let Err(cleanup_error) = WHvDeleteVirtualProcessor(p, 0) {
                    tracing::error!("Failed to delete virtual processor: {cleanup_error:?}");
                }
                if let Err(cleanup_error) = WHvDeletePartition(p) {
                    tracing::error!("Failed to delete partition: {cleanup_error:?}");
                }
                return Err(error);
            }

            p
        };

        let mut vm = WhpVm {
            partition,
            reset_partition,
            map_gpa_range2,
            _partition_permit: partition_permit,
            surrogate_process: None,
            file_mappings: Vec::new(),
            _no_surrogate_guard: no_surrogate_guard,
            #[cfg(gdb)]
            debug_enabled: false,
            #[cfg(gdb)]
            software_breakpoints: HashSet::new(),
            #[cfg(gdb)]
            _debug_cache_sync_host_memory: None,
            #[cfg(gdb)]
            _debug_cache_sync_guest_memory: None,
        };

        if !no_surrogate {
            let mgr = get_surrogate_process_manager()
                .map_err(|e| CreateVmError::SurrogateProcess(e.to_string()))?;
            vm.surrogate_process = Some(
                mgr.get_surrogate_process()
                    .map_err(|e| CreateVmError::SurrogateProcess(e.to_string()))?,
            );
        }

        #[cfg(gdb)]
        vm.initialize_debug_support()?;

        Ok(vm)
    }

    fn get_registers<const N: usize>(
        &self,
        names: &[WHV_REGISTER_NAME; N],
    ) -> Result<[Align16<WHV_REGISTER_VALUE>; N], HypervisorError> {
        let mut values: [Align16<WHV_REGISTER_VALUE>; N] = unsafe { core::mem::zeroed() };
        unsafe {
            WHvGetVirtualProcessorRegisters(
                self.partition,
                0,
                names.as_ptr(),
                N as u32,
                values.as_mut_ptr().cast(),
            )
            .map_err(HypervisorError::from)?;
        }
        Ok(values)
    }

    fn set_registers<const N: usize>(
        &self,
        names: &[WHV_REGISTER_NAME; N],
        values: &[Align16<WHV_REGISTER_VALUE>; N],
    ) -> Result<(), HypervisorError> {
        unsafe {
            WHvSetVirtualProcessorRegisters(
                self.partition,
                0,
                names.as_ptr(),
                N as u32,
                values.as_ptr().cast(),
            )
            .map_err(HypervisorError::from)?;
        }
        Ok(())
    }

    #[cfg(gdb)]
    fn initialize_debug_support(&mut self) -> Result<(), CreateVmError> {
        let mut memory = ExclusiveSharedMemory::new(page_size::get())
            .map_err(|e| CreateVmError::InitializeDebug(e.to_string()))?;
        memory
            .copy_from_slice(&DEBUG_CACHE_SYNC_CODE, 0)
            .map_err(|e| CreateVmError::InitializeDebug(e.to_string()))?;
        let (host_memory, guest_memory) = memory.build();
        let region = guest_memory.mapping_at(DEBUG_CACHE_SYNC_GPA, MemoryRegionType::Scratch);

        // SAFETY: Both shared-memory handles are retained for the VM lifetime.
        unsafe { self.map_memory((u32::MAX, &region)) }
            .map_err(|e| CreateVmError::InitializeDebug(e.to_string()))?;
        self._debug_cache_sync_host_memory = Some(host_memory);
        self._debug_cache_sync_guest_memory = Some(guest_memory);
        Ok(())
    }

    #[cfg(gdb)]
    fn run_debug_cache_sync(&mut self) -> std::result::Result<(), DebugError> {
        let original_regs = self
            .regs()
            .map_err(|e| DebugError::InstructionCacheSync(e.to_string()))?;
        let original_sctlr_values = self
            .get_registers(&[WHV_ARM64_REGISTER_SCTLR_EL1])
            .map_err(|e| DebugError::InstructionCacheSync(e.to_string()))?;
        let original_sctlr = unsafe { original_sctlr_values[0].0.Reg64 };

        let sync_result = (|| {
            let mut sync_regs = original_regs;
            sync_regs.pc = DEBUG_CACHE_SYNC_GPA;
            sync_regs.pstate = 0b11 << 6 | 0b100;
            self.set_regs(&sync_regs)
                .map_err(|e| DebugError::InstructionCacheSync(e.to_string()))?;
            self.set_registers(
                &[WHV_ARM64_REGISTER_SCTLR_EL1],
                &[Align16(WHV_REGISTER_VALUE {
                    Reg64: crate::hypervisor::regs::SCTLR_EL1_RES1,
                })],
            )
            .map_err(|e| DebugError::InstructionCacheSync(e.to_string()))?;

            let mut exit_context = Arm64ExitContext::default();
            // SAFETY: The partition and vCPU are live. `exit_context` has the
            // SDK-defined ARM64 exit-context size and remains valid for the call.
            unsafe {
                WHvRunVirtualProcessor(
                    self.partition,
                    0,
                    &mut exit_context as *mut _ as *mut c_void,
                    std::mem::size_of::<Arm64ExitContext>() as u32,
                )
                .map_err(|e| DebugError::InstructionCacheSync(e.to_string()))?;
            }

            if exit_context.exit_reason != arm64_exit_reasons::WHV_EXIT_REASON_HYPERCALL {
                return Err(DebugError::InstructionCacheSync(format!(
                    "unexpected WHP exit reason {:#x}",
                    exit_context.exit_reason.0 as u32
                )));
            }

            let hypercall = exit_context.hypercall_context();
            let expected_pc = DEBUG_CACHE_SYNC_GPA + (DEBUG_CACHE_SYNC_CODE.len() - 4) as u64;
            if hypercall.immediate != DEBUG_CACHE_SYNC_IMMEDIATE
                || hypercall.header.pc != expected_pc
            {
                return Err(DebugError::InstructionCacheSync(format!(
                    "unexpected hypercall immediate {:#x} at PC {:#x}",
                    hypercall.immediate, hypercall.header.pc
                )));
            }

            Ok(())
        })();

        let restore_sctlr = self
            .set_registers(
                &[WHV_ARM64_REGISTER_SCTLR_EL1],
                &[Align16(WHV_REGISTER_VALUE {
                    Reg64: original_sctlr,
                })],
            )
            .map_err(|e| DebugError::InstructionCacheSync(e.to_string()));
        let restore_regs = self
            .set_regs(&original_regs)
            .map_err(|e| DebugError::InstructionCacheSync(e.to_string()));

        sync_result?;
        restore_sctlr?;
        restore_regs
    }
}

impl VirtualMachine for WhpVm {
    unsafe fn map_memory(
        &mut self,
        (_slot, region): (u32, &MemoryRegion),
    ) -> Result<(), MapMemoryError> {
        let flags = region
            .flags
            .iter()
            .map(|flag| match flag {
                MemoryRegionFlags::NONE => Ok(WHvMapGpaRangeFlagNone),
                MemoryRegionFlags::READ => Ok(WHvMapGpaRangeFlagRead),
                MemoryRegionFlags::WRITE => Ok(WHvMapGpaRangeFlagWrite),
                MemoryRegionFlags::EXECUTE => Ok(WHvMapGpaRangeFlagExecute),
                _ => Err(MapMemoryError::InvalidFlags(format!(
                    "Invalid memory region flag: {:?}",
                    flag
                ))),
            })
            .collect::<Result<Vec<WHV_MAP_GPA_RANGE_FLAGS>, MapMemoryError>>()?
            .iter()
            .fold(WHvMapGpaRangeFlagNone, |acc, flag| acc | *flag);

        let (process_handle, host_addr) = match &mut self.surrogate_process {
            None => (
                unsafe { GetCurrentProcess() },
                (region.host_region.start.handle_base + region.host_region.start.offset)
                    as *const c_void,
            ),
            Some(surrogate) => {
                let surrogate_base = surrogate
                    .map(
                        region.host_region.start.from_handle,
                        region.host_region.start.handle_base,
                        region.host_region.start.handle_size,
                        &region.region_type.surrogate_mapping(),
                    )
                    .map_err(|e| MapMemoryError::SurrogateProcess(e.to_string()))?;
                let surrogate_addr = surrogate_base.wrapping_add(region.host_region.start.offset);
                (
                    surrogate.process_handle.into(),
                    surrogate_addr as *const c_void,
                )
            }
        };

        let result = unsafe {
            (self.map_gpa_range2)(
                self.partition,
                process_handle,
                host_addr,
                region.guest_region.start as u64,
                region.guest_region.len() as u64,
                flags,
            )
        };
        if result.is_err() {
            return Err(MapMemoryError::Hypervisor(
                super::super::HypervisorError::WindowsError(windows_result::Error::from_hresult(
                    result,
                )),
            ));
        }

        if region.region_type == MemoryRegionType::MappedFile {
            self.file_mappings.push((
                region.host_region.start.from_handle,
                region.host_region.start.handle_base as *mut c_void,
            ));
        }

        Ok(())
    }

    fn unmap_memory(
        &mut self,
        (_slot, region): (u32, &MemoryRegion),
    ) -> Result<(), UnmapMemoryError> {
        unsafe {
            WHvUnmapGpaRange(
                self.partition,
                region.guest_region.start as u64,
                region.guest_region.len() as u64,
            )
            .map_err(|e| {
                UnmapMemoryError::Hypervisor(super::super::HypervisorError::WindowsError(e))
            })?;
        }
        if let Some(surrogate) = &mut self.surrogate_process {
            surrogate.unmap(region.host_region.start.handle_base);
        }

        if region.region_type == MemoryRegionType::MappedFile {
            let handle_base = region.host_region.start.handle_base as *mut c_void;
            if let Some(pos) = self
                .file_mappings
                .iter()
                .position(|(_, vb)| *vb == handle_base)
            {
                let (handle, view) = self.file_mappings.swap_remove(pos);
                release_file_mapping(view, handle);
            }
        }

        Ok(())
    }

    fn run_vcpu(
        &mut self,
        #[cfg(feature = "trace_guest")] _tc: &mut SandboxTraceContext,
    ) -> Result<VmExit, RunVcpuError> {
        use arm64_exit_reasons::*;
        let mut exit_context = Arm64ExitContext::default();

        unsafe {
            WHvRunVirtualProcessor(
                self.partition,
                0,
                &mut exit_context as *mut _ as *mut c_void,
                std::mem::size_of::<Arm64ExitContext>() as u32,
            )
            .map_err(|e| RunVcpuError::Unknown(e.into()))?;
        }

        match exit_context.exit_reason {
            WHV_EXIT_REASON_UNMAPPED_GPA | WHV_EXIT_REASON_GPA_INTERCEPT => {
                let header = exit_context.intercept_header();
                let gpa = exit_context.memory_access_gpa();

                // On ARM64, I/O is performed via MMIO writes to the I/O page.
                let io_page_gpa = const { hyperlight_common::layout::io_page().unwrap().0 };
                let is_write = header.intercept_access_type == 1;

                if is_write
                    && gpa >= io_page_gpa
                    && (gpa - io_page_gpa) < hyperlight_common::vmem::PAGE_SIZE as u64
                {
                    let off = (gpa - io_page_gpa) as usize;
                    let port = off / core::mem::size_of::<u64>();

                    // Advance PC past the faulting instruction.
                    // WHP ARM64 does not auto-advance PC on intercepts.
                    let next_pc = header.pc + header.instruction_length as u64;
                    self.set_registers(
                        &[WHV_ARM64_REGISTER_PC],
                        &[Align16(WHV_REGISTER_VALUE { Reg64: next_pc })],
                    )
                    .map_err(RunVcpuError::IncrementRip)?;

                    if port == VmAction::Halt as usize {
                        Ok(VmExit::Halt())
                    } else {
                        let syndrome = exit_context.memory_access_syndrome();
                        const ISV: u64 = 1 << 24;
                        const WNR: u64 = 1 << 6;
                        if syndrome & (ISV | WNR) != ISV | WNR {
                            return Ok(VmExit::MmioWrite(gpa));
                        }
                        let source_register = ((syndrome >> 16) & 0x1f) as u32;
                        let access_size = 1usize << ((syndrome >> 22) & 0x3);
                        let value = if source_register == 31 {
                            0
                        } else {
                            let values = self
                                .get_registers(&[xreg(source_register)])
                                .map_err(RunVcpuError::Unknown)?;
                            unsafe { values[0].0.Reg64 }
                        };
                        Ok(VmExit::IoOut(
                            port as u16,
                            value.to_le_bytes()[..access_size].to_vec(),
                        ))
                    }
                } else {
                    // Non-I/O page memory access
                    if is_write {
                        Ok(VmExit::MmioWrite(gpa))
                    } else {
                        Ok(VmExit::MmioRead(gpa))
                    }
                }
            }
            WHV_EXIT_REASON_CANCELLED => Ok(VmExit::Cancelled()),
            #[cfg(gdb)]
            WHV_EXIT_REASON_HYPERCALL => {
                let context = exit_context.hypercall_context();
                match classify_hypercall(&context, self.debug_enabled, &self.software_breakpoints) {
                    Arm64HypercallClassification::SoftwareBreakpoint => Ok(VmExit::Debug {
                        reason: VcpuStopReason::SwBp,
                    }),
                    Arm64HypercallClassification::Unknown { immediate, pc } => {
                        Ok(VmExit::Unknown(format!(
                            "Unsupported ARM64 hypercall immediate {immediate:#x} at PC={pc:#x}"
                        )))
                    }
                }
            }
            WHV_EXIT_REASON_ARM64_RESET => Ok(VmExit::Halt()),
            WHV_EXIT_REASON_UNRECOVERABLE => {
                let header = exit_context.intercept_header();
                Ok(VmExit::Unknown(format!(
                    "Unrecoverable exception at PC={:#x}",
                    header.pc
                )))
            }
            WHV_EXIT_REASON_INVALID_VP_REGISTER => {
                Ok(VmExit::Unknown("Invalid VP register value".to_string()))
            }
            other => Ok(VmExit::Unknown(format!(
                "Unknown WHP ARM64 exit reason: {:#x}",
                other.0 as u32
            ))),
        }
    }

    fn regs(&self) -> Result<CommonRegisters, RegisterError> {
        // Get all 31 GP regs + PC + both stack pointers + PSTATE in one batch.
        const COUNT: usize = 31 + 4;
        let mut names = [WHV_REGISTER_NAME(0); COUNT];
        for i in 0..31u32 {
            names[i as usize] = xreg(i);
        }
        names[31] = WHV_ARM64_REGISTER_PC;
        names[32] = WHV_ARM64_REGISTER_SP_EL0;
        names[33] = WHV_ARM64_REGISTER_SP_EL1;
        names[34] = WHV_ARM64_REGISTER_PSTATE;

        let values = self.get_registers(&names).map_err(RegisterError::GetRegs)?;

        let mut x = [0u64; 31];
        for i in 0..31 {
            x[i] = unsafe { values[i].0.Reg64 };
        }

        let pstate = unsafe { values[34].0.Reg64 };
        let sp = if pstate & 1 == 0 {
            unsafe { values[32].0.Reg64 }
        } else {
            unsafe { values[33].0.Reg64 }
        };

        Ok(CommonRegisters {
            x,
            pc: unsafe { values[31].0.Reg64 },
            sp,
            pstate,
        })
    }

    fn set_regs(&mut self, regs: &CommonRegisters) -> Result<(), RegisterError> {
        const COUNT: usize = 31 + 3;
        let mut names = [WHV_REGISTER_NAME(0); COUNT];
        let mut values: [Align16<WHV_REGISTER_VALUE>; COUNT] = unsafe { core::mem::zeroed() };

        for i in 0..31u32 {
            names[i as usize] = xreg(i);
            values[i as usize] = Align16(WHV_REGISTER_VALUE {
                Reg64: regs.x[i as usize],
            });
        }
        names[31] = WHV_ARM64_REGISTER_PC;
        values[31] = Align16(WHV_REGISTER_VALUE { Reg64: regs.pc });
        names[32] = if regs.pstate & 1 == 0 {
            WHV_ARM64_REGISTER_SP_EL0
        } else {
            WHV_ARM64_REGISTER_SP_EL1
        };
        values[32] = Align16(WHV_REGISTER_VALUE { Reg64: regs.sp });
        names[33] = WHV_ARM64_REGISTER_PSTATE;
        values[33] = Align16(WHV_REGISTER_VALUE { Reg64: regs.pstate });

        self.set_registers(&names, &values)
            .map_err(RegisterError::SetRegs)
    }

    fn fpu(&self) -> Result<CommonFpu, RegisterError> {
        const COUNT: usize = 34;
        let mut names = [WHV_REGISTER_NAME(0); COUNT];
        for i in 0..32u32 {
            names[i as usize] = qreg(i);
        }
        names[32] = WHV_ARM64_REGISTER_FPSR;
        names[33] = WHV_ARM64_REGISTER_FPCR;

        let values = self.get_registers(&names).map_err(RegisterError::GetFpu)?;
        let mut v = [0u128; 32];
        for i in 0..32 {
            let value = unsafe { values[i].0.Reg128 };
            v[i] = (unsafe { value.Anonymous.High64 } as u128) << 64
                | unsafe { value.Anonymous.Low64 } as u128;
        }
        let fpsr = unsafe { values[32].0.Reg64 } as u32;
        let fpcr = unsafe { values[33].0.Reg64 } as u32;

        Ok(CommonFpu { v, fpsr, fpcr })
    }

    fn set_fpu(&mut self, fpu: &CommonFpu) -> Result<(), RegisterError> {
        const COUNT: usize = 34;
        let mut names = [WHV_REGISTER_NAME(0); COUNT];
        let mut values: [Align16<WHV_REGISTER_VALUE>; COUNT] = unsafe { core::mem::zeroed() };
        for i in 0..32u32 {
            let value = fpu.v[i as usize];
            names[i as usize] = qreg(i);
            values[i as usize] = Align16(WHV_REGISTER_VALUE {
                Reg128: WHV_UINT128 {
                    Anonymous: WHV_UINT128_0 {
                        Low64: value as u64,
                        High64: (value >> 64) as u64,
                    },
                },
            });
        }
        names[32] = WHV_ARM64_REGISTER_FPSR;
        values[32] = Align16(WHV_REGISTER_VALUE {
            Reg64: fpu.fpsr as u64,
        });
        names[33] = WHV_ARM64_REGISTER_FPCR;
        values[33] = Align16(WHV_REGISTER_VALUE {
            Reg64: fpu.fpcr as u64,
        });

        self.set_registers(&names, &values)
            .map_err(RegisterError::SetFpu)
    }

    fn sregs(&self) -> Result<CommonSpecialRegisters, RegisterError> {
        let names = [
            WHV_ARM64_REGISTER_TTBR0_EL1,
            WHV_ARM64_REGISTER_TCR_EL1,
            WHV_ARM64_REGISTER_MAIR_EL1,
            WHV_ARM64_REGISTER_SCTLR_EL1,
            WHV_ARM64_REGISTER_CPACR_EL1,
            WHV_ARM64_REGISTER_VBAR_EL1,
            WHV_ARM64_REGISTER_SP_EL1,
        ];
        let values = self.get_registers(&names).map_err(RegisterError::GetRegs)?;
        Ok(CommonSpecialRegisters {
            ttbr0_el1: unsafe { values[0].0.Reg64 },
            tcr_el1: unsafe { values[1].0.Reg64 },
            mair_el1: unsafe { values[2].0.Reg64 },
            sctlr_el1: unsafe { values[3].0.Reg64 },
            cpacr_el1: unsafe { values[4].0.Reg64 },
            vbar_el1: unsafe { values[5].0.Reg64 },
            sp_el1: unsafe { values[6].0.Reg64 },
        })
    }

    fn set_sregs(&mut self, sregs: &CommonSpecialRegisters) -> Result<(), RegisterError> {
        let names = [
            WHV_ARM64_REGISTER_TTBR0_EL1,
            WHV_ARM64_REGISTER_TCR_EL1,
            WHV_ARM64_REGISTER_MAIR_EL1,
            WHV_ARM64_REGISTER_SCTLR_EL1,
            WHV_ARM64_REGISTER_CPACR_EL1,
            WHV_ARM64_REGISTER_VBAR_EL1,
            WHV_ARM64_REGISTER_SP_EL1,
        ];
        let values = [
            Align16(WHV_REGISTER_VALUE {
                Reg64: sregs.ttbr0_el1,
            }),
            Align16(WHV_REGISTER_VALUE {
                Reg64: sregs.tcr_el1,
            }),
            Align16(WHV_REGISTER_VALUE {
                Reg64: sregs.mair_el1,
            }),
            Align16(WHV_REGISTER_VALUE {
                Reg64: sregs.sctlr_el1,
            }),
            Align16(WHV_REGISTER_VALUE {
                Reg64: sregs.cpacr_el1,
            }),
            Align16(WHV_REGISTER_VALUE {
                Reg64: sregs.vbar_el1,
            }),
            Align16(WHV_REGISTER_VALUE {
                Reg64: sregs.sp_el1,
            }),
        ];
        self.set_registers(&names, &values)
            .map_err(RegisterError::SetRegs)
    }

    fn debug_regs(&self) -> Result<CommonDebugRegs, RegisterError> {
        // Debug register support on ARM64 WHP not yet implemented
        Ok(CommonDebugRegs::default())
    }

    fn set_debug_regs(&self, _drs: &CommonDebugRegs) -> Result<(), RegisterError> {
        // Debug register support on ARM64 WHP not yet implemented
        Ok(())
    }

    fn can_reset_vcpu(&self) -> bool {
        true
    }

    fn reset_vcpu(&mut self) -> Result<(), ResetVcpuError> {
        unsafe {
            let result = (self.reset_partition)(self.partition);
            if result.is_err() {
                return Err(ResetVcpuError::Hypervisor(
                    windows_result::Error::from_hresult(result).into(),
                ));
            }

            let names = [WHV_ARM64_REGISTER_GICR_BASE_GPA];
            let values = [Align16(WHV_REGISTER_VALUE {
                Reg64: WHP_GICR_BASE_GPA,
            })];
            WHvSetVirtualProcessorRegisters(
                self.partition,
                0,
                names.as_ptr(),
                1,
                values.as_ptr().cast(),
            )
            .map_err(|e| ResetVcpuError::Hypervisor(e.into()))?;
        }
        Ok(())
    }

    fn partition_handle(&self) -> WHV_PARTITION_HANDLE {
        self.partition
    }
}

impl Drop for WhpVm {
    fn drop(&mut self) {
        // Clean up file mappings
        for (handle, view) in self.file_mappings.drain(..) {
            release_file_mapping(view, handle);
        }

        unsafe {
            if let Err(e) = WHvDeleteVirtualProcessor(self.partition, 0) {
                tracing::error!("Failed to delete virtual processor: {e:?}");
            }
            if let Err(e) = WHvDeletePartition(self.partition) {
                tracing::error!("Failed to delete partition: {e:?}");
            }
        }
    }
}

#[cfg(gdb)]
impl DebuggableVm for WhpVm {
    fn translate_gva(&self, gva: u64) -> std::result::Result<u64, DebugError> {
        let mut gpa = 0;
        let mut result = WHV_TRANSLATE_GVA_RESULT::default();

        unsafe {
            WHvTranslateGva(
                self.partition,
                0,
                gva,
                WHvTranslateGvaFlagValidateRead,
                &mut result,
                &mut gpa,
            )
            .map_err(|_| DebugError::TranslateGva(gva))?;
        }
        if result.ResultCode != WHvTranslateGvaResultSuccess {
            return Err(DebugError::TranslateGva(gva));
        }

        Ok(gpa)
    }

    fn set_debug(&mut self, enable: bool) -> std::result::Result<(), DebugError> {
        self.debug_enabled = enable;
        Ok(())
    }

    fn sync_instruction_cache(&mut self) -> std::result::Result<(), DebugError> {
        self.run_debug_cache_sync()
    }

    fn register_sw_breakpoint(&mut self, addr: u64) -> std::result::Result<(), DebugError> {
        self.software_breakpoints.insert(addr);
        Ok(())
    }

    fn unregister_sw_breakpoint(&mut self, addr: u64) -> std::result::Result<(), DebugError> {
        self.software_breakpoints.remove(&addr);
        Ok(())
    }
}

#[cfg(all(test, gdb))]
mod debug_tests {
    use std::ffi::c_void;

    use serial_test::serial;
    use windows::Win32::System::Diagnostics::Debug::FlushInstructionCache;
    use windows::Win32::System::Threading::GetCurrentProcess;

    use super::*;
    use crate::hypervisor::gdb::arch::SW_BP;
    use crate::mem::shared_mem::SharedMemory;

    fn context(immediate: u16, pc: u64) -> Arm64HypercallContext {
        Arm64HypercallContext {
            immediate,
            header: Arm64InterceptMessageHeader {
                pc,
                instruction_length: 4,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn classifies_only_tracked_debugger_hypercall() {
        let breakpoints = HashSet::from([0x4000]);
        assert_eq!(
            classify_hypercall(&context(SW_BP_IMMEDIATE, 0x4000), true, &breakpoints),
            Arm64HypercallClassification::SoftwareBreakpoint
        );
        assert!(matches!(
            classify_hypercall(&context(SW_BP_IMMEDIATE, 0x4004), true, &breakpoints),
            Arm64HypercallClassification::Unknown { .. }
        ));
        assert!(matches!(
            classify_hypercall(&context(0, 0x4000), true, &breakpoints),
            Arm64HypercallClassification::Unknown { .. }
        ));
        assert!(matches!(
            classify_hypercall(&context(SW_BP_IMMEDIATE, 0x4000), false, &breakpoints),
            Arm64HypercallClassification::Unknown { .. }
        ));
    }

    #[test]
    fn parses_arm64_hypercall_context_layout() {
        let expected = context(SW_BP_IMMEDIATE, 0x1234);
        let mut exit = Arm64ExitContext::default();
        // SAFETY: `payload` is larger than `Arm64HypercallContext`. The write is
        // unaligned and does not outlive the payload.
        unsafe {
            core::ptr::write_unaligned(exit.payload.as_mut_ptr().cast(), expected);
        }
        assert_eq!(exit.hypercall_context(), expected);
    }

    #[test]
    #[serial]
    fn cache_sync_trampoline_exits_through_reserved_hypercall() {
        if !is_hypervisor_present() {
            return;
        }

        let mut vm = WhpVm::new().unwrap();
        vm.sync_instruction_cache().unwrap();
    }

    #[test]
    #[serial]
    fn patched_software_breakpoint_is_runnable_without_pc_advance() {
        if !is_hypervisor_present() {
            return;
        }

        const BREAKPOINT_OFFSET: usize = 0x20;
        let mut vm = WhpVm::new().unwrap();
        let host_memory = vm._debug_cache_sync_host_memory.as_ref().unwrap();
        host_memory
            .copy_from_slice(&SW_BP, BREAKPOINT_OFFSET)
            .unwrap();
        // SAFETY: The current process handle is valid and the range is inside
        // the live shared-memory mapping.
        unsafe {
            FlushInstructionCache(
                GetCurrentProcess(),
                Some(
                    host_memory
                        .base_ptr()
                        .wrapping_add(BREAKPOINT_OFFSET)
                        .cast::<c_void>(),
                ),
                SW_BP.len(),
            )
            .unwrap();
        }
        vm.sync_instruction_cache().unwrap();

        let breakpoint_address = DEBUG_CACHE_SYNC_GPA + BREAKPOINT_OFFSET as u64;
        vm.set_debug(true).unwrap();
        vm.register_sw_breakpoint(breakpoint_address).unwrap();
        vm.set_registers(
            &[WHV_ARM64_REGISTER_SCTLR_EL1],
            &[Align16(WHV_REGISTER_VALUE {
                Reg64: crate::hypervisor::regs::SCTLR_EL1_RES1,
            })],
        )
        .unwrap();
        vm.set_regs(&CommonRegisters {
            pc: breakpoint_address,
            pstate: 0b11 << 6 | 0b100,
            ..Default::default()
        })
        .unwrap();

        assert!(matches!(
            vm.run_vcpu().unwrap(),
            VmExit::Debug {
                reason: VcpuStopReason::SwBp
            }
        ));
        assert_eq!(vm.regs().unwrap().pc, breakpoint_address);
    }
}

// ============================================================================
// Helpers: dynamically load optional WHP APIs
// ============================================================================

unsafe fn try_load_whv_reset_partition() -> Result<WhvResetPartitionFn, windows_result::Error> {
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::core::s;

    let module = unsafe { GetModuleHandleA(s!("winhvplatform.dll")) }?;
    let proc = unsafe { GetProcAddress(module, s!("WHvResetPartition")) };
    proc.map(|function| unsafe {
        std::mem::transmute::<unsafe extern "system" fn() -> isize, WhvResetPartitionFn>(function)
    })
    .ok_or_else(|| {
        windows_result::Error::new(
            HRESULT::from_win32(127),
            "Failed to find WHvResetPartition in winhvplatform.dll",
        )
    })
}

type WhvMapGpaRange2Fn = unsafe extern "system" fn(
    WHV_PARTITION_HANDLE,
    windows::Win32::Foundation::HANDLE,
    *const c_void,
    u64,
    u64,
    WHV_MAP_GPA_RANGE_FLAGS,
) -> HRESULT;

unsafe fn try_load_whv_map_gpa_range2() -> Result<WhvMapGpaRange2Fn, windows_result::Error> {
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::core::s;

    let module = unsafe { GetModuleHandleA(s!("winhvplatform.dll")) }?;
    let proc = unsafe { GetProcAddress(module, s!("WHvMapGpaRange2")) };
    proc.map(|function| unsafe {
        std::mem::transmute::<unsafe extern "system" fn() -> isize, WhvMapGpaRange2Fn>(function)
    })
    .ok_or_else(|| {
        windows_result::Error::new(
            HRESULT::from_win32(127),
            "Failed to find WHvMapGpaRange2 in winhvplatform.dll",
        )
    })
}
