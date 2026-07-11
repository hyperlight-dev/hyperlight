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

//! Windows Hypervisor Platform (WHP) backend for AArch64.
//!
//! This module provides the [`VirtualMachine`] trait implementation using the
//! WHP APIs on Windows ARM64 systems. Because the `windows` crate does not yet
//! expose ARM64 WHP structures, we define our own FFI bindings derived from
//! the Windows SDK header `WinHvPlatformDefs.h` (10.0.26100.0).

use std::os::raw::c_void;
use std::sync::atomic::Ordering;

use hyperlight_common::outb::VmAction;
#[cfg(feature = "trace_guest")]
use tracing::Span;
#[cfg(feature = "trace_guest")]
use tracing_opentelemetry::OpenTelemetrySpanExt;
use windows::Win32::System::Hypervisor::*;
use windows_result::HRESULT;

use crate::hypervisor::regs::{
    CommonDebugRegs, CommonFpu, CommonRegisters, CommonSpecialRegisters,
};
use crate::hypervisor::surrogate_process::SurrogateProcess;
use crate::hypervisor::surrogate_process_manager::{
    get_surrogate_process_manager, surrogates_disabled,
};
use crate::hypervisor::virtual_machine::{
    CreateVmError, MapMemoryError, RegisterError, ResetVcpuError, RunVcpuError, UnmapMemoryError,
    VirtualMachine, VmExit,
};
use crate::hypervisor::wrappers::HandleWrapper;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags, MemoryRegionType};
#[cfg(feature = "trace_guest")]
use crate::sandbox::trace::TraceContext as SandboxTraceContext;

// ============================================================================
// ARM64 WHP FFI bindings
//
// These are manually translated from WinHvPlatformDefs.h (Windows SDK 10.0.26100.0)
// because the `windows` crate does not expose ARM64 WHP types.
// ============================================================================

/// ARM64 WHP register name constants.
/// Mapped from `WHV_REGISTER_NAME` enum values in the SDK header under `_ARM64_`.
mod arm64_regs {
    use windows::Win32::System::Hypervisor::WHV_REGISTER_NAME;

    // General-purpose registers X0-X28
    pub const WHV_ARM64_REGISTER_X0: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x00020000);
    // Fp = X29
    pub const WHV_ARM64_REGISTER_FP: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x0002001D);
    // Lr = X30
    pub const WHV_ARM64_REGISTER_LR: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x0002001E);
    pub const WHV_ARM64_REGISTER_PC: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x00020022);
    pub const WHV_ARM64_REGISTER_PSTATE: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x00020023);
    pub const WHV_ARM64_REGISTER_SP: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x0002001F);
    pub const WHV_ARM64_REGISTER_SP_EL0: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x00020020);
    pub const WHV_ARM64_REGISTER_SP_EL1: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x00020021);

    // Floating-point registers Q0-Q31
    pub const WHV_ARM64_REGISTER_Q0: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x00030000);

    // FP status/control
    pub const WHV_ARM64_REGISTER_FPCR: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x00040012);
    pub const WHV_ARM64_REGISTER_FPSR: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x00040013);

    // System registers
    pub const WHV_ARM64_REGISTER_SCTLR_EL1: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x00040002);
    pub const WHV_ARM64_REGISTER_CPACR_EL1: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x00040004);
    pub const WHV_ARM64_REGISTER_TTBR0_EL1: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x00040005);
    pub const WHV_ARM64_REGISTER_TTBR1_EL1: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x00040006);
    pub const WHV_ARM64_REGISTER_TCR_EL1: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x00040007);
    pub const WHV_ARM64_REGISTER_MAIR_EL1: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x0004000B);
    pub const WHV_ARM64_REGISTER_VBAR_EL1: WHV_REGISTER_NAME = WHV_REGISTER_NAME(0x0004000C);

    /// Helper: produce the `WHV_REGISTER_NAME` for general-purpose register X<i>.
    /// For i in 0..29, uses sequential numbering from X0.
    /// i == 29 maps to FP, i == 30 maps to LR.
    pub fn xreg(i: u32) -> WHV_REGISTER_NAME {
        match i {
            0..=28 => WHV_REGISTER_NAME(WHV_ARM64_REGISTER_X0.0 + i as i32),
            29 => WHV_ARM64_REGISTER_FP,
            30 => WHV_ARM64_REGISTER_LR,
            _ => panic!("Invalid ARM64 GP register index: {i}"),
        }
    }

    /// Helper: produce the `WHV_REGISTER_NAME` for SIMD register Q<i>.
    pub fn qreg(i: u32) -> WHV_REGISTER_NAME {
        debug_assert!(i < 32, "Invalid ARM64 SIMD register index: {i}");
        WHV_REGISTER_NAME(WHV_ARM64_REGISTER_Q0.0 + i as i32)
    }

    // Suppress unused warnings for registers defined for completeness
    #[allow(dead_code)]
    pub const WHV_ARM64_REGISTER_TTBR1_EL1_: WHV_REGISTER_NAME = WHV_ARM64_REGISTER_TTBR1_EL1;
    #[allow(dead_code)]
    pub const WHV_ARM64_REGISTER_SP_EL0_: WHV_REGISTER_NAME = WHV_ARM64_REGISTER_SP_EL0;
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
#[repr(C)]
#[derive(Clone, Copy)]
struct Arm64ExitContext {
    exit_reason: WHV_RUN_VP_EXIT_REASON,
    reserved: u32,
    reserved1: u64,
    /// Raw payload — union of various context types. We interpret based on exit_reason.
    payload: [u64; 32],
}

impl Default for Arm64ExitContext {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

/// Parsed fields from `WHV_INTERCEPT_MESSAGE_HEADER` (ARM64 version).
struct InterceptHeader {
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
    fn intercept_header(&self) -> InterceptHeader {
        let bytes = unsafe { core::slice::from_raw_parts(self.payload.as_ptr() as *const u8, 24) };
        InterceptHeader {
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
    let mut capability: WHV_CAPABILITY = Default::default();
    let written_size: Option<*mut u32> = None;

    match unsafe {
        WHvGetCapability(
            WHvCapabilityCodeHypervisorPresent,
            &mut capability as *mut _ as *mut c_void,
            std::mem::size_of::<WHV_CAPABILITY>() as u32,
            written_size,
        )
    } {
        Ok(_) => unsafe { capability.HypervisorPresent.as_bool() },
        Err(_) => {
            tracing::info!("Windows Hypervisor Platform is not available on this system");
            false
        }
    }
}

/// Helper: release a host-side file mapping view and its handle.
fn release_file_mapping(view_base: *mut c_void, mapping_handle: HandleWrapper) {
    unsafe {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Memory::{MEMORY_MAPPED_VIEW_ADDRESS, UnmapViewOfFile};

        if let Err(e) = UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS { Value: view_base }) {
            tracing::error!("Failed to unmap view of file: {e:?}");
        }
        if let Err(e) = CloseHandle(mapping_handle.into()) {
            tracing::error!("Failed to close file mapping handle: {e:?}");
        }
    }
}

/// A WHP-backed single-vCPU VM on ARM64.
#[derive(Debug)]
pub(crate) struct WhpVm {
    partition: WHV_PARTITION_HANDLE,
    surrogate_process: Option<SurrogateProcess>,
    /// Tracks host-side file mappings for cleanup.
    file_mappings: Vec<(HandleWrapper, *mut c_void)>,
    _no_surrogate_guard: Option<NoSurrogateGuard>,
}

// Safety: same reasoning as x86_64 WhpVm — raw pointers are kernel resource handles,
// not dereferenced, safe to transfer between threads.
unsafe impl Send for WhpVm {}

impl WhpVm {
    pub(crate) fn new() -> Result<Self, CreateVmError> {
        const NUM_CPU: u32 = 1;

        let no_surrogate = surrogates_disabled();
        let no_surrogate_guard = if no_surrogate {
            Some(NoSurrogateGuard::acquire()?)
        } else {
            None
        };

        let partition = unsafe {
            let p = WHvCreatePartition().map_err(|e| CreateVmError::CreateVmFd(e.into()))?;
            WHvSetPartitionProperty(
                p,
                WHvPartitionPropertyCodeProcessorCount,
                &NUM_CPU as *const _ as *const _,
                std::mem::size_of_val(&NUM_CPU) as _,
            )
            .map_err(|e| CreateVmError::SetPartitionProperty(e.into()))?;

            WHvSetupPartition(p).map_err(|e| CreateVmError::InitializeVm(e.into()))?;
            WHvCreateVirtualProcessor(p, 0, 0)
                .map_err(|e| CreateVmError::CreateVcpuFd(e.into()))?;

            p
        };

        let surrogate_process = if no_surrogate {
            None
        } else {
            let mgr = get_surrogate_process_manager()
                .map_err(|e| CreateVmError::SurrogateProcess(e.to_string()))?;
            Some(
                mgr.get_surrogate_process()
                    .map_err(|e| CreateVmError::SurrogateProcess(e.to_string()))?,
            )
        };

        Ok(WhpVm {
            partition,
            surrogate_process,
            file_mappings: Vec::new(),
            _no_surrogate_guard: no_surrogate_guard,
        })
    }

    /// Get a single 64-bit register value.
    fn get_reg64(&self, name: WHV_REGISTER_NAME) -> Result<u64, RegisterError> {
        let names = [name];
        let mut values: [WHV_REGISTER_VALUE; 1] = unsafe { core::mem::zeroed() };
        unsafe {
            WHvGetVirtualProcessorRegisters(
                self.partition,
                0,
                names.as_ptr(),
                1,
                values.as_mut_ptr(),
            )
            .map_err(|e| RegisterError::GetRegs(e.into()))?;
        }
        Ok(unsafe { values[0].Reg64 })
    }

    /// Set a single 64-bit register value.
    fn set_reg64(&self, name: WHV_REGISTER_NAME, value: u64) -> Result<(), RegisterError> {
        let names = [name];
        let values = [WHV_REGISTER_VALUE { Reg64: value }];
        unsafe {
            WHvSetVirtualProcessorRegisters(self.partition, 0, names.as_ptr(), 1, values.as_ptr())
                .map_err(|e| RegisterError::SetRegs(e.into()))?;
        }
        Ok(())
    }

    /// Get a single 128-bit register value (for SIMD Q registers).
    fn get_reg128(&self, name: WHV_REGISTER_NAME) -> Result<u128, RegisterError> {
        let names = [name];
        let mut values: [WHV_REGISTER_VALUE; 1] = unsafe { core::mem::zeroed() };
        unsafe {
            WHvGetVirtualProcessorRegisters(
                self.partition,
                0,
                names.as_ptr(),
                1,
                values.as_mut_ptr(),
            )
            .map_err(|e| RegisterError::GetFpu(e.into()))?;
        }
        let v = unsafe { values[0].Reg128 };
        Ok((unsafe { v.Anonymous.High64 } as u128) << 64 | unsafe { v.Anonymous.Low64 } as u128)
    }

    /// Set a single 128-bit register value (for SIMD Q registers).
    fn set_reg128(&self, name: WHV_REGISTER_NAME, value: u128) -> Result<(), RegisterError> {
        let names = [name];
        let values = [WHV_REGISTER_VALUE {
            Reg128: WHV_UINT128 {
                Anonymous: WHV_UINT128_0 {
                    Low64: value as u64,
                    High64: (value >> 64) as u64,
                },
            },
        }];
        unsafe {
            WHvSetVirtualProcessorRegisters(self.partition, 0, names.as_ptr(), 1, values.as_ptr())
                .map_err(|e| RegisterError::SetFpu(e.into()))?;
        }
        Ok(())
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

        match &mut self.surrogate_process {
            None => {
                let host_addr = (region.host_region.start.handle_base
                    + region.host_region.start.offset)
                    as *const c_void;
                let res = unsafe {
                    WHvMapGpaRange(
                        self.partition,
                        host_addr,
                        region.guest_region.start as u64,
                        region.guest_region.len() as u64,
                        flags,
                    )
                };
                if let Err(e) = res {
                    return Err(MapMemoryError::Hypervisor(
                        super::super::HypervisorError::WindowsError(e),
                    ));
                }
            }
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

                let whvmapgparange2_func = unsafe {
                    match try_load_whv_map_gpa_range2() {
                        Ok(func) => func,
                        Err(e) => {
                            return Err(MapMemoryError::LoadApi {
                                api_name: "WHvMapGpaRange2",
                                source: e,
                            });
                        }
                    }
                };

                let res = unsafe {
                    whvmapgparange2_func(
                        self.partition,
                        surrogate.process_handle.into(),
                        surrogate_addr,
                        region.guest_region.start as u64,
                        region.guest_region.len() as u64,
                        flags,
                    )
                };
                if res.is_err() {
                    return Err(MapMemoryError::Hypervisor(
                        super::super::HypervisorError::WindowsError(
                            windows_result::Error::from_hresult(res),
                        ),
                    ));
                }
            }
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
        #[cfg(feature = "trace_guest")] tc: &mut SandboxTraceContext,
    ) -> Result<VmExit, RunVcpuError> {
        use arm64_exit_reasons::*;
        use arm64_regs::*;

        let mut exit_context = Arm64ExitContext::default();

        #[cfg(feature = "trace_guest")]
        tc.setup_guest_trace(Span::current().context());

        loop {
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
                    let is_write = header.intercept_access_type != 0;

                    if is_write
                        && gpa >= io_page_gpa
                        && (gpa - io_page_gpa) < hyperlight_common::vmem::PAGE_SIZE as u64
                    {
                        let off = (gpa - io_page_gpa) as usize;
                        let port = off / core::mem::size_of::<u64>();

                        // Advance PC past the faulting instruction.
                        // WHP ARM64 does not auto-advance PC on intercepts.
                        let next_pc = header.pc + header.instruction_length as u64;
                        self.set_reg64(WHV_ARM64_REGISTER_PC, next_pc)
                            .map_err(|e| match e {
                                RegisterError::SetRegs(he) => RunVcpuError::IncrementRip(he),
                                _ => RunVcpuError::Unknown(
                                    super::super::HypervisorError::WindowsError(
                                        windows_result::Error::from_hresult(HRESULT(0)),
                                    ),
                                ),
                            })?;

                        if port == VmAction::Halt as usize {
                            return Ok(VmExit::Halt());
                        } else {
                            return Ok(VmExit::IoOut(
                                port as u16,
                                (off as u64).to_le_bytes().to_vec(),
                            ));
                        }
                    } else {
                        // Non-I/O page memory access
                        if is_write {
                            return Ok(VmExit::MmioWrite(gpa));
                        } else {
                            return Ok(VmExit::MmioRead(gpa));
                        }
                    }
                }
                WHV_EXIT_REASON_CANCELLED => {
                    return Ok(VmExit::Cancelled());
                }
                WHV_EXIT_REASON_ARM64_RESET => {
                    return Ok(VmExit::Halt());
                }
                WHV_EXIT_REASON_UNRECOVERABLE => {
                    let header = exit_context.intercept_header();
                    return Ok(VmExit::Unknown(format!(
                        "Unrecoverable exception at PC={:#x}",
                        header.pc
                    )));
                }
                WHV_EXIT_REASON_INVALID_VP_REGISTER => {
                    return Ok(VmExit::Unknown("Invalid VP register value".to_string()));
                }
                other => {
                    return Ok(VmExit::Unknown(format!(
                        "Unknown WHP ARM64 exit reason: {:#x}",
                        other.0 as u32
                    )));
                }
            }
        }
    }

    fn regs(&self) -> Result<CommonRegisters, RegisterError> {
        use arm64_regs::*;

        // Get all 31 GP regs + PC + SP + PSTATE in one batch
        const COUNT: usize = 31 + 3; // X0..X30, PC, SP, PSTATE
        let mut names = [WHV_REGISTER_NAME(0); COUNT];
        for i in 0..31u32 {
            names[i as usize] = xreg(i);
        }
        names[31] = WHV_ARM64_REGISTER_PC;
        names[32] = WHV_ARM64_REGISTER_SP;
        names[33] = WHV_ARM64_REGISTER_PSTATE;

        let mut values: [WHV_REGISTER_VALUE; COUNT] = unsafe { core::mem::zeroed() };
        unsafe {
            WHvGetVirtualProcessorRegisters(
                self.partition,
                0,
                names.as_ptr(),
                COUNT as u32,
                values.as_mut_ptr(),
            )
            .map_err(|e| RegisterError::GetRegs(e.into()))?;
        }

        let mut x = [0u64; 31];
        for i in 0..31 {
            x[i] = unsafe { values[i].Reg64 };
        }

        Ok(CommonRegisters {
            x,
            pc: unsafe { values[31].Reg64 },
            sp: unsafe { values[32].Reg64 },
            pstate: unsafe { values[33].Reg64 },
        })
    }

    fn set_regs(&self, regs: &CommonRegisters) -> Result<(), RegisterError> {
        use arm64_regs::*;

        const COUNT: usize = 31 + 3;
        let mut names = [WHV_REGISTER_NAME(0); COUNT];
        let mut values: [WHV_REGISTER_VALUE; COUNT] = unsafe { core::mem::zeroed() };

        for i in 0..31u32 {
            names[i as usize] = xreg(i);
            values[i as usize] = WHV_REGISTER_VALUE {
                Reg64: regs.x[i as usize],
            };
        }
        names[31] = WHV_ARM64_REGISTER_PC;
        values[31] = WHV_REGISTER_VALUE { Reg64: regs.pc };
        names[32] = WHV_ARM64_REGISTER_SP;
        values[32] = WHV_REGISTER_VALUE { Reg64: regs.sp };
        names[33] = WHV_ARM64_REGISTER_PSTATE;
        values[33] = WHV_REGISTER_VALUE { Reg64: regs.pstate };

        unsafe {
            WHvSetVirtualProcessorRegisters(
                self.partition,
                0,
                names.as_ptr(),
                COUNT as u32,
                values.as_ptr(),
            )
            .map_err(|e| RegisterError::SetRegs(e.into()))?;
        }
        Ok(())
    }

    fn fpu(&self) -> Result<CommonFpu, RegisterError> {
        use arm64_regs::*;

        let mut v = [0u128; 32];
        for i in 0..32u32 {
            v[i as usize] = self.get_reg128(qreg(i))?;
        }
        let fpsr = self.get_reg64(WHV_ARM64_REGISTER_FPSR).map_err(|_| {
            RegisterError::GetFpu(super::super::HypervisorError::WindowsError(
                windows_result::Error::from_hresult(HRESULT(0)),
            ))
        })? as u32;
        let fpcr = self.get_reg64(WHV_ARM64_REGISTER_FPCR).map_err(|_| {
            RegisterError::GetFpu(super::super::HypervisorError::WindowsError(
                windows_result::Error::from_hresult(HRESULT(0)),
            ))
        })? as u32;

        Ok(CommonFpu { v, fpsr, fpcr })
    }

    fn set_fpu(&self, fpu: &CommonFpu) -> Result<(), RegisterError> {
        use arm64_regs::*;

        for i in 0..32u32 {
            self.set_reg128(qreg(i), fpu.v[i as usize])?;
        }
        self.set_reg64(WHV_ARM64_REGISTER_FPSR, fpu.fpsr as u64)
            .map_err(|_| {
                RegisterError::SetFpu(super::super::HypervisorError::WindowsError(
                    windows_result::Error::from_hresult(HRESULT(0)),
                ))
            })?;
        self.set_reg64(WHV_ARM64_REGISTER_FPCR, fpu.fpcr as u64)
            .map_err(|_| {
                RegisterError::SetFpu(super::super::HypervisorError::WindowsError(
                    windows_result::Error::from_hresult(HRESULT(0)),
                ))
            })?;
        Ok(())
    }

    fn sregs(&self) -> Result<CommonSpecialRegisters, RegisterError> {
        use arm64_regs::*;

        Ok(CommonSpecialRegisters {
            ttbr0_el1: self.get_reg64(WHV_ARM64_REGISTER_TTBR0_EL1)?,
            tcr_el1: self.get_reg64(WHV_ARM64_REGISTER_TCR_EL1)?,
            mair_el1: self.get_reg64(WHV_ARM64_REGISTER_MAIR_EL1)?,
            sctlr_el1: self.get_reg64(WHV_ARM64_REGISTER_SCTLR_EL1)?,
            cpacr_el1: self.get_reg64(WHV_ARM64_REGISTER_CPACR_EL1)?,
            vbar_el1: self.get_reg64(WHV_ARM64_REGISTER_VBAR_EL1)?,
            sp_el1: self.get_reg64(WHV_ARM64_REGISTER_SP_EL1)?,
        })
    }

    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> Result<(), RegisterError> {
        use arm64_regs::*;

        self.set_reg64(WHV_ARM64_REGISTER_TTBR0_EL1, sregs.ttbr0_el1)?;
        self.set_reg64(WHV_ARM64_REGISTER_TCR_EL1, sregs.tcr_el1)?;
        self.set_reg64(WHV_ARM64_REGISTER_MAIR_EL1, sregs.mair_el1)?;
        self.set_reg64(WHV_ARM64_REGISTER_SCTLR_EL1, sregs.sctlr_el1)?;
        self.set_reg64(WHV_ARM64_REGISTER_CPACR_EL1, sregs.cpacr_el1)?;
        self.set_reg64(WHV_ARM64_REGISTER_VBAR_EL1, sregs.vbar_el1)?;
        self.set_reg64(WHV_ARM64_REGISTER_SP_EL1, sregs.sp_el1)?;
        Ok(())
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
        // Reset by zeroing all GP registers, PC, SP, PSTATE
        let regs = CommonRegisters::default();
        self.set_regs(&regs).map_err(ResetVcpuError::Register)?;
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

// ============================================================================
// Helper: dynamically load WHvMapGpaRange2
// ============================================================================

type WhvMapGpaRange2Fn = unsafe extern "system" fn(
    WHV_PARTITION_HANDLE,
    windows::Win32::Foundation::HANDLE,
    *const c_void,
    u64,
    u64,
    WHV_MAP_GPA_RANGE_FLAGS,
) -> HRESULT;

unsafe fn try_load_whv_map_gpa_range2() -> Result<WhvMapGpaRange2Fn, windows_result::Error> {
    use windows::Win32::System::LibraryLoader::*;
    use windows::core::s;

    let module = unsafe { LoadLibraryA(s!("winhvplatform.dll"))? };
    let proc = unsafe { GetProcAddress(module, s!("WHvMapGpaRange2")) };
    match proc {
        Some(f) => Ok(unsafe { std::mem::transmute(f) }),
        None => {
            unsafe {
                windows::Win32::Foundation::FreeLibrary(module).ok();
            }
            Err(windows_result::Error::from_hresult(HRESULT(-1)))
        }
    }
}
