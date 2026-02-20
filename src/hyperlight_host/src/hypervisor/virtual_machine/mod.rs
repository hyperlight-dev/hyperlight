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

use std::fmt::Debug;
use std::sync::OnceLock;

use tracing::{Span, instrument};

#[cfg(gdb)]
use crate::hypervisor::gdb::DebugError;
use crate::hypervisor::regs::{
    CommonDebugRegs, CommonFpu, CommonRegisters, CommonSpecialRegisters,
};
use crate::mem::memory_region::MemoryRegion;
#[cfg(feature = "trace_guest")]
use crate::sandbox::trace::TraceContext as SandboxTraceContext;

/// KVM (Kernel-based Virtual Machine) functionality (linux)
#[cfg(kvm)]
pub(crate) mod kvm;
/// MSHV (Microsoft Hypervisor) functionality (linux)
#[cfg(mshv3)]
pub(crate) mod mshv;
/// WHP (Windows Hypervisor Platform) functionality (windows)
#[cfg(target_os = "windows")]
pub(crate) mod whp;

static AVAILABLE_HYPERVISOR: OnceLock<Option<HypervisorType>> = OnceLock::new();

/// Returns which type of hypervisor is available, if any
pub fn get_available_hypervisor() -> &'static Option<HypervisorType> {
    AVAILABLE_HYPERVISOR.get_or_init(|| {
        cfg_if::cfg_if! {
            if #[cfg(all(kvm, mshv3))] {
                // If both features are enabled, we need to determine hypervisor at runtime.
                // Currently /dev/kvm and /dev/mshv cannot exist on the same machine, so the first one
                // that works is guaranteed to be correct.
                if mshv::is_hypervisor_present() {
                    Some(HypervisorType::Mshv)
                } else if kvm::is_hypervisor_present() {
                    Some(HypervisorType::Kvm)
                } else {
                    None
                }
            } else if #[cfg(kvm)] {
                if kvm::is_hypervisor_present() {
                    Some(HypervisorType::Kvm)
                } else {
                    None
                }
            } else if #[cfg(mshv3)] {
                if mshv::is_hypervisor_present() {
                    Some(HypervisorType::Mshv)
                } else {
                    None
                }
            } else if #[cfg(target_os = "windows")] {
                if whp::is_hypervisor_present() {
                    Some(HypervisorType::Whp)
                } else {
                    None
                }
            } else {
                None
            }
        }
    })
}

/// Returns `true` if a suitable hypervisor is available.
/// If this returns `false`, no hypervisor-backed sandboxes can be created.
#[instrument(skip_all, parent = Span::current())]
pub fn is_hypervisor_present() -> bool {
    get_available_hypervisor().is_some()
}

/// The hypervisor types available for the current platform
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub(crate) enum HypervisorType {
    #[cfg(kvm)]
    Kvm,

    #[cfg(mshv3)]
    Mshv,

    #[cfg(target_os = "windows")]
    Whp,
}

/// Architectural default value for PAT (IA32_PAT, MSR 0x277).
/// Each byte encodes a memory type for one of the 8 PAT entries:
/// PA0=WB(6), PA1=WT(4), PA2=UC-(7), PA3=UC(0),
/// PA4=WB(6), PA5=WT(4), PA6=UC-(7), PA7=UC(0).
pub(crate) const PAT_RESET_VALUE: u64 = 0x0007_0406_0007_0406;

/// MSRs that the Microsoft hypervisor virtualizes internally and handles
/// without generating a VM exit — even when MSR intercepts are enabled via
/// `HV_INTERCEPT_TYPE_X64_MSR` (MSHV) or `WHvExtendedVmExitX64MsrExit` (WHP).
///
/// Both [`MSRS_TO_RESET`] and the MSR intercept tests are derived from this
/// list. Any new virtualized MSR must be added here.
///
/// Some MSRs in this list do NOT appear in [`MSRS_TO_RESET`] because they are
/// either read-only or already reset by other means (e.g. `set_sregs()`).
///
/// Each entry is `(msr_index, reset_value, needs_explicit_reset)`:
/// - `msr_index`: The architectural MSR index (same value used in RDMSR/WRMSR).
/// - `reset_value`: The value to write on reset (only meaningful when
///   `needs_explicit_reset` is true).
/// - `needs_explicit_reset`: `false` for MSRs that are read-only or already
///   restored via `set_sregs()` / `set_regs()`.
#[rustfmt::skip]
pub(crate) const VIRTUALIZED_MSRS: &[(u32, u64, bool)] = &[
    // ── Already handled by set_sregs() or read-only ─────────────────
    (0x1B,          0,               false), // APIC_BASE (set_sregs)
    (0xFE,          0,               false), // MTRR_CAP (read-only)
    (0xC000_0080,   0,               false), // EFER (set_sregs)
    (0xC000_0100,   0,               false), // FS_BASE (set_sregs)
    (0xC000_0101,   0,               false), // GS_BASE (set_sregs)

    // ── Must be explicitly reset ────────────────────────────────────
    // TSC: a guest WRMSR 0x10 adjusts the hypervisor's TSC offset, which
    // persists across sandbox executions. Reset to 0 to clear it.
    (0x10,          0,               true),  // TSC
    // SYSCALL MSRs
    (0xC000_0081,   0,               true),  // STAR
    (0xC000_0082,   0,               true),  // LSTAR
    (0xC000_0083,   0,               true),  // CSTAR
    (0xC000_0084,   0,               true),  // SFMASK
    // Kernel GS base (SWAPGS)
    (0xC000_0102,   0,               true),  // KERNEL_GS_BASE
    // SYSENTER MSRs
    (0x174,         0,               true),  // SYSENTER_CS
    (0x175,         0,               true),  // SYSENTER_ESP
    (0x176,         0,               true),  // SYSENTER_EIP
    // Misc MSRs
    (0xC000_0103,   0,               true),  // TSC_AUX
    (0x277,         PAT_RESET_VALUE, true),  // PAT
    (0x1D9,         0,               true),  // DEBUG_CTL
    // MTRR default type
    (0x2FF,         0,               true),  // MTRR_DEF_TYPE
    // Variable-range MTRRs (8 base + 8 mask)
    (0x200, 0, true), (0x201, 0, true),      // MTRRphysBase0 / MTRRphysMask0
    (0x202, 0, true), (0x203, 0, true),      // MTRRphysBase1 / MTRRphysMask1
    (0x204, 0, true), (0x205, 0, true),      // MTRRphysBase2 / MTRRphysMask2
    (0x206, 0, true), (0x207, 0, true),      // MTRRphysBase3 / MTRRphysMask3
    (0x208, 0, true), (0x209, 0, true),      // MTRRphysBase4 / MTRRphysMask4
    (0x20A, 0, true), (0x20B, 0, true),      // MTRRphysBase5 / MTRRphysMask5
    (0x20C, 0, true), (0x20D, 0, true),      // MTRRphysBase6 / MTRRphysMask6
    (0x20E, 0, true), (0x20F, 0, true),      // MTRRphysBase7 / MTRRphysMask7
    // Fixed-range MTRRs
    (0x250, 0, true),                        // MTRRfix64K_00000
    (0x258, 0, true),                        // MTRRfix16K_80000
    (0x259, 0, true),                        // MTRRfix16K_A0000
    (0x268, 0, true),                        // MTRRfix4K_C0000
    (0x269, 0, true),                        // MTRRfix4K_C8000
    (0x26A, 0, true),                        // MTRRfix4K_D0000
    (0x26B, 0, true),                        // MTRRfix4K_D8000
    (0x26C, 0, true),                        // MTRRfix4K_E0000
    (0x26D, 0, true),                        // MTRRfix4K_E8000
    (0x26E, 0, true),                        // MTRRfix4K_F0000
    (0x26F, 0, true),                        // MTRRfix4K_F8000

    // ── MSHV/WHP additional virtualizations ─────────────────────────
    // These MSRs are handled internally by the Microsoft Hypervisor
    // without generating VM exits, even when MSR intercepts are enabled.
    // On KVM, the deny-all MSR filter traps them instead.

    // Read-only MSRs (no reset needed)
    (0x17,          0,               false), // IA32_PLATFORM_ID (read-only)
    (0x8B,          0,               false), // IA32_BIOS_SIGN_ID (read-only)
    (0x10A,         0,               false), // IA32_ARCH_CAPABILITIES (read-only)
    (0x179,         0,               false), // IA32_MCG_CAP (read-only)
    (0x17A,         0,               false), // IA32_MCG_STATUS (read-only in guest)
    (0x4D0,         0,               false), // Platform-specific (read-only in guest)

    // Speculative execution control
    (0x48,          0,               true),  // IA32_SPEC_CTRL

    // CET (Control-flow Enforcement Technology) MSRs
    (0x6A0,         0,               true),  // IA32_U_CET
    (0x6A2,         0,               true),  // IA32_S_CET
    (0x6A4,         0,               true),  // IA32_PL0_SSP
    (0x6A5,         0,               true),  // IA32_PL1_SSP
    (0x6A6,         0,               true),  // IA32_PL2_SSP
    (0x6A7,         0,               true),  // IA32_PL3_SSP
    (0x6A8,         0,               true),  // IA32_INTERRUPT_SSP_TABLE_ADDR

    // Extended supervisor state
    (0xDA0,         0,               true),  // IA32_XSS

    // AMD-specific MSRs (read-only in guest context under MSHV)
    (0xC001_0010,   0,               false), // AMD SYSCFG
    (0xC001_0114,   0,               false), // AMD VM_CR
    (0xC001_0131,   0,               false), // AMD (platform-specific)
];

/// Returns `true` if the given MSR index is in [`VIRTUALIZED_MSRS`].
///
/// Used by tests to distinguish MSRs that are handled internally by the
/// hypervisor (and therefore won't generate VM exits) from those that
/// should be intercepted.
#[cfg(test)]
pub(crate) fn is_virtualized_msr(index: u32) -> bool {
    VIRTUALIZED_MSRS.iter().any(|&(msr, _, _)| msr == index)
}

/// Number of entries in [`MSRS_TO_RESET`], available at compile time so
/// backends can size const arrays.
pub(crate) const MSRS_TO_RESET_COUNT: usize = {
    let mut n = 0;
    let mut i = 0;
    while i < VIRTUALIZED_MSRS.len() {
        if VIRTUALIZED_MSRS[i].2 {
            n += 1;
        }
        i += 1;
    }
    n
};

/// The subset of [`VIRTUALIZED_MSRS`] where `needs_explicit_reset` is `true`.
///
/// These are guest-writable MSRs that are not restored by `set_sregs()` or
/// any other register-restore path and must be explicitly written back to
/// their default values during `reset_msrs()`.
pub(crate) const MSRS_TO_RESET: &[(u32, u64)] = &{
    let mut result = [(0u32, 0u64); MSRS_TO_RESET_COUNT];
    let mut j = 0;
    let mut i = 0;
    while i < VIRTUALIZED_MSRS.len() {
        if VIRTUALIZED_MSRS[i].2 {
            result[j] = (VIRTUALIZED_MSRS[i].0, VIRTUALIZED_MSRS[i].1);
            j += 1;
        }
        i += 1;
    }
    result
};

/// Minimum XSAVE buffer size: 512 bytes legacy region + 64 bytes header.
/// Only used by MSHV and WHP which use compacted XSAVE format and need to
/// validate buffer size before accessing XCOMP_BV.
#[cfg(any(mshv3, target_os = "windows"))]
pub(crate) const XSAVE_MIN_SIZE: usize = 576;

/// MSR index ranges covering all x86-64 MSR address spaces that the hardware
/// MSR bitmap can intercept.
///
/// Used by tests to verify that every MSR is either intercepted or listed
/// in [`VIRTUALIZED_MSRS`]. Each entry is `(start_inclusive, end_exclusive)`.
///
/// These ranges correspond exactly to the four MSR bitmap regions defined in
/// the hypervisor's `valx64.h` (`VAL_MSR_BITMAP_*_ADDRESS`), which in turn
/// match the hardware capabilities:
///
/// - **Intel VMX** supports two bitmap regions: low (`0x0..0x1FFF`) and
///   high (`0xC000_0000..0xC000_1FFF`).
///   See Intel SDM Vol. 3C §25.6.9 "MSR-Bitmap Address".
///
/// - **AMD SVM** supports three bitmap regions: low, high, and "very high"
///   (`0xC001_0000..0xC001_1FFF`).
///   See AMD APM Vol. 2 §15.11 "MSR Intercepts".
///
/// - **Microsoft Hypervisor** adds a fourth synthetic region
///   (`0x4000_0000..0x4000_1FFF`) for Hyper-V MSRs including nested
///   virtualization SINTs up to `~0x4000_109F`.
///   See TLFS §3 <https://learn.microsoft.com/en-us/virtualization/hyper-v/tlfs/>
///
/// Any MSR index outside these four regions cannot be intercepted via the
/// bitmap and will unconditionally #GP, so we don't need to test them.
///
/// Additional reference for the specific MSR indices defined within each
/// range:
/// - **Linux kernel** `arch/x86/include/asm/msr-index.h`
///   <https://github.com/torvalds/linux/blob/master/arch/x86/include/asm/msr-index.h>
/// - **Intel SDM Vol. 4** "Model-Specific Registers"
/// - **AMD APM Vol. 2** Appendix A "MSR Cross-Reference"
#[cfg(test)]
pub(crate) const MSR_TEST_RANGES: &[(u32, u32)] = &[
    // Low bitmap: Intel architectural + model-specific (IA32_*)
    // Includes: TSC, APIC_BASE, SYSENTER, MTRRs, PAT, DEBUGCTL, PMU,
    // x2APIC (0x800–0x8FF), Intel RDT (0xC80–0xCFF), BNDCFGS (0xD90),
    // XSS (0xDA0), LBR_INFO (0xDC0–0xDDF), Arch LBR (0x1500–0x1600),
    // PMC V6 (0x1900–0x1983), HW Feedback (0x17D0).
    // valx64.h: VAL_MSR_BITMAP_LOW 0x0000_0000..=0x0000_1FFF
    (0x0000_0000, 0x0000_2000),
    // Synthetic bitmap: Microsoft Hypervisor MSRs (HV_X64_MSR_*)
    // Includes: GUEST_OS_ID (0x40000000), HYPERCALL, VP_INDEX, timers,
    // SynIC (SCONTROL/SIEFP/SIMP/EOM/SINT0–15), crash MSRs (0x40000100–0x40000105),
    // nested SINTs (0x40001080–0x4000109F), TSC_INVARIANT_CONTROL (0x40000118).
    // valx64.h: VAL_MSR_BITMAP_SYNTHETIC 0x4000_0000..=0x4000_1FFF
    (0x4000_0000, 0x4000_2000),
    // High bitmap: AMD64 MSRs
    // Includes: EFER, STAR, LSTAR, CSTAR, SFMASK, FS/GS/KERNEL_GS_BASE,
    // TSC_AUX, perf global status (0xC000_0300+), MBA (0xC000_0200+).
    // valx64.h: VAL_MSR_BITMAP_HIGH 0xC000_0000..=0xC000_1FFF
    (0xC000_0000, 0xC000_2000),
    // Very-high bitmap: AMD K7/K8/Fam10h–19h MSRs
    // Includes: HWCR, SYSCFG, SVM, IBS, CPPC, SEV/SNP, perfctr, UMC.
    // valx64.h: VAL_MSR_BITMAP_VERY_HIGH 0xC001_0000..=0xC001_1FFF
    (0xC001_0000, 0xC001_2000),
];

/// Standard XSAVE buffer size (4KB) used by KVM and MSHV.
/// WHP queries the required size dynamically.
#[cfg(all(any(kvm, mshv3), test, feature = "init-paging"))]
pub(crate) const XSAVE_BUFFER_SIZE: usize = 4096;

// Compiler error if no hypervisor type is available
#[cfg(not(any(kvm, mshv3, target_os = "windows")))]
compile_error!(
    "No hypervisor type is available for the current platform. Please enable either the `kvm` or `mshv3` cargo feature."
);

/// The various reasons a VM's vCPU can exit
pub(crate) enum VmExit {
    /// The vCPU has exited due to a debug event (usually breakpoint)
    #[cfg(gdb)]
    Debug { dr6: u64, exception: u32 },
    /// The vCPU has halted
    Halt(),
    /// The vCPU has issued a write to the given port with the given value
    IoOut(u16, Vec<u8>),
    /// The vCPU tried to read from the given (unmapped) addr
    MmioRead(u64),
    /// The vCPU tried to write to the given (unmapped) addr
    MmioWrite(u64),
    /// The vCPU tried to read from the given MSR
    MsrRead(u32),
    /// The vCPU tried to write to the given MSR with the given value
    MsrWrite { msr_index: u32, value: u64 },
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
}

/// VM error
#[derive(Debug, Clone, thiserror::Error)]
pub enum VmError {
    #[error("Failed to create vm: {0}")]
    CreateVm(#[from] CreateVmError),
    #[cfg(gdb)]
    #[error("Debug operation failed: {0}")]
    Debug(#[from] DebugError),
    #[error("Map memory operation failed: {0}")]
    MapMemory(#[from] MapMemoryError),
    #[error("Register operation failed: {0}")]
    Register(#[from] RegisterError),
    #[error("Failed to run vcpu: {0}")]
    RunVcpu(#[from] RunVcpuError),
    #[error("Unmap memory operation failed: {0}")]
    UnmapMemory(#[from] UnmapMemoryError),
}

/// Create VM error
#[derive(Debug, Clone, thiserror::Error)]
pub enum CreateVmError {
    #[error("VCPU creation failed: {0}")]
    CreateVcpuFd(HypervisorError),
    #[error("VM creation failed: {0}")]
    CreateVmFd(HypervisorError),
    #[error("Failed to enable MSR intercept: {0}")]
    EnableMsrIntercept(HypervisorError),
    #[error("Hypervisor is not available: {0}")]
    HypervisorNotAvailable(HypervisorError),
    #[error("Initialize VM failed: {0}")]
    InitializeVm(HypervisorError),
    #[error("Set Partition Property failed: {0}")]
    SetPartitionProperty(HypervisorError),
    #[cfg(target_os = "windows")]
    #[error("Surrogate process creation failed: {0}")]
    SurrogateProcess(String),
}

/// RunVCPU error
#[derive(Debug, Clone, thiserror::Error)]
pub enum RunVcpuError {
    #[error("Failed to decode IO message type: {0}")]
    DecodeIOMessage(u32),
    #[error("Failed to decode MSR message type: {0}")]
    DecodeMsrMessage(u32),
    #[cfg(gdb)]
    #[error("Failed to get DR6 debug register: {0}")]
    GetDr6(HypervisorError),
    #[error("Increment RIP failed: {0}")]
    IncrementRip(HypervisorError),
    #[error("Parse GPA access info failed")]
    ParseGpaAccessInfo,
    #[error("Unknown error: {0}")]
    Unknown(HypervisorError),
}

/// Register error
#[derive(Debug, Clone, thiserror::Error)]
pub enum RegisterError {
    #[error("Failed to get registers: {0}")]
    GetRegs(HypervisorError),
    #[error("Failed to set registers: {0}")]
    SetRegs(HypervisorError),
    #[error("Failed to get FPU registers: {0}")]
    GetFpu(HypervisorError),
    #[error("Failed to set FPU registers: {0}")]
    SetFpu(HypervisorError),
    #[error("Failed to get special registers: {0}")]
    GetSregs(HypervisorError),
    #[error("Failed to set special registers: {0}")]
    SetSregs(HypervisorError),
    #[error("Failed to get debug registers: {0}")]
    GetDebugRegs(HypervisorError),
    #[error("Failed to set debug registers: {0}")]
    SetDebugRegs(HypervisorError),
    #[error("Failed to get xsave: {0}")]
    GetXsave(HypervisorError),
    #[error("Failed to set xsave: {0}")]
    SetXsave(HypervisorError),
    #[error("Xsave size mismatch: expected {expected} bytes, got {actual}")]
    XsaveSizeMismatch {
        /// Expected size in bytes
        expected: u32,
        /// Actual size in bytes
        actual: u32,
    },
    #[error("Invalid xsave alignment")]
    InvalidXsaveAlignment,
    #[error("Failed to reset MSR 0x{index:X}: {source}")]
    ResetMsr { index: u32, source: HypervisorError },
    #[error("Unknown MSR 0x{0:X}: no hypervisor register mapping")]
    UnknownMsr(u32),
    #[cfg(target_os = "windows")]
    #[error("Failed to get xsave size: {0}")]
    GetXsaveSize(#[from] HypervisorError),
    #[cfg(target_os = "windows")]
    #[error("Failed to convert WHP registers: {0}")]
    ConversionFailed(String),
}

/// Map memory error
#[derive(Debug, Clone, thiserror::Error)]
pub enum MapMemoryError {
    #[cfg(target_os = "windows")]
    #[error("Address conversion failed: {0}")]
    AddressConversion(std::num::TryFromIntError),
    #[error("Hypervisor error: {0}")]
    Hypervisor(HypervisorError),
    #[cfg(target_os = "windows")]
    #[error("Invalid memory region flags: {0}")]
    InvalidFlags(String),
    #[cfg(target_os = "windows")]
    #[error("Failed to load API '{api_name}': {source}")]
    LoadApi {
        api_name: &'static str,
        source: windows_result::Error,
    },
    #[cfg(target_os = "windows")]
    #[error("Operation not supported: {0}")]
    NotSupported(String),
    #[cfg(target_os = "windows")]
    #[error("Surrogate process creation failed: {0}")]
    SurrogateProcess(String),
}

/// Unmap memory error
#[derive(Debug, Clone, thiserror::Error)]
pub enum UnmapMemoryError {
    #[error("Hypervisor error: {0}")]
    Hypervisor(HypervisorError),
}

/// Implementation-specific Hypervisor error
#[derive(Debug, Clone, thiserror::Error)]
pub enum HypervisorError {
    #[cfg(kvm)]
    #[error("KVM error: {0}")]
    KvmError(#[from] kvm_ioctls::Error),
    #[cfg(mshv3)]
    #[error("MSHV error: {0}")]
    MshvError(#[from] mshv_ioctls::MshvError),
    #[cfg(target_os = "windows")]
    #[error("Windows error: {0}")]
    WindowsError(#[from] windows_result::Error),
}

/// Trait for single-vCPU VMs. Provides a common interface for basic VM operations.
/// Abstracts over differences between KVM, MSHV and WHP implementations.
pub(crate) trait VirtualMachine: Debug + Send {
    /// Map memory region into this VM
    ///
    /// # Safety
    /// The caller must ensure that the memory region is valid and points to valid memory,
    /// and lives long enough for the VM to use it.
    /// The caller must ensure that the given u32 is not already mapped, otherwise previously mapped
    /// memory regions may be overwritten.
    /// The memory region must not overlap with an existing region, and depending on platform, must be aligned to page boundaries.
    unsafe fn map_memory(
        &mut self,
        region: (u32, &MemoryRegion),
    ) -> std::result::Result<(), MapMemoryError>;

    /// Unmap memory region from this VM that has previously been mapped using `map_memory`.
    fn unmap_memory(
        &mut self,
        region: (u32, &MemoryRegion),
    ) -> std::result::Result<(), UnmapMemoryError>;

    /// Runs the vCPU until it exits.
    /// Note: this function emits traces spans for guests
    /// and the span setup is called right before the run virtual processor call of each hypervisor
    fn run_vcpu(
        &mut self,
        #[cfg(feature = "trace_guest")] tc: &mut SandboxTraceContext,
    ) -> std::result::Result<VmExit, RunVcpuError>;

    /// Get regs
    #[allow(dead_code)]
    fn regs(&self) -> std::result::Result<CommonRegisters, RegisterError>;
    /// Set regs
    fn set_regs(&self, regs: &CommonRegisters) -> std::result::Result<(), RegisterError>;
    /// Get fpu regs
    #[allow(dead_code)]
    fn fpu(&self) -> std::result::Result<CommonFpu, RegisterError>;
    /// Set fpu regs
    fn set_fpu(&self, fpu: &CommonFpu) -> std::result::Result<(), RegisterError>;
    /// Get special regs
    #[allow(dead_code)]
    fn sregs(&self) -> std::result::Result<CommonSpecialRegisters, RegisterError>;
    /// Set special regs
    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> std::result::Result<(), RegisterError>;
    /// Get the debug registers of the vCPU
    #[allow(dead_code)]
    fn debug_regs(&self) -> std::result::Result<CommonDebugRegs, RegisterError>;
    /// Set the debug registers of the vCPU
    fn set_debug_regs(&self, drs: &CommonDebugRegs) -> std::result::Result<(), RegisterError>;

    /// Get xsave
    #[allow(dead_code)]
    fn xsave(&self) -> std::result::Result<Vec<u8>, RegisterError>;
    /// Reset xsave to default state
    fn reset_xsave(&self) -> std::result::Result<(), RegisterError>;
    /// Set xsave - only used for tests
    #[cfg(test)]
    #[cfg(feature = "init-paging")]
    fn set_xsave(&self, xsave: &[u32]) -> std::result::Result<(), RegisterError>;

    /// Reset internally-virtualized MSRs to their architectural defaults.
    ///
    /// The Microsoft hypervisor (MSHV/WHP) handles certain MSRs internally
    /// without generating VM exits, even when MSR intercepts are enabled.
    /// These must be explicitly written back on snapshot restore to prevent
    /// state from one guest execution leaking into the next.
    ///
    /// On KVM this is a no-op because the MSR filter denies all guest MSR
    /// access at the hardware level.
    fn reset_msrs(&self) -> std::result::Result<(), RegisterError>;

    /// Enable MSR intercepts for this VM. When enabled, all MSR reads and
    /// writes by the guest will cause a VM exit instead of being executed.
    fn enable_msr_intercept(&mut self) -> std::result::Result<(), CreateVmError>;

    /// Get partition handle
    #[cfg(target_os = "windows")]
    fn partition_handle(&self) -> windows::Win32::System::Hypervisor::WHV_PARTITION_HANDLE;
}

#[cfg(test)]
mod tests {

    #[test]
    // TODO: add support for testing on WHP
    #[cfg(target_os = "linux")]
    fn is_hypervisor_present() {
        use std::path::Path;

        cfg_if::cfg_if! {
            if #[cfg(all(kvm, mshv3))] {
                assert_eq!(Path::new("/dev/kvm").exists() || Path::new("/dev/mshv").exists(), super::is_hypervisor_present());
            } else if #[cfg(kvm)] {
                assert_eq!(Path::new("/dev/kvm").exists(), super::is_hypervisor_present());
            } else if #[cfg(mshv3)] {
                assert_eq!(Path::new("/dev/mshv").exists(), super::is_hypervisor_present());
            } else {
                assert!(!super::is_hypervisor_present());
            }
        }
    }
}
