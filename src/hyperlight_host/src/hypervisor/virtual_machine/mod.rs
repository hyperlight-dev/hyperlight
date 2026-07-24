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
#[cfg(all(target_arch = "x86_64", any(mshv3, target_os = "windows")))]
use crate::hypervisor::regs::{
    MSR_MTRR_CAP, filterless_core_reset_candidates, hyperv_mtrr_reset_indices,
};
#[cfg(target_arch = "x86_64")]
use crate::hypervisor::regs::{MsrEntry, is_resettable_msr};
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

/// Shared x86-64 helpers for hardware interrupt support (MSHV and WHP)
#[cfg(feature = "hw-interrupts")]
pub(crate) mod x86_64;

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

/// Minimum XSAVE buffer size: 512 bytes legacy region + 64 bytes header.
/// Only used by MSHV and WHP which use compacted XSAVE format and need to
/// validate buffer size before accessing XCOMP_BV.
#[cfg(all(target_arch = "x86_64", any(mshv3, target_os = "windows")))]
pub(crate) const XSAVE_MIN_SIZE: usize = 576;

/// Standard XSAVE buffer size (4KB) used by KVM and MSHV.
/// WHP queries the required size dynamically.
#[cfg(all(any(kvm, mshv3), test, not(target_arch = "aarch64")))]
pub(crate) const XSAVE_BUFFER_SIZE: usize = 4096;

// Compiler error if no hypervisor type is available (not applicable on aarch64 yet)
#[cfg(not(any(kvm, mshv3, target_os = "windows", target_arch = "aarch64")))]
compile_error!(
    "No hypervisor type is available for the current platform. Please enable either the `kvm` or `mshv3` cargo feature."
);

/// The various reasons a VM's vCPU can exit
pub(crate) enum VmExit {
    /// The vCPU has exited due to a debug event (usually breakpoint)
    #[cfg(gdb)]
    Debug {
        #[cfg(target_arch = "x86_64")]
        dr6: u64,
        #[cfg(target_arch = "x86_64")]
        exception: u32,
    },
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
        any(target_os = "windows", feature = "hw-interrupts"),
        expect(
            dead_code,
            reason = "Retry() is never constructed on Windows or with hw-interrupts (EAGAIN causes continue instead)"
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
    #[error("Hypervisor is not available: {0}")]
    HypervisorNotAvailable(HypervisorError),
    #[error("Initialize VM failed: {0}")]
    InitializeVm(HypervisorError),
    #[cfg(all(kvm, target_arch = "x86_64"))]
    #[error("KVM MSR filtering requires KVM_CAP_X86_MSR_FILTER")]
    MsrFilterNotSupported,
    #[cfg(target_arch = "x86_64")]
    #[error("MSR {msr:#x} cannot be declared as a guest MSR: {reason}")]
    MsrNotDeclarable { msr: u32, reason: String },
    #[cfg(target_arch = "x86_64")]
    #[error("Failed to read IA32_MTRRCAP: {0}")]
    GetMtrrCap(RegisterError),
    #[cfg(target_arch = "x86_64")]
    #[error("Guest-visible MTRRs cannot be reset: {0}")]
    RequiredMtrrsNotResettable(RegisterError),
    #[cfg(target_arch = "x86_64")]
    #[error("Guest exposes {advertised} variable MTRR pairs, expected at most {maximum}")]
    UnexpectedVariableMtrrCount { advertised: u8, maximum: u8 },
    #[cfg(all(kvm, target_arch = "x86_64"))]
    #[error("Too many guest MSR filter ranges: {0}. Maximum is 16")]
    TooManyMsrRanges(usize),
    #[cfg(target_os = "windows")]
    #[error("Get Partition Property failed: {0}")]
    GetPartitionProperty(HypervisorError),
    #[cfg(target_os = "windows")]
    #[error("WHP exposes {advertised} processor feature banks, expected {expected}")]
    UnexpectedProcessorFeatureBankCount { advertised: u32, expected: u32 },
    #[error("Set Partition Property failed: {0}")]
    SetPartitionProperty(HypervisorError),
    #[cfg(target_os = "windows")]
    #[error("Surrogate process creation failed: {0}")]
    SurrogateProcess(String),
}

/// RunVCPU error
#[derive(Debug, Clone, thiserror::Error)]
pub enum RunVcpuError {
    #[error("Failed to decode message type: {0}")]
    DecodeIOMessage(u32),
    #[cfg(gdb)]
    #[error("Failed to get DR6 debug register: {0}")]
    GetDr6(HypervisorError),
    #[error("Increment RIP failed: {0}")]
    IncrementRip(HypervisorError),
    #[error("Parse GPA access info failed")]
    ParseGpaAccessInfo,
    #[cfg(target_arch = "aarch64")]
    #[error("Flush MMIO pending state failed: {0}")]
    FlushMmioPending(String),
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
    #[cfg(target_arch = "x86_64")]
    #[error("Snapshot APIC_BASE {value:#x} enables unsupported x2APIC mode")]
    InvalidSnapshotApicBase {
        /// APIC_BASE value supplied by the snapshot.
        value: u64,
    },
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
    #[cfg(target_arch = "x86_64")]
    #[error("MSR operation not supported on this hypervisor")]
    MsrsUnsupported,
    #[cfg(target_arch = "x86_64")]
    #[error("Failed to build MSR list: {0}")]
    MsrBuild(String),
    #[cfg(target_arch = "x86_64")]
    #[error("Failed to get MSRs: {0}")]
    GetMsrs(HypervisorError),
    #[cfg(target_arch = "x86_64")]
    #[error("Failed to set MSRs: {0}")]
    SetMsrs(HypervisorError),
    #[cfg(target_arch = "x86_64")]
    #[error("Snapshot MSR index {index:#x} is not in this VM's reset set")]
    InvalidSnapshotMsrIndex {
        /// Architectural MSR index supplied by the snapshot.
        index: u32,
    },
    #[cfg(all(kvm, target_arch = "x86_64"))]
    #[error("MSR batch short count: expected {expected}, applied {actual}")]
    MsrShortCount {
        /// Number of MSRs requested
        expected: usize,
        /// Number of MSRs actually applied before KVM stopped
        actual: usize,
    },
    #[cfg(target_os = "windows")]
    #[error("Failed to get xsave size: {0}")]
    GetXsaveSize(#[from] HypervisorError),
    #[cfg(target_os = "windows")]
    #[error("Failed to convert WHP registers: {0}")]
    ConversionFailed(String),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ResetVcpuError {
    #[error("Single-operation vcpu reset not supported on this hypervisor")]
    NotSupported,
    #[error("Hypervisor operation failed: {0}")]
    Hypervisor(HypervisorError),
    #[error("Register operation failed: {0}")]
    Register(#[from] RegisterError),
    #[error("Operation failed: {0}")]
    Unknown(String),
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
    #[allow(dead_code)]
    fn set_debug_regs(&self, drs: &CommonDebugRegs) -> std::result::Result<(), RegisterError>;

    /// Reads the requested MSRs.
    #[cfg(target_arch = "x86_64")]
    fn msrs(&self, indices: &[u32]) -> std::result::Result<Vec<MsrEntry>, RegisterError>;
    /// Writes the supplied MSRs.
    #[cfg(target_arch = "x86_64")]
    fn set_msrs(&self, msrs: &[MsrEntry]) -> std::result::Result<(), RegisterError>;
    /// Returns the MSRs whose state this backend must reset.
    #[cfg(target_arch = "x86_64")]
    fn msr_reset_indices(&self, guest_msrs: &[u32])
    -> std::result::Result<Vec<u32>, CreateVmError>;

    /// Get xsave
    #[allow(dead_code)]
    #[cfg(not(target_arch = "aarch64"))]
    fn xsave(&self) -> std::result::Result<Vec<u8>, RegisterError>;
    /// Reset xsave to default state
    #[cfg(not(target_arch = "aarch64"))]
    fn reset_xsave(&self) -> std::result::Result<(), RegisterError>;
    /// Set xsave - only used for tests
    #[cfg(test)]
    #[cfg(not(target_arch = "aarch64"))]
    fn set_xsave(&self, xsave: &[u32]) -> std::result::Result<(), RegisterError>;

    /// Single-operation vCPU reset
    #[cfg(target_arch = "aarch64")]
    fn can_reset_vcpu(&self) -> bool {
        false
    }
    #[cfg(target_arch = "aarch64")]
    fn reset_vcpu(&mut self) -> std::result::Result<(), ResetVcpuError> {
        Err(ResetVcpuError::NotSupported)
    }
    /// Get partition handle
    #[cfg(target_os = "windows")]
    fn partition_handle(&self) -> windows::Win32::System::Hypervisor::WHV_PARTITION_HANDLE;
}

/// Validates that each declared guest MSR is restorable: reset replays a
/// captured value, so the host must read and write it.
/// Rejects e.g. a variable MTRR above the host VCNT.
#[cfg(target_arch = "x86_64")]
pub(crate) fn validate_guest_msrs(
    vm: &dyn VirtualMachine,
    guest_msrs: &[u32],
) -> std::result::Result<(), CreateVmError> {
    for &msr in guest_msrs {
        if !is_resettable_msr(msr) {
            return Err(CreateVmError::MsrNotDeclarable {
                msr,
                reason: "MSR is not a resettable MSR".to_string(),
            });
        }
        let captured = vm
            .msrs(&[msr])
            .map_err(|_| CreateVmError::MsrNotDeclarable {
                msr,
                reason: "MSR cannot be read on this host".to_string(),
            })?;
        vm.set_msrs(&captured)
            .map_err(|_| CreateVmError::MsrNotDeclarable {
                msr,
                reason: "MSR cannot be written on this host".to_string(),
            })?;
    }
    Ok(())
}

/// Returns every guest-visible MTRR a filterless (MSHV/WHP) host must reset.
#[cfg(all(target_arch = "x86_64", any(mshv3, target_os = "windows")))]
pub(crate) fn mtrr_reset_indices(
    vm: &dyn VirtualMachine,
) -> std::result::Result<Vec<u32>, CreateVmError> {
    let mtrr_cap = vm
        .msrs(&[MSR_MTRR_CAP])
        .map_err(CreateVmError::GetMtrrCap)?[0]
        .value;
    let indices = hyperv_mtrr_reset_indices(mtrr_cap)?;
    vm.msrs(&indices)
        .map_err(CreateVmError::RequiredMtrrsNotResettable)?;
    Ok(indices)
}

/// Builds the reset index set required by a filterless Hyper-V backend.
#[cfg(all(target_arch = "x86_64", any(mshv3, target_os = "windows")))]
pub(crate) fn hyperv_msr_reset_indices(
    vm: &dyn VirtualMachine,
    guest_msrs: &[u32],
) -> std::result::Result<Vec<u32>, CreateVmError> {
    validate_guest_msrs(vm, guest_msrs)?;
    let mut indices: Vec<u32> = filterless_core_reset_candidates()
        .filter(|index| vm.msrs(&[*index]).is_ok())
        .chain(mtrr_reset_indices(vm)?)
        .chain(guest_msrs.iter().copied())
        .collect();
    indices.sort_unstable();
    indices.dedup();
    Ok(indices)
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
