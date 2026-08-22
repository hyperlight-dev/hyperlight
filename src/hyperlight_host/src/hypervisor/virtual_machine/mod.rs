// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

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

/// Hypervisor.framework functionality (MacOS)
#[cfg(hvf)]
pub(crate) mod hvf;
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
            } else if #[cfg(hvf)] {
                if hvf::is_hypervisor_present() {
                    Some(HypervisorType::Hvf)
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

    #[cfg(hvf)]
    Hvf,
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

/// Architectural XCR0 reset value. Only x87 state is enabled.
#[cfg(target_arch = "x86_64")]
pub(crate) const XCR0_RESET: u64 = 1;

// Compiler error if no hypervisor type is available (not applicable on aarch64 yet)
#[cfg(not(any(kvm, mshv3, target_os = "windows", target_arch = "aarch64")))]
compile_error!(
    "No hypervisor type is available for the current platform. Please enable either the `kvm` or `mshv3` cargo feature."
);

/// The various reasons a VM's vCPU can exit
#[cfg_attr(target_os = "macos", allow(unused))]
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
#[derive(Debug, thiserror::Error)]
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
    #[cfg(all(target_arch = "x86_64", any(mshv3, target_os = "windows")))]
    #[error("Core reset MSR {msr:#x} is readable but not writable on this host")]
    MsrNotResettable { msr: u32 },
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
#[derive(Debug, thiserror::Error)]
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
    #[cfg(hvf)]
    #[error("HVF sync error: {0}")]
    HvfSync(HvfSyncError),
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
    #[cfg(target_arch = "x86_64")]
    #[error("Failed to get XCRs: {0}")]
    GetXcrs(HypervisorError),
    #[cfg(target_arch = "x86_64")]
    #[error("Failed to set XCRs: {0}")]
    SetXcrs(HypervisorError),
    #[cfg(target_arch = "x86_64")]
    #[error("Hypervisor did not return XCR0")]
    MissingXcr0,
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

#[derive(Debug, thiserror::Error)]
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
#[derive(Debug, thiserror::Error)]
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
#[derive(Debug, thiserror::Error)]
pub enum UnmapMemoryError {
    #[error("Hypervisor error: {0}")]
    Hypervisor(HypervisorError),
}

/// Implementation-specific Hypervisor error
#[derive(Debug, Clone, thiserror::Error)]
pub enum HypervisorError {
    #[cfg(test)]
    #[error("Injected hypervisor error")]
    Injected,
    #[cfg(kvm)]
    #[error("KVM error: {0}")]
    KvmError(#[from] kvm_ioctls::Error),
    #[cfg(mshv3)]
    #[error("MSHV error: {0}")]
    MshvError(#[from] mshv_ioctls::MshvError),
    #[cfg(target_os = "windows")]
    #[error("Windows error: {0}")]
    WindowsError(#[from] windows_result::Error),
    #[cfg(hvf)]
    #[error("HVF error: {0}")]
    HvfError(hvf::bindings::hv_return_t),
}

/// HVF-specific error synchronising vcpu state
#[cfg(hvf)]
#[derive(Debug, thiserror::Error)]
pub enum MemorySpaceInstallError {
    #[error("Failed to update VM/VCPU state: {0}")]
    Hypervisor(#[from] HypervisorError),
    #[error("Unexpected VCPU exit: {0:?}")]
    UnexpectedExit(hvf::bindings::hv_vcpu_exit_t),
    #[error("Failed to allocate ReadonlySharedMemory: {0}")]
    SharedMemoryCreation(#[from] crate::mem::shared_mem::SharedMemoryError),
}
#[cfg(hvf)]
#[derive(Debug, thiserror::Error)]
pub enum HvfSyncError {
    #[error("Error creating VCPU: {0}")]
    CreateVcpu(HypervisorError),
    #[error("Error resetting VCPU: {0}")]
    ResetVcpu(HypervisorError),
    #[error("Error reading/writing registers: {0}")]
    Register(#[from] RegisterError),
    #[error("Error updating memory space: {0}")]
    MemorySpace(#[from] MemorySpaceInstallError),
    #[error("Invariant violation: vcpu in unexpected sync state: {0}")]
    SyncInvariant(String),
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
    fn set_regs(&mut self, regs: &CommonRegisters) -> std::result::Result<(), RegisterError>;
    /// Get fpu regs
    #[allow(dead_code)]
    fn fpu(&self) -> std::result::Result<CommonFpu, RegisterError>;
    /// Set fpu regs
    fn set_fpu(&mut self, fpu: &CommonFpu) -> std::result::Result<(), RegisterError>;
    /// Get special regs
    #[allow(dead_code)]
    fn sregs(&self) -> std::result::Result<CommonSpecialRegisters, RegisterError>;
    /// Set special regs
    fn set_sregs(
        &mut self,
        sregs: &CommonSpecialRegisters,
    ) -> std::result::Result<(), RegisterError>;
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

    #[cfg(all(test, target_arch = "x86_64"))]
    fn xcr0(&self) -> std::result::Result<u64, RegisterError>;
    #[cfg(target_arch = "x86_64")]
    fn set_xcr0(&self, value: u64) -> std::result::Result<(), RegisterError>;

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

/// Why an MSR failed the read-then-write-back probe that restore relies on.
#[cfg(target_arch = "x86_64")]
enum MsrProbe {
    /// The host cannot read the MSR.
    Unreadable,
    /// The host reads the MSR but rejects writing the value back.
    Unwritable,
}

/// Reads `msr` and writes the captured value back, the round trip restore
/// replays. Success means the host can reset the MSR.
#[cfg(target_arch = "x86_64")]
fn probe_resettable(vm: &dyn VirtualMachine, msr: u32) -> Result<(), MsrProbe> {
    let captured = vm.msrs(&[msr]).map_err(|_| MsrProbe::Unreadable)?;
    vm.set_msrs(&captured).map_err(|_| MsrProbe::Unwritable)
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
        // A declared MSR is user-named, so either failure is a config error.
        probe_resettable(vm, msr).map_err(|probe| CreateVmError::MsrNotDeclarable {
            msr,
            reason: match probe {
                MsrProbe::Unreadable => "MSR cannot be read on this host",
                MsrProbe::Unwritable => "MSR cannot be written on this host",
            }
            .to_string(),
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
    let mut indices = filterless_core_reset_candidates()
        .filter_map(|index| match probe_resettable(vm, index) {
            // Readable and writable, so it joins the reset set.
            Ok(()) => Some(Ok(index)),
            // A read failure means the feature is absent, so nothing is retained. This is fine.
            Err(MsrProbe::Unreadable) => None,
            // A readable candidate must be writable, or restore cannot scrub it.
            Err(MsrProbe::Unwritable) => Some(Err(CreateVmError::MsrNotResettable { msr: index })),
        })
        .collect::<Result<Vec<u32>, _>>()?;
    // Guest-visible MTRRs, sized from the host MTRRCAP. mtrr_reset_indices
    // read-probes them. Hyper-V stores MTRRs unconditionally, so a readable
    // MTRR is always writable and needs no write probe.
    indices.extend(mtrr_reset_indices(vm)?);
    // The declared guest MSRs, validated above.
    indices.extend(guest_msrs.iter().copied());
    indices.sort_unstable();
    indices.dedup();
    Ok(indices)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hypervisor::regs::{CommonSegmentRegister, CommonTableRegister};

    fn boxed_vm() -> Box<dyn VirtualMachine> {
        let available_vm = get_available_hypervisor().as_ref().unwrap();
        match available_vm {
            #[cfg(kvm)]
            HypervisorType::Kvm => {
                use crate::hypervisor::virtual_machine::kvm::KvmVm;
                Box::new(KvmVm::new().unwrap())
            }
            #[cfg(mshv3)]
            HypervisorType::Mshv => {
                use crate::hypervisor::virtual_machine::mshv::MshvVm;
                Box::new(MshvVm::new().unwrap())
            }
            #[cfg(target_os = "windows")]
            HypervisorType::Whp => {
                use crate::hypervisor::virtual_machine::whp::WhpVm;
                Box::new(WhpVm::new().unwrap())
            }
        }
    }

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

    #[test]
    fn regs() {
        let vm = boxed_vm();

        let regs = CommonRegisters {
            rax: 1,
            rbx: 2,
            rcx: 3,
            rdx: 4,
            rsi: 5,
            rdi: 6,
            rsp: 7,
            rbp: 8,
            r8: 9,
            r9: 10,
            r10: 11,
            r11: 12,
            r12: 13,
            r13: 14,
            r14: 15,
            r15: 16,
            rip: 17,
            rflags: 0x2,
        };

        vm.set_regs(&regs).unwrap();
        let read_regs = vm.regs().unwrap();
        assert_eq!(regs, read_regs);
    }

    #[test]
    fn fpu() {
        let vm = boxed_vm();

        // x87 FPU registers are 80-bit (10 bytes), stored in 16-byte slots for alignment.
        // Only the first 10 bytes are preserved; the remaining 6 bytes are reserved/zeroed.
        // See Intel® 64 and IA-32 Architectures SDM, Vol. 1, Sec. 10.5.1.1 (x87 State)
        let fpr_entry: [u8; 16] = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0];
        let fpu = CommonFpu {
            fpr: [fpr_entry; 8],
            fcw: 2,
            fsw: 3,
            ftwx: 4,
            last_opcode: 5,
            last_ip: 6,
            last_dp: 7,
            xmm: [[8; 16]; 16],
            mxcsr: 9,
        };
        vm.set_fpu(&fpu).unwrap();
        #[cfg_attr(not(kvm), allow(unused_mut))]
        let mut read_fpu = vm.fpu().unwrap();
        #[cfg(kvm)]
        {
            read_fpu.mxcsr = fpu.mxcsr; // KVM get/set fpu does not preserve mxcsr
        }
        assert_eq!(fpu, read_fpu);
    }

    #[test]
    fn sregs() {
        let vm = boxed_vm();

        let data_segment = CommonSegmentRegister {
            base: 1,
            limit: 2,
            selector: 3,
            type_: 3,
            present: 1,
            dpl: 1,
            db: 0,
            s: 1, // non-system (code/data) segment
            l: 0, // must be 0 for data segments
            g: 0,
            avl: 1,
            unusable: 0,
            padding: 0,
        };

        let cs_segment = CommonSegmentRegister {
            base: 1,
            limit: 0xFFFF,
            selector: 0x08,
            type_: 0b1011, // code segment, execute/read, accessed
            present: 1,
            dpl: 1,
            db: 0, // must be 0 in 64-bit mode
            s: 1,
            l: 1, // 64-bit mode
            g: 0, // KVM normalizes g to 0 for segments with small limits
            avl: 1,
            unusable: 0,
            padding: 0,
        };

        let tr_segment = CommonSegmentRegister {
            base: 1,
            limit: 2,
            selector: 3,
            type_: 0b1011, // 64-bit TSS (busy)
            present: 1,
            dpl: 0,
            db: 0,
            s: 0, // system segment
            l: 0,
            g: 0,
            avl: 0,
            unusable: 0,
            padding: 0,
        };

        let ldt_segment = CommonSegmentRegister {
            base: 1,
            limit: 2,
            selector: 3,
            type_: 0b0010, // LDT
            present: 1,
            dpl: 0,
            db: 0,
            s: 0, // system segment
            l: 0,
            g: 0,
            avl: 0,
            unusable: 0,
            padding: 0,
        };

        let table = CommonTableRegister {
            base: 12,
            limit: 13,
        };
        let sregs = CommonSpecialRegisters {
            cs: cs_segment,
            ds: data_segment,
            es: data_segment,
            fs: data_segment,
            gs: data_segment,
            ss: data_segment,
            tr: tr_segment,
            ldt: ldt_segment,
            gdt: table,
            idt: table,
            cr0: 0x80000011, // bit 0 (PE) + bit 4 (ET) + bit 31 (PG)
            cr2: 2,
            cr3: 3,
            cr4: 0x20,
            cr8: 5,
            efer: 0x500,
            apic_base: 0xFEE00900,
            interrupt_bitmap: [0; 4],
        };
        vm.set_sregs(&sregs).unwrap();
        let read_sregs = vm.sregs().unwrap();
        assert_eq!(sregs, read_sregs);
    }

    /// Helper to create a page-aligned memory region for testing
    #[cfg(any(kvm, mshv3))]
    fn create_test_memory(size: usize) -> crate::mem::shared_mem::ExclusiveSharedMemory {
        use hyperlight_common::mem::PAGE_SIZE_USIZE;
        let aligned_size = size.div_ceil(PAGE_SIZE_USIZE) * PAGE_SIZE_USIZE;
        crate::mem::shared_mem::ExclusiveSharedMemory::new(aligned_size).unwrap()
    }

    /// Helper to create a MemoryRegion from ExclusiveSharedMemory
    #[cfg(any(kvm, mshv3))]
    fn region_for_test_memory(
        mem: &crate::mem::shared_mem::ExclusiveSharedMemory,
        guest_base: usize,
        flags: crate::mem::memory_region::MemoryRegionFlags,
    ) -> MemoryRegion {
        use crate::mem::memory_region::MemoryRegionType;
        use crate::mem::shared_mem::SharedMemory;
        let ptr = mem.base_addr();
        let len = mem.mem_size();
        MemoryRegion {
            host_region: ptr..(ptr + len),
            guest_region: guest_base..(guest_base + len),
            flags,
            region_type: MemoryRegionType::Heap,
        }
    }

    #[test]
    #[cfg(any(kvm, mshv3))] // Requires memory mapping support (TODO on WHP)
    fn map_memory() {
        use crate::mem::memory_region::MemoryRegionFlags;

        let mut vm = boxed_vm();

        let mem1 = create_test_memory(4096);
        let guest_addr: usize = 0x1000;
        let region = region_for_test_memory(
            &mem1,
            guest_addr,
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
        );

        // SAFETY: The memory region points to valid memory allocated by ExclusiveSharedMemory,
        // and will live until we drop mem1 at the end of the test.
        // Slot 0 is not already mapped.
        unsafe {
            vm.map_memory((0, &region)).unwrap();
        }

        // Unmap the region
        vm.unmap_memory((0, &region)).unwrap();

        // Unmapping a region that was already unmapped should fail
        vm.unmap_memory((0, &region)).unwrap_err();

        // Unmapping a region that was never mapped should fail
        vm.unmap_memory((99, &region)).unwrap_err();

        // Re-map the same region to a different slot
        // SAFETY: Same as above - memory is still valid and slot 1 is not mapped.
        unsafe {
            vm.map_memory((1, &region)).unwrap();
        }

        // Map a second region to a different slot
        let mem2 = create_test_memory(4096);
        let guest_addr2: usize = 0x2000;
        let region2 = region_for_test_memory(
            &mem2,
            guest_addr2,
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
        );

        // SAFETY: Memory is valid from ExclusiveSharedMemory, slot 2 is not mapped.
        unsafe {
            vm.map_memory((2, &region2)).unwrap();
        }

        // Clean up: unmap both regions
        vm.unmap_memory((1, &region)).unwrap();
        vm.unmap_memory((2, &region2)).unwrap();
    }
}
