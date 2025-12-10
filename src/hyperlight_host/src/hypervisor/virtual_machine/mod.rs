use crate::Result;
use crate::hypervisor::regs::{CommonFpu, CommonRegisters, CommonSpecialRegisters};
use crate::mem::memory_region::MemoryRegion;
use std::fmt::Debug;

#[cfg(kvm)]
/// Functionality to manipulate KVM-based virtual machines
pub(crate) mod kvm;
/// HyperV-on-linux functionality
#[cfg(mshv3)]
pub(crate) mod mshv;
#[cfg(target_os = "windows")]
pub(crate) mod whp;

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
    unsafe fn map_memory(&mut self, region: (u32, &MemoryRegion)) -> Result<()>;

    /// Unmap memory region from this VM that has previously been mapped using `map_memory`.
    fn unmap_memory(&mut self, region: (u32, &MemoryRegion)) -> Result<()>;

    /// Runs the vCPU until it exits.
    /// Note: this function should not emit any traces or spans as it is called after guest span is setup
    fn run_vcpu(&mut self) -> Result<VmExit>;

    /// Get regs
    #[allow(dead_code)]
    fn regs(&self) -> Result<CommonRegisters>;
    /// Set regs
    fn set_regs(&self, regs: &CommonRegisters) -> Result<()>;
    /// Get fpu regs
    #[allow(dead_code)]
    fn fpu(&self) -> Result<CommonFpu>;
    /// Set fpu regs
    fn set_fpu(&self, fpu: &CommonFpu) -> Result<()>;
    /// Get special regs
    #[allow(dead_code)]
    fn sregs(&self) -> Result<CommonSpecialRegisters>;
    /// Set special regs
    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> Result<()>;

    /// xsave
    #[cfg(crashdump)]
    fn xsave(&self) -> Result<Vec<u8>>;

    /// Get partition handle
    #[cfg(target_os = "windows")]
    fn partition_handle(&self) -> windows::Win32::System::Hypervisor::WHV_PARTITION_HANDLE;

    /// Mark that initial memory setup is complete. After this, map_memory will fail.
    /// This is only needed on Windows where dynamic memory mapping is not yet supported.
    #[cfg(target_os = "windows")]
    fn complete_initial_memory_setup(&mut self);
}
