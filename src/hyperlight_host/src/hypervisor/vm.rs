use std::fmt::Debug;
#[cfg(gdb)]
use std::sync::Arc;
#[cfg(gdb)]
use std::sync::Mutex;

use super::regs::{CommonFpu, CommonRegisters, CommonSpecialRegisters};
#[cfg(gdb)]
use crate::hypervisor::handlers::DbgMemAccessHandlerCaller;
use crate::mem::memory_region::MemoryRegion;
use crate::Result;

pub(crate) trait Vm: Send + Sync + Debug {
    /// Get the standard registers of the vCPU
    #[allow(dead_code)]
    fn get_regs(&self) -> Result<CommonRegisters>;
    /// Set the standard registers of the vCPU
    fn set_regs(&self, regs: &CommonRegisters) -> Result<()>;

    /// Get the special registers of the vCPU
    fn get_sregs(&self) -> Result<CommonSpecialRegisters>;
    /// Set the special registers of the vCPU
    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> Result<()>;

    /// Get the FPU registers of the vCPU
    #[allow(dead_code)]
    fn get_fpu(&self) -> Result<CommonFpu>;
    /// Set the FPU registers of the vCPU
    fn set_fpu(&self, fpu: &CommonFpu) -> Result<()>;

    /// Map memory regions into this VM
    ///
    /// Safety: Should only be called once, since memory slots will otherwise be overwritten on KVM
    unsafe fn map_memory(&mut self, region: &[MemoryRegion]) -> Result<()>;

    /// Runs the vCPU until it exits
    fn run_vcpu(&mut self) -> Result<HyperlightExit>;

    #[cfg(target_os = "windows")]
    fn get_partition_handle(&self) -> windows::Win32::System::Hypervisor::WHV_PARTITION_HANDLE;

    // --- DEBUGGING ------------

    /// Translates a guest virtual address to a guest physical address
    #[cfg(gdb)]
    fn translate_gva(&self, gva: u64) -> Result<u64>;

    /// Enable/disable debugging
    #[cfg(gdb)]
    fn set_debug(&mut self, enable: bool) -> Result<()>;

    /// Enable/disable single stepping
    #[cfg(gdb)]
    fn set_single_step(&mut self, enable: bool) -> Result<()>;

    /// Add a hardware breakpoint at the given address
    #[cfg(gdb)]
    fn add_hw_breakpoint(&mut self, addr: u64) -> Result<()>;

    /// Remove a hardware breakpoint at the given address
    #[cfg(gdb)]
    fn remove_hw_breakpoint(&mut self, addr: u64) -> Result<()>;

    /// Add a software breakpoint at the given address
    #[cfg(gdb)]
    fn add_sw_breakpoint(
        &mut self,
        addr: u64,
        dbg_mem_access_fn: Arc<Mutex<dyn DbgMemAccessHandlerCaller>>,
    ) -> Result<()>;

    /// Remove a software breakpoint at the given address
    #[cfg(gdb)]
    fn remove_sw_breakpoint(
        &mut self,
        addr: u64,
        dbg_mem_access_fn: Arc<Mutex<dyn DbgMemAccessHandlerCaller>>,
    ) -> Result<()>;
}

#[derive(Debug)]
#[cfg(gdb)]
pub(super) enum DebugExit {
    /// The vCPU has exited due to a debug event (usually breakpoint)
    Debug { dr6: u64, exception: u32 },
    /// The user has requested to stop the VM during execution (e.g. via Ctrl+C inside GDB)
    Interrupt,
}

/// Possible exit reasons of a VM's vCPU
pub(super) enum HyperlightExit {
    #[cfg(gdb)]
    /// The vCPU has exited due to a debug event
    Debug(DebugExit),
    /// The vCPU has halted
    Halt(),
    /// The vCPU has issued a write to the given port with the given value
    IoOut(u16, Vec<u8>),
    /// The vCPU tried to read from the given (unmapped) addr
    MmioRead(u64),
    /// The vCPU tried to write to the given (unmapped) addr
    MmioWrite(u64),
    /// The vCPU execution has been cancelled
    #[allow(dead_code)]
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
