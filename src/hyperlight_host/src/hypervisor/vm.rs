use std::fmt::Debug;
#[cfg(gdb)]
use std::sync::Arc;
#[cfg(gdb)]
use std::sync::Mutex;

#[cfg(gdb)]
use crate::hypervisor::handlers::DbgMemAccessHandlerCaller;
use crate::hypervisor::HyperlightExit;
use crate::mem::memory_region::MemoryRegion;
use crate::Result;

use super::regs::CommonFpu;
use super::regs::CommonRegisters;
use super::regs::CommonSpecialRegisters;

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
    unsafe fn map_memory(&self, region: &[MemoryRegion]) -> Result<()>;

    /// Runs the vCPU until it exits
    fn run_vcpu(&mut self) -> Result<HyperlightExit>;

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
