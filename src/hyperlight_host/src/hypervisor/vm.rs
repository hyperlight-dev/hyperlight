/*
Copyright 2025  The Hyperlight Authors.

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

use super::regs::{CommonFpu, CommonRegisters, CommonSpecialRegisters};
use crate::Result;
use crate::hypervisor::regs::CommonDebugRegs;
use crate::mem::memory_region::MemoryRegion;

/// Trait for single-vCPU VMs. Provides a common interface for basic VM operations.
/// Abstracts over differences between KVM, MSHV and WHP implementations.
pub(crate) trait Vm: Send + Sync + Debug {
    /// Get the standard registers of the vCPU
    #[allow(dead_code)]
    fn regs(&self) -> Result<CommonRegisters>;
    /// Set the standard registers of the vCPU
    fn set_regs(&self, regs: &CommonRegisters) -> Result<()>;

    /// Get the special registers of the vCPU
    #[allow(dead_code)]
    fn sregs(&self) -> Result<CommonSpecialRegisters>;
    /// Set the special registers of the vCPU
    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> Result<()>;

    /// Get the FPU registers of the vCPU
    #[allow(dead_code)]
    fn fpu(&self) -> Result<CommonFpu>;
    /// Set the FPU registers of the vCPU
    fn set_fpu(&self, fpu: &CommonFpu) -> Result<()>;

    /// Get xsave
    #[allow(dead_code)]
    fn xsave(&self) -> Result<Vec<u8>>;
    /// Set xsave
    fn set_xsave(&self, xsave: &[u32; 1024]) -> Result<()>;

    /// Get the debug registers of the vCPU
    #[allow(dead_code)]
    fn debug_regs(&self) -> Result<CommonDebugRegs>;
    /// Set the debug registers of the vCPU
    fn set_debug_regs(&self, drs: &CommonDebugRegs) -> Result<()>;

    /// Map memory region into this VM
    ///
    /// # Safety
    /// The caller must ensure that the memory region is valid and points to valid memory,
    /// and lives long enough for the VM to use it.
    /// The caller must ensure that the given u32 is not already mapped, otherwise previously mapped
    /// memory regions may be overwritten.
    unsafe fn map_memory(&mut self, region: (u32, &MemoryRegion)) -> Result<()>;

    /// Unmap memory region from this VM that has previously been mapped using `map_memory`.
    fn unmap_memory(&mut self, region: (u32, &MemoryRegion)) -> Result<()>;

    /// Runs the vCPU until it exits
    fn run_vcpu(&mut self) -> Result<VmExit>;

    /// Enable MSR intercepts to trap all MSR accesses (read and write).
    fn enable_msr_intercept(&mut self) -> Result<()>;

    // --------------------------
    // --- DEBUGGING BELOW ------
    // --------------------------

    /// Translates a guest virtual address to a guest physical address
    #[cfg(gdb)]
    fn translate_gva(&self, gva: u64) -> Result<u64>;

    /// Enable/disable debugging
    #[cfg(gdb)]
    fn set_debug(&mut self, enable: bool) -> Result<()>;

    /// Enable/disable single stepping
    #[cfg(gdb)]
    fn set_single_step(&mut self, enable: bool) -> Result<()>;

    /// Add a hardware breakpoint at the given address.
    /// Must be idempotent.
    #[cfg(gdb)]
    fn add_hw_breakpoint(&mut self, addr: u64) -> Result<()>;

    /// Remove a hardware breakpoint at the given address
    #[cfg(gdb)]
    fn remove_hw_breakpoint(&mut self, addr: u64) -> Result<()>;

    /// Get partition handle
    #[cfg(target_os = "windows")]
    fn partition_handle(&self) -> windows::Win32::System::Hypervisor::WHV_PARTITION_HANDLE;

    /// Mark that initial memory setup is complete. After this, map_memory will fail.
    /// This is only needed on Windows where dynamic memory mapping is not yet supported.
    #[cfg(target_os = "windows")]
    fn complete_initial_memory_setup(&mut self);
}

/// Possible exit reasons of a VM's vCPU
pub(crate) enum VmExit {
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
    /// The vCPU tried to read from the given MSR
    MsrRead(u32),
    /// The vCPU tried to write to the given MSR with the given value
    MsrWrite { msr_index: u32, value: u64 },
    /// The operation should be retried, for example this can happen on Linux where a call to run the CPU can return EAGAIN
    #[cfg_attr(
        target_os = "windows",
        expect(
            dead_code,
            reason = "Retry() is never constructed on Windows, but it is still matched on (which dead_code lint ignores)"
        )
    )]
    Retry(),
    #[cfg(gdb)]
    /// The vCPU has exited due to a debug event (usually breakpoint)
    Debug { dr6: u64, exception: u32 },
}
