/*
Copyright 2024 The Hyperlight Authors.

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

//! This file contains architecture specific code for the x86_64

use super::VcpuStopReason;
use crate::hypervisor::regs::CommonRegisters;
use crate::hypervisor::vm::Vm;
use crate::Result;

// Described in Table 6-1. Exceptions and Interrupts at Page 6-13 Vol. 1
// of Intel 64 and IA-32 Architectures Software Developer's Manual
/// Exception id for #DB
const DB_EX_ID: u32 = 1;
/// Exception id for #BP - triggered by the INT3 instruction
const BP_EX_ID: u32 = 3;

/// Software Breakpoint size in memory
pub(crate) const SW_BP_SIZE: usize = 1;
/// Software Breakpoint opcode - INT3
/// Check page 7-28 Vol. 3A of Intel 64 and IA-32
/// Architectures Software Developer's Manual
pub(crate) const SW_BP_OP: u8 = 0xCC;
/// Software Breakpoint written to memory
pub(crate) const SW_BP: [u8; SW_BP_SIZE] = [SW_BP_OP];

/// Check page 19-4 Vol. 3B of Intel 64 and IA-32
/// Architectures Software Developer's Manual
/// Bit position of BS flag in DR6 debug register
pub(crate) const DR6_BS_FLAG_POS: usize = 14;
/// Bit mask of BS flag in DR6 debug register
pub(crate) const DR6_BS_FLAG_MASK: u64 = 1 << DR6_BS_FLAG_POS;
/// Bit position of HW breakpoints status in DR6 debug register
pub(crate) const DR6_HW_BP_FLAGS_POS: usize = 0;
/// Bit mask of HW breakpoints status in DR6 debug register
pub(crate) const DR6_HW_BP_FLAGS_MASK: u64 = 0x0F << DR6_HW_BP_FLAGS_POS;

/// Determine the reason the vCPU stopped
/// This is done by checking the DR6 register and the exception id
/// NOTE: Additional checks are done for the entrypoint, stored hw_breakpoints
/// and sw_breakpoints to ensure the stop reason is valid with internal state
pub(crate) fn vcpu_stop_reason(
    vm: &mut dyn Vm,
    entrypoint: u64,
    dr6: u64,
    exception: u32,
) -> Result<VcpuStopReason> {
    let CommonRegisters { rip, .. } = vm.get_regs()?;
    if DB_EX_ID == exception {
        // If the BS flag in DR6 register is set, it means a single step
        // instruction triggered the exit
        // Check page 19-4 Vol. 3B of Intel 64 and IA-32
        // Architectures Software Developer's Manual
        if dr6 & DR6_BS_FLAG_MASK != 0 {
            log::info!("Done Step stop reason");
            return Ok(VcpuStopReason::DoneStep);
        }

        // If any of the B0-B3 flags in DR6 register is set, it means a
        // hardware breakpoint triggered the exit
        // Check page 19-4 Vol. 3B of Intel 64 and IA-32
        // Architectures Software Developer's Manual
        if DR6_HW_BP_FLAGS_MASK & dr6 != 0 {
            if rip == entrypoint {
                log::info!("EntryPoint stop reason");
                vm.remove_hw_breakpoint(entrypoint)?;
                return Ok(VcpuStopReason::EntryPointBp);
            }
            log::info!("Hardware breakpoint stop reason");
            return Ok(VcpuStopReason::HwBp);
        }
    }

    if BP_EX_ID == exception {
        log::info!("Software breakpoint stop reason");
        return Ok(VcpuStopReason::SwBp);
    }

    // Log an error and provide internal debugging info
    log::error!(
        r"The vCPU exited because of an unknown reason:
        rip: {:?}
        dr6: {:?}
        entrypoint: {:?}
        exception: {:?}

        ",
        rip,
        dr6,
        entrypoint,
        exception,
    );

    Ok(VcpuStopReason::Unknown)
}
