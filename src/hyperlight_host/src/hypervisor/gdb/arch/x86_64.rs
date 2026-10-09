// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use super::super::{DebugError, DebuggableVm, VcpuStopReason};
use crate::hypervisor::regs::CommonRegisters;
use crate::hypervisor::virtual_machine::RegisterError;

#[derive(Debug, thiserror::Error)]
pub enum VcpuStopReasonError {
    #[error("Failed to get registers: {0}")]
    GetRegs(#[from] RegisterError),
    #[error("Failed to remove hardware breakpoint: {0}")]
    RemoveHwBreakpoint(#[from] DebugError),
}

pub(crate) const DB_EX_ID: u32 = 1;
pub(crate) const BP_EX_ID: u32 = 3;
pub(crate) const SW_BP_SIZE: usize = 1;
pub(crate) const SW_BP: [u8; SW_BP_SIZE] = [0xCC];
pub(crate) const MAX_NO_OF_HW_BP: usize = 4;

const DR6_BS_FLAG_MASK: u64 = 1 << 14;
const DR6_HW_BP_FLAGS_MASK: u64 = 0x0F;

pub(crate) fn valid_sw_breakpoint_address(_addr: u64) -> bool {
    true
}

pub(crate) fn vcpu_stop_reason(
    vm: &dyn DebuggableVm,
    dr6: u64,
    exception: u32,
) -> std::result::Result<VcpuStopReason, VcpuStopReasonError> {
    let CommonRegisters { rip, .. } = vm.regs()?;
    if DB_EX_ID == exception {
        if dr6 & DR6_BS_FLAG_MASK != 0 {
            return Ok(VcpuStopReason::DoneStep);
        }

        if DR6_HW_BP_FLAGS_MASK & dr6 != 0 {
            return Ok(VcpuStopReason::HwBp);
        }
    }

    if BP_EX_ID == exception {
        return Ok(VcpuStopReason::SwBp);
    }

    tracing::error!(
        r"The vCPU exited because of an unknown reason:
        rip: {:?}
        dr6: {:?}
        exception: {:?}
        ",
        rip,
        dr6,
        exception,
    );

    Ok(VcpuStopReason::Unknown)
}
