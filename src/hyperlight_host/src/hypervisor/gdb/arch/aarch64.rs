// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use crate::hypervisor::regs::CommonRegisters;

pub(crate) const SW_BP_SIZE: usize = 4;
pub(crate) const SW_BP_IMMEDIATE: u16 = 0x4859;
const HVC_BASE: u32 = 0xd400_0002;
const SW_BP_INSTRUCTION: u32 = HVC_BASE | ((SW_BP_IMMEDIATE as u32) << 5);
pub(crate) const SW_BP: [u8; SW_BP_SIZE] = SW_BP_INSTRUCTION.to_le_bytes();

pub(crate) fn valid_sw_breakpoint_address(addr: u64) -> bool {
    addr.is_multiple_of(SW_BP_SIZE as u64)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SoftwareStepError {
    #[error("Software single-step does not support instruction {instruction:#010x} at {pc:#x}")]
    UnsupportedInstruction { pc: u64, instruction: u32 },
    #[error("Software single-step target overflow for instruction at {0:#x}")]
    TargetOverflow(u64),
    #[error("Software single-step target is the current PC {0:#x}")]
    SelfLoop(u64),
    #[error("Software single-step branch register X{0} is invalid")]
    InvalidBranchRegister(u8),
    #[error("Software single-step target {0:#x} is not instruction-aligned")]
    UnalignedTarget(u64),
}

fn sign_extend(value: u32, bits: u32) -> i64 {
    ((value as i64) << (64 - bits)) >> (64 - bits)
}

fn relative_target(pc: u64, immediate: u32, bits: u32) -> Result<u64, SoftwareStepError> {
    let offset = sign_extend(immediate, bits) << 2;
    pc.checked_add_signed(offset)
        .ok_or(SoftwareStepError::TargetOverflow(pc))
}

fn branch_register(instruction: u32, regs: &CommonRegisters) -> Result<u64, SoftwareStepError> {
    let register = ((instruction >> 5) & 0x1f) as u8;
    regs.x
        .get(register as usize)
        .copied()
        .ok_or(SoftwareStepError::InvalidBranchRegister(register))
}

pub(crate) fn software_step_targets(
    pc: u64,
    instruction: u32,
    regs: &CommonRegisters,
) -> Result<Vec<u64>, SoftwareStepError> {
    let fallthrough = pc
        .checked_add(SW_BP_SIZE as u64)
        .ok_or(SoftwareStepError::TargetOverflow(pc))?;

    let mut targets = if instruction & 0x7c00_0000 == 0x1400_0000 {
        vec![relative_target(pc, instruction & 0x03ff_ffff, 26)?]
    } else if instruction & 0xff00_0000 == 0x5400_0000 || instruction & 0x7e00_0000 == 0x3400_0000 {
        vec![
            fallthrough,
            relative_target(pc, (instruction >> 5) & 0x7ffff, 19)?,
        ]
    } else if instruction & 0x7e00_0000 == 0x3600_0000 {
        vec![
            fallthrough,
            relative_target(pc, (instruction >> 5) & 0x3fff, 14)?,
        ]
    } else if instruction & 0xffff_fc1f == 0xd61f_0000
        || instruction & 0xffff_fc1f == 0xd63f_0000
        || instruction & 0xffff_fc1f == 0xd65f_0000
    {
        vec![branch_register(instruction, regs)?]
    } else if instruction & 0xfe00_0000 == 0xd600_0000 || instruction & 0xff00_0000 == 0xd400_0000 {
        return Err(SoftwareStepError::UnsupportedInstruction { pc, instruction });
    } else {
        vec![fallthrough]
    };

    targets.sort_unstable();
    targets.dedup();
    if targets.contains(&pc) {
        return Err(SoftwareStepError::SelfLoop(pc));
    }
    if let Some(target) = targets
        .iter()
        .find(|&&target| !valid_sw_breakpoint_address(target))
    {
        return Err(SoftwareStepError::UnalignedTarget(*target));
    }
    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_breakpoint_is_reserved_hvc() {
        assert_eq!(SW_BP, [0x22, 0x0b, 0x09, 0xd4]);
    }

    #[test]
    fn software_breakpoints_require_instruction_alignment() {
        assert!(valid_sw_breakpoint_address(0x4000));
        assert!(!valid_sw_breakpoint_address(0x4001));
        assert!(!valid_sw_breakpoint_address(0x4002));
        assert!(!valid_sw_breakpoint_address(0x4003));
    }

    #[test]
    fn software_step_decodes_linear_instruction() {
        assert_eq!(
            software_step_targets(0x1000, 0xd503_201f, &CommonRegisters::default()).unwrap(),
            vec![0x1004]
        );
    }

    #[test]
    fn software_step_decodes_direct_branches() {
        assert_eq!(
            software_step_targets(0x1000, 0x1400_0002, &CommonRegisters::default()).unwrap(),
            vec![0x1008]
        );
        assert_eq!(
            software_step_targets(0x1000, 0x17ff_ffff, &CommonRegisters::default()).unwrap(),
            vec![0xffc]
        );
        assert_eq!(
            software_step_targets(0x1000, 0x9400_0002, &CommonRegisters::default()).unwrap(),
            vec![0x1008]
        );
    }

    #[test]
    fn software_step_decodes_conditional_branches() {
        assert_eq!(
            software_step_targets(0x1000, 0x5400_0040, &CommonRegisters::default()).unwrap(),
            vec![0x1004, 0x1008]
        );
        assert_eq!(
            software_step_targets(0x1000, 0x5400_0050, &CommonRegisters::default()).unwrap(),
            vec![0x1004, 0x1008]
        );
        assert_eq!(
            software_step_targets(0x1000, 0xb400_0040, &CommonRegisters::default()).unwrap(),
            vec![0x1004, 0x1008]
        );
        assert_eq!(
            software_step_targets(0x1000, 0x3600_0040, &CommonRegisters::default()).unwrap(),
            vec![0x1004, 0x1008]
        );
    }

    #[test]
    fn software_step_decodes_register_branches() {
        let mut regs = CommonRegisters::default();
        regs.x[30] = 0x1234;
        assert_eq!(
            software_step_targets(0x1000, 0xd65f_03c0, &regs).unwrap(),
            vec![0x1234]
        );
    }

    #[test]
    fn software_step_rejects_unsupported_control_flow() {
        assert!(matches!(
            software_step_targets(0x1000, 0xd400_0002, &CommonRegisters::default()),
            Err(SoftwareStepError::UnsupportedInstruction { .. })
        ));
        assert_eq!(
            software_step_targets(0x1000, 0x1400_0000, &CommonRegisters::default()),
            Err(SoftwareStepError::SelfLoop(0x1000))
        );

        let mut regs = CommonRegisters::default();
        regs.x[30] = 0x1235;
        assert_eq!(
            software_step_targets(0x1000, 0xd65f_03c0, &regs),
            Err(SoftwareStepError::UnalignedTarget(0x1235))
        );
    }
}
