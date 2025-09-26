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

#[cfg(mshv2)]
extern crate mshv_bindings2 as mshv_bindings;
#[cfg(mshv2)]
extern crate mshv_ioctls2 as mshv_ioctls;

#[cfg(mshv3)]
extern crate mshv_bindings3 as mshv_bindings;
#[cfg(mshv3)]
extern crate mshv_ioctls3 as mshv_ioctls;

#[cfg(kvm)]
use kvm_bindings::kvm_regs;
#[cfg(mshv)]
use mshv_bindings::StandardRegisters;

#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub(crate) struct CommonRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

// --- KVM ---
#[cfg(kvm)]
impl From<&kvm_regs> for CommonRegisters {
    fn from(kvm_regs: &kvm_regs) -> Self {
        CommonRegisters {
            rax: kvm_regs.rax,
            rbx: kvm_regs.rbx,
            rcx: kvm_regs.rcx,
            rdx: kvm_regs.rdx,
            rsi: kvm_regs.rsi,
            rdi: kvm_regs.rdi,
            rsp: kvm_regs.rsp,
            rbp: kvm_regs.rbp,
            r8: kvm_regs.r8,
            r9: kvm_regs.r9,
            r10: kvm_regs.r10,
            r11: kvm_regs.r11,
            r12: kvm_regs.r12,
            r13: kvm_regs.r13,
            r14: kvm_regs.r14,
            r15: kvm_regs.r15,
            rip: kvm_regs.rip,
            rflags: kvm_regs.rflags,
        }
    }
}

#[cfg(kvm)]
impl From<&CommonRegisters> for kvm_regs {
    fn from(regs: &CommonRegisters) -> Self {
        kvm_regs {
            rax: regs.rax,
            rbx: regs.rbx,
            rcx: regs.rcx,
            rdx: regs.rdx,
            rsi: regs.rsi,
            rdi: regs.rdi,
            rsp: regs.rsp,
            rbp: regs.rbp,
            r8: regs.r8,
            r9: regs.r9,
            r10: regs.r10,
            r11: regs.r11,
            r12: regs.r12,
            r13: regs.r13,
            r14: regs.r14,
            r15: regs.r15,
            rip: regs.rip,
            rflags: regs.rflags,
        }
    }
}

// --- MSHV ---

#[cfg(mshv)]
impl From<&StandardRegisters> for CommonRegisters {
    fn from(mshv_regs: &StandardRegisters) -> Self {
        CommonRegisters {
            rax: mshv_regs.rax,
            rbx: mshv_regs.rbx,
            rcx: mshv_regs.rcx,
            rdx: mshv_regs.rdx,
            rsi: mshv_regs.rsi,
            rdi: mshv_regs.rdi,
            rsp: mshv_regs.rsp,
            rbp: mshv_regs.rbp,
            r8: mshv_regs.r8,
            r9: mshv_regs.r9,
            r10: mshv_regs.r10,
            r11: mshv_regs.r11,
            r12: mshv_regs.r12,
            r13: mshv_regs.r13,
            r14: mshv_regs.r14,
            r15: mshv_regs.r15,
            rip: mshv_regs.rip,
            rflags: mshv_regs.rflags,
        }
    }
}

#[cfg(mshv)]
impl From<&CommonRegisters> for StandardRegisters {
    fn from(regs: &CommonRegisters) -> Self {
        StandardRegisters {
            rax: regs.rax,
            rbx: regs.rbx,
            rcx: regs.rcx,
            rdx: regs.rdx,
            rsi: regs.rsi,
            rdi: regs.rdi,
            rsp: regs.rsp,
            rbp: regs.rbp,
            r8: regs.r8,
            r9: regs.r9,
            r10: regs.r10,
            r11: regs.r11,
            r12: regs.r12,
            r13: regs.r13,
            r14: regs.r14,
            r15: regs.r15,
            rip: regs.rip,
            rflags: regs.rflags,
        }
    }
}

#[cfg(target_os = "windows")]
use windows::Win32::System::Hypervisor::*;

#[cfg(target_os = "windows")]
impl From<&CommonRegisters>
    for [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>); WHP_REGS_NAMES_LEN]
{
    fn from(regs: &CommonRegisters) -> Self {
        [
            (
                WHvX64RegisterRax,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.rax }),
            ),
            (
                WHvX64RegisterRbx,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.rbx }),
            ),
            (
                WHvX64RegisterRcx,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.rcx }),
            ),
            (
                WHvX64RegisterRdx,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.rdx }),
            ),
            (
                WHvX64RegisterRsi,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.rsi }),
            ),
            (
                WHvX64RegisterRdi,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.rdi }),
            ),
            (
                WHvX64RegisterRsp,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.rsp }),
            ),
            (
                WHvX64RegisterRbp,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.rbp }),
            ),
            (
                WHvX64RegisterR8,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.r8 }),
            ),
            (
                WHvX64RegisterR9,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.r9 }),
            ),
            (
                WHvX64RegisterR10,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.r10 }),
            ),
            (
                WHvX64RegisterR11,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.r11 }),
            ),
            (
                WHvX64RegisterR12,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.r12 }),
            ),
            (
                WHvX64RegisterR13,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.r13 }),
            ),
            (
                WHvX64RegisterR14,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.r14 }),
            ),
            (
                WHvX64RegisterR15,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.r15 }),
            ),
            (
                WHvX64RegisterRip,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.rip }),
            ),
            (
                WHvX64RegisterRflags,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.rflags }),
            ),
        ]
    }
}

#[cfg(target_os = "windows")]
use std::collections::HashSet;

#[cfg(target_os = "windows")]
use super::{Align16, FromWhpRegisterError};

#[cfg(target_os = "windows")]
pub(crate) const WHP_REGS_NAMES_LEN: usize = 18;
#[cfg(target_os = "windows")]
pub(crate) const WHP_REGS_NAMES: [WHV_REGISTER_NAME; WHP_REGS_NAMES_LEN] = [
    WHvX64RegisterRax,
    WHvX64RegisterRbx,
    WHvX64RegisterRcx,
    WHvX64RegisterRdx,
    WHvX64RegisterRsi,
    WHvX64RegisterRdi,
    WHvX64RegisterRsp,
    WHvX64RegisterRbp,
    WHvX64RegisterR8,
    WHvX64RegisterR9,
    WHvX64RegisterR10,
    WHvX64RegisterR11,
    WHvX64RegisterR12,
    WHvX64RegisterR13,
    WHvX64RegisterR14,
    WHvX64RegisterR15,
    WHvX64RegisterRip,
    WHvX64RegisterRflags,
];

#[cfg(target_os = "windows")]
impl TryFrom<&[(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>)]> for CommonRegisters {
    type Error = FromWhpRegisterError;

    #[expect(
        non_upper_case_globals,
        reason = "Windows API has lowercase register names"
    )]
    fn try_from(
        regs: &[(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>)],
    ) -> Result<Self, Self::Error> {
        if regs.len() != WHP_REGS_NAMES_LEN {
            return Err(FromWhpRegisterError::InvalidLength(regs.len()));
        }
        let mut registers = CommonRegisters::default();
        let mut seen_registers = HashSet::new();

        for &(name, value) in regs {
            let name_id = name.0;

            // Check for duplicates
            if !seen_registers.insert(name_id) {
                return Err(FromWhpRegisterError::DuplicateRegister(name_id));
            }

            unsafe {
                match name {
                    WHvX64RegisterRax => registers.rax = value.0.Reg64,
                    WHvX64RegisterRbx => registers.rbx = value.0.Reg64,
                    WHvX64RegisterRcx => registers.rcx = value.0.Reg64,
                    WHvX64RegisterRdx => registers.rdx = value.0.Reg64,
                    WHvX64RegisterRsi => registers.rsi = value.0.Reg64,
                    WHvX64RegisterRdi => registers.rdi = value.0.Reg64,
                    WHvX64RegisterRsp => registers.rsp = value.0.Reg64,
                    WHvX64RegisterRbp => registers.rbp = value.0.Reg64,
                    WHvX64RegisterR8 => registers.r8 = value.0.Reg64,
                    WHvX64RegisterR9 => registers.r9 = value.0.Reg64,
                    WHvX64RegisterR10 => registers.r10 = value.0.Reg64,
                    WHvX64RegisterR11 => registers.r11 = value.0.Reg64,
                    WHvX64RegisterR12 => registers.r12 = value.0.Reg64,
                    WHvX64RegisterR13 => registers.r13 = value.0.Reg64,
                    WHvX64RegisterR14 => registers.r14 = value.0.Reg64,
                    WHvX64RegisterR15 => registers.r15 = value.0.Reg64,
                    WHvX64RegisterRip => registers.rip = value.0.Reg64,
                    WHvX64RegisterRflags => registers.rflags = value.0.Reg64,
                    _ => {
                        // Given unexpected register
                        return Err(FromWhpRegisterError::InvalidRegister(name_id));
                    }
                }
            }
        }

        // Set of all expected register names
        let expected_registers: HashSet<i32> =
            WHP_REGS_NAMES.map(|name| name.0).into_iter().collect();

        // Technically it should not be possible to have any missing registers at this point
        // since we are guaranteed to have WHP_REGS_NAMES_LEN (18) non-duplicate registers that have passed the match-arm above, but leaving this here for safety anyway
        let missing: HashSet<_> = expected_registers
            .difference(&seen_registers)
            .cloned()
            .collect();

        if !missing.is_empty() {
            return Err(FromWhpRegisterError::MissingRegister(missing));
        }

        Ok(registers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn common_regs() -> CommonRegisters {
        CommonRegisters {
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
            rflags: 18,
        }
    }
    #[cfg(kvm)]
    #[test]
    fn round_trip_kvm_regs() {
        let original = common_regs();
        let kvm_regs: kvm_regs = (&original).into();
        let converted: CommonRegisters = (&kvm_regs).into();
        assert_eq!(original, converted);
    }

    #[cfg(mshv)]
    #[test]
    fn round_trip_mshv_regs() {
        let original = common_regs();
        let mshv_regs: StandardRegisters = (&original).into();
        let converted: CommonRegisters = (&mshv_regs).into();
        assert_eq!(original, converted);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn round_trip_whp_regs() {
        let original = common_regs();
        let whp_regs: [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>); WHP_REGS_NAMES_LEN] =
            (&original).into();
        let converted: CommonRegisters = whp_regs.as_ref().try_into().unwrap();
        assert_eq!(original, converted);

        // test for duplicate register error handling
        let original = common_regs();
        let mut whp_regs: [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>); WHP_REGS_NAMES_LEN] =
            (&original).into();
        whp_regs[0].0 = WHvX64RegisterRbx;
        let err = CommonRegisters::try_from(whp_regs.as_ref()).unwrap_err();
        assert_eq!(
            err,
            FromWhpRegisterError::DuplicateRegister(WHvX64RegisterRbx.0)
        );

        // test for passing non-standard register (e.g. CR8)
        let original = common_regs();
        let mut whp_regs: [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>); WHP_REGS_NAMES_LEN] =
            (&original).into();
        whp_regs[0].0 = WHvX64RegisterCr8;
        let err = CommonRegisters::try_from(whp_regs.as_ref()).unwrap_err();
        assert_eq!(
            err,
            FromWhpRegisterError::InvalidRegister(WHvX64RegisterCr8.0)
        );
    }
}
