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

#[cfg(kvm)]
use kvm_bindings::kvm_debugregs;
#[cfg(mshv3)]
use mshv_bindings::DebugRegisters;

/// Common abstraction for x86 debug registers (DR0-DR7).
#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub(crate) struct CommonDebugRegs {
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
}

#[cfg(kvm)]
impl From<kvm_debugregs> for CommonDebugRegs {
    fn from(kvm_regs: kvm_debugregs) -> Self {
        Self {
            dr0: kvm_regs.db[0],
            dr1: kvm_regs.db[1],
            dr2: kvm_regs.db[2],
            dr3: kvm_regs.db[3],
            dr6: kvm_regs.dr6,
            dr7: kvm_regs.dr7,
        }
    }
}
#[cfg(kvm)]
impl From<&CommonDebugRegs> for kvm_debugregs {
    fn from(common_regs: &CommonDebugRegs) -> Self {
        kvm_debugregs {
            db: [
                common_regs.dr0,
                common_regs.dr1,
                common_regs.dr2,
                common_regs.dr3,
            ],
            dr6: common_regs.dr6,
            dr7: common_regs.dr7,
            ..Default::default()
        }
    }
}
#[cfg(mshv3)]
impl From<DebugRegisters> for CommonDebugRegs {
    fn from(mshv_regs: DebugRegisters) -> Self {
        Self {
            dr0: mshv_regs.dr0,
            dr1: mshv_regs.dr1,
            dr2: mshv_regs.dr2,
            dr3: mshv_regs.dr3,
            dr6: mshv_regs.dr6,
            dr7: mshv_regs.dr7,
        }
    }
}
#[cfg(mshv3)]
impl From<&CommonDebugRegs> for DebugRegisters {
    fn from(common_regs: &CommonDebugRegs) -> Self {
        DebugRegisters {
            dr0: common_regs.dr0,
            dr1: common_regs.dr1,
            dr2: common_regs.dr2,
            dr3: common_regs.dr3,
            dr6: common_regs.dr6,
            dr7: common_regs.dr7,
        }
    }
}

#[cfg(target_os = "windows")]
use windows::Win32::System::Hypervisor::*;

#[cfg(target_os = "windows")]
impl From<&CommonDebugRegs>
    for [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>); WHP_DEBUG_REGS_NAMES_LEN]
{
    fn from(regs: &CommonDebugRegs) -> Self {
        [
            (
                WHvX64RegisterDr0,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.dr0 }),
            ),
            (
                WHvX64RegisterDr1,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.dr1 }),
            ),
            (
                WHvX64RegisterDr2,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.dr2 }),
            ),
            (
                WHvX64RegisterDr3,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.dr3 }),
            ),
            (
                WHvX64RegisterDr6,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.dr6 }),
            ),
            (
                WHvX64RegisterDr7,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.dr7 }),
            ),
        ]
    }
}

#[cfg(target_os = "windows")]
use std::collections::HashSet;

#[cfg(target_os = "windows")]
use super::{Align16, FromWhpRegisterError};

#[cfg(target_os = "windows")]
pub(crate) const WHP_DEBUG_REGS_NAMES_LEN: usize = 6;
#[cfg(target_os = "windows")]
pub(crate) const WHP_DEBUG_REGS_NAMES: [WHV_REGISTER_NAME; WHP_DEBUG_REGS_NAMES_LEN] = [
    WHvX64RegisterDr0,
    WHvX64RegisterDr1,
    WHvX64RegisterDr2,
    WHvX64RegisterDr3,
    WHvX64RegisterDr6,
    WHvX64RegisterDr7,
];

#[cfg(target_os = "windows")]
impl TryFrom<&[(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>)]> for CommonDebugRegs {
    type Error = FromWhpRegisterError;

    #[expect(
        non_upper_case_globals,
        reason = "Windows API has lowercase register names"
    )]
    fn try_from(
        regs: &[(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>)],
    ) -> Result<Self, Self::Error> {
        if regs.len() != WHP_DEBUG_REGS_NAMES_LEN {
            return Err(FromWhpRegisterError::InvalidLength(regs.len()));
        }
        let mut registers = CommonDebugRegs::default();
        let mut seen_registers = HashSet::new();

        for &(name, value) in regs {
            let name_id = name.0;

            // Check for duplicates
            if !seen_registers.insert(name_id) {
                return Err(FromWhpRegisterError::DuplicateRegister(name_id));
            }

            unsafe {
                match name {
                    WHvX64RegisterDr0 => registers.dr0 = value.0.Reg64,
                    WHvX64RegisterDr1 => registers.dr1 = value.0.Reg64,
                    WHvX64RegisterDr2 => registers.dr2 = value.0.Reg64,
                    WHvX64RegisterDr3 => registers.dr3 = value.0.Reg64,
                    WHvX64RegisterDr6 => registers.dr6 = value.0.Reg64,
                    WHvX64RegisterDr7 => registers.dr7 = value.0.Reg64,
                    _ => {
                        // Given unexpected register
                        return Err(FromWhpRegisterError::InvalidRegister(name_id));
                    }
                }
            }
        }

        // Set of all expected register names
        let expected_registers: HashSet<i32> = WHP_DEBUG_REGS_NAMES
            .map(|name| name.0)
            .into_iter()
            .collect();

        // Technically it should not be possible to have any missing registers at this point
        // since we are guaranteed to have WHP_DEBUG_REGS_NAMES_LEN (6) non-duplicate registers that have passed the match-arm above, but leaving this here for safety anyway
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

    fn common_debug_regs() -> CommonDebugRegs {
        CommonDebugRegs {
            dr0: 1,
            dr1: 2,
            dr2: 3,
            dr3: 4,
            dr6: 5,
            dr7: 6,
        }
    }

    #[cfg(kvm)]
    #[test]
    fn round_trip_kvm_debug_regs() {
        let original = common_debug_regs();
        let kvm_regs: kvm_debugregs = (&original).into();
        let converted: CommonDebugRegs = kvm_regs.into();
        assert_eq!(original, converted);
    }

    #[cfg(mshv3)]
    #[test]
    fn round_trip_mshv_debug_regs() {
        let original = common_debug_regs();
        let mshv_regs: DebugRegisters = (&original).into();
        let converted: CommonDebugRegs = mshv_regs.into();
        assert_eq!(original, converted);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn round_trip_whp_debug_regs() {
        let original = common_debug_regs();
        let whp_regs: [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>); WHP_DEBUG_REGS_NAMES_LEN] =
            (&original).into();
        let converted: CommonDebugRegs = whp_regs.as_ref().try_into().unwrap();
        assert_eq!(original, converted);

        // test for duplicate register error handling
        let original = common_debug_regs();
        let mut whp_regs: [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>);
            WHP_DEBUG_REGS_NAMES_LEN] = (&original).into();
        whp_regs[0].0 = WHvX64RegisterDr1;
        let err = CommonDebugRegs::try_from(whp_regs.as_ref()).unwrap_err();
        assert_eq!(
            err,
            FromWhpRegisterError::DuplicateRegister(WHvX64RegisterDr1.0)
        );

        // test for passing non-standard register (e.g. CR8)
        let original = common_debug_regs();
        let mut whp_regs: [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>);
            WHP_DEBUG_REGS_NAMES_LEN] = (&original).into();
        whp_regs[0].0 = WHvX64RegisterCr8;
        let err = CommonDebugRegs::try_from(whp_regs.as_ref()).unwrap_err();
        assert_eq!(
            err,
            FromWhpRegisterError::InvalidRegister(WHvX64RegisterCr8.0)
        );
    }
}
