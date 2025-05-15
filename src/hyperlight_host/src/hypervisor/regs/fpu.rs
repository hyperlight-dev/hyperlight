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
#[cfg(mshv2)]
extern crate mshv_bindings2 as mshv_bindings;
#[cfg(mshv2)]
extern crate mshv_ioctls2 as mshv_ioctls;

#[cfg(mshv3)]
extern crate mshv_bindings3 as mshv_bindings;
#[cfg(mshv3)]
extern crate mshv_ioctls3 as mshv_ioctls;

#[cfg(target_os = "windows")]
use std::collections::HashSet;

#[cfg(kvm)]
use kvm_bindings::kvm_fpu;
#[cfg(mshv)]
use mshv_bindings::FloatingPointUnit;

#[cfg(target_os = "windows")]
use crate::hypervisor::regs::FromWhpRegisterError;

pub(crate) const FP_CONTROL_WORD_DEFAULT: u16 = 0x37f; // mask all fp-exception, set rounding to nearest, set precision to 64-bit
pub(crate) const FP_TAG_WORD_DEFAULT: u8 = 0xff; // each 8 of x87 fpu registers is empty
pub(crate) const MXCSR_DEFAULT: u32 = 0x1f80; // mask simd fp-exceptions, clear exception flags, set rounding to nearest, disable flush-to-zero mode, disable denormals-are-zero mode

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub(crate) struct CommonFpu {
    pub fpr: [[u8; 16]; 8],
    pub fcw: u16,
    pub fsw: u16,
    pub ftwx: u8,
    pub pad1: u8,
    pub last_opcode: u16,
    pub last_ip: u64,
    pub last_dp: u64,
    pub xmm: [[u8; 16]; 16],
    pub mxcsr: u32,
    pub pad2: u32,
}

#[cfg(kvm)]
impl From<CommonFpu> for kvm_fpu {
    fn from(common_fpu: CommonFpu) -> Self {
        kvm_fpu {
            fpr: common_fpu.fpr,
            fcw: common_fpu.fcw,
            fsw: common_fpu.fsw,
            ftwx: common_fpu.ftwx,
            pad1: common_fpu.pad1,
            last_opcode: common_fpu.last_opcode,
            last_ip: common_fpu.last_ip,
            last_dp: common_fpu.last_dp,
            xmm: common_fpu.xmm,
            mxcsr: common_fpu.mxcsr,
            pad2: common_fpu.pad2,
        }
    }
}

#[cfg(mshv)]
impl From<CommonFpu> for FloatingPointUnit {
    fn from(common_fpu: CommonFpu) -> FloatingPointUnit {
        FloatingPointUnit {
            fpr: common_fpu.fpr,
            fcw: common_fpu.fcw,
            fsw: common_fpu.fsw,
            ftwx: common_fpu.ftwx,
            pad1: common_fpu.pad1,
            last_opcode: common_fpu.last_opcode,
            last_ip: common_fpu.last_ip,
            last_dp: common_fpu.last_dp,
            xmm: common_fpu.xmm,
            mxcsr: common_fpu.mxcsr,
            pad2: common_fpu.pad2,
        }
    }
}

#[cfg(kvm)]
impl From<kvm_fpu> for CommonFpu {
    fn from(kvm_fpu: kvm_fpu) -> Self {
        Self {
            fpr: kvm_fpu.fpr,
            fcw: kvm_fpu.fcw,
            fsw: kvm_fpu.fsw,
            ftwx: kvm_fpu.ftwx,
            pad1: kvm_fpu.pad1,
            last_opcode: kvm_fpu.last_opcode,
            last_ip: kvm_fpu.last_ip,
            last_dp: kvm_fpu.last_dp,
            xmm: kvm_fpu.xmm,
            mxcsr: kvm_fpu.mxcsr,
            pad2: kvm_fpu.pad2,
        }
    }
}

#[cfg(mshv)]
impl From<FloatingPointUnit> for CommonFpu {
    fn from(mshv_fpu: FloatingPointUnit) -> Self {
        Self {
            fpr: mshv_fpu.fpr,
            fcw: mshv_fpu.fcw,
            fsw: mshv_fpu.fsw,
            ftwx: mshv_fpu.ftwx,
            pad1: mshv_fpu.pad1,
            last_opcode: mshv_fpu.last_opcode,
            last_ip: mshv_fpu.last_ip,
            last_dp: mshv_fpu.last_dp,
            xmm: mshv_fpu.xmm,
            mxcsr: mshv_fpu.mxcsr,
            pad2: mshv_fpu.pad2,
        }
    }
}

#[cfg(target_os = "windows")]
use windows::Win32::System::Hypervisor::*;

#[cfg(target_os = "windows")]
impl From<&CommonFpu> for [(WHV_REGISTER_NAME, WHV_REGISTER_VALUE); 26] {
    fn from(fpu: &CommonFpu) -> Self {
        let mut regs: [(WHV_REGISTER_NAME, WHV_REGISTER_VALUE); 26] = [Default::default(); 26];
        let mut idx = 0;

        // FPU/MMX registers (8 x 128-bit)
        for (i, reg) in fpu.fpr.iter().enumerate() {
            let mut value = WHV_REGISTER_VALUE::default();
            value.Reg128 = WHV_UINT128 {
                Dword: [
                    u32::from_le_bytes([reg[0], reg[1], reg[2], reg[3]]),
                    u32::from_le_bytes([reg[4], reg[5], reg[6], reg[7]]),
                    u32::from_le_bytes([reg[8], reg[9], reg[10], reg[11]]),
                    u32::from_le_bytes([reg[12], reg[13], reg[14], reg[15]]),
                ],
            };
            regs[idx] = (WHV_REGISTER_NAME(WHvX64RegisterFpMmx0.0 + i as i32), value);
            idx += 1;
        }

        // FpControlStatus
        let mut fp_control_status = WHV_REGISTER_VALUE::default();
        fp_control_status.FpControlStatus = WHV_X64_FP_CONTROL_STATUS_REGISTER {
            Anonymous: WHV_X64_FP_CONTROL_STATUS_REGISTER_0 {
                FpControl: fpu.fcw,
                FpStatus: fpu.fsw,
                FpTag: fpu.ftwx,
                Reserved: fpu.pad1,
                LastFpOp: fpu.last_opcode,
                Anonymous: WHV_X64_FP_CONTROL_STATUS_REGISTER_0_0 {
                    LastFpRip: fpu.last_ip,
                },
            },
        };
        regs[idx] = (WHvX64RegisterFpControlStatus, fp_control_status);
        idx += 1;

        // XMM registers (16 x 128-bit)
        for (i, reg) in fpu.xmm.iter().enumerate() {
            let mut value = WHV_REGISTER_VALUE::default();
            value.Reg128 = WHV_UINT128 {
                Dword: [
                    u32::from_le_bytes([reg[0], reg[1], reg[2], reg[3]]),
                    u32::from_le_bytes([reg[4], reg[5], reg[6], reg[7]]),
                    u32::from_le_bytes([reg[8], reg[9], reg[10], reg[11]]),
                    u32::from_le_bytes([reg[12], reg[13], reg[14], reg[15]]),
                ],
            };
            regs[idx] = (WHV_REGISTER_NAME(WHvX64RegisterXmm0.0 + i as i32), value);
            idx += 1;
        }

        // XmmControlStatus
        let mut xmm_control_status = WHV_REGISTER_VALUE::default();
        xmm_control_status.XmmControlStatus = WHV_X64_XMM_CONTROL_STATUS_REGISTER {
            Anonymous: WHV_X64_XMM_CONTROL_STATUS_REGISTER_0 {
                XmmStatusControl: fpu.mxcsr,
                XmmStatusControlMask: !0,
                Anonymous: WHV_X64_XMM_CONTROL_STATUS_REGISTER_0_0 {
                    LastFpRdp: fpu.last_dp,
                },
            },
        };
        regs[idx] = (WHvX64RegisterXmmControlStatus, xmm_control_status);

        regs
    }
}

#[cfg(target_os = "windows")]
pub(crate) const WHP_FPU_NAMES_LEN: usize = 26;
#[expect(dead_code, reason = "Used in get_fpu, but get_fpu is currently unused")]
#[cfg(target_os = "windows")]
pub(crate) const WHP_FPU_NAMES: [WHV_REGISTER_NAME; WHP_FPU_NAMES_LEN] = [
    WHvX64RegisterFpMmx0,
    WHvX64RegisterFpMmx1,
    WHvX64RegisterFpMmx2,
    WHvX64RegisterFpMmx3,
    WHvX64RegisterFpMmx4,
    WHvX64RegisterFpMmx5,
    WHvX64RegisterFpMmx6,
    WHvX64RegisterFpMmx7,
    WHvX64RegisterFpControlStatus,
    WHvX64RegisterXmm0,
    WHvX64RegisterXmm1,
    WHvX64RegisterXmm2,
    WHvX64RegisterXmm3,
    WHvX64RegisterXmm4,
    WHvX64RegisterXmm5,
    WHvX64RegisterXmm6,
    WHvX64RegisterXmm7,
    WHvX64RegisterXmm8,
    WHvX64RegisterXmm9,
    WHvX64RegisterXmm10,
    WHvX64RegisterXmm11,
    WHvX64RegisterXmm12,
    WHvX64RegisterXmm13,
    WHvX64RegisterXmm14,
    WHvX64RegisterXmm15,
    WHvX64RegisterXmmControlStatus,
];

#[cfg(target_os = "windows")]
impl TryFrom<&[(WHV_REGISTER_NAME, WHV_REGISTER_VALUE)]> for CommonFpu {
    type Error = FromWhpRegisterError;

    fn try_from(regs: &[(WHV_REGISTER_NAME, WHV_REGISTER_VALUE)]) -> Result<Self, Self::Error> {
        if regs.len() != WHP_FPU_NAMES_LEN {
            return Err(FromWhpRegisterError::InvalidLength(regs.len()));
        }

        let mut fpu = CommonFpu::default();
        let mut seen_registers = HashSet::new();

        for (name, value) in regs {
            let name_id = name.0;

            // Check for duplicates
            if !seen_registers.insert(name_id) {
                return Err(FromWhpRegisterError::DuplicateRegister(name_id));
            }

            match name_id {
                id if (WHvX64RegisterFpMmx0.0..WHvX64RegisterFpMmx0.0 + 8).contains(&id) => {
                    let idx = (id - WHvX64RegisterFpMmx0.0) as usize;
                    let dwords = unsafe { value.Reg128.Dword };
                    fpu.fpr[idx] = [
                        dwords[0].to_le_bytes(),
                        dwords[1].to_le_bytes(),
                        dwords[2].to_le_bytes(),
                        dwords[3].to_le_bytes(),
                    ]
                    .concat()
                    .try_into()
                    .map_err(|_| FromWhpRegisterError::InvalidEncoding)?;
                }

                id if id == WHvX64RegisterFpControlStatus.0 => {
                    let control = unsafe { value.FpControlStatus.Anonymous };
                    fpu.fcw = control.FpControl;
                    fpu.fsw = control.FpStatus;
                    fpu.ftwx = control.FpTag;
                    fpu.pad1 = control.Reserved;
                    fpu.last_opcode = control.LastFpOp;
                    fpu.last_ip = unsafe { control.Anonymous.LastFpRip };
                }

                id if (WHvX64RegisterXmm0.0..WHvX64RegisterXmm0.0 + 16).contains(&id) => {
                    let idx = (id - WHvX64RegisterXmm0.0) as usize;
                    let dwords = unsafe { value.Reg128.Dword };
                    fpu.xmm[idx] = [
                        dwords[0].to_le_bytes(),
                        dwords[1].to_le_bytes(),
                        dwords[2].to_le_bytes(),
                        dwords[3].to_le_bytes(),
                    ]
                    .concat()
                    .try_into()
                    .map_err(|_| FromWhpRegisterError::InvalidEncoding)?;
                }

                id if id == WHvX64RegisterXmmControlStatus.0 => {
                    let control = unsafe { value.XmmControlStatus.Anonymous };
                    fpu.mxcsr = control.XmmStatusControl;
                    fpu.last_dp = unsafe { control.Anonymous.LastFpRdp };
                }

                _ => {
                    return Err(FromWhpRegisterError::InvalidRegister(name_id));
                }
            }
        }

        // Set of all expected register names
        let expected_registers: HashSet<i32> = [
            WHvX64RegisterFpMmx0.0,
            WHvX64RegisterFpMmx1.0,
            WHvX64RegisterFpMmx2.0,
            WHvX64RegisterFpMmx3.0,
            WHvX64RegisterFpMmx4.0,
            WHvX64RegisterFpMmx5.0,
            WHvX64RegisterFpMmx6.0,
            WHvX64RegisterFpMmx7.0,
            WHvX64RegisterFpControlStatus.0,
            WHvX64RegisterXmm0.0,
            WHvX64RegisterXmm1.0,
            WHvX64RegisterXmm2.0,
            WHvX64RegisterXmm3.0,
            WHvX64RegisterXmm4.0,
            WHvX64RegisterXmm5.0,
            WHvX64RegisterXmm6.0,
            WHvX64RegisterXmm7.0,
            WHvX64RegisterXmm8.0,
            WHvX64RegisterXmm9.0,
            WHvX64RegisterXmm10.0,
            WHvX64RegisterXmm11.0,
            WHvX64RegisterXmm12.0,
            WHvX64RegisterXmm13.0,
            WHvX64RegisterXmm14.0,
            WHvX64RegisterXmm15.0,
            WHvX64RegisterXmmControlStatus.0,
        ]
        .into_iter()
        .collect();

        // Technically it should not be possible to have any missing registers at this point
        // since we are guaranteed to have 18 non-duplicate registers that have passed the match-arm above, but leaving this here for safety anyway
        let missing: HashSet<i32> = expected_registers
            .difference(&seen_registers)
            .cloned()
            .collect();

        if !missing.is_empty() {
            return Err(FromWhpRegisterError::MissingRegister(missing));
        }

        Ok(fpu)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_common_fpu() -> CommonFpu {
        CommonFpu {
            fpr: [
                [1u8; 16], [2u8; 16], [3u8; 16], [4u8; 16], [5u8; 16], [6u8; 16], [7u8; 16],
                [8u8; 16],
            ],
            fcw: 0x1234,
            fsw: 0x5678,
            ftwx: 0x9a,
            pad1: 0xbc,
            last_opcode: 0xdef0,
            last_ip: 0xdeadbeefcafebabe,
            last_dp: 0xabad1deaf00dbabe,
            xmm: [
                [8u8; 16], [9u8; 16], [10u8; 16], [11u8; 16], [12u8; 16], [13u8; 16], [14u8; 16],
                [15u8; 16], [16u8; 16], [17u8; 16], [18u8; 16], [19u8; 16], [20u8; 16], [21u8; 16],
                [22u8; 16], [23u8; 16],
            ],
            mxcsr: 0x1f80,
            pad2: 0,
        }
    }

    #[cfg(kvm)]
    #[test]
    fn round_trip_kvm_fpu() {
        use kvm_bindings::kvm_fpu;

        let original = sample_common_fpu();
        let kvm: kvm_fpu = original.into();
        let round_tripped = CommonFpu::from(kvm);

        assert_eq!(original, round_tripped);
    }

    #[cfg(mshv)]
    #[test]
    fn round_trip_mshv_fpu() {
        use mshv_bindings::FloatingPointUnit;

        let original = sample_common_fpu();
        let mshv: FloatingPointUnit = original.into();
        let round_tripped = CommonFpu::from(mshv);

        assert_eq!(original, round_tripped);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn round_trip_windows_fpu() {
        use windows::Win32::System::Hypervisor::*;

        let original = sample_common_fpu();
        let windows: [(WHV_REGISTER_NAME, WHV_REGISTER_VALUE); 26] = (&original).into();
        let round_tripped = CommonFpu::try_from(windows.as_ref()).unwrap();
        assert_eq!(original, round_tripped);

        // test for duplicate register error handling
        let original = sample_common_fpu();
        let mut windows: [(WHV_REGISTER_NAME, WHV_REGISTER_VALUE); 26] = (&original).into();
        windows[0].0 = WHvX64RegisterFpMmx1;
        let err = CommonFpu::try_from(windows.as_ref()).unwrap_err();
        assert_eq!(
            err,
            FromWhpRegisterError::DuplicateRegister(WHvX64RegisterFpMmx1.0)
        );

        // test for passing non-fpu register (e.g. RAX)
        let original = sample_common_fpu();
        let mut windows: [(WHV_REGISTER_NAME, WHV_REGISTER_VALUE); 26] = (&original).into();
        windows[0] = (WHvX64RegisterRax, windows[0].1);
        let err = CommonFpu::try_from(windows.as_ref()).unwrap_err();
        assert_eq!(
            err,
            FromWhpRegisterError::InvalidRegister(WHvX64RegisterRax.0)
        );
    }
}
