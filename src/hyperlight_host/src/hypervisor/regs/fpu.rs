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

#[cfg(kvm)]
use kvm_bindings::kvm_fpu;
#[cfg(mshv)]
use mshv_bindings::FloatingPointUnit;

pub(crate) const FP_CONTROL_WORD_DEFAULT: u16 = 0x37f; // mask all fp-exception, set rounding to nearest, set precision to 64-bit
pub(crate) const FP_TAG_WORD_DEFAULT: u8 = 0xff; // each 8 of x87 fpu registers is empty
pub(crate) const MXCSR_DEFAULT: u32 = 0x1f80; // mask simd fp-exceptions, clear exception flags, set rounding to nearest, disable flush-to-zero mode, disable denormals-are-zero mode

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct CommonFpu {
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
impl From<&CommonFpu> for Vec<(WHV_REGISTER_NAME, WHV_REGISTER_VALUE)> {
    fn from(fpu: &CommonFpu) -> Self {
        let mut regs = Vec::new();

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
            // WHvX64RegisterFpMmx{i}
            regs.push((WHV_REGISTER_NAME(WHvX64RegisterFpMmx0.0 + i as i32), value));
        }

        // FCW, FSW, FTWX, LastOpcode, LastIP → FpControlStatus
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
        regs.push((WHvX64RegisterFpControlStatus, fp_control_status));

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
            regs.push((WHV_REGISTER_NAME(WHvX64RegisterXmm0.0 + i as i32), value));
            // WHvX64RegisterXmm{i}
        }

        // LastDP, MXCSR → XmmControlStatus
        let mut xmm_control_status = WHV_REGISTER_VALUE::default();
        xmm_control_status.XmmControlStatus = WHV_X64_XMM_CONTROL_STATUS_REGISTER {
            Anonymous: WHV_X64_XMM_CONTROL_STATUS_REGISTER_0 {
                XmmStatusControl: fpu.mxcsr,
                XmmStatusControlMask: !0, // Not sure what else this should be
                Anonymous: WHV_X64_XMM_CONTROL_STATUS_REGISTER_0_0 {
                    LastFpRdp: fpu.last_dp,
                },
            },
        };
        regs.push((WHvX64RegisterXmmControlStatus, xmm_control_status)); // WHvX64RegisterXmmControlStatus
        regs
    }
}
