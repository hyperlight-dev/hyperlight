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
use kvm_bindings::kvm_fpu;
use mshv_bindings2::FloatingPointUnit;

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
