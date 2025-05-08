use kvm_bindings::kvm_fpu;
use mshv_bindings2::FloatingPointUnit;

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
