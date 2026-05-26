use kvm_bindings::{
    KVM_REG_ARM64, KVM_REG_ARM64_SYSREG, KVM_REG_ARM64_SYSREG_CRM_MASK,
    KVM_REG_ARM64_SYSREG_CRM_SHIFT, KVM_REG_ARM64_SYSREG_CRN_MASK, KVM_REG_ARM64_SYSREG_CRN_SHIFT,
    KVM_REG_ARM64_SYSREG_OP0_MASK, KVM_REG_ARM64_SYSREG_OP0_SHIFT, KVM_REG_ARM64_SYSREG_OP1_MASK,
    KVM_REG_ARM64_SYSREG_OP1_SHIFT, KVM_REG_ARM64_SYSREG_OP2_MASK, KVM_REG_ARM64_SYSREG_OP2_SHIFT,
    KVM_REG_SIZE_U32, KVM_REG_SIZE_U64, KVM_REG_SIZE_U128,
};
use kvm_ioctls::VcpuFd;

enum Size {
    U32,
    U64,
    U128,
}
const fn size_kvm_bits(s: Size) -> u64 {
    match s {
        Size::U32 => KVM_REG_SIZE_U32,
        Size::U64 => KVM_REG_SIZE_U64,
        Size::U128 => KVM_REG_SIZE_U128,
    }
}
const fn kvm_sys_reg(op0: u8, op1: u8, crn: u8, crm: u8, op2: u8, s: Size) -> u64 {
    KVM_REG_ARM64
        | (KVM_REG_ARM64_SYSREG as u64)
        | (((op0 as u64) << KVM_REG_ARM64_SYSREG_OP0_SHIFT) & KVM_REG_ARM64_SYSREG_OP0_MASK as u64)
        | (((op1 as u64) << KVM_REG_ARM64_SYSREG_OP1_SHIFT) & KVM_REG_ARM64_SYSREG_OP1_MASK as u64)
        | (((crn as u64) << KVM_REG_ARM64_SYSREG_CRN_SHIFT) & KVM_REG_ARM64_SYSREG_CRN_MASK as u64)
        | (((crm as u64) << KVM_REG_ARM64_SYSREG_CRM_SHIFT) & KVM_REG_ARM64_SYSREG_CRM_MASK as u64)
        | (((op2 as u64) << KVM_REG_ARM64_SYSREG_OP2_SHIFT) & KVM_REG_ARM64_SYSREG_OP2_MASK as u64)
        | size_kvm_bits(s)
}
macro_rules! decl_sys_reg {
    ($name:ident, $op0:expr, $op1:expr, $crn:expr, $crm:expr, $op2:expr, $size:ident) => {
        pub const $name: u64 = kvm_sys_reg($op0, $op1, $crn, $crm, $op2, Size::$size);
    };
}
decl_sys_reg!(TTBR0_EL1, 0b11, 0b000, 0b0010, 0b0000, 0b000, U64);
decl_sys_reg!(TCR_EL1, 0b11, 0b000, 0b0010, 0b0000, 0b010, U64);
decl_sys_reg!(MAIR_EL1, 0b11, 0b000, 0b1010, 0b0010, 0b000, U64);
decl_sys_reg!(SCTLR_EL1, 0b11, 0b000, 0b0001, 0b0000, 0b000, U64);
decl_sys_reg!(CPACR_EL1, 0b11, 0b000, 0b0001, 0b0000, 0b010, U64);
decl_sys_reg!(VBAR_EL1, 0b11, 0b000, 0b1100, 0b0000, 0b000, U64);

const fn kvm_core_reg(offset: u8, s: Size) -> u64 {
    KVM_REG_ARM64 | 0x10_0000u64 | offset as u64 | size_kvm_bits(s)
}
macro_rules! decl_core_reg {
    ($name:ident, $offset:expr, $size:ident) => {
        pub const $name: u64 = kvm_core_reg($offset, Size::$size);
    };
}
decl_core_reg!(X0, 0x00, U64);
decl_core_reg!(X1, 0x02, U64);
decl_core_reg!(X2, 0x04, U64);
decl_core_reg!(X3, 0x06, U64);
decl_core_reg!(X4, 0x08, U64);
decl_core_reg!(X5, 0x0A, U64);
decl_core_reg!(X6, 0x0C, U64);
decl_core_reg!(X7, 0x0E, U64);
decl_core_reg!(X8, 0x10, U64);
decl_core_reg!(X9, 0x12, U64);
decl_core_reg!(X10, 0x14, U64);
decl_core_reg!(X11, 0x16, U64);
decl_core_reg!(X12, 0x18, U64);
decl_core_reg!(X13, 0x1A, U64);
decl_core_reg!(X14, 0x1C, U64);
decl_core_reg!(X15, 0x1E, U64);
decl_core_reg!(X16, 0x20, U64);
decl_core_reg!(X17, 0x22, U64);
decl_core_reg!(X18, 0x24, U64);
decl_core_reg!(X19, 0x26, U64);
decl_core_reg!(X20, 0x28, U64);
decl_core_reg!(X21, 0x2A, U64);
decl_core_reg!(X22, 0x2C, U64);
decl_core_reg!(X23, 0x2E, U64);
decl_core_reg!(X24, 0x30, U64);
decl_core_reg!(X25, 0x32, U64);
decl_core_reg!(X26, 0x34, U64);
decl_core_reg!(X27, 0x36, U64);
decl_core_reg!(X28, 0x38, U64);
decl_core_reg!(X29, 0x3A, U64);
decl_core_reg!(X30, 0x3C, U64);
decl_core_reg!(SP, 0x3E, U64);
decl_core_reg!(PC, 0x40, U64);
decl_core_reg!(PSTATE, 0x42, U64);
decl_core_reg!(SP_EL1, 0x44, U64);
// ignore the other SPSRs that are just for AA32-compat
decl_core_reg!(V0, 0x54, U128);
decl_core_reg!(V1, 0x58, U128);
decl_core_reg!(V2, 0x5c, U128);
decl_core_reg!(V3, 0x60, U128);
decl_core_reg!(V4, 0x64, U128);
decl_core_reg!(V5, 0x68, U128);
decl_core_reg!(V6, 0x6c, U128);
decl_core_reg!(V7, 0x70, U128);
decl_core_reg!(V8, 0x74, U128);
decl_core_reg!(V9, 0x78, U128);
decl_core_reg!(V10, 0x7c, U128);
decl_core_reg!(V11, 0x80, U128);
decl_core_reg!(V12, 0x84, U128);
decl_core_reg!(V13, 0x88, U128);
decl_core_reg!(V14, 0x8c, U128);
decl_core_reg!(V15, 0x90, U128);
decl_core_reg!(V16, 0x94, U128);
decl_core_reg!(V17, 0x98, U128);
decl_core_reg!(V18, 0x9c, U128);
decl_core_reg!(V19, 0xa0, U128);
decl_core_reg!(V20, 0xa4, U128);
decl_core_reg!(V21, 0xa8, U128);
decl_core_reg!(V22, 0xac, U128);
decl_core_reg!(V23, 0xb0, U128);
decl_core_reg!(V24, 0xb4, U128);
decl_core_reg!(V25, 0xb8, U128);
decl_core_reg!(V26, 0xbc, U128);
decl_core_reg!(V27, 0xc0, U128);
decl_core_reg!(V28, 0xc4, U128);
decl_core_reg!(V29, 0xc8, U128);
decl_core_reg!(V30, 0xcc, U128);
decl_core_reg!(V31, 0xd0, U128);
decl_core_reg!(FPSR, 0xd4, U32);
decl_core_reg!(FPCR, 0xd4, U32);

pub(crate) fn get_reg_bytes<const N: usize, E>(
    fd: &VcpuFd,
    id: u64,
    err: impl Fn(kvm_ioctls::Error) -> E,
) -> Result<[u8; N], E> {
    let mut buf: [u8; N] = [0; N];
    fd.get_one_reg(id, &mut buf).map_err(err)?;
    Ok(buf)
}
macro_rules! get_reg {
    ($fd:expr, $err:expr, $reg:ident, $t:ident) => {
        $crate::hypervisor::regs::kvm_reg::get_reg_bytes::<{ core::mem::size_of::<$t>() }, _>(
            $fd,
            $crate::hypervisor::regs::kvm_reg::$reg,
            $err,
        )
        .map($t::from_ne_bytes)
    };
}
pub(crate) use get_reg;
pub(crate) fn set_reg_bytes<const N: usize, E>(
    fd: &VcpuFd,
    err: impl Fn(kvm_ioctls::Error) -> E,
    id: u64,
    bytes: [u8; N],
) -> Result<(), E> {
    fd.set_one_reg(id, &bytes).map_err(err)?;
    Ok(())
}
macro_rules! set_reg {
    ($fd:expr, $err:expr, $reg:ident, $t:ident, $val:expr) => {
        $crate::hypervisor::regs::kvm_reg::set_reg_bytes::<{ core::mem::size_of::<$t>() }, _>(
            $fd,
            $err,
            $crate::hypervisor::regs::kvm_reg::$reg,
            $val.to_ne_bytes(),
        )
    };
}
pub(crate) use set_reg;
