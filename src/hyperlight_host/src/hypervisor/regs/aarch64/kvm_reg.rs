use core::marker::PhantomData;
use core::mem::{self, MaybeUninit};

use kvm_bindings::{
    KVM_REG_ARM64, KVM_REG_ARM64_SYSREG, KVM_REG_ARM64_SYSREG_CRM_MASK,
    KVM_REG_ARM64_SYSREG_CRM_SHIFT, KVM_REG_ARM64_SYSREG_CRN_MASK, KVM_REG_ARM64_SYSREG_CRN_SHIFT,
    KVM_REG_ARM64_SYSREG_OP0_MASK, KVM_REG_ARM64_SYSREG_OP0_SHIFT, KVM_REG_ARM64_SYSREG_OP1_MASK,
    KVM_REG_ARM64_SYSREG_OP1_SHIFT, KVM_REG_ARM64_SYSREG_OP2_MASK, KVM_REG_ARM64_SYSREG_OP2_SHIFT,
    KVM_REG_SIZE_U32, KVM_REG_SIZE_U64, KVM_REG_SIZE_U128,
};
use kvm_ioctls::VcpuFd;

trait KvmRegisterType: Sized {
    const KVM_REG_SIZE: u64;
    fn get_reg(fd: &VcpuFd, reg: KvmRegister<Self>) -> Result<Self, kvm_ioctls::Error>;
    fn set_reg(fd: &VcpuFd, reg: KvmRegister<Self>, val: Self) -> Result<(), kvm_ioctls::Error>;
}
macro_rules! kvm_register_type {
    ($t:ident, $k:ident) => {
        impl KvmRegisterType for $t {
            const KVM_REG_SIZE: u64 = $k;
            fn get_reg(fd: &VcpuFd, reg: KvmRegister<Self>) -> Result<Self, kvm_ioctls::Error> {
                get_reg_bytes::<{core::mem::size_of::<Self>()}>(fd, reg.kvm_encoding()).map(Self::from_ne_bytes)
            }
            fn set_reg(fd: &VcpuFd, reg: KvmRegister<Self>, val: Self) -> Result<(), kvm_ioctls::Error> {
                set_reg_bytes::<{core::mem::size_of::<Self>()}>(fd, reg.kvm_encoding(), val.to_ne_bytes())
            }
        }
    }
}
kvm_register_type!(u32, KVM_REG_SIZE_U32);
kvm_register_type!(u64, KVM_REG_SIZE_U64);
kvm_register_type!(u128, KVM_REG_SIZE_U128);

#[derive(Clone, Copy)]
enum KvmRegister_ {
    Sysreg { op0: u8, op1: u8, crn: u8, crm: u8, op2: u8 },
    Core { offset: u16 },
}
#[derive(Clone, Copy)]
pub(crate) struct KvmRegister<T: KvmRegisterType>(KvmRegister_, PhantomData<T>);
impl<T: KvmRegisterType> KvmRegister<T> {
    const fn kvm_encoding(&self) -> u64 {
        KVM_REG_ARM64 | match self.0 {
            KvmRegister_::Sysreg { op0, op1, crn, crm, op2 } => (KVM_REG_ARM64_SYSREG as u64)
                | (((op0 as u64) << KVM_REG_ARM64_SYSREG_OP0_SHIFT) & KVM_REG_ARM64_SYSREG_OP0_MASK as u64)
                | (((op1 as u64) << KVM_REG_ARM64_SYSREG_OP1_SHIFT) & KVM_REG_ARM64_SYSREG_OP1_MASK as u64)
                | (((crn as u64) << KVM_REG_ARM64_SYSREG_CRN_SHIFT) & KVM_REG_ARM64_SYSREG_CRN_MASK as u64)
                | (((crm as u64) << KVM_REG_ARM64_SYSREG_CRM_SHIFT) & KVM_REG_ARM64_SYSREG_CRM_MASK as u64)
                | (((op2 as u64) << KVM_REG_ARM64_SYSREG_OP2_SHIFT) & KVM_REG_ARM64_SYSREG_OP2_MASK as u64),
            KvmRegister_::Core { offset } =>  0x10_0000u64 | offset as u64
        } | T::KVM_REG_SIZE
    }
    pub(crate) fn get<E1: From<kvm_ioctls::Error>, E2>(self, err: impl Fn(E1) -> E2, fd: &VcpuFd) -> Result<T, E2> {
        T::get_reg(fd, self).map_err(|e| err(e.into()))
    }
    pub(crate) fn set<E1: From<kvm_ioctls::Error>, E2>(self, err: impl Fn(E1) -> E2, fd: &VcpuFd, val: T) -> Result<(), E2> {
        T::set_reg(fd, self, val).map_err(|e| err(e.into()))
    }
}

macro_rules! decl_sys_reg {
    ($name:ident, $op0:expr, $op1:expr, $crn:expr, $crm:expr, $op2:expr, $size:ident) => {
        pub const $name: KvmRegister<$size> = KvmRegister(KvmRegister_::Sysreg { op0: $op0, op1: $op1, crn: $crn, crm: $crm, op2: $op2 }, PhantomData);
    };
}
decl_sys_reg!(TTBR0_EL1, 0b11, 0b000, 0b0010, 0b0000, 0b000, u64);
decl_sys_reg!(TCR_EL1,   0b11, 0b000, 0b0010, 0b0000, 0b010, u64);
decl_sys_reg!(MAIR_EL1,  0b11, 0b000, 0b1010, 0b0010, 0b000, u64);
decl_sys_reg!(SCTLR_EL1, 0b11, 0b000, 0b0001, 0b0000, 0b000, u64);
decl_sys_reg!(CPACR_EL1, 0b11, 0b000, 0b0001, 0b0000, 0b010, u64);
decl_sys_reg!(VBAR_EL1,  0b11, 0b000, 0b1100, 0b0000, 0b000, u64);

pub const X: [KvmRegister<u64>; 31] = {
    let mut r: [MaybeUninit<KvmRegister<u64>>; 31] = [MaybeUninit::uninit(); 31];
    let mut i: u16 = 0;
    while i < 31 {
        r[i as usize].write(KvmRegister(
            KvmRegister_::Core { offset: i * 2 },
            PhantomData,
        ));
        i += 1;
    }
    unsafe { mem::transmute::<_, [KvmRegister<u64>; 31]>(r) }
};
macro_rules! decl_core_reg {
    ($name:ident, $offset:expr, $size:ident) => {
        pub const $name: KvmRegister<$size> = KvmRegister(KvmRegister_::Core { offset: $offset }, PhantomData);
    };
}
decl_core_reg!(SP,     0x3E, u64);
decl_core_reg!(PC,     0x40, u64);
decl_core_reg!(PSTATE, 0x42, u64);
decl_core_reg!(SP_EL1, 0x44, u64);
// ignore the other SPSRs that are just for AA32-compat
pub const V: [KvmRegister<u128>; 32] = {
    let mut r: [MaybeUninit<KvmRegister<u128>>; 32] = [MaybeUninit::uninit(); 32];
    let mut i: u16 = 0;
    while i < 32 {
        r[i as usize].write(KvmRegister(
            KvmRegister_::Core { offset: 0x54 + i * 4 },
            PhantomData,
        ));
        i += 1;
    }
    unsafe { mem::transmute::<_, [KvmRegister<u128>; 32]>(r) }

};
decl_core_reg!(FPSR, 0xd4, u32);
decl_core_reg!(FPCR, 0xd5, u32);

fn get_reg_bytes<const N: usize>(
    fd: &VcpuFd,
    id: u64,
) -> Result<[u8; N], kvm_ioctls::Error> {
    let mut buf: [u8; N] = [0; N];
    fd.get_one_reg(id, &mut buf)?;
    Ok(buf)
}

pub(crate) fn set_reg_bytes<const N: usize>(
    fd: &VcpuFd,
    id: u64,
    bytes: [u8; N],
) -> Result<(), kvm_ioctls::Error> {
    fd.set_one_reg(id, &bytes)?;
    Ok(())
}
