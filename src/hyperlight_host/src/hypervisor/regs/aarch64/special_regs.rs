#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub(crate) struct CommonSpecialRegisters {
    pub(crate) ttbr0_el1: u64,
    // todo: handle ttbr1 as well
    pub(crate) tcr_el1: u64,
    pub(crate) mair_el1: u64,
    pub(crate) sctlr_el1: u64,
    pub(crate) cpacr_el1: u64,
    pub(crate) vbar_el1: u64,
    pub(crate) sp_el1: u64,
}

pub(crate) const TCR_EL1_PS_48: u64 = 0b101u64 << 32;
pub(crate) const TCR_EL1_TG0_4K: u64 = 0b00u64 << 14;
pub(crate) const TCR_EL1_TG1_4K: u64 = 0b00u64 << 30;
#[allow(clippy::identity_op)]
pub(crate) const TCR_EL1_T0SZ_48: u64 = 16u64 << 0;
pub(crate) const TCR_EL1_T1SZ_48: u64 = 16u64 << 16;

pub(crate) const MAIR_NORMAL_OWT_NT_AA: u64 = 0b10111011;
pub(crate) const MAIR_ITEM_WIDTH: u8 = 8;

pub(crate) const SCTLR_EL1_RES1: u64 = 0b11u64 << 28 | 0b11u64 << 22 | 0b1u64 << 20 | 0b1u64 << 11;
pub(crate) const SCTLR_EL1_M: u64 = 0b1u64 << 0;
pub(crate) const SCTLR_EL1_C: u64 = 0b1u64 << 2;

pub(crate) const CPACR_EL1_FPEN_NO_TRAP: u64 = 0b11 << 20;

impl CommonSpecialRegisters {
    pub(crate) fn defaults(root_pt_addr: u64) -> Self {
        CommonSpecialRegisters {
            ttbr0_el1: root_pt_addr & !0xfff,
            tcr_el1: TCR_EL1_PS_48
                | TCR_EL1_TG0_4K
                | TCR_EL1_TG1_4K
                | TCR_EL1_T0SZ_48
                | TCR_EL1_T1SZ_48,
            mair_el1: MAIR_NORMAL_OWT_NT_AA
                << (MAIR_ITEM_WIDTH * hyperlight_common::vmem::ATTR_INDEX_NORMAL),
            sctlr_el1: SCTLR_EL1_RES1 | SCTLR_EL1_M | SCTLR_EL1_C,
            cpacr_el1: CPACR_EL1_FPEN_NO_TRAP,
            vbar_el1: 0,
            sp_el1: 0,
        }
    }
}
