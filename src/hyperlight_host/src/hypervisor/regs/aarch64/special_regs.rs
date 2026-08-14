/*
Copyright 2026 The Hyperlight Authors.

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

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Copy, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommonSpecialRegisters {
    // When serializing for a snapshot, skip TTBRs which will be
    // recomputed from the snapshot layout
    #[serde(skip)]
    pub(crate) ttbr0_el1: u64,
    // todo: handle ttbr1 as well
    pub(crate) tcr_el1: u64,
    pub(crate) mair_el1: u64,
    pub(crate) sctlr_el1: u64,
    pub(crate) cpacr_el1: u64,
    pub(crate) vbar_el1: u64,
    pub(crate) sp_el1: u64,
}

#[cfg(any(kvm, mshv3, hvf))]
pub(crate) const TCR_EL1_PS_48: u64 = 0b101u64 << 32;
#[cfg(any(kvm, mshv3, hvf))]
pub(crate) const TCR_EL1_TG0_4K: u64 = 0b00u64 << 14;
#[cfg(any(kvm, mshv3, hvf))]
pub(crate) const TCR_EL1_TG1_4K: u64 = 0b10u64 << 30;
#[cfg(any(kvm, mshv3, hvf))]
#[allow(clippy::identity_op)]
pub(crate) const TCR_EL1_T0SZ_48: u64 = 16u64 << 0;
#[cfg(any(kvm, mshv3, hvf))]
pub(crate) const TCR_EL1_T1SZ_48: u64 = 16u64 << 16;
#[cfg(any(kvm, mshv3, hvf))]
pub(crate) const TCR_EL1_IRGN0_WB_AA: u64 = 0b01 << 8;
#[cfg(any(kvm, mshv3, hvf))]
pub(crate) const TCR_EL1_ORGN0_WB_AA: u64 = 0b01 << 10;
#[cfg(any(kvm, mshv3, hvf))]
pub(crate) const TCR_EL1_SH0_ISH: u64 = 0b11 << 12;

#[cfg(any(kvm, mshv3, hvf))]
pub(crate) const MAIR_NORMAL_OWB_NT_AA: u64 = 0b1111_1111;
#[cfg(any(kvm, mshv3, hvf))]
pub(crate) const MAIR_ITEM_WIDTH: u8 = 8;

#[cfg(any(kvm, mshv3, hvf))]
pub(crate) const SCTLR_EL1_RES1: u64 = 0b11u64 << 28 | 0b11u64 << 22 | 0b1u64 << 20 | 0b1u64 << 11;
#[cfg(any(kvm, mshv3, hvf))]
pub(crate) const SCTLR_EL1_M: u64 = 0b1u64 << 0;
#[cfg(any(kvm, mshv3, hvf))]
pub(crate) const SCTLR_EL1_C: u64 = 0b1u64 << 2;
#[cfg(any(kvm, mshv3, hvf))]
pub(crate) const SCTLR_EL1_I: u64 = 0b1u64 << 12;

#[cfg(any(kvm, mshv3, hvf))]
pub(crate) const CPACR_EL1_FPEN_NO_TRAP: u64 = 0b11 << 20;

#[cfg(any(kvm, mshv3, hvf))]
impl CommonSpecialRegisters {
    pub(crate) fn defaults(root_pt_addr: u64) -> Self {
        CommonSpecialRegisters {
            ttbr0_el1: root_pt_addr & !0xfff,
            tcr_el1: TCR_EL1_PS_48
                | TCR_EL1_TG0_4K
                | TCR_EL1_TG1_4K
                | TCR_EL1_T0SZ_48
                | TCR_EL1_T1SZ_48
                | TCR_EL1_IRGN0_WB_AA
                | TCR_EL1_ORGN0_WB_AA
                | TCR_EL1_SH0_ISH,
            mair_el1: MAIR_NORMAL_OWB_NT_AA
                << (MAIR_ITEM_WIDTH * hyperlight_common::vmem::ATTR_INDEX_NORMAL),
            sctlr_el1: SCTLR_EL1_RES1 | SCTLR_EL1_M | SCTLR_EL1_C | SCTLR_EL1_I,
            cpacr_el1: CPACR_EL1_FPEN_NO_TRAP,
            vbar_el1: 0,
            sp_el1: 0,
        }
    }
}
