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

//! Model-specific register (MSR) state restored with a snapshot.
//!
//! The reset set contains every MSR whose guest-written state can persist.
//! Allowing guest access to an MSR is a separate concern. Allowed MSRs still
//! reset.

use serde::{Deserialize, Serialize};

/// A single MSR captured for reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MsrEntry {
    /// The index passed to `RDMSR` and `WRMSR`.
    pub index: u32,
    /// The captured value.
    pub value: u64,
}

/// The MSR reset set and initialization baseline for one VM.
#[derive(Debug, Clone)]
pub(crate) struct MsrResetState {
    /// Creation-time value for every MSR this VM resets on restore and
    /// captures in a snapshot: core indices, required MTRRs, and the allow
    /// list. Sorted by index and deduplicated.
    baseline: Vec<MsrEntry>,
    /// The user-supplied allow list (`SandboxConfiguration::allow_msrs`),
    /// sorted and deduplicated. A subset of the `baseline` indices, kept as a
    /// separate copy so restore can compare it, as a superset, against a
    /// snapshot's allow list.
    allowed: Vec<u32>,
}

impl MsrResetState {
    /// Builds the reset state from the creation-time baseline entries and the
    /// requested allow list.
    pub fn new(baseline: Vec<MsrEntry>, allowed: Vec<u32>) -> Self {
        Self { baseline, allowed }
    }

    /// The creation-time baseline entries.
    pub fn baseline(&self) -> &[MsrEntry] {
        &self.baseline
    }

    /// This VM's requested allow list.
    pub fn allowed(&self) -> &[u32] {
        &self.allowed
    }

    /// The MSR indices this VM resets, for host reads.
    pub fn indices(&self) -> Vec<u32> {
        self.baseline.iter().map(|entry| entry.index).collect()
    }

    /// Resolves an untrusted snapshot's MSRs against this VM's reset set.
    ///
    /// The snapshot's allow list must be a subset of this VM's, so a
    /// destination that allows at least as much accepts the snapshot on every
    /// backend. Each supplied index must belong to this reset set. Returns the
    /// entries to write: the snapshot's value for each reset index, or the
    /// baseline where the snapshot omits it.
    pub fn validate_snapshot(
        &self,
        snapshot: &[MsrEntry],
        snap_allowed: &[u32],
    ) -> Result<Vec<MsrEntry>, crate::hypervisor::virtual_machine::RegisterError> {
        use crate::hypervisor::virtual_machine::RegisterError;

        let missing: Vec<u32> = snap_allowed
            .iter()
            .copied()
            .filter(|index| !self.allowed.contains(index))
            .collect();
        if !missing.is_empty() {
            return Err(RegisterError::SnapshotMsrNotAllowed { missing });
        }

        for entry in snapshot {
            if !self.baseline.iter().any(|base| base.index == entry.index) {
                return Err(RegisterError::InvalidSnapshotMsrIndex { index: entry.index });
            }
        }

        Ok(self
            .baseline
            .iter()
            .map(|base| MsrEntry {
                index: base.index,
                value: snapshot
                    .iter()
                    .find(|entry| entry.index == base.index)
                    .map_or(base.value, |entry| entry.value),
            })
            .collect())
    }
}

pub(crate) const MSR_TSC: u32 = 0x10;
pub(crate) const MSR_TSC_ADJUST: u32 = 0x3B;
pub(crate) const MSR_SPEC_CTRL: u32 = 0x48;
pub(crate) const MSR_UMWAIT_CONTROL: u32 = 0xE1;
pub(crate) const MSR_MPERF: u32 = 0xE7;
pub(crate) const MSR_APERF: u32 = 0xE8;
pub(crate) const MSR_MTRR_CAP: u32 = 0xFE;
pub(crate) const MSR_TSX_CTRL: u32 = 0x122;
pub(crate) const MSR_SYSENTER_CS: u32 = 0x174;
pub(crate) const MSR_SYSENTER_ESP: u32 = 0x175;
pub(crate) const MSR_SYSENTER_EIP: u32 = 0x176;
pub(crate) const MSR_XFD: u32 = 0x1C4;
pub(crate) const MSR_XFD_ERR: u32 = 0x1C5;
pub(crate) const MSR_DEBUGCTL: u32 = 0x1D9;
pub(crate) const MSR_MTRR_FIX64K_00000: u32 = 0x250;
pub(crate) const MSR_PAT: u32 = 0x277;
pub(crate) const MSR_MTRR_DEF_TYPE: u32 = 0x2FF;
pub(crate) const MSR_U_CET: u32 = 0x6A0;
pub(crate) const MSR_S_CET: u32 = 0x6A2;
pub(crate) const MSR_PL0_SSP: u32 = 0x6A4;
pub(crate) const MSR_PL1_SSP: u32 = 0x6A5;
pub(crate) const MSR_PL2_SSP: u32 = 0x6A6;
pub(crate) const MSR_PL3_SSP: u32 = 0x6A7;
pub(crate) const MSR_INTERRUPT_SSP_TABLE_ADDR: u32 = 0x6A8;
pub(crate) const MSR_TSC_DEADLINE: u32 = 0x6E0;
pub(crate) const MSR_BNDCFGS: u32 = 0xD90;
pub(crate) const MSR_XSS: u32 = 0xDA0;
pub(crate) const MSR_STAR: u32 = 0xC000_0081;
pub(crate) const MSR_LSTAR: u32 = 0xC000_0082;
pub(crate) const MSR_CSTAR: u32 = 0xC000_0083;
pub(crate) const MSR_SFMASK: u32 = 0xC000_0084;
pub(crate) const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;
pub(crate) const MSR_TSC_AUX: u32 = 0xC000_0103;
pub(crate) const MSR_VIRT_SPEC_CTRL: u32 = 0xC001_011F;

const HYPERV_VARIABLE_MTRR_COUNT: u8 = 16;

// Every guest-writable retained value must be host-readable and host-writable.
// EFER, APIC_BASE, FS_BASE, and GS_BASE are part of the special-register state.
// PRED_CMD (0x49) and FLUSH_CMD (0x10B) are intentionally absent: they are
// write-only commands with no retained state, so they cannot be reset and
// therefore cannot be allowed.
const MSR_TABLE: &[u32] = &[
    // Guest and host access use the matching SYSENTER state.
    MSR_SYSENTER_CS,
    MSR_SYSENTER_ESP,
    MSR_SYSENTER_EIP,
    // WHP exposes no writable DEBUGCTL bits under its default feature banks.
    MSR_DEBUGCTL,
    // Guest and host access use the same PAT state.
    MSR_PAT,
    // Guest and host access use the matching syscall state.
    MSR_STAR,
    MSR_LSTAR,
    MSR_CSTAR,
    MSR_SFMASK,
    // SWAPGS and host access use the same KERNEL_GS_BASE state.
    MSR_KERNEL_GS_BASE,
    // Guest and host access use the same SPEC_CTRL state.
    MSR_SPEC_CTRL,
    // AMD virtualized SSBD control. Guest-writable only where the host exposes
    // the legacy VIRT_SPEC_CTRL SSBD mechanism. Host probing omits it otherwise.
    MSR_VIRT_SPEC_CTRL,
    // Host probing omits CET state when CET is unavailable.
    MSR_U_CET,
    MSR_S_CET,
    // Host probing omits shadow-stack state when it is unavailable.
    MSR_PL0_SSP,
    MSR_PL1_SSP,
    MSR_PL2_SSP,
    MSR_PL3_SSP,
    MSR_INTERRUPT_SSP_TABLE_ADDR,
    // MSHV maps XSS through its U_XSS alias.
    MSR_XSS,
    // Guest and host access use the same virtual counter.
    MSR_TSC,
    // Hyper-V stores TSC_ADJUST independently from TSC.
    MSR_TSC_ADJUST,
    // Host probing omits TSC_AUX when RDTSCP is unavailable.
    MSR_TSC_AUX,
    // Hyper-V exposes MPERF and APERF as per-VP counters.
    MSR_MPERF,
    MSR_APERF,
    // Host probing omits TSX_CTRL when TSX control is unavailable.
    MSR_TSX_CTRL,
    // Host probing omits XFD state when XFD is unavailable.
    MSR_XFD,
    MSR_XFD_ERR,
    // Feature MSRs enabled by default on capable hosts. Host probing omits
    // each when its feature is unavailable.
    MSR_UMWAIT_CONTROL,
    MSR_TSC_DEADLINE,
    MSR_BNDCFGS,
    // Hyper-V accepts fixed-MTRR writes even when MTRRCAP.FIX is clear.
    MSR_MTRR_DEF_TYPE,
    0x200,                 // PHYSBASE0
    0x201,                 // PHYSMASK0
    0x202,                 // PHYSBASE1
    0x203,                 // PHYSMASK1
    0x204,                 // PHYSBASE2
    0x205,                 // PHYSMASK2
    0x206,                 // PHYSBASE3
    0x207,                 // PHYSMASK3
    0x208,                 // PHYSBASE4
    0x209,                 // PHYSMASK4
    0x20A,                 // PHYSBASE5
    0x20B,                 // PHYSMASK5
    0x20C,                 // PHYSBASE6
    0x20D,                 // PHYSMASK6
    0x20E,                 // PHYSBASE7
    0x20F,                 // PHYSMASK7
    0x210,                 // PHYSBASE8
    0x211,                 // PHYSMASK8
    0x212,                 // PHYSBASE9
    0x213,                 // PHYSMASK9
    0x214,                 // PHYSBASEA
    0x215,                 // PHYSMASKA
    0x216,                 // PHYSBASEB
    0x217,                 // PHYSMASKB
    0x218,                 // PHYSBASEC
    0x219,                 // PHYSMASKC
    0x21A,                 // PHYSBASED
    0x21B,                 // PHYSMASKD
    0x21C,                 // PHYSBASEE
    0x21D,                 // PHYSMASKE
    0x21E,                 // PHYSBASEF
    0x21F,                 // PHYSMASKF
    MSR_MTRR_FIX64K_00000, // FIX64K_00000
    0x258,                 // FIX16K_80000
    0x259,                 // FIX16K_A0000
    0x268,                 // FIX4K_C0000
    0x269,                 // FIX4K_C8000
    0x26A,                 // FIX4K_D0000
    0x26B,                 // FIX4K_D8000
    0x26C,                 // FIX4K_E0000
    0x26D,                 // FIX4K_E8000
    0x26E,                 // FIX4K_F0000
    0x26F,                 // FIX4K_F8000
];

/// Whether an MSR carries retained state eligible for the reset set.
pub(crate) fn is_resettable_msr(index: u32) -> bool {
    MSR_TABLE.contains(&index)
}

/// Returns core stateful indices for host filtering.
pub(crate) fn core_reset_indices() -> impl Iterator<Item = u32> {
    MSR_TABLE.iter().copied()
}

pub(crate) fn hyperv_mtrr_reset_indices(
    mtrr_cap: u64,
) -> Result<Vec<u32>, crate::hypervisor::virtual_machine::CreateVmError> {
    use crate::hypervisor::virtual_machine::CreateVmError;

    let advertised = (mtrr_cap & 0xff) as u8;
    if advertised > HYPERV_VARIABLE_MTRR_COUNT {
        return Err(CreateVmError::UnexpectedVariableMtrrCount {
            advertised,
            maximum: HYPERV_VARIABLE_MTRR_COUNT,
        });
    }

    let mut indices = Vec::with_capacity(1 + usize::from(advertised) * 2 + 11);
    indices.push(MSR_MTRR_DEF_TYPE);
    indices.extend((0..u32::from(advertised) * 2).map(|offset| 0x200 + offset));
    indices.extend([
        MSR_MTRR_FIX64K_00000,
        0x258,
        0x259,
        0x268,
        0x269,
        0x26A,
        0x26B,
        0x26C,
        0x26D,
        0x26E,
        0x26F,
    ]);
    Ok(indices)
}

pub(crate) fn is_mtrr_reset_index(index: u32) -> bool {
    index == MSR_MTRR_DEF_TYPE
        || (0x200..=0x21F).contains(&index)
        || matches!(
            index,
            MSR_MTRR_FIX64K_00000
                | 0x258
                | 0x259
                | 0x268
                | 0x269
                | 0x26A
                | 0x26B
                | 0x26C
                | 0x26D
                | 0x26E
                | 0x26F
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hypervisor::virtual_machine::{CreateVmError, RegisterError};

    fn state() -> MsrResetState {
        MsrResetState {
            baseline: vec![
                MsrEntry {
                    index: MSR_SYSENTER_CS,
                    value: 0x1C,
                },
                MsrEntry {
                    index: MSR_SYSENTER_ESP,
                    value: 0x2C,
                },
                MsrEntry {
                    index: MSR_KERNEL_GS_BASE,
                    value: 0x3C,
                },
            ],
            allowed: vec![MSR_SYSENTER_CS, MSR_SYSENTER_ESP],
        }
    }

    #[test]
    fn hyperv_mtrr_indices_follow_guest_capability() {
        assert_eq!(
            hyperv_mtrr_reset_indices(2).unwrap(),
            [
                MSR_MTRR_DEF_TYPE,
                0x200,
                0x201,
                0x202,
                0x203,
                MSR_MTRR_FIX64K_00000,
                0x258,
                0x259,
                0x268,
                0x269,
                0x26A,
                0x26B,
                0x26C,
                0x26D,
                0x26E,
                0x26F,
            ]
        );
        let fixed_bit_does_not_change_reset_set = hyperv_mtrr_reset_indices(2 | (1 << 8)).unwrap();
        assert_eq!(
            fixed_bit_does_not_change_reset_set,
            hyperv_mtrr_reset_indices(2).unwrap()
        );
    }

    #[test]
    fn hyperv_mtrr_count_rejects_more_than_sixteen_pairs() {
        let indices = hyperv_mtrr_reset_indices(16).unwrap();
        assert!(indices.contains(&0x21F));
        assert_eq!(indices.last(), Some(&0x26F));
        assert!(indices.iter().all(|&index| is_resettable_msr(index)));
        assert!(matches!(
            hyperv_mtrr_reset_indices(17),
            Err(CreateVmError::UnexpectedVariableMtrrCount {
                advertised: 17,
                maximum: 16
            })
        ));
    }

    #[test]
    fn snapshot_msr_validation_accepts_exact_canonical_set() {
        let supplied = vec![
            MsrEntry {
                index: MSR_SYSENTER_CS,
                value: 1,
            },
            MsrEntry {
                index: MSR_SYSENTER_ESP,
                value: 2,
            },
            MsrEntry {
                index: MSR_KERNEL_GS_BASE,
                value: 3,
            },
        ];

        assert_eq!(
            state()
                .validate_snapshot(&supplied, &[MSR_SYSENTER_CS])
                .unwrap(),
            supplied
        );
    }

    #[test]
    fn snapshot_msr_validation_baselines_omitted_indices() {
        // A snapshot covering a subset of this VM's reset set is accepted.
        // The omitted index takes the creation-time baseline value.
        let supplied = vec![
            MsrEntry {
                index: MSR_SYSENTER_CS,
                value: 1,
            },
            MsrEntry {
                index: MSR_KERNEL_GS_BASE,
                value: 3,
            },
        ];

        assert_eq!(
            state().validate_snapshot(&supplied, &[]).unwrap(),
            vec![
                MsrEntry {
                    index: MSR_SYSENTER_CS,
                    value: 1
                },
                MsrEntry {
                    index: MSR_SYSENTER_ESP,
                    value: 0x2C
                },
                MsrEntry {
                    index: MSR_KERNEL_GS_BASE,
                    value: 3
                },
            ]
        );
    }

    #[test]
    fn snapshot_msr_validation_rejects_non_superset_allow_list() {
        // The snapshot allows an MSR the destination does not.
        assert!(matches!(
            state().validate_snapshot(&[], &[MSR_KERNEL_GS_BASE]),
            Err(RegisterError::SnapshotMsrNotAllowed { missing }) if missing == vec![MSR_KERNEL_GS_BASE]
        ));
    }

    #[test]
    fn snapshot_msr_validation_rejects_index_outside_reset_set() {
        let supplied = vec![
            MsrEntry {
                index: MSR_SYSENTER_CS,
                value: 1,
            },
            MsrEntry {
                index: MSR_SYSENTER_ESP,
                value: 2,
            },
            MsrEntry {
                index: MSR_PAT,
                value: 3,
            },
        ];

        assert!(matches!(
            state().validate_snapshot(&supplied, &[]),
            Err(RegisterError::InvalidSnapshotMsrIndex { index }) if index == MSR_PAT
        ));
    }

    #[test]
    fn snapshot_msr_validation_accepts_empty_canonical_set() {
        let state = MsrResetState {
            baseline: Vec::new(),
            allowed: Vec::new(),
        };
        assert!(state.validate_snapshot(&[], &[]).unwrap().is_empty());
    }
}
