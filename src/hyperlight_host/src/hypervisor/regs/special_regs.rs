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
use kvm_bindings::{kvm_dtable, kvm_segment, kvm_sregs};
#[cfg(mshv)]
use mshv_bindings::{SegmentRegister, SpecialRegisters, TableRegister};
#[cfg(target_os = "windows")]
use windows::Win32::System::Hypervisor::*;

#[cfg(target_os = "windows")]
use super::FromWhpRegisterError;

#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub(crate) struct CommonSpecialRegisters {
    pub cs: CommonSegmentRegister,
    pub ds: CommonSegmentRegister,
    pub es: CommonSegmentRegister,
    pub fs: CommonSegmentRegister,
    pub gs: CommonSegmentRegister,
    pub ss: CommonSegmentRegister,
    pub tr: CommonSegmentRegister,
    pub ldt: CommonSegmentRegister,
    pub gdt: CommonTableRegister,
    pub idt: CommonTableRegister,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; 4],
}

#[cfg(mshv)]
impl From<&SpecialRegisters> for CommonSpecialRegisters {
    fn from(value: &SpecialRegisters) -> Self {
        CommonSpecialRegisters {
            cs: value.cs.into(),
            ds: value.ds.into(),
            es: value.es.into(),
            fs: value.fs.into(),
            gs: value.gs.into(),
            ss: value.ss.into(),
            tr: value.tr.into(),
            ldt: value.ldt.into(),
            gdt: value.gdt.into(),
            idt: value.idt.into(),
            cr0: value.cr0,
            cr2: value.cr2,
            cr3: value.cr3,
            cr4: value.cr4,
            cr8: value.cr8,
            efer: value.efer,
            apic_base: value.apic_base,
            interrupt_bitmap: value.interrupt_bitmap,
        }
    }
}

#[cfg(mshv)]
impl From<&CommonSpecialRegisters> for SpecialRegisters {
    fn from(other: &CommonSpecialRegisters) -> Self {
        SpecialRegisters {
            cs: other.cs.into(),
            ds: other.ds.into(),
            es: other.es.into(),
            fs: other.fs.into(),
            gs: other.gs.into(),
            ss: other.ss.into(),
            tr: other.tr.into(),
            ldt: other.ldt.into(),
            gdt: other.gdt.into(),
            idt: other.idt.into(),
            cr0: other.cr0,
            cr2: other.cr2,
            cr3: other.cr3,
            cr4: other.cr4,
            cr8: other.cr8,
            efer: other.efer,
            apic_base: other.apic_base,
            interrupt_bitmap: other.interrupt_bitmap,
        }
    }
}

#[cfg(kvm)]
impl From<&kvm_sregs> for CommonSpecialRegisters {
    fn from(kvm_sregs: &kvm_sregs) -> Self {
        CommonSpecialRegisters {
            cs: kvm_sregs.cs.into(),
            ds: kvm_sregs.ds.into(),
            es: kvm_sregs.es.into(),
            fs: kvm_sregs.fs.into(),
            gs: kvm_sregs.gs.into(),
            ss: kvm_sregs.ss.into(),
            tr: kvm_sregs.tr.into(),
            ldt: kvm_sregs.ldt.into(),
            gdt: kvm_sregs.gdt.into(),
            idt: kvm_sregs.idt.into(),
            cr0: kvm_sregs.cr0,
            cr2: kvm_sregs.cr2,
            cr3: kvm_sregs.cr3,
            cr4: kvm_sregs.cr4,
            cr8: kvm_sregs.cr8,
            efer: kvm_sregs.efer,
            apic_base: kvm_sregs.apic_base,
            interrupt_bitmap: kvm_sregs.interrupt_bitmap,
        }
    }
}

#[cfg(kvm)]
impl From<&CommonSpecialRegisters> for kvm_sregs {
    fn from(common_sregs: &CommonSpecialRegisters) -> Self {
        kvm_sregs {
            cs: common_sregs.cs.into(),
            ds: common_sregs.ds.into(),
            es: common_sregs.es.into(),
            fs: common_sregs.fs.into(),
            gs: common_sregs.gs.into(),
            ss: common_sregs.ss.into(),
            tr: common_sregs.tr.into(),
            ldt: common_sregs.ldt.into(),
            gdt: common_sregs.gdt.into(),
            idt: common_sregs.idt.into(),
            cr0: common_sregs.cr0,
            cr2: common_sregs.cr2,
            cr3: common_sregs.cr3,
            cr4: common_sregs.cr4,
            cr8: common_sregs.cr8,
            efer: common_sregs.efer,
            apic_base: common_sregs.apic_base,
            interrupt_bitmap: common_sregs.interrupt_bitmap,
        }
    }
}

/// WHV_REGISTER_VALUE must be 16-byte aligned, but the rust struct is incorrectly generated
/// as 8-byte aligned. This is a workaround to ensure that the struct is 16-byte aligned.
#[cfg(target_os = "windows")]
#[repr(C, align(16))]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub(crate) struct Align16<T>(pub(crate) T);

#[cfg(target_os = "windows")]
#[allow(clippy::disallowed_macros)] // compile time
const _: () = {
    assert!(
        std::mem::size_of::<Align16<WHV_REGISTER_VALUE>>()
            == std::mem::size_of::<WHV_REGISTER_VALUE>()
    );
};

#[cfg(target_os = "windows")]
pub(crate) const WHP_SREGS_NAMES_LEN: usize = 17;
#[cfg(target_os = "windows")]
pub(crate) static WHP_SREGS_NAMES: [WHV_REGISTER_NAME; WHP_SREGS_NAMES_LEN] = [
    WHvX64RegisterCs,
    WHvX64RegisterDs,
    WHvX64RegisterEs,
    WHvX64RegisterFs,
    WHvX64RegisterGs,
    WHvX64RegisterSs,
    WHvX64RegisterTr,
    WHvX64RegisterLdtr,
    WHvX64RegisterGdtr,
    WHvX64RegisterIdtr,
    WHvX64RegisterCr0,
    WHvX64RegisterCr2,
    WHvX64RegisterCr3,
    WHvX64RegisterCr4,
    WHvX64RegisterCr8,
    WHvX64RegisterEfer,
    WHvX64RegisterApicBase,
];

#[cfg(target_os = "windows")]
impl From<&CommonSpecialRegisters>
    for [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>); WHP_SREGS_NAMES_LEN]
{
    fn from(other: &CommonSpecialRegisters) -> Self {
        [
            (WHvX64RegisterCs, Align16(other.cs.into())),
            (WHvX64RegisterDs, Align16(other.ds.into())),
            (WHvX64RegisterEs, Align16(other.es.into())),
            (WHvX64RegisterFs, Align16(other.fs.into())),
            (WHvX64RegisterGs, Align16(other.gs.into())),
            (WHvX64RegisterSs, Align16(other.ss.into())),
            (WHvX64RegisterTr, Align16(other.tr.into())),
            (WHvX64RegisterLdtr, Align16(other.ldt.into())),
            (WHvX64RegisterGdtr, Align16(other.gdt.into())),
            (WHvX64RegisterIdtr, Align16(other.idt.into())),
            (
                WHvX64RegisterCr0,
                Align16(WHV_REGISTER_VALUE { Reg64: other.cr0 }),
            ),
            (
                WHvX64RegisterCr2,
                Align16(WHV_REGISTER_VALUE { Reg64: other.cr2 }),
            ),
            (
                WHvX64RegisterCr3,
                Align16(WHV_REGISTER_VALUE { Reg64: other.cr3 }),
            ),
            (
                WHvX64RegisterCr4,
                Align16(WHV_REGISTER_VALUE { Reg64: other.cr4 }),
            ),
            (
                WHvX64RegisterCr8,
                Align16(WHV_REGISTER_VALUE { Reg64: other.cr8 }),
            ),
            (
                WHvX64RegisterEfer,
                Align16(WHV_REGISTER_VALUE { Reg64: other.efer }),
            ),
            (
                WHvX64RegisterApicBase,
                Align16(WHV_REGISTER_VALUE {
                    Reg64: other.apic_base,
                }),
            ),
        ]
    }
}

#[cfg(target_os = "windows")]
impl TryFrom<&[(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>)]> for CommonSpecialRegisters {
    type Error = FromWhpRegisterError;

    #[expect(
        non_upper_case_globals,
        reason = "Windows API has lowercase register names"
    )]
    fn try_from(
        regs: &[(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>)],
    ) -> Result<Self, Self::Error> {
        if regs.len() != WHP_SREGS_NAMES_LEN {
            return Err(FromWhpRegisterError::InvalidLength(regs.len()));
        }
        let mut registers = CommonSpecialRegisters::default();
        let mut seen_registers = HashSet::new();

        for &(name, ref value) in regs {
            let name_id = name.0;

            // Check for duplicates
            if !seen_registers.insert(name_id) {
                return Err(FromWhpRegisterError::DuplicateRegister(name_id));
            }

            unsafe {
                match name {
                    WHvX64RegisterCs => registers.cs = value.0.into(),
                    WHvX64RegisterDs => registers.ds = value.0.into(),
                    WHvX64RegisterEs => registers.es = value.0.into(),
                    WHvX64RegisterFs => registers.fs = value.0.into(),
                    WHvX64RegisterGs => registers.gs = value.0.into(),
                    WHvX64RegisterSs => registers.ss = value.0.into(),
                    WHvX64RegisterTr => registers.tr = value.0.into(),
                    WHvX64RegisterLdtr => registers.ldt = value.0.into(),
                    WHvX64RegisterGdtr => registers.gdt = value.0.into(),
                    WHvX64RegisterIdtr => registers.idt = value.0.into(),
                    WHvX64RegisterCr0 => registers.cr0 = value.0.Reg64,
                    WHvX64RegisterCr2 => registers.cr2 = value.0.Reg64,
                    WHvX64RegisterCr3 => registers.cr3 = value.0.Reg64,
                    WHvX64RegisterCr4 => registers.cr4 = value.0.Reg64,
                    WHvX64RegisterCr8 => registers.cr8 = value.0.Reg64,
                    WHvX64RegisterEfer => registers.efer = value.0.Reg64,
                    WHvX64RegisterApicBase => registers.apic_base = value.0.Reg64,
                    _ => {
                        // Given unexpected register
                        return Err(FromWhpRegisterError::InvalidRegister(name_id));
                    }
                }
            }
        }

        // TODO: I'm not sure how to get this from WHP at the moment
        registers.interrupt_bitmap = Default::default();

        // Set of all expected register names
        let expected_registers: HashSet<i32> =
            WHP_SREGS_NAMES.map(|name| name.0).into_iter().collect();

        // Technically it should not be possible to have any missing registers at this point
        // since we are guaranteed to have WHP_SREGS_NAMES_LEN (17) non-duplicate registers that have passed the match-arm above, but leaving this here for safety anyway
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

// --- Segment Register ---

#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub(crate) struct CommonSegmentRegister {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub type_: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
    pub unusable: u8,
    pub padding: u8,
}

#[cfg(mshv)]
impl From<SegmentRegister> for CommonSegmentRegister {
    fn from(other: SegmentRegister) -> Self {
        CommonSegmentRegister {
            base: other.base,
            limit: other.limit,
            selector: other.selector,
            type_: other.type_,
            present: other.present,
            dpl: other.dpl,
            db: other.db,
            s: other.s,
            l: other.l,
            g: other.g,
            avl: other.avl,
            unusable: other.unusable,
            padding: other.padding,
        }
    }
}

#[cfg(mshv)]
impl From<CommonSegmentRegister> for SegmentRegister {
    fn from(other: CommonSegmentRegister) -> Self {
        SegmentRegister {
            base: other.base,
            limit: other.limit,
            selector: other.selector,
            type_: other.type_,
            present: other.present,
            dpl: other.dpl,
            db: other.db,
            s: other.s,
            l: other.l,
            g: other.g,
            avl: other.avl,
            unusable: other.unusable,
            padding: other.padding,
        }
    }
}

#[cfg(kvm)]
impl From<kvm_segment> for CommonSegmentRegister {
    fn from(kvm_segment: kvm_segment) -> Self {
        CommonSegmentRegister {
            base: kvm_segment.base,
            limit: kvm_segment.limit,
            selector: kvm_segment.selector,
            type_: kvm_segment.type_,
            present: kvm_segment.present,
            dpl: kvm_segment.dpl,
            db: kvm_segment.db,
            s: kvm_segment.s,
            l: kvm_segment.l,
            g: kvm_segment.g,
            avl: kvm_segment.avl,
            unusable: kvm_segment.unusable,
            padding: kvm_segment.padding,
        }
    }
}

#[cfg(kvm)]
impl From<CommonSegmentRegister> for kvm_segment {
    fn from(common_segment: CommonSegmentRegister) -> Self {
        kvm_segment {
            base: common_segment.base,
            limit: common_segment.limit,
            selector: common_segment.selector,
            type_: common_segment.type_,
            present: common_segment.present,
            dpl: common_segment.dpl,
            db: common_segment.db,
            s: common_segment.s,
            l: common_segment.l,
            g: common_segment.g,
            avl: common_segment.avl,
            unusable: common_segment.unusable,
            padding: common_segment.padding,
        }
    }
}

#[cfg(target_os = "windows")]
impl From<WHV_REGISTER_VALUE> for CommonSegmentRegister {
    fn from(other: WHV_REGISTER_VALUE) -> Self {
        unsafe {
            let segment = other.Segment;
            let bits = segment.Anonymous.Attributes;

            // Source of bit layout: https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvvirtualprocessordatatypes
            CommonSegmentRegister {
                base: segment.Base,
                limit: segment.Limit,
                selector: segment.Selector,
                type_: (bits & 0b1111) as u8,    // bits 0–3: SegmentType
                s: ((bits >> 4) & 0b1) as u8,    // bit 4: NonSystemSegment
                dpl: ((bits >> 5) & 0b11) as u8, // bits 5–6: DPL
                present: ((bits >> 7) & 0b1) as u8, // bit 7: Present
                // bits 8–11: Reserved
                avl: ((bits >> 12) & 0b1) as u8, // bit 12: Available
                l: ((bits >> 13) & 0b1) as u8,   // bit 13: Long mode
                db: ((bits >> 14) & 0b1) as u8,  // bit 14: Default
                g: ((bits >> 15) & 0b1) as u8,   // bit 15: Granularity
                unusable: 0,
                padding: 0,
            }
        }
    }
}

#[cfg(target_os = "windows")]
impl From<CommonSegmentRegister> for WHV_REGISTER_VALUE {
    fn from(other: CommonSegmentRegister) -> Self {
        // Truncate each field to its valid bit width before composing `Attributes`.
        let type_ = other.type_ & 0xF; // 4 bits
        let s = other.s & 0x1; // 1 bit
        let dpl = other.dpl & 0x3; // 2 bits
        let present = other.present & 0x1; // 1 bit
        let avl = other.avl & 0x1; // 1 bit
        let l = other.l & 0x1; // 1 bit
        let db = other.db & 0x1; // 1 bit
        let g = other.g & 0x1; // 1 bit

        WHV_REGISTER_VALUE {
            Segment: WHV_X64_SEGMENT_REGISTER {
                Base: other.base,
                Limit: other.limit,
                Selector: other.selector,
                Anonymous: WHV_X64_SEGMENT_REGISTER_0 {
                    Attributes: (type_ as u16) // bit 0-3
                        | ((s as u16) << 4) // bit 4
                        | ((dpl as u16) << 5) // bit 5-6
                        | ((present as u16) << 7) // bit 7
                        | ((avl as u16) << 12) // bit 12
                        | ((l as u16) << 13) // bit 13
                        | ((db as u16) << 14) // bit 14
                        | ((g as u16) << 15), // bit 15
                },
            },
        }
    }
}

// --- Table Register ---

#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub(crate) struct CommonTableRegister {
    pub base: u64,
    pub limit: u16,
}

#[cfg(mshv)]
impl From<TableRegister> for CommonTableRegister {
    fn from(other: TableRegister) -> Self {
        CommonTableRegister {
            base: other.base,
            limit: other.limit,
        }
    }
}

#[cfg(mshv)]
impl From<CommonTableRegister> for TableRegister {
    fn from(other: CommonTableRegister) -> Self {
        TableRegister {
            base: other.base,
            limit: other.limit,
        }
    }
}

#[cfg(kvm)]
impl From<kvm_dtable> for CommonTableRegister {
    fn from(kvm_dtable: kvm_dtable) -> Self {
        CommonTableRegister {
            base: kvm_dtable.base,
            limit: kvm_dtable.limit,
        }
    }
}

#[cfg(kvm)]
impl From<CommonTableRegister> for kvm_dtable {
    fn from(common_dtable: CommonTableRegister) -> Self {
        kvm_dtable {
            base: common_dtable.base,
            limit: common_dtable.limit,
            padding: Default::default(),
        }
    }
}

#[cfg(target_os = "windows")]
impl From<WHV_REGISTER_VALUE> for CommonTableRegister {
    fn from(other: WHV_REGISTER_VALUE) -> Self {
        unsafe {
            let table = other.Table;
            CommonTableRegister {
                base: table.Base,
                limit: table.Limit,
            }
        }
    }
}

#[cfg(target_os = "windows")]
impl From<CommonTableRegister> for WHV_REGISTER_VALUE {
    fn from(other: CommonTableRegister) -> Self {
        WHV_REGISTER_VALUE {
            Table: WHV_X64_TABLE_REGISTER {
                Base: other.base,
                Limit: other.limit,
                Pad: Default::default(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_common_special_registers() -> CommonSpecialRegisters {
        let sample_segment = CommonSegmentRegister {
            base: 0x1000,
            limit: 0xFFFF,
            selector: 0x10,
            type_: 0xB,
            present: 1,
            dpl: 0,
            db: 1,
            s: 1,
            l: 0,
            g: 1,
            avl: 0,
            unusable: 0,
            padding: 0,
        };

        let sample_table = CommonTableRegister {
            base: 0x2000,
            limit: 0x1000,
        };

        CommonSpecialRegisters {
            cs: sample_segment,
            ds: sample_segment,
            es: sample_segment,
            fs: sample_segment,
            gs: sample_segment,
            ss: sample_segment,
            tr: sample_segment,
            ldt: sample_segment,
            gdt: sample_table,
            idt: sample_table,
            cr0: 0xDEAD_BEEF,
            cr2: 0xBAD_C0DE,
            cr3: 0xC0FFEE,
            cr4: 0xFACE_CAFE,
            cr8: 0x1234,
            efer: 0x5678,
            apic_base: 0x9ABC,
            interrupt_bitmap: [0; 4],
        }
    }

    #[cfg(kvm)]
    #[test]
    fn round_trip_kvm_sregs() {
        let original = sample_common_special_registers();
        let kvm_sregs: kvm_sregs = (&original).into();
        let roundtrip = CommonSpecialRegisters::from(&kvm_sregs);

        assert_eq!(original, roundtrip);
    }

    #[cfg(mshv)]
    #[test]
    fn round_trip_mshv_sregs() {
        let original = sample_common_special_registers();
        let mshv_sregs: SpecialRegisters = (&original).into();
        let roundtrip = CommonSpecialRegisters::from(&mshv_sregs);

        assert_eq!(original, roundtrip);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn round_trip_whp_sregs() {
        let original = sample_common_special_registers();
        let whp_sregs: [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>); WHP_SREGS_NAMES_LEN] =
            (&original).into();
        let roundtrip = CommonSpecialRegisters::try_from(whp_sregs.as_ref()).unwrap();
        assert_eq!(original, roundtrip);

        // Test duplicate register error
        let original = sample_common_special_registers();
        let mut whp_sregs: [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>); WHP_SREGS_NAMES_LEN] =
            (&original).into();
        whp_sregs[0].0 = WHvX64RegisterDs;
        let err = CommonSpecialRegisters::try_from(whp_sregs.as_ref()).unwrap_err();
        assert_eq!(
            err,
            FromWhpRegisterError::DuplicateRegister(WHvX64RegisterDs.0)
        );

        // Test passing non-sregs register (e.g. RIP)
        let original = sample_common_special_registers();
        let mut whp_sregs: [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>); WHP_SREGS_NAMES_LEN] =
            (&original).into();
        whp_sregs[0].0 = WHvX64RegisterRip;
        let err = CommonSpecialRegisters::try_from(whp_sregs.as_ref()).unwrap_err();
        assert_eq!(
            err,
            FromWhpRegisterError::InvalidRegister(WHvX64RegisterRip.0)
        );
    }
}
