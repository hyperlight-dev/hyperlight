#[cfg(mshv2)]
extern crate mshv_bindings2 as mshv_bindings;
#[cfg(mshv2)]
extern crate mshv_ioctls2 as mshv_ioctls;

#[cfg(mshv3)]
extern crate mshv_bindings3 as mshv_bindings;
#[cfg(mshv3)]
extern crate mshv_ioctls3 as mshv_ioctls;

#[cfg(kvm)]
use kvm_bindings::{kvm_dtable, kvm_segment, kvm_sregs};
#[cfg(mshv)]
use mshv_bindings::{SegmentRegister, SpecialRegisters, TableRegister};

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
impl From<SpecialRegisters> for CommonSpecialRegisters {
    fn from(value: SpecialRegisters) -> Self {
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
impl From<CommonSpecialRegisters> for SpecialRegisters {
    fn from(other: CommonSpecialRegisters) -> Self {
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
impl From<kvm_sregs> for CommonSpecialRegisters {
    fn from(kvm_sregs: kvm_sregs) -> Self {
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
impl From<CommonSpecialRegisters> for kvm_sregs {
    fn from(common_sregs: CommonSpecialRegisters) -> Self {
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

// --- Sement Register ---

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
