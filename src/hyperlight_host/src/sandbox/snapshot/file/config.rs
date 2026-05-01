/*
Copyright 2025 The Hyperlight Authors.

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

use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterType, ReturnType};
use hyperlight_common::flatbuffer_wrappers::host_function_definition::HostFunctionDefinition;
use hyperlight_common::vmem::PAGE_SIZE;
use serde::{Deserialize, Serialize};

use super::media_types::SNAPSHOT_ABI_VERSION;
use crate::hypervisor::regs::{CommonSegmentRegister, CommonSpecialRegisters, CommonTableRegister};
use crate::mem::layout::SandboxMemoryLayout;
use crate::mem::memory_region::MemoryRegionFlags;

// --- Arch and hypervisor identifiers --------------------------------

/// Guest architecture the snapshot was captured for. Checked on load
/// against the running host.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Arch {
    X86_64,
    Aarch64,
    I686,
}

impl Arch {
    pub(super) fn current() -> Self {
        #[cfg(feature = "i686-guest")]
        {
            Self::I686
        }
        #[cfg(all(not(feature = "i686-guest"), target_arch = "x86_64"))]
        {
            Self::X86_64
        }
        #[cfg(all(not(feature = "i686-guest"), target_arch = "aarch64"))]
        {
            Self::Aarch64
        }
    }
}

/// Hypervisor backend the snapshot was captured under. Checked on
/// load because vCPU register state is backend-specific.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Hypervisor {
    Kvm,
    Mshv,
    Whp,
}

impl Hypervisor {
    pub(super) fn current() -> Option<Self> {
        #[allow(unused_imports)]
        use crate::hypervisor::virtual_machine::HypervisorType;
        use crate::hypervisor::virtual_machine::get_available_hypervisor;

        match get_available_hypervisor() {
            #[cfg(kvm)]
            Some(HypervisorType::Kvm) => Some(Self::Kvm),
            #[cfg(mshv3)]
            Some(HypervisorType::Mshv) => Some(Self::Mshv),
            #[cfg(target_os = "windows")]
            Some(HypervisorType::Whp) => Some(Self::Whp),
            None => None,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Kvm => "KVM",
            Self::Mshv => "MSHV",
            Self::Whp => "WHP",
        }
    }
}

// --- Config JSON shape ----------------------------------------------

/// Top-level Hyperlight snapshot config JSON. Lives at
/// `blobs/sha256/<config-digest>` with media type
/// `application/vnd.hyperlight.snapshot.config.v1+json`.
///
/// In OCI terms this is the "image config" blob that the manifest's
/// `config` descriptor points to. It describes the accompanying
/// memory layer (the snapshot bytes) and everything the loader needs
/// to reconstruct a runnable `Snapshot`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OciSnapshotConfig {
    /// Hyperlight crate version that produced this config. Recorded
    /// for diagnostics. Not checked on load.
    pub(super) hyperlight_version: String,
    pub(super) arch: Arch,
    /// Memory blob ABI version. See [`SNAPSHOT_ABI_VERSION`].
    pub(super) abi_version: u32,
    pub(super) hypervisor: Hypervisor,
    /// Top of the guest stack, in guest virtual address space.
    pub(super) stack_top_gva: u64,
    pub(super) entrypoint: Entrypoint,
    pub(super) layout: MemoryLayout,
    /// Total size of the memory blob in bytes (including the guest
    /// page-table tail, if any). Equal to `self.memory.mem_size()`.
    pub(super) memory_size: u64,
    /// Names and signatures of host functions registered when this
    /// snapshot was taken. Validated against the loader's registry.
    pub(super) host_functions: Vec<HostFunction>,
    /// Generation counter for the snapshot. Restored verbatim into
    /// the `Snapshot` so guest-visible bookkeeping at
    /// `SCRATCH_TOP_SNAPSHOT_GENERATION_OFFSET` is continuous across
    /// save/load.
    pub(super) snapshot_generation: u64,
}

/// What the loader should do with the restored sandbox: jump to the
/// guest entrypoint, or resume a paused call with captured sregs.
/// The enum shape enforces that `Call` carries sregs and `Initialise`
/// does not.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub(super) enum Entrypoint {
    Initialise { addr: u64 },
    Call { addr: u64, sregs: Box<Sregs> },
}

/// Sizes and permissions of the regions inside the snapshot blob,
/// enough for the loader to rebuild a `SandboxMemoryLayout`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MemoryLayout {
    pub(super) input_data_size: usize,
    pub(super) output_data_size: usize,
    pub(super) heap_size: usize,
    pub(super) code_size: usize,
    pub(super) init_data_size: usize,
    /// Memory region flag bits. `None` means default permissions.
    pub(super) init_data_permissions: Option<u32>,
    pub(super) scratch_size: usize,
    pub(super) snapshot_size: usize,
    pub(super) pt_size: Option<usize>,
}

/// Name and signature of one host function registered when the
/// snapshot was taken. The loader validates these against the
/// registry of the sandbox it is restoring into.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HostFunction {
    function_name: String,
    parameter_types: Vec<ParameterTypeRepr>,
    return_type: ReturnTypeRepr,
}

/// JSON-friendly mirror of
/// [`hyperlight_common::flatbuffer_wrappers::function_types::ParameterType`].
/// Kept local so we don't have to plumb serde through `hyperlight_common`.
/// The `match`es below are exhaustive: any new variant upstream forces
/// an explicit decision here.
#[derive(Serialize, Deserialize, Copy, Clone)]
#[serde(rename_all = "snake_case")]
enum ParameterTypeRepr {
    Int,
    UInt,
    Long,
    ULong,
    Float,
    Double,
    String,
    Bool,
    VecBytes,
}

/// JSON-friendly mirror of
/// [`hyperlight_common::flatbuffer_wrappers::function_types::ReturnType`].
#[derive(Serialize, Deserialize, Copy, Clone)]
#[serde(rename_all = "snake_case")]
enum ReturnTypeRepr {
    Int,
    UInt,
    Long,
    ULong,
    Float,
    Double,
    String,
    Bool,
    Void,
    VecBytes,
}

impl From<&ParameterType> for ParameterTypeRepr {
    fn from(p: &ParameterType) -> Self {
        match p {
            ParameterType::Int => Self::Int,
            ParameterType::UInt => Self::UInt,
            ParameterType::Long => Self::Long,
            ParameterType::ULong => Self::ULong,
            ParameterType::Float => Self::Float,
            ParameterType::Double => Self::Double,
            ParameterType::String => Self::String,
            ParameterType::Bool => Self::Bool,
            ParameterType::VecBytes => Self::VecBytes,
        }
    }
}

impl From<ParameterTypeRepr> for ParameterType {
    fn from(r: ParameterTypeRepr) -> Self {
        match r {
            ParameterTypeRepr::Int => Self::Int,
            ParameterTypeRepr::UInt => Self::UInt,
            ParameterTypeRepr::Long => Self::Long,
            ParameterTypeRepr::ULong => Self::ULong,
            ParameterTypeRepr::Float => Self::Float,
            ParameterTypeRepr::Double => Self::Double,
            ParameterTypeRepr::String => Self::String,
            ParameterTypeRepr::Bool => Self::Bool,
            ParameterTypeRepr::VecBytes => Self::VecBytes,
        }
    }
}

impl From<&ReturnType> for ReturnTypeRepr {
    fn from(r: &ReturnType) -> Self {
        match r {
            ReturnType::Int => Self::Int,
            ReturnType::UInt => Self::UInt,
            ReturnType::Long => Self::Long,
            ReturnType::ULong => Self::ULong,
            ReturnType::Float => Self::Float,
            ReturnType::Double => Self::Double,
            ReturnType::String => Self::String,
            ReturnType::Bool => Self::Bool,
            ReturnType::Void => Self::Void,
            ReturnType::VecBytes => Self::VecBytes,
        }
    }
}

impl From<ReturnTypeRepr> for ReturnType {
    fn from(r: ReturnTypeRepr) -> Self {
        match r {
            ReturnTypeRepr::Int => Self::Int,
            ReturnTypeRepr::UInt => Self::UInt,
            ReturnTypeRepr::Long => Self::Long,
            ReturnTypeRepr::ULong => Self::ULong,
            ReturnTypeRepr::Float => Self::Float,
            ReturnTypeRepr::Double => Self::Double,
            ReturnTypeRepr::String => Self::String,
            ReturnTypeRepr::Bool => Self::Bool,
            ReturnTypeRepr::Void => Self::Void,
            ReturnTypeRepr::VecBytes => Self::VecBytes,
        }
    }
}

/// Captured x86_64 special registers for a paused vCPU. Round-trips
/// to/from [`CommonSpecialRegisters`] and is restored verbatim when
/// resuming a `Call` entrypoint.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Sregs {
    cs: SegmentRegister,
    ds: SegmentRegister,
    es: SegmentRegister,
    fs: SegmentRegister,
    gs: SegmentRegister,
    ss: SegmentRegister,
    tr: SegmentRegister,
    ldt: SegmentRegister,
    gdt: TableRegister,
    idt: TableRegister,
    cr0: u64,
    cr2: u64,
    cr3: u64,
    cr4: u64,
    cr8: u64,
    efer: u64,
    apic_base: u64,
    interrupt_bitmap: [u64; 4],
}

/// Serde mirror of [`CommonSegmentRegister`].
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SegmentRegister {
    base: u64,
    limit: u32,
    selector: u16,
    type_: u8,
    present: u8,
    dpl: u8,
    db: u8,
    s: u8,
    l: u8,
    g: u8,
    avl: u8,
    unusable: u8,
    padding: u8,
}

/// Serde mirror of [`CommonTableRegister`].
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TableRegister {
    base: u64,
    limit: u16,
}

// --- Conversions between repr and runtime types ---------------------

impl From<&CommonSpecialRegisters> for Sregs {
    fn from(s: &CommonSpecialRegisters) -> Self {
        let seg = |r: &CommonSegmentRegister| SegmentRegister {
            base: r.base,
            limit: r.limit,
            selector: r.selector,
            type_: r.type_,
            present: r.present,
            dpl: r.dpl,
            db: r.db,
            s: r.s,
            l: r.l,
            g: r.g,
            avl: r.avl,
            unusable: r.unusable,
            padding: r.padding,
        };
        let tab = |r: &CommonTableRegister| TableRegister {
            base: r.base,
            limit: r.limit,
        };
        Self {
            cs: seg(&s.cs),
            ds: seg(&s.ds),
            es: seg(&s.es),
            fs: seg(&s.fs),
            gs: seg(&s.gs),
            ss: seg(&s.ss),
            tr: seg(&s.tr),
            ldt: seg(&s.ldt),
            gdt: tab(&s.gdt),
            idt: tab(&s.idt),
            cr0: s.cr0,
            cr2: s.cr2,
            cr3: s.cr3,
            cr4: s.cr4,
            cr8: s.cr8,
            efer: s.efer,
            apic_base: s.apic_base,
            interrupt_bitmap: s.interrupt_bitmap,
        }
    }
}

impl From<Sregs> for CommonSpecialRegisters {
    fn from(r: Sregs) -> Self {
        let seg = |s: SegmentRegister| CommonSegmentRegister {
            base: s.base,
            limit: s.limit,
            selector: s.selector,
            type_: s.type_,
            present: s.present,
            dpl: s.dpl,
            db: s.db,
            s: s.s,
            l: s.l,
            g: s.g,
            avl: s.avl,
            unusable: s.unusable,
            padding: s.padding,
        };
        let tab = |t: TableRegister| CommonTableRegister {
            base: t.base,
            limit: t.limit,
        };
        Self {
            cs: seg(r.cs),
            ds: seg(r.ds),
            es: seg(r.es),
            fs: seg(r.fs),
            gs: seg(r.gs),
            ss: seg(r.ss),
            tr: seg(r.tr),
            ldt: seg(r.ldt),
            gdt: tab(r.gdt),
            idt: tab(r.idt),
            cr0: r.cr0,
            cr2: r.cr2,
            cr3: r.cr3,
            cr4: r.cr4,
            cr8: r.cr8,
            efer: r.efer,
            apic_base: r.apic_base,
            interrupt_bitmap: r.interrupt_bitmap,
        }
    }
}

impl From<&HostFunctionDefinition> for HostFunction {
    fn from(d: &HostFunctionDefinition) -> Self {
        let parameter_types = d
            .parameter_types
            .as_ref()
            .map(|v| v.iter().map(ParameterTypeRepr::from).collect())
            .unwrap_or_default();
        Self {
            function_name: d.function_name.clone(),
            parameter_types,
            return_type: ReturnTypeRepr::from(&d.return_type),
        }
    }
}

impl From<HostFunction> for HostFunctionDefinition {
    fn from(r: HostFunction) -> Self {
        Self {
            function_name: r.function_name,
            parameter_types: Some(r.parameter_types.into_iter().map(Into::into).collect()),
            return_type: r.return_type.into(),
        }
    }
}

impl OciSnapshotConfig {
    pub(super) fn validate_for_load(&self) -> crate::Result<()> {
        if self.arch != Arch::current() {
            return Err(crate::new_error!(
                "snapshot architecture mismatch: file is {:?}, current host is {:?}",
                self.arch,
                Arch::current()
            ));
        }
        if self.abi_version != SNAPSHOT_ABI_VERSION {
            return Err(crate::new_error!(
                "snapshot ABI version mismatch: file has version {}, this build expects {}. \
                 The snapshot must be regenerated from the guest binary.",
                self.abi_version,
                SNAPSHOT_ABI_VERSION
            ));
        }
        let current_hv = Hypervisor::current()
            .ok_or_else(|| crate::new_error!("no hypervisor available to load snapshot"))?;
        if self.hypervisor != current_hv {
            return Err(crate::new_error!(
                "snapshot hypervisor mismatch: file was created on {} but the current hypervisor is {}",
                self.hypervisor.name(),
                current_hv.name()
            ));
        }
        // Bound memory size early so the subsequent file-size check
        // does not have to deal with absurd values.
        if self.memory_size == 0 || self.memory_size > SandboxMemoryLayout::MAX_MEMORY_SIZE as u64 {
            return Err(crate::new_error!(
                "snapshot memory_size ({}) is out of range",
                self.memory_size
            ));
        }
        if self.memory_size as usize % PAGE_SIZE != 0 {
            return Err(crate::new_error!(
                "snapshot memory_size ({}) is not a multiple of PAGE_SIZE",
                self.memory_size
            ));
        }
        // Invariant: `snapshot_size + pt_size == memory_size`.
        // `snapshot_size` is the guest-visible prefix of the blob,
        // mapped into guest PA space at `BASE_ADDRESS`. `pt_size`
        // is the page-table tail that sits after it in the blob and
        // the host mapping, outside the guest mapping of the
        // snapshot region.
        if self.layout.snapshot_size == 0 {
            return Err(crate::new_error!("snapshot snapshot_size must be nonzero"));
        }
        if self.layout.snapshot_size % PAGE_SIZE != 0 {
            return Err(crate::new_error!(
                "snapshot snapshot_size ({}) is not a multiple of PAGE_SIZE",
                self.layout.snapshot_size
            ));
        }
        let pt = self.layout.pt_size.unwrap_or(0);
        if pt % PAGE_SIZE != 0 {
            return Err(crate::new_error!(
                "snapshot pt_size ({}) is not a multiple of PAGE_SIZE",
                pt
            ));
        }
        if (self.layout.snapshot_size as u64).saturating_add(pt as u64) != self.memory_size {
            return Err(crate::new_error!(
                "snapshot snapshot_size ({}) + pt_size ({}) does not equal memory_size ({})",
                self.layout.snapshot_size,
                pt,
                self.memory_size
            ));
        }
        if let Some(bits) = self.layout.init_data_permissions {
            MemoryRegionFlags::from_bits(bits).ok_or_else(|| {
                crate::new_error!(
                    "snapshot init_data_permissions {:#x} contains unknown flag bits",
                    bits
                )
            })?;
        }

        // Entrypoint address must point inside the guest snapshot
        // region. Hyperlight identity-maps the snapshot region in low
        // GPAs, so the same bounds apply to virtual and physical
        // addresses there. A crafted config could otherwise direct
        // execution into unmapped GPA space (which only catches the
        // bug at vCPU run time) or, worse, into the scratch region
        // (which is writable). The bound here is
        // `[BASE_ADDRESS, BASE_ADDRESS + snapshot_size)` because the
        // snapshot blob covers exactly the snapshot region.
        let snap_lo = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let snap_hi = snap_lo
            .checked_add(self.layout.snapshot_size as u64)
            .ok_or_else(|| {
                crate::new_error!(
                    "snapshot layout overflow: BASE_ADDRESS + snapshot_size ({}) does not fit in u64",
                    self.layout.snapshot_size
                )
            })?;
        let entry_addr = match &self.entrypoint {
            Entrypoint::Initialise { addr } => *addr,
            Entrypoint::Call { addr, .. } => *addr,
        };
        if entry_addr < snap_lo || entry_addr >= snap_hi {
            return Err(crate::new_error!(
                "snapshot entrypoint addr {:#x} is outside the snapshot region [{:#x}, {:#x})",
                entry_addr,
                snap_lo,
                snap_hi
            ));
        }
        Ok(())
    }
}
