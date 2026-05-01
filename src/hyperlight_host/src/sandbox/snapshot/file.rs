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

//! Snapshot file format: serialization, deserialization, and the
//! associated `Snapshot::to_file` / `Snapshot::from_file` methods.
//!
//! The on-disk byte layout is whatever the three `#[repr(C)]` POD
//! structs below declare: `RawPreamble`, `RawHeaderV1`, `RawSregs`.
//! Each derives `bytemuck::Pod` and `bytemuck::Zeroable`, which the
//! derive macro proves at compile time means there is no padding and
//! every bit pattern is a valid value of the struct's fields. There
//! are no separate numeric offsets to keep in sync with the code.
//!
//! All multi-byte integers are little-endian (gated by a
//! `compile_error!` on big-endian targets below).
//!
//! The fixed-position prefix is followed by an optional host-function
//! flatbuffer of length `host_funcs_size`, then zero padding to the
//! next PAGE_SIZE boundary, then the memory blob (the mmap target).
//! The memory blob's file offset is recorded in `memory_offset` and
//! is always page-aligned. A PAGE_SIZE trailing zero region follows
//! the blob (Windows guard-page backing).
//!
//! ```text
//!   +----------------------+
//!   | RawPreamble          |  magic "HLS\0" + format_version
//!   +----------------------+
//!   | RawHeaderV1          |  arch, abi_version, hash, stack_top_gva,
//!   |                      |  entrypoint tag+addr, layout fields,
//!   |                      |  memory_size, memory_offset, has_sregs,
//!   |                      |  hypervisor, host_funcs_size
//!   +----------------------+
//!   | RawSregs             |  segments, tables, control regs, bitmap.
//!   |                      |  Always written; ignored on load if
//!   |                      |  has_sregs == 0.
//!   +----------------------+
//!   | host_funcs blob      |  host_funcs_size bytes (0 if absent),
//!   |                      |  serialized HostFunctionDetails flatbuffer
//!   +----------------------+
//!   | zero padding         |  pads to next PAGE_SIZE boundary
//!   +----------------------+ <- memory_offset
//!   | memory blob          |  memory_size bytes (mmap target)
//!   +----------------------+
//!   | trailing PAGE_SIZE   |  Windows guard-page backing; ignored on Linux
//!   +----------------------+
//! ```
//!
//! `memory_offset == align_up(FIXED_PREFIX_SIZE + host_funcs_size,
//! PAGE_SIZE)`, where `FIXED_PREFIX_SIZE = sizeof(RawPreamble) +
//! sizeof(RawHeaderV1) + sizeof(RawSregs)`. With no host functions
//! this lands at exactly PAGE_SIZE.

use hyperlight_common::flatbuffer_wrappers::host_function_details::HostFunctionDetails;
use hyperlight_common::vmem::PAGE_SIZE;

use super::{NextAction, SANDBOX_CONFIGURATION_COUNTER, Snapshot};
use crate::hypervisor::regs::CommonSpecialRegisters;
use crate::mem::layout::SandboxMemoryLayout;
use crate::mem::shared_mem::{ReadonlySharedMemory, SharedMemory};

const SNAPSHOT_MAGIC: &[u8; 4] = b"HLS\0";

/// ABI version for the snapshot memory blob. This must be bumped
/// whenever a change affects the contents or interpretation of the
/// memory blob - i.e., the contract between the host runtime and
/// the guest binary that determines how snapshot memory is produced
/// and consumed.
///
/// Examples of changes that require a bump:
///
/// - Memory layout: `SandboxMemoryLayout` offset computation, memory
///   region definitions, page table format
/// - Host-guest interface: PEB struct layout, calling convention,
///   dispatch mechanism, input/output buffer format
/// - Guest init state: entry point setup, GDT/IDT/TSS initialization,
///   or any startup code in `hyperlight_guest_bin` whose results are
///   captured in the snapshot (e.g. sregs)
///
/// Unlike `FormatVersion` (which covers the file header byte layout
/// and may allow conversion between versions), an ABI mismatch means
/// the memory blob is incompatible and the snapshot must be
/// regenerated from the guest binary.
const SNAPSHOT_ABI_VERSION: u64 = 1;

/// Maximum size of the host-functions flatbuffer blob in a snapshot
/// file. Bounds the allocation done at load time before the
/// flatbuffer is parsed. The legitimate size for hundreds of host
/// functions is well under this cap.
const MAX_HOST_FUNCS_SIZE: u64 = 1024 * 1024;

/// Snapshot file format version.
#[derive(Copy, Clone, Debug, PartialEq)]
enum FormatVersion {
    V1 = 1,
}

impl FormatVersion {
    fn from_u32(v: u32) -> crate::Result<Self> {
        match v {
            1 => Ok(Self::V1),
            _ => Err(crate::new_error!(
                "unsupported snapshot format version {} (this build supports V1). \
                 The file header layout may be convertible to the current format",
                v
            )),
        }
    }
}

/// Architecture tag for snapshot files.
#[derive(Copy, Clone, Debug, PartialEq)]
enum ArchTag {
    X86_64 = 1,
    Aarch64 = 2,
    I686 = 3,
}

impl ArchTag {
    fn current() -> Self {
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

    fn from_u64(v: u64) -> crate::Result<Self> {
        match v {
            1 => Ok(Self::X86_64),
            2 => Ok(Self::Aarch64),
            3 => Ok(Self::I686),
            _ => Err(crate::new_error!("unknown architecture tag: {}", v)),
        }
    }
}

/// Hypervisor tag for snapshot files.
///
/// Segment register hidden-cache fields (unusable, type_, granularity,
/// db) differ between hypervisors for the same architectural state.
/// Restoring sregs captured on one hypervisor into another may be
/// rejected or produce subtly wrong behavior.  The tag ensures
/// snapshots are only loaded on the same hypervisor that created them.
#[derive(Copy, Clone, Debug, PartialEq)]
pub(super) enum HypervisorTag {
    Kvm = 1,
    Mshv = 2,
    Whp = 3,
}

impl HypervisorTag {
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

    fn from_u64(v: u64) -> crate::Result<Self> {
        match v {
            1 => Ok(Self::Kvm),
            2 => Ok(Self::Mshv),
            3 => Ok(Self::Whp),
            _ => Err(crate::new_error!("unknown hypervisor tag: {}", v)),
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

// All raw header structs use little-endian on-disk encoding. Both
// supported architectures (x86_64, aarch64) are little-endian, so we
// just refuse to compile on a hypothetical big-endian target rather
// than byte-swap on every field access.
#[cfg(not(target_endian = "little"))]
compile_error!("snapshot file format requires a little-endian target");

/// Memory layout fields stored in the snapshot file (validated form).
/// These are the primary inputs needed to reconstruct a `SandboxMemoryLayout`.
struct LayoutFields {
    input_data_size: usize,
    output_data_size: usize,
    heap_size: usize,
    code_size: usize,
    init_data_size: usize,
    init_data_permissions: Option<crate::mem::memory_region::MemoryRegionFlags>,
    scratch_size: usize,
    snapshot_size: usize,
    pt_size: Option<usize>,
}

/// Fixed preamble at the start of every snapshot file (validated form).
/// Never changes across format versions so it can always be read to
/// determine which version-specific header follows.
struct SnapshotPreamble {
    magic: [u8; 4],
    format_version: FormatVersion,
}

/// V1 snapshot header (validated form).
struct SnapshotHeaderV1 {
    arch: ArchTag,
    abi_version: u64,
    stack_top_gva: u64,
    entrypoint: NextAction,
    layout: LayoutFields,
    memory_size: usize,
    memory_offset: u64,
    has_sregs: bool,
    hypervisor: HypervisorTag,
    /// Byte length of the host-function-details flatbuffer that
    /// follows the fixed header. `0` means no host functions are
    /// stored.
    host_funcs_size: u64,
}

// --- Raw POD on-disk structs ---
//
// These mirror the bytes on disk one-for-one. Reading and writing
// goes through `bytemuck`; field-level validation lives in `From` /
// `TryFrom` impls below.

#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub(super) struct RawPreamble {
    pub(super) magic: [u8; 4],
    pub(super) format_version: u32,
}

#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub(super) struct RawHeaderV1 {
    pub(super) arch: u64,
    pub(super) abi_version: u64,
    pub(super) stack_top_gva: u64,
    pub(super) entrypoint_tag: u64,
    pub(super) entrypoint_addr: u64,
    pub(super) input_data_size: u64,
    pub(super) output_data_size: u64,
    pub(super) heap_size: u64,
    pub(super) code_size: u64,
    pub(super) init_data_size: u64,
    pub(super) init_data_permissions: u64,
    pub(super) scratch_size: u64,
    pub(super) snapshot_size: u64,
    pub(super) pt_size: u64,
    pub(super) memory_size: u64,
    pub(super) memory_offset: u64,
    pub(super) has_sregs: u64,
    pub(super) hypervisor: u64,
    pub(super) host_funcs_size: u64,
}

#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
struct RawSegmentRegister {
    base: u64,
    limit: u64,
    selector: u64,
    type_: u64,
    present: u64,
    dpl: u64,
    db: u64,
    s: u64,
    l: u64,
    g: u64,
    avl: u64,
    unusable: u64,
    padding: u64,
}

#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
struct RawTableRegister {
    base: u64,
    limit: u64,
}

#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
struct RawSregs {
    cs: RawSegmentRegister,
    ds: RawSegmentRegister,
    es: RawSegmentRegister,
    fs: RawSegmentRegister,
    gs: RawSegmentRegister,
    ss: RawSegmentRegister,
    tr: RawSegmentRegister,
    ldt: RawSegmentRegister,
    gdt: RawTableRegister,
    idt: RawTableRegister,
    cr0: u64,
    cr2: u64,
    cr3: u64,
    cr4: u64,
    cr8: u64,
    efer: u64,
    apic_base: u64,
    interrupt_bitmap: [u64; 4],
}

/// Integrity hashes for corruption detection. Not signatures: a
/// writer who can edit the file can recompute both.
///
/// `header_hash` covers `preamble || header || sregs || blob_hash
/// || host_funcs_blob`. Always verified.
///
/// `blob_hash` covers the memory blob and is skipped by
/// `from_file_unchecked` (the O(blob size) check). It is folded
/// into `header_hash` so a partial edit that updates only
/// `blob_hash` is still rejected by `from_file_unchecked`.
#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub(super) struct RawHashes {
    pub(super) header_hash: [u8; 32],
    pub(super) blob_hash: [u8; 32],
}

/// Total byte length of the fixed-position prefix of a V1 snapshot
/// file (preamble + header + sregs + hashes). The `bytemuck::Pod`
/// derives on the raw structs already guarantee they have no
/// padding, so this is exactly the on-disk byte count.
pub(super) const FIXED_PREFIX_SIZE: usize = std::mem::size_of::<RawPreamble>()
    + std::mem::size_of::<RawHeaderV1>()
    + std::mem::size_of::<RawSregs>()
    + std::mem::size_of::<RawHashes>();

// --- Raw <-> rich conversions ---

impl From<&SnapshotPreamble> for RawPreamble {
    fn from(p: &SnapshotPreamble) -> Self {
        Self {
            magic: p.magic,
            format_version: p.format_version as u32,
        }
    }
}

impl TryFrom<RawPreamble> for SnapshotPreamble {
    type Error = crate::HyperlightError;
    fn try_from(raw: RawPreamble) -> crate::Result<Self> {
        if &raw.magic != SNAPSHOT_MAGIC {
            return Err(crate::new_error!(
                "invalid snapshot file: bad magic bytes (expected {:?}, got {:?})",
                SNAPSHOT_MAGIC,
                raw.magic
            ));
        }
        Ok(Self {
            magic: raw.magic,
            format_version: FormatVersion::from_u32(raw.format_version)?,
        })
    }
}

impl From<&SnapshotHeaderV1> for RawHeaderV1 {
    fn from(h: &SnapshotHeaderV1) -> Self {
        let (entrypoint_tag, entrypoint_addr) = match h.entrypoint {
            NextAction::Initialise(a) => (0u64, a),
            NextAction::Call(a) => (1u64, a),
            #[cfg(test)]
            NextAction::None => (u64::MAX, 0),
        };
        let l = &h.layout;
        Self {
            arch: h.arch as u64,
            abi_version: h.abi_version,
            stack_top_gva: h.stack_top_gva,
            entrypoint_tag,
            entrypoint_addr,
            input_data_size: l.input_data_size as u64,
            output_data_size: l.output_data_size as u64,
            heap_size: l.heap_size as u64,
            code_size: l.code_size as u64,
            init_data_size: l.init_data_size as u64,
            init_data_permissions: l.init_data_permissions.map_or(0, |f| f.bits() as u64),
            scratch_size: l.scratch_size as u64,
            snapshot_size: l.snapshot_size as u64,
            pt_size: l.pt_size.map_or(0, |v| v as u64),
            memory_size: h.memory_size as u64,
            memory_offset: h.memory_offset,
            has_sregs: if h.has_sregs { 1 } else { 0 },
            hypervisor: h.hypervisor as u64,
            host_funcs_size: h.host_funcs_size,
        }
    }
}

impl TryFrom<RawHeaderV1> for SnapshotHeaderV1 {
    type Error = crate::HyperlightError;
    fn try_from(raw: RawHeaderV1) -> crate::Result<Self> {
        use crate::mem::memory_region::MemoryRegionFlags;

        let arch = ArchTag::from_u64(raw.arch)?;
        let entrypoint = match raw.entrypoint_tag {
            0 => NextAction::Initialise(raw.entrypoint_addr),
            1 => NextAction::Call(raw.entrypoint_addr),
            _ => {
                return Err(crate::new_error!(
                    "invalid entrypoint tag in snapshot: {}",
                    raw.entrypoint_tag
                ));
            }
        };
        let init_data_permissions = if raw.init_data_permissions == 0 {
            None
        } else {
            // Field is `u64` on disk for layout uniformity but the
            // flag set is `u32`. Reject any high bits before
            // narrowing so we don't silently truncate them.
            let bits = u32::try_from(raw.init_data_permissions).map_err(|_| {
                crate::new_error!(
                    "snapshot init_data_permissions ({:#x}) exceeds u32 range",
                    raw.init_data_permissions
                )
            })?;
            Some(MemoryRegionFlags::from_bits(bits).ok_or_else(|| {
                crate::new_error!("snapshot contains unknown memory region flags: {:#x}", bits)
            })?)
        };
        let pt_size = if raw.pt_size == 0 {
            None
        } else {
            Some(raw.pt_size as usize)
        };
        let has_sregs = match raw.has_sregs {
            0 => false,
            1 => true,
            other => {
                return Err(crate::new_error!(
                    "snapshot has_sregs must be 0 or 1, got {}",
                    other
                ));
            }
        };
        let hypervisor = HypervisorTag::from_u64(raw.hypervisor)?;
        Ok(Self {
            arch,
            abi_version: raw.abi_version,
            stack_top_gva: raw.stack_top_gva,
            entrypoint,
            layout: LayoutFields {
                input_data_size: raw.input_data_size as usize,
                output_data_size: raw.output_data_size as usize,
                heap_size: raw.heap_size as usize,
                code_size: raw.code_size as usize,
                init_data_size: raw.init_data_size as usize,
                init_data_permissions,
                scratch_size: raw.scratch_size as usize,
                snapshot_size: raw.snapshot_size as usize,
                pt_size,
            },
            memory_size: raw.memory_size as usize,
            memory_offset: raw.memory_offset,
            has_sregs,
            hypervisor,
            host_funcs_size: raw.host_funcs_size,
        })
    }
}

impl SnapshotHeaderV1 {
    /// File-bound and environment validation: checks that a
    /// well-formed header (already produced by `TryFrom`) is also
    /// consistent with the actual file size and the runtime
    /// environment (architecture, hypervisor, ABI version).
    fn validate_against_file(&self, file_len: u64) -> crate::Result<()> {
        if self.arch != ArchTag::current() {
            return Err(crate::new_error!(
                "snapshot architecture mismatch: expected {:?}, got {:?}",
                ArchTag::current(),
                self.arch
            ));
        }
        if self.abi_version != SNAPSHOT_ABI_VERSION {
            return Err(crate::new_error!(
                "snapshot ABI version mismatch: file has ABI version {}, \
                 but this build expects {}. The snapshot must be regenerated \
                 from the guest binary.",
                self.abi_version,
                SNAPSHOT_ABI_VERSION
            ));
        }
        let current_hv = HypervisorTag::current()
            .ok_or_else(|| crate::new_error!("no hypervisor available to load snapshot"))?;
        if self.hypervisor != current_hv {
            return Err(crate::new_error!(
                "snapshot hypervisor mismatch: file was created on {} but the current hypervisor is {}.",
                self.hypervisor.name(),
                current_hv.name()
            ));
        }

        if self.memory_offset == 0 || self.memory_offset % PAGE_SIZE as u64 != 0 {
            return Err(crate::new_error!(
                "invalid snapshot memory_offset {} (must be a non-zero multiple of PAGE_SIZE)",
                self.memory_offset
            ));
        }

        // host_funcs region must fit between the fixed prefix and
        // the page-aligned memory_offset.
        if self.host_funcs_size > MAX_HOST_FUNCS_SIZE {
            return Err(crate::new_error!(
                "snapshot host_funcs_size ({}) exceeds maximum ({})",
                self.host_funcs_size,
                MAX_HOST_FUNCS_SIZE
            ));
        }
        let after_hf = (FIXED_PREFIX_SIZE as u64)
            .checked_add(self.host_funcs_size)
            .ok_or_else(|| {
                crate::new_error!(
                    "snapshot host_funcs_size ({}) overflows file offset",
                    self.host_funcs_size
                )
            })?;
        if after_hf > self.memory_offset {
            return Err(crate::new_error!(
                "snapshot host_funcs_size ({}) does not fit between fixed prefix and memory_offset ({})",
                self.host_funcs_size,
                self.memory_offset
            ));
        }
        // host_funcs region must fit in the file too (defends
        // against memory_offset being extended past the file end by
        // a malicious header).
        let max_host_funcs = file_len.saturating_sub(FIXED_PREFIX_SIZE as u64);
        if self.host_funcs_size > max_host_funcs {
            return Err(crate::new_error!(
                "snapshot host_funcs_size ({}) exceeds remaining file bytes ({})",
                self.host_funcs_size,
                max_host_funcs
            ));
        }

        // Memory blob plus the trailing PAGE_SIZE guard must fit in
        // the file.
        let blob_end = self
            .memory_offset
            .checked_add(self.memory_size as u64)
            .and_then(|n| n.checked_add(PAGE_SIZE as u64))
            .ok_or_else(|| crate::new_error!("snapshot memory blob bounds overflow"))?;
        if blob_end > file_len {
            return Err(crate::new_error!(
                "snapshot memory blob extends past the end of the file (need {} bytes, file has {})",
                blob_end,
                file_len
            ));
        }

        // `entrypoint` and `has_sregs` must agree: a `Call` snapshot
        // is mid-execution and therefore has a captured sregs state,
        // while an `Initialise` snapshot has not yet run on the vCPU
        // and has none. Anything else is a malformed header.
        let call_entry = matches!(self.entrypoint, NextAction::Call(_));
        if call_entry != self.has_sregs {
            return Err(crate::new_error!(
                "snapshot entrypoint and has_sregs disagree: entrypoint requires sregs={}, has_sregs={}",
                call_entry,
                self.has_sregs
            ));
        }

        Ok(())
    }
}

impl From<&CommonSpecialRegisters> for RawSregs {
    fn from(s: &CommonSpecialRegisters) -> Self {
        let seg = |r: &crate::hypervisor::regs::CommonSegmentRegister| RawSegmentRegister {
            base: r.base,
            limit: r.limit as u64,
            selector: r.selector as u64,
            type_: r.type_ as u64,
            present: r.present as u64,
            dpl: r.dpl as u64,
            db: r.db as u64,
            s: r.s as u64,
            l: r.l as u64,
            g: r.g as u64,
            avl: r.avl as u64,
            unusable: r.unusable as u64,
            padding: r.padding as u64,
        };
        let tab = |r: &crate::hypervisor::regs::CommonTableRegister| RawTableRegister {
            base: r.base,
            limit: r.limit as u64,
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

impl From<RawSregs> for CommonSpecialRegisters {
    fn from(r: RawSregs) -> Self {
        use crate::hypervisor::regs::{CommonSegmentRegister, CommonTableRegister};
        // Truncating casts are intentional and lossless on
        // well-formed input: the original fields have those widths
        // and were widened to u64 only for on-disk uniformity.
        let seg = |s: RawSegmentRegister| CommonSegmentRegister {
            base: s.base,
            limit: s.limit as u32,
            selector: s.selector as u16,
            type_: s.type_ as u8,
            present: s.present as u8,
            dpl: s.dpl as u8,
            db: s.db as u8,
            s: s.s as u8,
            l: s.l as u8,
            g: s.g as u8,
            avl: s.avl as u8,
            unusable: s.unusable as u8,
            padding: s.padding as u8,
        };
        let tab = |t: RawTableRegister| CommonTableRegister {
            base: t.base,
            limit: t.limit as u16,
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

impl Snapshot {
    /// Save this snapshot to a file on disk.
    ///
    /// The file format uses a page-aligned memory blob that can be
    /// mmapped directly on load for zero-copy instantiation.
    ///
    /// If a file already exists at `path`, it is truncated and
    /// overwritten.
    ///
    /// # Portability
    ///
    /// Snapshot files are **not portable** across CPU architectures,
    /// hypervisors, or operating systems. All three are checked at
    /// load time and a mismatch produces an error.
    pub fn to_file(&self, path: impl AsRef<std::path::Path>) -> crate::Result<()> {
        use std::io::{BufWriter, Write};

        let file = std::fs::File::create(path.as_ref())
            .map_err(|e| crate::new_error!("failed to create snapshot file: {}", e))?;
        let mut w = BufWriter::new(file);

        let layout = &self.layout;

        // Serialize host-function metadata up-front so we can compute
        // `memory_offset` (which depends on `host_funcs_size`) before
        // writing the header.
        let host_funcs_bytes: Vec<u8> = if self
            .host_functions
            .host_functions
            .as_ref()
            .is_some_and(|v| !v.is_empty())
        {
            (&self.host_functions).try_into().map_err(|e| {
                crate::new_error!("failed to serialize host function details: {:?}", e)
            })?
        } else {
            Vec::new()
        };

        // The memory blob sits immediately after the host-function
        // blob, page-aligned. With no host functions this lands at
        // exactly PAGE_SIZE.
        let memory_offset =
            (FIXED_PREFIX_SIZE + host_funcs_bytes.len()).next_multiple_of(PAGE_SIZE) as u64;

        let preamble = SnapshotPreamble {
            magic: *SNAPSHOT_MAGIC,
            format_version: FormatVersion::V1,
        };
        let v1 = SnapshotHeaderV1 {
            arch: ArchTag::current(),
            abi_version: SNAPSHOT_ABI_VERSION,
            stack_top_gva: self.stack_top_gva,
            entrypoint: self.entrypoint,
            layout: LayoutFields {
                input_data_size: layout.input_data_size,
                output_data_size: layout.output_data_size,
                heap_size: layout.heap_size,
                code_size: layout.code_size,
                init_data_size: layout.init_data_size,
                init_data_permissions: layout.init_data_permissions,
                scratch_size: layout.get_scratch_size(),
                snapshot_size: layout.snapshot_size,
                pt_size: layout.pt_size,
            },
            memory_size: self.memory.mem_size(),
            memory_offset,
            has_sregs: self.sregs.is_some(),
            hypervisor: HypervisorTag::current()
                .ok_or_else(|| crate::new_error!("no hypervisor available to tag snapshot"))?,
            host_funcs_size: host_funcs_bytes.len() as u64,
        };
        let sregs = self.sregs.unwrap_or_default();

        let raw_preamble = RawPreamble::from(&preamble);
        let raw_header = RawHeaderV1::from(&v1);
        let raw_sregs = RawSregs::from(&sregs);

        // Corruption-detection hashes (not signatures). `blob_hash`
        // is folded into `header_hash` so the unchecked loader
        // catches partial edits that only update `blob_hash`.
        let blob_hash: [u8; 32] = blake3::hash(self.memory.as_slice()).into();
        let mut hasher = blake3::Hasher::new();
        hasher.update(bytemuck::bytes_of(&raw_preamble));
        hasher.update(bytemuck::bytes_of(&raw_header));
        hasher.update(bytemuck::bytes_of(&raw_sregs));
        hasher.update(&blob_hash);
        hasher.update(&host_funcs_bytes);
        let header_hash: [u8; 32] = hasher.finalize().into();
        let raw_hashes = RawHashes {
            header_hash,
            blob_hash,
        };

        w.write_all(bytemuck::bytes_of(&raw_preamble))
            .map_err(|e| crate::new_error!("snapshot write error: {}", e))?;
        w.write_all(bytemuck::bytes_of(&raw_header))
            .map_err(|e| crate::new_error!("snapshot write error: {}", e))?;
        w.write_all(bytemuck::bytes_of(&raw_sregs))
            .map_err(|e| crate::new_error!("snapshot write error: {}", e))?;
        w.write_all(bytemuck::bytes_of(&raw_hashes))
            .map_err(|e| crate::new_error!("snapshot write error: {}", e))?;

        // Host function metadata (variable length, not mmapped).
        if !host_funcs_bytes.is_empty() {
            w.write_all(&host_funcs_bytes)
                .map_err(|e| crate::new_error!("snapshot write error: {}", e))?;
        }

        // Zero-pad up to the page-aligned memory_offset so the blob
        // is mmap-aligned in the file. Padding is always less than
        // `PAGE_SIZE`.
        let pre_blob_pos = FIXED_PREFIX_SIZE + host_funcs_bytes.len();
        let pad_len = memory_offset as usize - pre_blob_pos;
        debug_assert!(pad_len < PAGE_SIZE);
        w.write_all(&[0u8; PAGE_SIZE][..pad_len])
            .map_err(|e| crate::new_error!("snapshot write error: {}", e))?;

        w.write_all(self.memory.as_slice())
            .map_err(|e| crate::new_error!("snapshot write error: {}", e))?;

        // Trailing PAGE_SIZE padding: Windows read-only file mappings
        // cannot extend beyond the file's actual size, so the file must
        // contain backing bytes for the trailing guard page used by
        // ReadonlySharedMemory::from_file_windows. Linux ignores this
        // padding (its guard pages come from an anonymous mmap reservation).
        w.write_all(&[0u8; PAGE_SIZE])
            .map_err(|e| crate::new_error!("snapshot write error: {}", e))?;

        w.flush()
            .map_err(|e| crate::new_error!("snapshot write error: {}", e))?;

        Ok(())
    }

    /// Load a snapshot from a file on disk.
    ///
    /// The memory blob is mapped directly from the file for zero-copy
    /// loading using platform-specific CoW mechanisms.
    ///
    /// Returns an error if the file is from a different CPU
    /// architecture, hypervisor, or OS than this host. See
    /// [`Snapshot::to_file`] for the full portability story.
    ///
    /// Note: ELF unwind info (`LoadInfo`) is not persisted in the
    /// snapshot file, so the `mem_profile` feature will not have
    /// accurate profiling data for sandboxes created from disk
    /// snapshots.
    ///
    /// # File-mutation hazard
    ///
    /// The file at `path` must not be modified, truncated, renamed
    /// over, or deleted while the returned `Snapshot` (or any
    /// [`MultiUseSandbox`](crate::MultiUseSandbox) constructed from
    /// it) is still alive.
    pub fn from_file(path: impl AsRef<std::path::Path>) -> crate::Result<Self> {
        Self::from_file_impl(path, true)
    }

    /// Load a snapshot from a file on disk without verifying the
    /// memory blob's content hash. The fixed-prefix integrity check
    /// (preamble + header + sregs + host_funcs) is still performed.
    ///
    /// This is faster for large snapshots in trusted environments
    /// where blob integrity is guaranteed by other means. All other
    /// portability checks (architecture, hypervisor, OS) still
    /// apply. See [`Snapshot::to_file`] for details.
    ///
    /// # File-mutation hazard
    ///
    /// The file at `path` must not be modified, truncated, renamed
    /// over, or deleted while the returned `Snapshot` (or any
    /// [`MultiUseSandbox`](crate::MultiUseSandbox) constructed from
    /// it) is still alive.
    pub fn from_file_unchecked(path: impl AsRef<std::path::Path>) -> crate::Result<Self> {
        Self::from_file_impl(path, false)
    }

    fn from_file_impl(
        path: impl AsRef<std::path::Path>,
        verify_blob_hash: bool,
    ) -> crate::Result<Self> {
        use std::io::BufReader;

        let file = std::fs::File::open(path.as_ref())
            .map_err(|e| crate::new_error!("failed to open snapshot file: {}", e))?;
        let file_len = file
            .metadata()
            .map_err(|e| crate::new_error!("snapshot stat error: {}", e))?
            .len();
        let mut r = BufReader::new(&file);

        // Phase 1: read raw bytes into POD structs.
        use std::io::Read;
        let mut preamble_buf = [0u8; std::mem::size_of::<RawPreamble>()];
        r.read_exact(&mut preamble_buf)
            .map_err(|e| crate::new_error!("snapshot read error: {}", e))?;
        let raw_preamble: RawPreamble = bytemuck::pod_read_unaligned(&preamble_buf);
        // Validate magic + format version. Future format versions
        // would dispatch here on `preamble.format_version`.
        let preamble = SnapshotPreamble::try_from(raw_preamble)?;
        let mut header_buf = [0u8; std::mem::size_of::<RawHeaderV1>()];
        let raw_v1: RawHeaderV1 = match preamble.format_version {
            FormatVersion::V1 => {
                r.read_exact(&mut header_buf)
                    .map_err(|e| crate::new_error!("snapshot read error: {}", e))?;
                bytemuck::pod_read_unaligned(&header_buf)
            }
        };
        let mut sregs_buf = [0u8; std::mem::size_of::<RawSregs>()];
        r.read_exact(&mut sregs_buf)
            .map_err(|e| crate::new_error!("snapshot read error: {}", e))?;
        let raw_sregs: RawSregs = bytemuck::pod_read_unaligned(&sregs_buf);

        let mut hashes_buf = [0u8; std::mem::size_of::<RawHashes>()];
        r.read_exact(&mut hashes_buf)
            .map_err(|e| crate::new_error!("snapshot read error: {}", e))?;
        let hashes: RawHashes = bytemuck::pod_read_unaligned(&hashes_buf);

        // Phase 2: parse + validate against the file size and the
        // current runtime environment.
        let hdr = SnapshotHeaderV1::try_from(raw_v1)?;
        hdr.validate_against_file(file_len)?;

        // Read the optional host-function-details blob into a
        // buffer. It is needed both for `header_hash` verification
        // and for the flatbuffer parse below.
        let mut host_funcs_buf = vec![0u8; hdr.host_funcs_size as usize];
        if !host_funcs_buf.is_empty() {
            r.read_exact(&mut host_funcs_buf)
                .map_err(|e| crate::new_error!("snapshot read error: {}", e))?;
        }

        // Phase 3: always-verified `header_hash` over preamble ||
        // header || sregs || blob_hash || host_funcs.
        {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&preamble_buf);
            hasher.update(&header_buf);
            hasher.update(&sregs_buf);
            hasher.update(&hashes.blob_hash);
            hasher.update(&host_funcs_buf);
            let computed: [u8; 32] = hasher.finalize().into();
            if computed != hashes.header_hash {
                return Err(crate::new_error!(
                    "snapshot header_hash mismatch: file may be corrupted"
                ));
            }
        }

        // Reconstruct layout
        let l = &hdr.layout;
        let mut cfg = crate::sandbox::SandboxConfiguration::default();
        cfg.set_input_data_size(l.input_data_size);
        cfg.set_output_data_size(l.output_data_size);
        cfg.set_heap_size(l.heap_size as u64);
        cfg.set_scratch_size(l.scratch_size);
        let mut layout =
            SandboxMemoryLayout::new(cfg, l.code_size, l.init_data_size, l.init_data_permissions)?;
        // Order matters: `set_pt_size` recomputes `snapshot_size`
        // internally, so call it before `set_snapshot_size` so the
        // explicit on-disk value is the one that ends up in `layout`.
        if let Some(pt) = l.pt_size {
            layout.set_pt_size(pt)?;
        }
        layout.set_snapshot_size(l.snapshot_size);

        let sregs = if hdr.has_sregs {
            Some(CommonSpecialRegisters::from(raw_sregs))
        } else {
            None
        };

        let host_functions = if !host_funcs_buf.is_empty() {
            HostFunctionDetails::try_from(host_funcs_buf.as_slice())
                .map_err(|e| crate::new_error!("failed to parse host function details: {:?}", e))?
        } else {
            HostFunctionDetails {
                host_functions: None,
            }
        };

        // Map the memory blob directly from the file (zero-copy CoW).
        // When the blob contains a PT tail (memory_size > snapshot_size),
        // only snapshot_size bytes should be mapped into guest PA space.
        let guest_mapped_size = if hdr.memory_size > layout.snapshot_size {
            Some(layout.snapshot_size)
        } else {
            None
        };
        let memory = ReadonlySharedMemory::from_file(
            &file,
            hdr.memory_offset.try_into().map_err(|_| {
                crate::new_error!(
                    "snapshot memory_offset {} exceeds usize range",
                    hdr.memory_offset
                )
            })?,
            hdr.memory_size,
            guest_mapped_size,
        )?;

        // Phase 4: verify the memory blob's hash. Skipped by
        // `from_file_unchecked` since this is the expensive check
        // (proportional to blob size).
        if verify_blob_hash {
            let computed: [u8; 32] = blake3::hash(memory.as_slice()).into();
            if computed != hashes.blob_hash {
                return Err(crate::new_error!(
                    "snapshot hash mismatch: file may be corrupted"
                ));
            }
        }

        Ok(Snapshot {
            sandbox_id: SANDBOX_CONFIGURATION_COUNTER
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            layout,
            memory,
            regions: Vec::new(),
            load_info: crate::mem::exe::LoadInfo::dummy(),
            // In-memory `Snapshot::hash` is `blake3(memory)` (matches
            // `Snapshot::new`/`Snapshot::from_env`), used as the
            // `PartialEq` key. This is the on-disk `blob_hash`.
            hash: hashes.blob_hash,
            stack_top_gva: hdr.stack_top_gva,
            sregs,
            entrypoint: hdr.entrypoint,
            snapshot_generation: 0,
            host_functions,
        })
    }
}
