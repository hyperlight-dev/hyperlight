// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

mod file;
mod file_tests;
mod memory;
mod tripwires;

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::sync::Arc;

pub(crate) use file::host_cpu_vendor_golden_tag;
pub use file::reference::{OciDigest, OciReference, OciTag};
use hyperlight_common::flatbuffer_wrappers::host_function_details::HostFunctionDetails;
use hyperlight_common::layout::{io_page, scratch_base_gpa, scratch_base_gva};
use hyperlight_common::vmem;
use hyperlight_common::vmem::{
    BasicMapping, CowMapping, Mapping, MappingKind, PAGE_SIZE, PAGE_TABLE_SIZE, SpaceAwareMapping,
    SpaceId, TableOps,
};
use tracing::{Span, instrument};

pub(crate) use self::memory::{
    MAX_SNAPSHOT_BLOBS, MAX_SNAPSHOT_LIVE_EXTENTS, MAX_SNAPSHOT_RETAINED_BYTES, SnapshotBlob,
    SnapshotLayer, SnapshotMemory, SnapshotMemoryBacking,
};
use crate::Result;
use crate::hypervisor::regs::CommonSpecialRegisters;
#[cfg(target_arch = "x86_64")]
use crate::hypervisor::regs::MsrEntry;
use crate::mem::exe::{ExeInfo, LoadInfo};
use crate::mem::layout::SandboxMemoryLayout;
use crate::mem::memory_region::{GuestMemoryRegion, MemoryRegion, MemoryRegionFlags};
use crate::mem::mgr::{GuestBacking, GuestPageTableBuffer, GuestPhysicalMemoryView};
use crate::mem::shared_mem::{
    ExclusiveSharedMemory, HostSharedMemory, ReadonlySharedMemory, SharedMemory,
};
use crate::sandbox::SandboxConfiguration;
use crate::sandbox::uninitialized::{GuestBinary, GuestEnvironment};

const PTE_SIZE: usize = size_of::<vmem::PageTableEntry>();
const MAX_SNAPSHOT_PAGE_TABLE_READS: usize = 2 * (SandboxMemoryLayout::MAX_MEMORY_SIZE / PAGE_SIZE);

/// Presently, a snapshot can be of a preinitialised sandbox, which
/// still needs an initialise function called in order to determine
/// how to call into it, or of an already-properly-initialised sandbox
/// which can be immediately called into. This keeps track of the
/// difference.
///
/// TODO: this should not necessarily be around in the long term:
/// ideally we would just preinitialise earlier in the snapshot
/// creation process and never need this.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum NextAction {
    /// A sandbox in the preinitialise state still needs to be
    /// initialised by calling the initialise function
    Initialise(u64),
    /// A sandbox in the ready state can immediately be called into,
    /// using the dispatch function pointer.
    Call(u64),
    /// Only when compiling for tests: a sandbox that cannot actually
    /// be used
    #[cfg(test)]
    None,
}

/// A wrapper around a `SharedMemory` reference and a snapshot
/// of the memory therein
pub struct Snapshot {
    /// Layout object for the sandbox. TODO: get rid of this and
    /// replace with something saner and set up from the guest (early
    /// on?).
    layout: crate::mem::layout::SandboxMemoryLayout,
    /// Memory of the sandbox at the time this snapshot was taken
    memory: Arc<SnapshotMemory>,
    /// Extra debug information about the binary in this snapshot,
    /// from when the binary was first loaded into the snapshot.
    ///
    /// This information is provided on a best-effort basis, and there
    /// is a pretty good chance that it does not exist; generally speaking,
    /// things like persisting a snapshot and reloading it are likely
    /// to destroy this information.
    load_info: LoadInfo,
    /// The address of the top of the guest stack
    stack_top_gva: u64,

    /// Special register state captured from the vCPU during snapshot.
    /// None for snapshots created directly from a binary (before
    /// guest runs).  Some for snapshots taken from a running sandbox.
    /// Note: CR3 in this struct is NOT used on restore, since page
    /// tables are relocated during snapshot.
    sregs: Option<CommonSpecialRegisters>,

    /// The MSRs saved in this snapshot. None before the guest has run.
    #[cfg(target_arch = "x86_64")]
    msrs: Option<Vec<MsrEntry>>,

    /// The next action that should be performed on this snapshot
    next_action: NextAction,

    /// Guest virtual address of the guest binary's ELF entry point
    /// (`load_addr + e_entry - base_va`). Unlike `next_action`, which
    /// transitions to `Call(dispatch_addr)` once the guest has run,
    /// this preserves the original entry across that transition. Used
    /// to fill `AT_ENTRY` in guest core dumps so a debugger can
    /// compute the PIE load bias. 0 if unknown (e.g. an older
    /// on-disk snapshot that predates this field).
    original_entrypoint: u64,

    /// The generation number assigned to this snapshot when it was
    /// taken — i.e. "this is the Nth snapshot taken from the sandbox's
    /// execution path from init to here". Propagated into the
    /// restored sandbox's guest-visible counter so the guest can tell
    /// which snapshot it is currently a clone of.
    snapshot_generation: u64,

    /// Names and signatures of host functions registered on the
    /// sandbox at the time this snapshot was taken. Used by
    /// [`crate::MultiUseSandbox::from_snapshot`] to reject a
    /// `HostFunctions` set that is missing required functions or
    /// has mismatched signatures.
    host_functions: HostFunctionDetails,
}
impl core::convert::AsRef<Snapshot> for Snapshot {
    fn as_ref(&self) -> &Self {
        self
    }
}
impl hyperlight_common::vmem::TableReadOps for Snapshot {
    type TableAddr = u64;
    fn entry_addr(addr: u64, offset: u64) -> u64 {
        addr.saturating_add(offset)
    }
    unsafe fn read_entry(&self, addr: u64) -> vmem::PageTableEntry {
        let mut pte_bytes = [0u8; PTE_SIZE];
        if self
            .memory
            .read_page_tables(self.layout.get_pt_base_gpa(), addr, &mut pte_bytes)
            .is_err()
        {
            // Attacker-controlled data pointed out-of-bounds. We'll
            // default to returning 0 in this case, which, for most
            // architectures (including x86-64 and arm64, the ones we
            // care about presently) will be a not-present entry.
            return 0;
        }
        vmem::PageTableEntry::from_le_bytes(pte_bytes)
    }
    #[allow(clippy::unnecessary_cast)]
    fn to_phys(addr: u64) -> vmem::PhysAddr {
        addr as vmem::PhysAddr
    }
    #[allow(clippy::unnecessary_cast)]
    fn from_phys(addr: vmem::PhysAddr) -> u64 {
        addr as u64
    }
    fn root_table(&self) -> u64 {
        self.root_pt_gpa()
    }
}

pub(crate) struct PageTableReader<'a> {
    memory: &'a GuestPhysicalMemoryView<'a>,
    root: u64,
    reads: Cell<usize>,
    failure: Cell<Option<&'static str>>,
}
impl<'a> PageTableReader<'a> {
    pub(crate) fn new(memory: &'a GuestPhysicalMemoryView<'a>, root: u64) -> Self {
        Self {
            memory,
            root,
            reads: Cell::new(0),
            failure: Cell::new(None),
        }
    }

    fn failure(&self) -> Option<&'static str> {
        self.failure.get()
    }
}
impl<'a> hyperlight_common::vmem::TableReadOps for PageTableReader<'a> {
    type TableAddr = u64;
    fn entry_addr(addr: u64, offset: u64) -> u64 {
        addr.saturating_add(offset)
    }
    unsafe fn read_entry(&self, addr: u64) -> vmem::PageTableEntry {
        // TableReadOps cannot return errors. Preserve the first failure and
        // return a not-present entry until the caller checks it after the walk.
        if self.failure.get().is_some() {
            return 0;
        }
        let reads = self.reads.get();
        if reads >= MAX_SNAPSHOT_PAGE_TABLE_READS {
            self.failure
                .set(Some("snapshot page-table walk limit exceeded"));
            return 0;
        }
        self.reads.set(reads + 1);

        let mut pte_bytes = [0u8; PTE_SIZE];
        if self.memory.read(addr, &mut pte_bytes).is_err() {
            self.failure
                .set(Some("snapshot page-table walk accessed unbacked memory"));
            return 0;
        }
        vmem::PageTableEntry::from_le_bytes(pte_bytes)
    }
    #[allow(clippy::unnecessary_cast)]
    fn to_phys(addr: u64) -> vmem::PhysAddr {
        addr as vmem::PhysAddr
    }
    #[allow(clippy::unnecessary_cast)]
    fn from_phys(addr: vmem::PhysAddr) -> u64 {
        addr as u64
    }
    fn root_table(&self) -> u64 {
        self.root
    }
}
impl<'a> core::convert::AsRef<PageTableReader<'a>> for PageTableReader<'a> {
    fn as_ref(&self) -> &Self {
        self
    }
}
/// Return true if `virt_base` is a VA we must not preserve into the
/// rebuilt snapshot page tables: it is either part of the scratch
/// region (re-mapped freshly by `map_specials`) or, on amd64, part of
/// the self-map of the snapshot's own page tables.
fn skip_virt(virt_base: u64, scratch_gva: u64) -> bool {
    if virt_base >= scratch_gva {
        return true;
    }
    if virt_base >= hyperlight_common::layout::SNAPSHOT_PT_GVA_MIN as u64
        && virt_base <= hyperlight_common::layout::SNAPSHOT_PT_GVA_MAX as u64
    {
        return true;
    }
    false
}

fn for_each_mapping_page(
    mapping: &Mapping,
    mut visitor: impl FnMut(u64, u64, MappingKind) -> Result<()>,
) -> Result<()> {
    if !validate_mapping(mapping)? {
        return Ok(());
    }
    let mut offset = 0u64;
    while offset < mapping.len {
        let phys = mapping
            .phys_base
            .checked_add(offset)
            .ok_or_else(|| crate::new_error!("guest physical mapping overflows"))?;
        let virt = mapping
            .virt_base
            .checked_add(offset)
            .ok_or_else(|| crate::new_error!("guest virtual mapping overflows"))?;
        visitor(phys, virt, mapping.kind)?;
        offset = offset
            .checked_add(PAGE_SIZE as u64)
            .ok_or_else(|| crate::new_error!("guest mapping offset overflows"))?;
    }
    Ok(())
}

fn validate_mapping(mapping: &Mapping) -> Result<bool> {
    if mapping.kind == MappingKind::Unmapped {
        return Ok(false);
    }
    if mapping.len == 0
        || !mapping.phys_base.is_multiple_of(PAGE_SIZE as u64)
        || !mapping.virt_base.is_multiple_of(PAGE_SIZE as u64)
        || !mapping.len.is_multiple_of(PAGE_SIZE as u64)
    {
        return Err(crate::new_error!("guest mapping is not page aligned"));
    }
    Ok(true)
}

fn mapping_has_skipped_pages(mapping: &Mapping, scratch_gva: u64) -> Result<bool> {
    let last_page = mapping
        .virt_base
        .checked_add(mapping.len - PAGE_SIZE as u64)
        .ok_or_else(|| crate::new_error!("guest virtual mapping overflows"))?;
    let snapshot_pt_start = hyperlight_common::layout::SNAPSHOT_PT_GVA_MIN as u64;
    let snapshot_pt_end = hyperlight_common::layout::SNAPSHOT_PT_GVA_MAX as u64;
    Ok(last_page >= scratch_gva
        || (mapping.virt_base <= snapshot_pt_end && snapshot_pt_start <= last_page))
}

fn coalesce_pages(pages: &[bool]) -> Box<[Range<usize>]> {
    let mut ranges: Vec<Range<usize>> = Vec::new();
    for (page_index, retained) in pages.iter().enumerate() {
        if !retained {
            continue;
        }
        let page = page_index * PAGE_SIZE;
        let end = page + PAGE_SIZE;
        if let Some(previous) = ranges.last_mut()
            && previous.end == page
        {
            previous.end = end;
        } else {
            ranges.push(page..end);
        }
    }
    ranges.into_boxed_slice()
}

#[derive(Clone, Copy)]
struct NewPage {
    source_gpa: u64,
    backing: GuestBacking,
}

fn backing_with_offset(backing: GuestBacking, offset: usize) -> Option<GuestBacking> {
    match backing {
        GuestBacking::Snapshot {
            layer_index,
            offset: backing_offset,
        } => Some(GuestBacking::Snapshot {
            layer_index,
            offset: backing_offset.checked_add(offset)?,
        }),
        GuestBacking::Scratch {
            offset: backing_offset,
        } => Some(GuestBacking::Scratch {
            offset: backing_offset.checked_add(offset)?,
        }),
        GuestBacking::Dynamic {
            region_index,
            offset: backing_offset,
        } => Some(GuestBacking::Dynamic {
            region_index,
            offset: backing_offset.checked_add(offset)?,
        }),
    }
}

fn record_backed_pages(
    backing: GuestBacking,
    source_gpa: u64,
    len: usize,
    retained_pages: Option<&mut [Vec<bool>]>,
    new_pages: &mut Vec<NewPage>,
) -> Result<()> {
    if let GuestBacking::Snapshot { offset, .. } = backing
        && (!offset.is_multiple_of(PAGE_SIZE) || !len.is_multiple_of(PAGE_SIZE))
    {
        return Err(crate::new_error!(
            "snapshot backing range is not page aligned"
        ));
    }

    if let GuestBacking::Snapshot {
        layer_index,
        offset,
    } = backing
        && let Some(retained_pages) = retained_pages
    {
        let start = offset / PAGE_SIZE;
        let end = offset
            .checked_add(len)
            .map(|end| end / PAGE_SIZE)
            .ok_or_else(|| crate::new_error!("snapshot backing range overflows"))?;
        retained_pages
            .get_mut(layer_index)
            .and_then(|pages| pages.get_mut(start..end))
            .ok_or_else(|| crate::new_error!("snapshot backing range is out of bounds"))?
            .fill(true);
        return Ok(());
    }

    for offset in (0..len).step_by(PAGE_SIZE) {
        new_pages.push(NewPage {
            source_gpa: source_gpa
                .checked_add(u64::try_from(offset)?)
                .ok_or_else(|| crate::new_error!("snapshot source GPA overflows"))?,
            backing: backing_with_offset(backing, offset)
                .ok_or_else(|| crate::new_error!("snapshot source backing offset overflows"))?,
        });
    }
    Ok(())
}

fn move_partial_host_pages(
    layer_index: usize,
    retained_pages: &mut [bool],
    blob_gpa_start: u64,
    host_page_size: usize,
    new_pages: &mut Vec<NewPage>,
) -> Result<()> {
    if host_page_size < PAGE_SIZE || !host_page_size.is_multiple_of(PAGE_SIZE) {
        return Err(crate::new_error!(
            "host page size {host_page_size} is incompatible with guest page size {PAGE_SIZE}"
        ));
    }
    if host_page_size == PAGE_SIZE {
        return Ok(());
    }

    let pages_per_host_page = host_page_size / PAGE_SIZE;
    for (host_page_index, pages) in retained_pages.chunks_mut(pages_per_host_page).enumerate() {
        if pages.iter().all(|retained| *retained) {
            continue;
        }
        for (page_index, retained) in pages.iter_mut().enumerate() {
            if !*retained {
                continue;
            }
            *retained = false;
            let offset = host_page_index
                .checked_mul(host_page_size)
                .and_then(|offset| offset.checked_add(page_index * PAGE_SIZE))
                .ok_or_else(|| crate::new_error!("snapshot retained-page offset overflows"))?;
            let gpa = blob_gpa_start
                .checked_add(u64::try_from(offset)?)
                .ok_or_else(|| crate::new_error!("snapshot retained-page GPA overflows"))?;
            new_pages.push(NewPage {
                source_gpa: gpa,
                backing: GuestBacking::Snapshot {
                    layer_index,
                    offset,
                },
            });
        }
    }
    Ok(())
}

struct NewPageRun {
    source: Range<u64>,
    destination_start: u64,
}

struct NewPageCopy {
    backing: GuestBacking,
    destination: Range<usize>,
}

fn backing_is_contiguous(first: GuestBacking, next: GuestBacking, len: usize) -> bool {
    match (first, next) {
        (
            GuestBacking::Snapshot {
                layer_index: first_layer,
                offset: first_offset,
            },
            GuestBacking::Snapshot {
                layer_index: next_layer,
                offset: next_offset,
            },
        ) => first_layer == next_layer && first_offset.checked_add(len) == Some(next_offset),
        (
            GuestBacking::Scratch {
                offset: first_offset,
            },
            GuestBacking::Scratch {
                offset: next_offset,
            },
        ) => first_offset.checked_add(len) == Some(next_offset),
        (
            GuestBacking::Dynamic {
                region_index: first_region,
                offset: first_offset,
            },
            GuestBacking::Dynamic {
                region_index: next_region,
                offset: next_offset,
            },
        ) => first_region == next_region && first_offset.checked_add(len) == Some(next_offset),
        _ => false,
    }
}

fn new_page_copies(pages: &[NewPage]) -> Result<Vec<NewPageCopy>> {
    let mut copies = Vec::<NewPageCopy>::new();
    for (index, page) in pages.iter().enumerate() {
        let start = index
            .checked_mul(PAGE_SIZE)
            .ok_or_else(|| crate::new_error!("snapshot page offset overflows"))?;
        let end = start
            .checked_add(PAGE_SIZE)
            .ok_or_else(|| crate::new_error!("snapshot page range overflows"))?;
        if let Some(copy) = copies.last_mut()
            && backing_is_contiguous(copy.backing, page.backing, copy.destination.len())
        {
            copy.destination.end = end;
        } else {
            copies.push(NewPageCopy {
                backing: page.backing,
                destination: start..end,
            });
        }
    }
    Ok(copies)
}

fn new_page_runs(pages: &[NewPage], destination_start: u64) -> Result<Vec<NewPageRun>> {
    let mut runs = Vec::<NewPageRun>::new();
    for (index, page) in pages.iter().enumerate() {
        let source_gpa = page.source_gpa;
        let destination = destination_start
            .checked_add(u64::try_from(index.checked_mul(PAGE_SIZE).ok_or_else(
                || crate::new_error!("snapshot page offset overflows"),
            )?)?)
            .ok_or_else(|| crate::new_error!("snapshot page GPA overflows"))?;
        if let Some(run) = runs.last_mut()
            && run.source.end == source_gpa
        {
            run.source.end = run
                .source
                .end
                .checked_add(PAGE_SIZE as u64)
                .ok_or_else(|| crate::new_error!("snapshot source page run overflows"))?;
        } else {
            let source_end = source_gpa
                .checked_add(PAGE_SIZE as u64)
                .ok_or_else(|| crate::new_error!("snapshot source page overflows"))?;
            runs.push(NewPageRun {
                source: source_gpa..source_end,
                destination_start: destination,
            });
        }
    }
    Ok(runs)
}

fn page_destination(runs: &[NewPageRun], source_gpa: u64) -> Option<u64> {
    let index = runs.partition_point(|run| run.source.end <= source_gpa);
    let run = runs.get(index)?;
    let offset = source_gpa.checked_sub(run.source.start)?;
    (source_gpa < run.source.end).then(|| run.destination_start.checked_add(offset))?
}

fn packed_data_len(page_count: usize, host_page_size: usize) -> Result<usize> {
    let page_bytes = page_count
        .checked_mul(PAGE_SIZE)
        .ok_or_else(|| crate::new_error!("snapshot data size overflows"))?;
    page_bytes
        .checked_next_multiple_of(host_page_size)
        .ok_or_else(|| crate::new_error!("snapshot data padding overflows"))
}

fn add_page_table_range(
    tables: &mut BTreeSet<(usize, u8, u64)>,
    root_index: usize,
    start: u64,
    len: u64,
) -> Result<()> {
    if len == 0 {
        return Ok(());
    }
    let end = start
        .checked_add(len - 1)
        .ok_or_else(|| crate::new_error!("snapshot virtual mapping overflows"))?;
    for shift in [39u8, 30, 21] {
        for prefix in (start >> shift)..=(end >> shift) {
            tables.insert((root_index, shift, prefix));
        }
    }
    Ok(())
}

fn add_page_table_page(
    tables: &mut BTreeSet<(usize, u8, u64)>,
    previous_prefixes: &mut [Option<u64>; 3],
    root_index: usize,
    virt_gva: u64,
) {
    for (previous, shift) in previous_prefixes.iter_mut().zip([39u8, 30, 21]) {
        let prefix = virt_gva >> shift;
        if *previous != Some(prefix) {
            tables.insert((root_index, shift, prefix));
            *previous = Some(prefix);
        }
    }
}

fn first_fit_blob_gpa(data_len: usize, layers: &[SnapshotLayer], scratch_base: u64) -> Option<u64> {
    if data_len == 0 {
        return None;
    }
    let data_len = u64::try_from(data_len).ok()?;
    let mut candidate = SandboxMemoryLayout::BASE_ADDRESS as u64;
    for range in layers
        .iter()
        .filter_map(|layer| layer.blob().data_gpa_range().map(|data| data.gpa_range()))
    {
        let end = candidate.checked_add(data_len)?;
        if end <= range.start {
            return Some(candidate);
        }
        candidate = candidate.max(range.end);
    }
    (candidate.checked_add(data_len)? <= scratch_base).then_some(candidate)
}

fn validate_layered_capture(
    retained_layer_count: usize,
    retained_extent_count: usize,
    projected_retained_bytes: usize,
    layered_data_len: usize,
    layered_gpa: Option<u64>,
) -> Result<Option<u64>> {
    let layer_count = retained_layer_count
        .checked_add(1)
        .ok_or_else(|| crate::new_error!("snapshot blob count overflows"))?;
    if layer_count > MAX_SNAPSHOT_BLOBS {
        return Err(crate::new_error!(
            "snapshot blob count {} exceeds {}",
            layer_count,
            MAX_SNAPSHOT_BLOBS
        ));
    }

    let extent_count = retained_extent_count
        .checked_add(usize::from(layered_data_len != 0))
        .ok_or_else(|| crate::new_error!("snapshot live-extent count overflows"))?;
    if extent_count > MAX_SNAPSHOT_LIVE_EXTENTS {
        return Err(crate::new_error!(
            "snapshot live-extent count {} exceeds {}",
            extent_count,
            MAX_SNAPSHOT_LIVE_EXTENTS
        ));
    }

    if projected_retained_bytes > MAX_SNAPSHOT_RETAINED_BYTES {
        return Err(crate::new_error!(
            "snapshot retained byte count {} exceeds {}",
            projected_retained_bytes,
            MAX_SNAPSHOT_RETAINED_BYTES
        ));
    }

    if layered_data_len == 0 {
        Ok(None)
    } else {
        layered_gpa
            .map(Some)
            .ok_or_else(|| crate::new_error!("snapshot has no address space for a new layer"))
    }
}

fn snapshot_mapping_kind(kind: MappingKind) -> Option<MappingKind> {
    match kind {
        MappingKind::Cow(mapping) => Some(MappingKind::Cow(mapping)),
        MappingKind::Basic(mapping) if mapping.writable => Some(MappingKind::Cow(CowMapping {
            readable: mapping.readable,
            executable: mapping.executable,
        })),
        MappingKind::Basic(mapping) => Some(MappingKind::Basic(BasicMapping {
            readable: mapping.readable,
            writable: false,
            executable: mapping.executable,
        })),
        MappingKind::Unmapped => None,
    }
}

fn map_specials(pt_buf: &GuestPageTableBuffer, scratch_size: usize) {
    if let Some((phys_base, virt_base)) = io_page() {
        // Map the IO page
        let mapping = Mapping {
            phys_base,
            virt_base,
            len: PAGE_SIZE as u64,
            kind: MappingKind::Basic(BasicMapping {
                readable: true,
                writable: true,
                executable: false,
            }),
        };
        unsafe { vmem::map(pt_buf, mapping) };
    }
    // Map the scratch region
    let mapping = Mapping {
        phys_base: scratch_base_gpa(scratch_size),
        virt_base: scratch_base_gva(scratch_size),
        len: scratch_size as u64,
        kind: MappingKind::Basic(BasicMapping {
            readable: true,
            writable: true,
            // assume that the guest will map these pages elsewhere if
            // it actually needs to execute from them
            executable: false,
        }),
    };
    unsafe { vmem::map(pt_buf, mapping) };
}

impl Snapshot {
    fn flat_snapshot_memory(
        memory: ReadonlySharedMemory,
        layout: &SandboxMemoryLayout,
        data_len: usize,
        page_table_len: usize,
    ) -> Result<SnapshotMemory> {
        let page_table_end = data_len
            .checked_add(page_table_len)
            .ok_or_else(|| crate::new_error!("snapshot memory size overflows"))?;
        SnapshotMemory::from_flat(
            memory,
            SandboxMemoryLayout::BASE_ADDRESS as u64,
            data_len,
            data_len..page_table_end,
            scratch_base_gpa(layout.get_scratch_size()),
        )
    }

    /// Create a new snapshot from the guest binary identified by `env`. With the configuration
    /// specified in `cfg`.
    pub(crate) fn from_env<'b>(
        env: impl Into<GuestEnvironment<'b>>,
        cfg: SandboxConfiguration,
    ) -> Result<Self> {
        let env = env.into();
        let mut bin = env.guest_binary;
        bin.canonicalize()?;
        let blob = env.init_data;

        let exe_info = match bin {
            GuestBinary::FilePath(bin_path) => ExeInfo::from_file(&bin_path)?,
            GuestBinary::Buffer(buffer) => ExeInfo::from_buf(buffer)?,
        };

        // Check guest/host version compatibility.
        let host_version = env!("CARGO_PKG_VERSION");
        if let Some(v) = exe_info.guest_bin_version()
            && v != host_version
        {
            return Err(crate::HyperlightError::GuestBinVersionMismatch {
                guest_bin_version: v.to_string(),
                host_version: host_version.to_string(),
            });
        }

        let guest_blob_size = blob.as_ref().map(|b| b.data.len()).unwrap_or(0);
        let guest_blob_mem_flags = blob.as_ref().map(|b| b.permissions);

        let layout = crate::mem::layout::SandboxMemoryLayout::new(
            cfg,
            exe_info.loaded_size(),
            guest_blob_size,
            guest_blob_mem_flags,
        )?;

        let load_addr = layout.get_guest_code_address() as u64;
        let base_va = exe_info.base_va();
        let entrypoint_va: u64 = exe_info.entrypoint().into();

        let data_len = layout.get_memory_size()?;
        let mut memory = vec![0; data_len];

        let load_info = exe_info.load(
            load_addr.try_into()?,
            &mut memory[layout.guest_code_offset()..],
        )?;

        layout.write_peb(&mut memory)?;

        blob.map(|x| layout.write_init_data(&mut memory, x.data))
            .transpose()?;

        // Set up page table entries for the snapshot
        let pt_buf = GuestPageTableBuffer::new(layout.get_pt_base_gpa() as usize);

        // 1. Map the (ideally readonly) pages of snapshot data
        for rgn in layout.get_memory_regions_::<GuestMemoryRegion>(())?.iter() {
            let readable = rgn.flags.contains(MemoryRegionFlags::READ);
            let executable = rgn.flags.contains(MemoryRegionFlags::EXECUTE);
            let writable = rgn.flags.contains(MemoryRegionFlags::WRITE);
            let kind = if writable {
                MappingKind::Cow(CowMapping {
                    readable,
                    executable,
                })
            } else {
                MappingKind::Basic(BasicMapping {
                    readable,
                    writable: false,
                    executable,
                })
            };
            let mapping = Mapping {
                phys_base: rgn.guest_region.start as u64,
                virt_base: rgn.guest_region.start as u64,
                len: rgn.guest_region.len() as u64,
                kind,
            };
            unsafe { vmem::map(&pt_buf, mapping) };
        }

        // 2. Map the special mappings
        map_specials(&pt_buf, layout.get_scratch_size());

        let pt_bytes = pt_buf.into_bytes();
        layout.ensure_page_tables_fit(pt_bytes.len())?;
        memory.extend(&pt_bytes);

        let exn_stack_top_gva = hyperlight_common::layout::SCRATCH_TOP_GVA as u64
            - hyperlight_common::layout::SCRATCH_TOP_EXN_STACK_OFFSET
            + 1;

        let entrypoint_gva = load_addr + entrypoint_va - base_va;

        let memory = ReadonlySharedMemory::from_bytes(&memory)?;
        let memory = Arc::new(Self::flat_snapshot_memory(
            memory,
            &layout,
            data_len,
            pt_bytes.len(),
        )?);

        Ok(Self {
            memory,
            layout,
            load_info,
            stack_top_gva: exn_stack_top_gva,
            sregs: None,
            #[cfg(target_arch = "x86_64")]
            msrs: None,
            next_action: NextAction::Initialise(entrypoint_gva),
            original_entrypoint: entrypoint_gva,
            snapshot_generation: 0,
            host_functions: HostFunctionDetails {
                host_functions: None,
            },
        })
    }

    // It might be nice to consider moving at least stack_top_gva into
    // layout, and sharing (via RwLock or similar) the layout between
    // the (host-side) mem mgr (where it can be passed in here) and
    // the sandbox vm itself (which modifies it as it receives
    // requests from the sandbox).
    #[allow(clippy::too_many_arguments)]
    /// Take a snapshot of the memory in `shared_mem`, then create a new
    /// instance of `Self` with the snapshot stored therein.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn new(
        shared_mem: &SnapshotMemoryBacking<HostSharedMemory>,
        scratch_mem: &HostSharedMemory,
        layout: SandboxMemoryLayout,
        load_info: LoadInfo,
        regions: Vec<MemoryRegion>,
        root_pt_gpas: &[u64],
        stack_top_gva: u64,
        sregs: CommonSpecialRegisters,
        #[cfg(target_arch = "x86_64")] msrs: Vec<MsrEntry>,
        next_action: NextAction,
        original_entrypoint: u64,
        snapshot_generation: u64,
        host_functions: HostFunctionDetails,
    ) -> Result<Self> {
        if root_pt_gpas.is_empty() {
            return Err(crate::new_error!("snapshot has no page-table roots"));
        }
        let scratch_gva = scratch_base_gva(layout.get_scratch_size());
        let memory_view = GuestPhysicalMemoryView::for_snapshot_capture(
            shared_mem,
            scratch_mem,
            &regions,
            layout,
        )?;
        let mut unique_roots = BTreeSet::new();
        for &root in root_pt_gpas {
            if !root.is_multiple_of(PAGE_SIZE as u64) {
                return Err(crate::new_error!(
                    "snapshot page-table root {root:#x} is not aligned"
                ));
            }
            if !unique_roots.insert(root) {
                return Err(crate::new_error!(
                    "snapshot page-table root {root:#x} is duplicated"
                ));
            }
            if memory_view.resolve(root, PAGE_SIZE).is_none() {
                return Err(crate::new_error!(
                    "snapshot page-table root {root:#x} is unbacked"
                ));
            }
        }
        // Walk every PT root together. Results retain topological order for
        // cross-space table references.
        let op = PageTableReader::new(&memory_view, root_pt_gpas[0]);
        // SAFETY: Snapshot capture runs with the vCPU stopped, so the source
        // page tables cannot change during the walk.
        let walk = unsafe {
            vmem::walk_va_spaces(
                &op,
                root_pt_gpas,
                0,
                hyperlight_common::layout::SCRATCH_TOP_GVA as u64,
            )
        };
        if let Some(failure) = op.failure() {
            return Err(crate::new_error!("{}", failure));
        }
        let source_layers = shared_mem.retainable_layers();
        let mut retained_pages = source_layers.map(|layers| {
            layers
                .iter()
                .map(|layer| {
                    layer
                        .blob()
                        .data_gpa_range()
                        .map_or_else(Vec::new, |data| vec![false; data.len() / PAGE_SIZE])
                })
                .collect::<Vec<_>>()
        });
        let mut new_pages = Vec::new();
        let mut required_tables = BTreeSet::new();
        for (root_index, (_, mappings)) in walk.iter().enumerate() {
            let mut previous_table_prefixes = [None; 3];
            for mapping in mappings {
                let SpaceAwareMapping::ThisSpace(mapping) = mapping else {
                    continue;
                };
                if validate_mapping(mapping)? && !mapping_has_skipped_pages(mapping, scratch_gva)? {
                    let mapping_len = usize::try_from(mapping.len)?;
                    if let Some(backing) = memory_view.resolve(mapping.phys_base, mapping_len) {
                        add_page_table_range(
                            &mut required_tables,
                            root_index,
                            mapping.virt_base,
                            mapping.len,
                        )?;
                        record_backed_pages(
                            backing,
                            mapping.phys_base,
                            mapping_len,
                            retained_pages.as_deref_mut(),
                            &mut new_pages,
                        )?;
                        continue;
                    }
                }
                for_each_mapping_page(mapping, |source_gpa, virt_gva, _| {
                    if skip_virt(virt_gva, scratch_gva) {
                        return Ok(());
                    }
                    add_page_table_page(
                        &mut required_tables,
                        &mut previous_table_prefixes,
                        root_index,
                        virt_gva,
                    );
                    let backing = memory_view.resolve(source_gpa, PAGE_SIZE).ok_or_else(|| {
                        crate::new_error!("snapshot leaf names unbacked GPA {source_gpa:#x}")
                    })?;
                    record_backed_pages(
                        backing,
                        source_gpa,
                        PAGE_SIZE,
                        retained_pages.as_deref_mut(),
                        &mut new_pages,
                    )?;
                    Ok(())
                })?;
            }
            if let Some((_, io_gva)) = io_page() {
                add_page_table_range(&mut required_tables, root_index, io_gva, PAGE_SIZE as u64)?;
            }
            add_page_table_range(
                &mut required_tables,
                root_index,
                scratch_gva,
                u64::try_from(layout.get_scratch_size())?,
            )?;
        }
        let rebuilt_page_table_len = walk
            .len()
            .checked_add(required_tables.len())
            .and_then(|count| count.checked_mul(PAGE_TABLE_SIZE))
            .ok_or_else(|| crate::new_error!("snapshot page-table size overflows"))?;
        drop(required_tables);

        let host_page_size = page_size::get();
        if let (Some(source_layers), Some(retained_pages)) =
            (source_layers, retained_pages.as_mut())
        {
            for (layer_index, (layer, pages)) in
                source_layers.iter().zip(retained_pages).enumerate()
            {
                if let Some(data) = layer.blob().data_gpa_range() {
                    move_partial_host_pages(
                        layer_index,
                        pages,
                        data.gpa_start(),
                        host_page_size,
                        &mut new_pages,
                    )?;
                }
            }
        }
        new_pages.sort_unstable_by_key(|page| page.source_gpa);
        new_pages.dedup_by_key(|page| page.source_gpa);

        let mut retained_layers = if let (Some(source_layers), Some(retained_pages)) =
            (source_layers, retained_pages.as_deref())
        {
            source_layers
                .iter()
                .zip(retained_pages)
                .filter(|(_, pages)| pages.iter().any(|retained| *retained))
                .map(|(layer, pages)| {
                    SnapshotLayer::new(layer.blob().clone(), coalesce_pages(pages))
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            Vec::new()
        };
        let retained_extent_count = retained_layers
            .iter()
            .map(|layer| layer.live_data_ranges().len())
            .sum::<usize>();
        let layered_data_len = packed_data_len(new_pages.len(), host_page_size)?;
        let layered_gpa = first_fit_blob_gpa(
            layered_data_len,
            &retained_layers,
            scratch_base_gpa(layout.get_scratch_size()),
        );
        let projected_retained_bytes = retained_layers
            .iter()
            .fold(0usize, |total, layer| {
                total.saturating_add(layer.blob().memory().mem_size())
            })
            .saturating_add(
                layered_data_len
                    .saturating_add(rebuilt_page_table_len)
                    .next_multiple_of(host_page_size),
            );
        let new_blob_gpa = validate_layered_capture(
            retained_layers.len(),
            retained_extent_count,
            projected_retained_bytes,
            layered_data_len,
            layered_gpa,
        )?;

        let data_len = layered_data_len;
        let ordered_new_pages = new_pages;
        let new_page_runs = new_blob_gpa.map_or_else(
            || Ok(Vec::new()),
            |destination_start| new_page_runs(&ordered_new_pages, destination_start),
        )?;
        let new_page_copies = new_page_copies(&ordered_new_pages)?;

        let pt_buf = GuestPageTableBuffer::with_capacity(
            layout.get_pt_base_gpa() as usize,
            rebuilt_page_table_len,
        );
        let mut root_addrs = Vec::with_capacity(root_pt_gpas.len());
        root_addrs.push(pt_buf.initial_root());
        for _ in 1..root_pt_gpas.len() {
            // SAFETY: `pt_buf` is local to this capture and accessed serially.
            root_addrs.push(unsafe { pt_buf.alloc_table() });
        }

        let mut built_roots: BTreeMap<SpaceId, u64> = BTreeMap::new();
        for (root_index, (space_id, mappings)) in walk.into_iter().enumerate() {
            pt_buf.set_root(root_addrs[root_index]);
            built_roots.insert(space_id, root_addrs[root_index]);
            let mut pending_mapping: Option<Mapping> = None;
            let flush_mapping = |pending: &mut Option<Mapping>| {
                if let Some(mapping) = pending.take() {
                    // SAFETY: The mapping is page-aligned and `pt_buf` is local
                    // to this capture.
                    unsafe { vmem::map(&pt_buf, mapping) };
                }
            };
            for mapping in mappings {
                match mapping {
                    SpaceAwareMapping::ThisSpace(mapping) => {
                        for_each_mapping_page(&mapping, |source_gpa, virt_gva, kind| {
                            if skip_virt(virt_gva, scratch_gva) {
                                flush_mapping(&mut pending_mapping);
                                return Ok(());
                            }
                            let kind = snapshot_mapping_kind(kind).ok_or_else(|| {
                                crate::new_error!("snapshot walker returned an unmapped leaf")
                            })?;
                            let destination_gpa =
                                page_destination(&new_page_runs, source_gpa).unwrap_or(source_gpa);
                            if let Some(pending) = pending_mapping.as_mut()
                                && pending.kind == kind
                                && pending.phys_base.checked_add(pending.len)
                                    == Some(destination_gpa)
                                && pending.virt_base.checked_add(pending.len) == Some(virt_gva)
                            {
                                pending.len =
                                    pending.len.checked_add(PAGE_SIZE as u64).ok_or_else(|| {
                                        crate::new_error!("snapshot mapping length overflows")
                                    })?;
                            } else {
                                flush_mapping(&mut pending_mapping);
                                pending_mapping = Some(Mapping {
                                    phys_base: destination_gpa,
                                    virt_base: virt_gva,
                                    len: PAGE_SIZE as u64,
                                    kind,
                                });
                            }
                            Ok(())
                        })?;
                    }
                    SpaceAwareMapping::AnotherSpace(reference) => {
                        flush_mapping(&mut pending_mapping);
                        // SAFETY: The reference came from the source walk and
                        // `pt_buf` is local to this capture.
                        unsafe { vmem::space_aware_map(&pt_buf, reference, &built_roots) };
                    }
                }
            }
            flush_mapping(&mut pending_mapping);
        }

        for &root_addr in &root_addrs {
            pt_buf.set_root(root_addr);
            map_specials(&pt_buf, layout.get_scratch_size());
        }
        pt_buf.set_root(pt_buf.initial_root());
        let page_tables = pt_buf.into_bytes();
        debug_assert_eq!(page_tables.len(), rebuilt_page_table_len);
        layout.ensure_page_tables_fit(page_tables.len())?;

        let logical_allocation_len = data_len
            .checked_add(page_tables.len())
            .ok_or_else(|| crate::new_error!("snapshot allocation size overflows"))?;
        let allocation_len = logical_allocation_len
            .checked_next_multiple_of(host_page_size)
            .ok_or_else(|| crate::new_error!("snapshot allocation padding overflows"))?;
        let mut allocation = ExclusiveSharedMemory::new(allocation_len)?;
        for copy in new_page_copies {
            let destination = allocation
                .as_mut_slice()
                .get_mut(copy.destination)
                .ok_or_else(|| crate::new_error!("snapshot destination page is out of bounds"))?;
            memory_view.read_backing(copy.backing, destination)?;
        }
        allocation.copy_from_slice(&page_tables, data_len)?;
        let storage = allocation.freeze()?;
        let blob = Arc::new(SnapshotBlob::new(
            storage,
            new_blob_gpa,
            data_len,
            Some(data_len..logical_allocation_len),
            scratch_base_gpa(layout.get_scratch_size()),
        )?);
        let live_data: Box<[Range<usize>]> = if data_len == 0 {
            Box::new([])
        } else {
            std::iter::once(0..data_len).collect()
        };
        retained_layers.push(SnapshotLayer::new(blob, live_data)?);
        let restore_page_table_layer_index = retained_layers.len() - 1;
        let memory = Arc::new(SnapshotMemory::new(
            retained_layers.into_boxed_slice(),
            restore_page_table_layer_index,
        )?);

        Ok(Self {
            layout,
            memory,
            load_info,
            stack_top_gva,
            sregs: Some(sregs),
            #[cfg(target_arch = "x86_64")]
            msrs: Some(msrs),
            next_action,
            original_entrypoint,
            snapshot_generation,
            host_functions,
        })
    }

    /// Generation number assigned to this snapshot when it was taken.
    pub(crate) fn snapshot_generation(&self) -> u64 {
        self.snapshot_generation
    }

    pub(crate) fn snapshot_memory(&self) -> &Arc<SnapshotMemory> {
        &self.memory
    }

    /// Return a copy of the load info for the exe in the snapshot
    pub(crate) fn load_info(&self) -> LoadInfo {
        self.load_info.clone()
    }

    pub(crate) fn layout(&self) -> &crate::mem::layout::SandboxMemoryLayout {
        &self.layout
    }

    pub(crate) fn root_pt_gpa(&self) -> u64 {
        self.layout.get_pt_base_gpa()
    }

    pub(crate) fn stack_top_gva(&self) -> u64 {
        self.stack_top_gva
    }

    /// Returns the special registers stored in this snapshot.
    /// Returns None for snapshots created directly from a binary (before preinitialisation).
    /// Returns Some for snapshots taken from a running sandbox.
    /// Note: The CR3 value in the returned struct should NOT be used for restore;
    /// use `root_pt_gpa()` instead since page tables are relocated during snapshot.
    pub(crate) fn sregs(&self) -> Option<&CommonSpecialRegisters> {
        self.sregs.as_ref()
    }

    /// The MSRs saved in this snapshot.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn msrs(&self) -> Option<&Vec<MsrEntry>> {
        self.msrs.as_ref()
    }

    pub(crate) fn next_action(&self) -> NextAction {
        self.next_action
    }

    /// Guest virtual address of the guest binary's ELF entry point,
    /// preserved across the `Initialise` -> `Call` transition. Used
    /// to fill `AT_ENTRY` in guest core dumps. 0 if unknown.
    pub(crate) fn original_entrypoint(&self) -> u64 {
        self.original_entrypoint
    }

    /// Validate that `provided` is a superset of the host functions
    /// recorded in this snapshot: every function that was registered
    /// at snapshot time must also be present in `provided` with a
    /// matching signature. Extras in `provided` are allowed.
    ///
    /// A snapshot with no recorded host functions (e.g. one
    /// produced by a test-only constructor) accepts any `provided`
    /// set.
    pub(crate) fn validate_host_functions(
        &self,
        provided: &crate::sandbox::host_funcs::FunctionRegistry,
    ) -> Result<()> {
        let required = match &self.host_functions.host_functions {
            Some(v) => v,
            None => return Ok(()),
        };
        if required.is_empty() {
            return Ok(());
        }

        let mut missing: Vec<String> = Vec::new();
        let mut signature_mismatches: Vec<String> = Vec::new();

        for req in required {
            match provided.function_signature(&req.function_name) {
                // Function name is absent from the provided registry.
                None => missing.push(req.function_name.clone()),
                // Function exists, but signature does not match.
                Some((found_parameter_types, found_return_type))
                    if {
                        let params_match = match req.parameter_types.as_deref() {
                            Some(params) => params == found_parameter_types,
                            None => found_parameter_types.is_empty(),
                        };
                        !params_match || req.return_type != found_return_type
                    } =>
                {
                    signature_mismatches.push(format!(
                        "{}: snapshot has {:?} -> {:?}, registered {:?} -> {:?}",
                        req.function_name,
                        req.parameter_types,
                        req.return_type,
                        Some(found_parameter_types.to_vec()),
                        found_return_type,
                    ));
                }
                // Function exists and signature matches.
                Some(_) => {}
            }
        }

        if missing.is_empty() && signature_mismatches.is_empty() {
            return Ok(());
        }

        Err(crate::HyperlightError::SnapshotHostFunctionMismatch {
            missing,
            signature_mismatches,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperlight_common::flatbuffer_wrappers::host_function_details::HostFunctionDetails;
    use hyperlight_common::vmem::{
        self, BasicMapping, Mapping, MappingKind, PAGE_SIZE, PAGE_TABLE_SIZE,
    };

    use super::SnapshotMemoryBacking;
    use crate::hypervisor::regs::CommonSpecialRegisters;
    use crate::mem::exe::LoadInfo;
    use crate::mem::layout::SandboxMemoryLayout;
    use crate::mem::mgr::{
        GuestBacking, GuestPageTableBuffer, GuestPhysicalMemoryView, SandboxMemoryManager,
    };
    use crate::mem::shared_mem::{ExclusiveSharedMemory, HostSharedMemory, ReadonlySharedMemory};

    fn default_sregs() -> CommonSpecialRegisters {
        CommonSpecialRegisters::default()
    }

    #[test]
    fn partial_host_pages_move_to_the_new_blob() {
        let host_page_size = 4 * PAGE_SIZE;
        let blob_gpa = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let mut retained = vec![true, true, false, false, true, true, true, true];
        let mut copied = Vec::new();

        super::move_partial_host_pages(0, &mut retained, blob_gpa, host_page_size, &mut copied)
            .unwrap();

        assert_eq!(
            retained,
            vec![false, false, false, false, true, true, true, true]
        );
        assert_eq!(
            copied
                .iter()
                .map(|page| page.source_gpa)
                .collect::<Vec<_>>(),
            vec![blob_gpa, blob_gpa + PAGE_SIZE as u64]
        );
        assert_eq!(
            super::packed_data_len(copied.len(), host_page_size).unwrap(),
            host_page_size
        );
    }

    #[test]
    fn guest_sized_host_pages_need_no_regrouping() {
        let blob_gpa = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let expected = vec![true, true, false, true];
        let mut retained = expected.clone();
        let mut copied = Vec::new();

        super::move_partial_host_pages(0, &mut retained, blob_gpa, PAGE_SIZE, &mut copied).unwrap();

        assert_eq!(retained, expected);
        assert!(copied.is_empty());
    }

    #[test]
    fn snapshot_page_policy_retains_shared_and_copies_private_backings() {
        let source_gpa = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let backing = GuestBacking::Snapshot {
            layer_index: 0,
            offset: 0,
        };
        let mut retained = vec![vec![false; 2]];
        let mut copied = Vec::new();

        super::record_backed_pages(
            backing,
            source_gpa,
            2 * PAGE_SIZE,
            Some(retained.as_mut_slice()),
            &mut copied,
        )
        .unwrap();
        assert_eq!(retained, [vec![true; 2]]);
        assert!(copied.is_empty());

        retained[0].fill(false);
        super::record_backed_pages(backing, source_gpa, 2 * PAGE_SIZE, None, &mut copied).unwrap();
        assert_eq!(retained, [vec![false; 2]]);
        assert_eq!(copied.len(), 2);
        assert_eq!(copied[0].source_gpa, source_gpa);
        assert_eq!(copied[0].backing, backing);
        assert_eq!(copied[1].source_gpa, source_gpa + PAGE_SIZE as u64);
        assert_eq!(
            copied[1].backing,
            GuestBacking::Snapshot {
                layer_index: 0,
                offset: PAGE_SIZE,
            }
        );
    }

    #[test]
    fn layered_capture_enforces_every_hard_limit() {
        let gpa = Some(SandboxMemoryLayout::BASE_ADDRESS as u64);

        assert_eq!(
            super::validate_layered_capture(
                super::MAX_SNAPSHOT_BLOBS - 1,
                super::MAX_SNAPSHOT_LIVE_EXTENTS,
                super::MAX_SNAPSHOT_RETAINED_BYTES,
                0,
                None,
            )
            .unwrap(),
            None
        );
        assert!(
            super::validate_layered_capture(super::MAX_SNAPSHOT_BLOBS, 1, PAGE_SIZE, 0, None,)
                .is_err()
        );
        assert!(
            super::validate_layered_capture(
                1,
                super::MAX_SNAPSHOT_LIVE_EXTENTS,
                PAGE_SIZE,
                PAGE_SIZE,
                gpa,
            )
            .is_err()
        );
        assert!(
            super::validate_layered_capture(1, 1, super::MAX_SNAPSHOT_RETAINED_BYTES + 1, 0, None,)
                .is_err()
        );
        assert!(super::validate_layered_capture(1, 1, PAGE_SIZE, PAGE_SIZE, None).is_err());
    }

    fn make_simple_pt_memory(contents: &[u8], pt_base: u64) -> super::SnapshotMemory {
        let pt_buf = GuestPageTableBuffer::new(pt_base as usize);
        let mapping = Mapping {
            phys_base: SandboxMemoryLayout::BASE_ADDRESS as u64,
            virt_base: SandboxMemoryLayout::BASE_ADDRESS as u64,
            len: page_size::get() as u64,
            kind: MappingKind::Basic(BasicMapping {
                readable: true,
                writable: true,
                executable: true,
            }),
        };
        unsafe { vmem::map(&pt_buf, mapping) };
        super::map_specials(&pt_buf, PAGE_SIZE);
        let pt_bytes = pt_buf.into_bytes();

        let mut snapshot_mem = vec![0u8; page_size::get() + pt_bytes.len()];
        snapshot_mem[0..page_size::get()].copy_from_slice(contents);
        snapshot_mem[page_size::get()..].copy_from_slice(&pt_bytes);
        let storage = ReadonlySharedMemory::from_bytes(&snapshot_mem).unwrap();
        super::SnapshotMemory::from_flat(
            storage,
            SandboxMemoryLayout::BASE_ADDRESS as u64,
            page_size::get(),
            page_size::get()..snapshot_mem.len(),
            hyperlight_common::layout::scratch_base_gpa(PAGE_SIZE),
        )
        .unwrap()
    }

    fn make_simple_pt_host_mem(
        contents: &[u8],
        pt_base: u64,
    ) -> SnapshotMemoryBacking<HostSharedMemory> {
        SnapshotMemoryBacking::from_snapshot(Arc::new(make_simple_pt_memory(contents, pt_base)))
            .unwrap()
            .build()
            .0
    }

    fn make_simple_pt_mgr() -> (SandboxMemoryManager<HostSharedMemory>, u64) {
        let cfg = crate::sandbox::SandboxConfiguration::default();
        let scratch_mem = ExclusiveSharedMemory::new(cfg.get_scratch_size()).unwrap();
        let layout = SandboxMemoryLayout::new(cfg, 4096, 0x3000, None).unwrap();
        let pt_base = layout.get_pt_base_gpa();
        let memory = make_simple_pt_memory(&vec![0u8; page_size::get()], pt_base);
        let page_table_len = memory.layers()[0]
            .blob()
            .page_table_memory_range()
            .unwrap()
            .len();
        layout.ensure_page_tables_fit(page_table_len).unwrap();
        let mgr = SandboxMemoryManager::new(
            layout,
            SnapshotMemoryBacking::from_snapshot(Arc::new(memory)).unwrap(),
            scratch_mem,
            super::NextAction::None,
        );
        let (mgr, _) = mgr.build().unwrap();
        (mgr, pt_base)
    }

    #[test]
    fn capture_rejects_invalid_page_table_roots() {
        let (manager, pt_base) = make_simple_pt_mgr();
        for roots in [vec![pt_base, pt_base], vec![!(PAGE_SIZE as u64 - 1)]] {
            let result = super::Snapshot::new(
                &manager.shared_mem,
                &manager.scratch_mem,
                manager.layout,
                LoadInfo::dummy(),
                Vec::new(),
                &roots,
                0,
                default_sregs(),
                #[cfg(target_arch = "x86_64")]
                Vec::new(),
                super::NextAction::None,
                0,
                1,
                HostFunctionDetails::default(),
            );
            assert!(result.is_err());
        }
    }

    #[test]
    fn capture_and_restore_preserve_multiple_page_table_roots() {
        let cfg = crate::sandbox::SandboxConfiguration::default();
        let layout = SandboxMemoryLayout::new(cfg, 4096, 0x3000, None).unwrap();
        let pt_base = layout.get_pt_base_gpa();
        let base = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let pt_buf = GuestPageTableBuffer::new(pt_base as usize);
        let first_root = pt_buf.initial_root();
        let second_root = unsafe { <GuestPageTableBuffer as vmem::TableOps>::alloc_table(&pt_buf) };
        let kind = MappingKind::Basic(BasicMapping {
            readable: true,
            writable: false,
            executable: false,
        });
        unsafe {
            vmem::map(
                &pt_buf,
                Mapping {
                    phys_base: base,
                    virt_base: base,
                    len: PAGE_SIZE as u64,
                    kind,
                },
            );
            pt_buf.set_root(second_root);
            vmem::map(
                &pt_buf,
                Mapping {
                    phys_base: base + PAGE_SIZE as u64,
                    virt_base: base + PAGE_SIZE as u64,
                    len: PAGE_SIZE as u64,
                    kind,
                },
            );
        }
        pt_buf.set_root(first_root);
        let page_tables = pt_buf.into_bytes();
        layout.ensure_page_tables_fit(page_tables.len()).unwrap();

        let data_len = 2 * page_size::get();
        let logical_len = data_len + page_tables.len();
        let mut bytes = vec![0u8; logical_len.next_multiple_of(page_size::get())];
        bytes[..PAGE_SIZE].fill(0x11);
        bytes[PAGE_SIZE..2 * PAGE_SIZE].fill(0x22);
        bytes[data_len..logical_len].copy_from_slice(&page_tables);
        let memory = super::SnapshotMemory::from_flat(
            ReadonlySharedMemory::from_bytes(&bytes).unwrap(),
            base,
            data_len,
            data_len..logical_len,
            hyperlight_common::layout::scratch_base_gpa(layout.get_scratch_size()),
        )
        .unwrap();
        let manager = SandboxMemoryManager::new(
            layout,
            SnapshotMemoryBacking::from_snapshot(Arc::new(memory)).unwrap(),
            ExclusiveSharedMemory::new(layout.get_scratch_size()).unwrap(),
            super::NextAction::None,
        );
        let (mut manager, _) = manager.build().unwrap();

        let snapshot = super::Snapshot::new(
            &manager.shared_mem,
            &manager.scratch_mem,
            manager.layout,
            LoadInfo::dummy(),
            Vec::new(),
            &[first_root, second_root],
            0,
            default_sregs(),
            #[cfg(target_arch = "x86_64")]
            Vec::new(),
            super::NextAction::None,
            0,
            1,
            HostFunctionDetails::default(),
        )
        .unwrap();
        let rebuilt_first_root = snapshot.root_pt_gpa();
        let rebuilt_second_root = rebuilt_first_root + PAGE_TABLE_SIZE as u64;
        let roots = [rebuilt_first_root, rebuilt_second_root];
        let walked = unsafe { vmem::walk_va_spaces(&snapshot, &roots, base, 2 * PAGE_SIZE as u64) };
        assert_eq!(walked.len(), 2);
        assert!(walked[0].1.iter().any(|mapping| matches!(
            mapping,
            vmem::SpaceAwareMapping::ThisSpace(mapping) if mapping.virt_base == base
        )));
        assert!(walked[1].1.iter().any(|mapping| matches!(
            mapping,
            vmem::SpaceAwareMapping::ThisSpace(mapping)
                if mapping.virt_base == base + PAGE_SIZE as u64
        )));

        manager.restore_snapshot(&snapshot).unwrap();
        let memory = GuestPhysicalMemoryView::new(
            &manager.shared_mem,
            &manager.scratch_mem,
            &[],
            manager.layout,
        );
        for (root, gva, expected) in [
            (rebuilt_first_root, base, 0x11),
            (rebuilt_second_root, base + PAGE_SIZE as u64, 0x22),
        ] {
            let reader = super::PageTableReader::new(&memory, root);
            let mapping = unsafe { vmem::virt_to_phys(&reader, gva, 1) }
                .next()
                .unwrap();
            let gpa = mapping.phys_base + gva - mapping.virt_base;
            let mut byte = [0u8; 1];
            memory.read(gpa, &mut byte).unwrap();
            assert_eq!(byte, [expected]);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn capture_rejects_unbacked_intermediate_page_table() {
        let (manager, pt_base) = make_simple_pt_mgr();
        let scratch_base =
            hyperlight_common::layout::scratch_base_gpa(manager.layout.get_scratch_size());
        let root_offset = usize::try_from(pt_base - scratch_base).unwrap();
        let invalid_entry = (0xdead_0000 | vmem::PAGE_PRESENT).to_le_bytes();
        manager
            .scratch_mem
            .copy_from_slice(&invalid_entry, root_offset)
            .unwrap();

        let result = super::Snapshot::new(
            &manager.shared_mem,
            &manager.scratch_mem,
            manager.layout,
            LoadInfo::dummy(),
            Vec::new(),
            &[pt_base],
            0,
            default_sregs(),
            Vec::new(),
            super::NextAction::None,
            0,
            1,
            HostFunctionDetails::default(),
        );
        let error = match result {
            Ok(_) => panic!("capture unexpectedly accepted an unbacked page table"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("accessed unbacked memory"));
    }

    #[test]
    fn multiple_snapshots_independent() {
        let (mut mgr, pt_base) = make_simple_pt_mgr();

        // Create first snapshot with pattern A
        let pattern_a = vec![0xAA; page_size::get()];
        let pattern_a_memory = make_simple_pt_host_mem(&pattern_a, pt_base);
        let snapshot_a = super::Snapshot::new(
            &pattern_a_memory,
            &mgr.scratch_mem,
            mgr.layout,
            LoadInfo::dummy(),
            Vec::new(),
            &[pt_base],
            0,
            default_sregs(),
            #[cfg(target_arch = "x86_64")]
            Vec::new(),
            super::NextAction::None,
            0,
            1,
            HostFunctionDetails::default(),
        )
        .unwrap();
        assert_eq!(snapshot_a.snapshot_memory().layers().len(), 2);
        assert!(
            snapshot_a.snapshot_memory().layers()[1]
                .blob()
                .data_gpa_range()
                .is_none()
        );
        assert!(
            snapshot_a.snapshot_memory().layers()[1]
                .live_data_ranges()
                .is_empty()
        );

        // Create second snapshot with pattern B
        let pattern_b = vec![0xBB; page_size::get()];
        let pattern_b_memory = make_simple_pt_host_mem(&pattern_b, pt_base);
        let snapshot_b = super::Snapshot::new(
            &pattern_b_memory,
            &mgr.scratch_mem,
            mgr.layout,
            LoadInfo::dummy(),
            Vec::new(),
            &[pt_base],
            0,
            default_sregs(),
            #[cfg(target_arch = "x86_64")]
            Vec::new(),
            super::NextAction::None,
            0,
            2,
            HostFunctionDetails::default(),
        )
        .unwrap();

        // Restore snapshot A
        mgr.restore_snapshot(&snapshot_a).unwrap();
        let mut restored = vec![0u8; pattern_a.len()];
        mgr.shared_mem
            .read_snapshot_gpa(SandboxMemoryLayout::BASE_ADDRESS as u64, &mut restored)
            .unwrap();
        assert_eq!(restored, pattern_a);

        // Restore snapshot B
        mgr.restore_snapshot(&snapshot_b).unwrap();
        restored.fill(0);
        mgr.shared_mem
            .read_snapshot_gpa(SandboxMemoryLayout::BASE_ADDRESS as u64, &mut restored)
            .unwrap();
        assert_eq!(restored, pattern_b);
    }

    #[test]
    fn capture_retains_shared_pages_and_materializes_private_pages() {
        let cfg = crate::sandbox::SandboxConfiguration::default();
        let layout = SandboxMemoryLayout::new(cfg, 4096, 0x3000, None).unwrap();
        let pt_base = layout.get_pt_base_gpa();
        let scratch_offset = layout.get_scratch_size() / 2;
        let scratch_gpa = hyperlight_common::layout::scratch_base_gpa(layout.get_scratch_size())
            + scratch_offset as u64;
        let base = SandboxMemoryLayout::BASE_ADDRESS as u64;

        let pt_buf = GuestPageTableBuffer::new(pt_base as usize);
        // SAFETY: The page-aligned mappings are written serially to this local
        // page-table buffer.
        unsafe {
            vmem::map(
                &pt_buf,
                Mapping {
                    phys_base: base,
                    virt_base: base,
                    len: PAGE_SIZE as u64,
                    kind: MappingKind::Basic(BasicMapping {
                        readable: true,
                        writable: false,
                        executable: true,
                    }),
                },
            );
            vmem::map(
                &pt_buf,
                Mapping {
                    phys_base: scratch_gpa,
                    virt_base: base + (2 * PAGE_SIZE) as u64,
                    len: PAGE_SIZE as u64,
                    kind: MappingKind::Basic(BasicMapping {
                        readable: true,
                        writable: true,
                        executable: false,
                    }),
                },
            );
            vmem::map(
                &pt_buf,
                Mapping {
                    phys_base: scratch_gpa,
                    virt_base: base + PAGE_SIZE as u64,
                    len: PAGE_SIZE as u64,
                    kind: MappingKind::Basic(BasicMapping {
                        readable: true,
                        writable: true,
                        executable: false,
                    }),
                },
            );
        }
        super::map_specials(&pt_buf, layout.get_scratch_size());
        let page_tables = pt_buf.into_bytes();
        layout.ensure_page_tables_fit(page_tables.len()).unwrap();

        let mut source_bytes = vec![0u8; 2 * PAGE_SIZE + page_tables.len()];
        source_bytes[..PAGE_SIZE].fill(0x11);
        source_bytes[PAGE_SIZE..2 * PAGE_SIZE].fill(0x22);
        source_bytes[2 * PAGE_SIZE..].copy_from_slice(&page_tables);
        let storage = ReadonlySharedMemory::from_bytes(&source_bytes).unwrap();
        let source = super::SnapshotMemory::from_flat(
            storage,
            base,
            2 * PAGE_SIZE,
            2 * PAGE_SIZE..source_bytes.len(),
            hyperlight_common::layout::scratch_base_gpa(layout.get_scratch_size()),
        )
        .unwrap();
        let source_blob = source.layers()[0].blob().clone();
        let managed = SnapshotMemoryBacking::from_snapshot(Arc::new(source)).unwrap();
        let scratch = ExclusiveSharedMemory::new(layout.get_scratch_size()).unwrap();
        let manager = SandboxMemoryManager::new(layout, managed, scratch, super::NextAction::None);
        let (manager, _) = manager.build().unwrap();
        let retains_source_layers = manager.shared_mem.retainable_layers().is_some();
        #[cfg(gdb)]
        manager
            .shared_mem
            .write_snapshot_gpa(base, &[0x44; PAGE_SIZE])
            .unwrap();
        let mut source_page = [0u8; PAGE_SIZE];
        manager
            .shared_mem
            .read_snapshot_gpa(base, &mut source_page)
            .unwrap();
        manager
            .scratch_mem
            .copy_from_slice(&vec![0x33; PAGE_SIZE], scratch_offset)
            .unwrap();

        let captured = super::Snapshot::new(
            &manager.shared_mem,
            &manager.scratch_mem,
            manager.layout,
            LoadInfo::dummy(),
            Vec::new(),
            &[pt_base],
            0,
            default_sregs(),
            #[cfg(target_arch = "x86_64")]
            Vec::new(),
            super::NextAction::None,
            0,
            1,
            HostFunctionDetails::default(),
        )
        .unwrap();

        let layers = captured.snapshot_memory().layers();
        let delta_gpa = if retains_source_layers {
            assert_eq!(layers.len(), 2);
            assert!(std::sync::Arc::ptr_eq(layers[0].blob(), &source_blob));
            assert_eq!(layers[0].live_data_ranges().len(), 1);
            assert_eq!(layers[0].live_data_ranges()[0], 0..PAGE_SIZE);
            assert_eq!(layers[1].blob().data_gpa_range().unwrap().len(), PAGE_SIZE);
            assert_eq!(
                layers[1].blob().data_gpa_range().unwrap().gpa_start(),
                base + (2 * PAGE_SIZE) as u64
            );
            base + (2 * PAGE_SIZE) as u64
        } else {
            assert_eq!(layers.len(), 1);
            assert!(!std::sync::Arc::ptr_eq(layers[0].blob(), &source_blob));
            assert_eq!(
                layers[0].blob().data_gpa_range().unwrap().len(),
                2 * PAGE_SIZE
            );
            assert_eq!(layers[0].blob().data_gpa_range().unwrap().gpa_start(), base);
            base + PAGE_SIZE as u64
        };
        assert_eq!(
            captured
                .snapshot_memory()
                .resolve(base + PAGE_SIZE as u64, PAGE_SIZE)
                .is_none(),
            retains_source_layers
        );

        // SAFETY: `captured` is immutable for the duration of this walk.
        let mappings = unsafe { vmem::virt_to_phys(&captured, base, 3 * PAGE_SIZE as u64) }
            .collect::<Vec<_>>();
        assert_eq!(mappings.len(), 3);
        assert_eq!(mappings[0].phys_base, base);
        assert_eq!(mappings[1].phys_base, delta_gpa);
        assert_eq!(mappings[2].phys_base, mappings[1].phys_base);
        assert_eq!(
            mappings[0].kind,
            MappingKind::Basic(BasicMapping {
                readable: true,
                writable: false,
                executable: true,
            })
        );
        assert_eq!(
            mappings[1].kind,
            MappingKind::Cow(hyperlight_common::vmem::CowMapping {
                readable: true,
                executable: false,
            })
        );
        let mut delta = [0u8; PAGE_SIZE];
        captured
            .snapshot_memory()
            .read_gpa(mappings[1].phys_base, &mut delta)
            .unwrap();
        assert_eq!(delta, [0x33; PAGE_SIZE]);

        let flat = captured.snapshot_memory().flat_image().unwrap();
        assert_eq!(
            flat.len(),
            captured.snapshot_memory().gpa_span_len() + captured.snapshot_memory().page_table_len()
        );
        assert_eq!(&flat[..PAGE_SIZE], &source_page);
        if retains_source_layers {
            assert_eq!(&flat[PAGE_SIZE..2 * PAGE_SIZE], &[0; PAGE_SIZE]);
            assert_eq!(&flat[2 * PAGE_SIZE..3 * PAGE_SIZE], &[0x33; PAGE_SIZE]);
        } else {
            assert_eq!(&flat[PAGE_SIZE..2 * PAGE_SIZE], &[0x33; PAGE_SIZE]);
        }
    }

    #[test]
    fn capture_rejects_leaf_into_page_table_tail() {
        let cfg = crate::sandbox::SandboxConfiguration::default();
        let layout = SandboxMemoryLayout::new(cfg, 4096, 0x3000, None).unwrap();
        let pt_base = layout.get_pt_base_gpa();
        let base = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let pt_buf = GuestPageTableBuffer::new(pt_base as usize);
        // SAFETY: The page-aligned mapping is written to a local page-table
        // buffer with no concurrent access.
        unsafe {
            vmem::map(
                &pt_buf,
                Mapping {
                    phys_base: base + PAGE_SIZE as u64,
                    virt_base: base,
                    len: PAGE_SIZE as u64,
                    kind: MappingKind::Basic(BasicMapping {
                        readable: true,
                        writable: false,
                        executable: false,
                    }),
                },
            );
        }
        super::map_specials(&pt_buf, layout.get_scratch_size());
        let page_tables = pt_buf.into_bytes();
        layout.ensure_page_tables_fit(page_tables.len()).unwrap();

        let mut bytes = vec![0u8; PAGE_SIZE + page_tables.len()];
        bytes[PAGE_SIZE..].copy_from_slice(&page_tables);
        let source = super::SnapshotMemory::from_flat(
            ReadonlySharedMemory::from_bytes(&bytes).unwrap(),
            base,
            PAGE_SIZE,
            PAGE_SIZE..bytes.len(),
            hyperlight_common::layout::scratch_base_gpa(layout.get_scratch_size()),
        )
        .unwrap();
        let manager = SandboxMemoryManager::new(
            layout,
            SnapshotMemoryBacking::from_snapshot(Arc::new(source)).unwrap(),
            ExclusiveSharedMemory::new(layout.get_scratch_size()).unwrap(),
            super::NextAction::None,
        );
        let (manager, _) = manager.build().unwrap();

        let result = super::Snapshot::new(
            &manager.shared_mem,
            &manager.scratch_mem,
            manager.layout,
            LoadInfo::dummy(),
            Vec::new(),
            &[pt_base],
            0,
            default_sregs(),
            #[cfg(target_arch = "x86_64")]
            Vec::new(),
            super::NextAction::None,
            0,
            1,
            HostFunctionDetails::default(),
        );
        let error = match result {
            Ok(_) => panic!("capture unexpectedly accepted a page-table-tail leaf"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("snapshot leaf names unbacked GPA")
        );
    }

    #[test]
    fn capture_rejects_delta_exceeding_extent_limit() {
        let cfg = crate::sandbox::SandboxConfiguration::default();
        let layout = SandboxMemoryLayout::new(cfg, 4096, 0x3000, None).unwrap();
        let pt_base = layout.get_pt_base_gpa();
        let scratch_offset = layout.get_scratch_size() / 2;
        let scratch_gpa = hyperlight_common::layout::scratch_base_gpa(layout.get_scratch_size())
            + scratch_offset as u64;
        let base = SandboxMemoryLayout::BASE_ADDRESS as u64;

        let pt_buf = GuestPageTableBuffer::new(pt_base as usize);
        for index in 0..super::MAX_SNAPSHOT_LIVE_EXTENTS {
            // SAFETY: The page-aligned mapping is written to a local page-table
            // buffer with no concurrent access.
            unsafe {
                vmem::map(
                    &pt_buf,
                    Mapping {
                        phys_base: base + (2 * index * PAGE_SIZE) as u64,
                        virt_base: base + (index * PAGE_SIZE) as u64,
                        len: PAGE_SIZE as u64,
                        kind: MappingKind::Basic(BasicMapping {
                            readable: true,
                            writable: false,
                            executable: false,
                        }),
                    },
                );
            }
        }
        // SAFETY: The page-aligned mapping is written to a local page-table
        // buffer with no concurrent access.
        unsafe {
            vmem::map(
                &pt_buf,
                Mapping {
                    phys_base: scratch_gpa,
                    virt_base: base + (super::MAX_SNAPSHOT_LIVE_EXTENTS * PAGE_SIZE) as u64,
                    len: PAGE_SIZE as u64,
                    kind: MappingKind::Basic(BasicMapping {
                        readable: true,
                        writable: true,
                        executable: false,
                    }),
                },
            );
        }
        super::map_specials(&pt_buf, layout.get_scratch_size());
        let page_tables = pt_buf.into_bytes();
        layout.ensure_page_tables_fit(page_tables.len()).unwrap();

        let data_pages = 2 * super::MAX_SNAPSHOT_LIVE_EXTENTS - 1;
        let data_len = data_pages * PAGE_SIZE;
        let mut source_bytes = vec![0u8; data_len + page_tables.len()];
        let live_data = (0..super::MAX_SNAPSHOT_LIVE_EXTENTS)
            .map(|index| {
                let start = 2 * index * PAGE_SIZE;
                source_bytes[start..start + PAGE_SIZE].fill(index as u8);
                start..start + PAGE_SIZE
            })
            .collect();
        source_bytes[data_len..].copy_from_slice(&page_tables);
        let storage = ReadonlySharedMemory::from_bytes(&source_bytes).unwrap();
        let source_blob = std::sync::Arc::new(
            super::SnapshotBlob::new(
                storage,
                Some(base),
                data_len,
                Some(data_len..source_bytes.len()),
                hyperlight_common::layout::scratch_base_gpa(layout.get_scratch_size()),
            )
            .unwrap(),
        );
        let source_layer = super::SnapshotLayer::new(source_blob.clone(), live_data).unwrap();
        let source = super::SnapshotMemory::new(Box::new([source_layer]), 0).unwrap();
        let managed = SnapshotMemoryBacking::from_snapshot(Arc::new(source)).unwrap();
        let scratch = ExclusiveSharedMemory::new(layout.get_scratch_size()).unwrap();
        let manager = SandboxMemoryManager::new(layout, managed, scratch, super::NextAction::None);
        let (mut manager, _) = manager.build().unwrap();
        manager
            .scratch_mem
            .copy_from_slice(&vec![0x55; PAGE_SIZE], scratch_offset)
            .unwrap();

        let result = manager.snapshot(
            Vec::new(),
            &[pt_base],
            0,
            default_sregs(),
            #[cfg(target_arch = "x86_64")]
            Vec::new(),
            super::NextAction::None,
            HostFunctionDetails::default(),
        );
        let error = match result {
            Ok(_) => panic!("capture unexpectedly exceeded the live-extent limit"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("live-extent count 31 exceeds 30")
        );
        assert_eq!(manager.snapshot_count, 0);
        assert_eq!(manager.shared_mem.layers().len(), 1);
        assert!(std::sync::Arc::ptr_eq(
            manager.shared_mem.layers()[0].blob(),
            &source_blob
        ));
        assert_eq!(
            manager.scratch_mem.read::<u8>(scratch_offset).unwrap(),
            0x55
        );
    }
}
