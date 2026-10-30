// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

mod file;
mod file_tests;
pub(crate) mod memory;
mod tripwires;

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Arc;

pub(crate) use file::host_cpu_vendor_golden_tag;
pub use file::reference::{OciDigest, OciReference, OciTag};
use hyperlight_common::flatbuffer_wrappers::host_function_details::HostFunctionDetails;
use hyperlight_common::layout::{
    SCRATCH_TOP_GVA, io_page, scratch_base_gpa, scratch_base_gva, scratch_reserved_top_gpa,
    scratch_reserved_top_gva, scratch_transport_end_gva,
};
use hyperlight_common::vmem;
use hyperlight_common::vmem::{
    BasicMapping, CowMapping, Mapping, MappingKind, PAGE_SIZE, SpaceAwareMapping, SpaceId, TableOps,
};
use tracing::{Span, instrument};

pub(crate) use self::memory::{SnapshotBlob, SnapshotMemory, SnapshotMemoryBacking};
use crate::Result;
use crate::hypervisor::regs::CommonSpecialRegisters;
#[cfg(target_arch = "x86_64")]
use crate::hypervisor::regs::MsrEntry;
use crate::mem::exe::{ExeInfo, LoadInfo};
use crate::mem::layout::SandboxMemoryLayout;
use crate::mem::memory_region::MemoryRegionFlags;
use crate::mem::mgr::{BackingSource, GuestBacking, GuestPageTableBuffer, GuestPhysicalMemoryView};
use crate::mem::shared_mem::ExclusiveSharedMemory;
use crate::mem::virtq::VirtqSnapshot;
use crate::sandbox::SandboxConfiguration;
use crate::sandbox::uninitialized::{GuestBinary, GuestEnvironment};

const PTE_SIZE: usize = size_of::<vmem::PageTableEntry>();

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

/// Options for
/// [`Sandbox::snapshot_with_options`](crate::Sandbox::snapshot_with_options).
/// The default options take the same snapshot as
/// [`Sandbox::snapshot`](crate::Sandbox::snapshot).
#[derive(Clone, Debug, Default)]
pub struct SnapshotOptions {
    pub(crate) scratch_size: Option<usize>,
}

impl SnapshotOptions {
    /// The snapshot, and the sandbox it is taken from, get a scratch region
    /// of `scratch_size` bytes. By default the scratch size stays the same.
    ///
    /// A sandbox can boot with the scratch its initialisation needs, then
    /// run guest function calls from a snapshot with only the scratch they
    /// need, which makes each restore cheaper, or with more scratch than it
    /// booted with.
    ///
    /// A size larger than the maximum memory size (`MemoryRequestTooBig`),
    /// too small for the transport (`MemoryRequestTooSmall`), or not a
    /// whole number of host pages is rejected before the guest is entered.
    /// Room for the page tables depends on the guest's mappings and is
    /// checked when the snapshot is built, after a pending transport
    /// checkpoint has run in the guest: a size without it fails then, with
    /// `MemoryRequestTooSmall`. A larger size whose scratch window would
    /// cover a guest mapping below the current one fails then too. Both
    /// failures leave the sandbox usable. Whether guest function calls fit
    /// is not checked: one that needs more scratch fails in the guest, and
    /// a later restore recovers the sandbox.
    #[must_use]
    pub fn scratch_size(mut self, scratch_size: usize) -> Self {
        self.scratch_size = Some(scratch_size);
        self
    }
}

/// An immutable snapshot of sandbox state.
pub struct Snapshot {
    state: Arc<SnapshotState>,
    // Stable key order keeps config bytes deterministic.
    metadata: BTreeMap<String, serde_json::Value>,
}

/// Immutable sandbox state held by a snapshot.
struct SnapshotState {
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
    /// (`code GVA + e_entry - base_va`). Unlike `next_action`, which
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
    /// [`crate::Sandbox::from_snapshot`] to reject a
    /// `HostFunctions` set that is missing required functions or
    /// has mismatched signatures.
    host_functions: HostFunctionDetails,

    /// Validated ring images omitted from ordinary snapshot pages.
    ///
    /// Construction and loading validate these images against `layout`.
    /// Both the images and layout remain immutable afterwards.
    virtq: Option<VirtqSnapshot>,
}

impl core::convert::AsRef<Snapshot> for Snapshot {
    fn as_ref(&self) -> &Self {
        self
    }
}
impl hyperlight_common::vmem::TableReadOps for Snapshot {
    type TableAddr = u64;
    fn entry_addr(addr: u64, offset: u64) -> u64 {
        addr + offset
    }
    unsafe fn read_entry(&self, addr: u64) -> vmem::PageTableEntry {
        let mut pte_bytes = [0u8; PTE_SIZE];
        if self
            .state
            .memory
            .read_page_tables(self.state.layout.get_pt_base_gpa(), addr, &mut pte_bytes)
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
    failure: Cell<Option<&'static str>>,
    /// Address and copy of the last table page read. A walk reads the
    /// entries of one table in sequence.
    cache: RefCell<(u64, [u8; PAGE_SIZE])>,
}
impl<'a> PageTableReader<'a> {
    pub(crate) fn new(memory: &'a GuestPhysicalMemoryView<'a>, root: u64) -> Self {
        Self {
            memory,
            root,
            failure: Cell::new(None),
            // An unaligned address never matches a table page.
            cache: RefCell::new((u64::MAX, [0; PAGE_SIZE])),
        }
    }

    /// Returns suppressed page-table read failures.
    pub(crate) fn finish(&self) -> Result<()> {
        match self.failure.get() {
            Some(failure) => Err(crate::new_error!("{}", failure)),
            None => Ok(()),
        }
    }

    fn read_cached(&self, addr: u64) -> Option<vmem::PageTableEntry> {
        let page = addr & !(PAGE_SIZE as u64 - 1);
        let offset = usize::try_from(addr - page).ok()?;
        let mut cache = self.cache.borrow_mut();
        if cache.0 != page {
            cache.0 = u64::MAX;
            self.memory.read(page, &mut cache.1).ok()?;
            cache.0 = page;
        }
        let entry = cache.1.get(offset..offset + PTE_SIZE)?;
        Some(vmem::PageTableEntry::from_le_bytes(entry.try_into().ok()?))
    }
}
impl<'a> hyperlight_common::vmem::TableReadOps for PageTableReader<'a> {
    type TableAddr = u64;
    fn entry_addr(addr: u64, offset: u64) -> u64 {
        addr + offset
    }
    unsafe fn read_entry(&self, addr: u64) -> vmem::PageTableEntry {
        if let Some(entry) = self.read_cached(addr) {
            return entry;
        }
        let mut pte_bytes = [0u8; PTE_SIZE];
        if self.memory.read(addr, &mut pte_bytes).is_err() {
            // Attacker-controlled data pointed out-of-bounds. We'll
            // default to returning 0 in this case, which, for most
            // architectures (including x86-64 and arm64, the ones we
            // care about presently) will be a not-present entry.
            // `finish` reports the failure.
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

#[derive(Clone, Copy)]
struct NewPage {
    source_gpa: u64,
    backing: GuestBacking,
}

/// Marks reused layers, or queues pages for copying into the new layer.
fn record_backed_pages(
    backing: GuestBacking,
    source_gpa: u64,
    len: usize,
    reused_layers: Option<&mut [bool]>,
    new_pages: &mut Vec<NewPage>,
) -> Result<()> {
    if let BackingSource::Snapshot(layer_index) = backing.source
        && let Some(reused_layers) = reused_layers
    {
        *reused_layers
            .get_mut(layer_index)
            .ok_or_else(|| crate::new_error!("snapshot layer index is out of bounds"))? = true;
        return Ok(());
    }

    for offset in (0..len).step_by(PAGE_SIZE) {
        new_pages.push(NewPage {
            source_gpa: source_gpa
                .checked_add(u64::try_from(offset)?)
                .ok_or_else(|| crate::new_error!("snapshot source GPA overflows"))?,
            backing: GuestBacking {
                offset: backing
                    .offset
                    .checked_add(offset)
                    .ok_or_else(|| crate::new_error!("snapshot source backing offset overflows"))?,
                ..backing
            },
        });
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
            && copy.backing.source == page.backing.source
            && copy.backing.offset.checked_add(copy.destination.len()) == Some(page.backing.offset)
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

fn first_fit_blob_gpa(
    data_len: usize,
    layers: &[Arc<SnapshotBlob>],
    scratch_base: u64,
) -> Option<u64> {
    if data_len == 0 {
        return None;
    }
    let data_len = u64::try_from(data_len).ok()?;
    let mut candidate = SandboxMemoryLayout::BASE_ADDRESS as u64;
    for range in layers.iter().map(|layer| layer.gpa_range()) {
        let end = candidate.checked_add(data_len)?;
        if end <= range.start {
            return Some(candidate);
        }
        candidate = candidate.max(range.end);
    }
    (candidate.checked_add(data_len)? <= scratch_base).then_some(candidate)
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
        MappingKind::ZeroInit(mapping) => Some(MappingKind::ZeroInit(mapping)),
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
    // Map the scratch region, except the guard pages under the reserved top
    // pages. Left unmapped, they make an amd64 exception stack overrun fault
    // before it reaches the transport arena.
    let base_gpa = scratch_base_gpa(scratch_size);
    let base_gva = scratch_base_gva(scratch_size);
    let gap_gva = scratch_transport_end_gva();
    let top_gva = scratch_reserved_top_gva();
    let ranges = if base_gva < gap_gva {
        [
            (base_gpa, base_gva, gap_gva - base_gva),
            (
                scratch_reserved_top_gpa(),
                top_gva,
                SCRATCH_TOP_GVA as u64 + 1 - top_gva,
            ),
        ]
    } else {
        // Only tests build a scratch window too small to reach the gap.
        [(base_gpa, base_gva, scratch_size as u64), (0, 0, 0)]
    };
    for (phys_base, virt_base, len) in ranges.into_iter().filter(|r| r.2 != 0) {
        let mapping = Mapping {
            phys_base,
            virt_base,
            len,
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
}

impl Snapshot {
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

        let mut layout = crate::mem::layout::SandboxMemoryLayout::new(
            cfg,
            exe_info.loaded_size(),
            guest_blob_size,
            guest_blob_mem_flags,
        )?;

        let load_addr = layout.get_guest_code_gpa() as u64;
        let base_va = exe_info.base_va();
        let entrypoint_va: u64 = exe_info.entrypoint().into();
        let is_pie = exe_info.is_pie();

        let code_gva = if is_pie { load_addr } else { base_va };
        layout.set_code_gva(code_gva)?;
        let regions = layout.get_memory_regions()?;

        // Set up page table entries for the snapshot
        let pt_buf = GuestPageTableBuffer::new(layout.get_pt_base_gpa() as usize);

        // 1. Map the (ideally readonly) pages of snapshot data
        for rgn in regions.iter() {
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
                phys_base: rgn.host_region.start as u64,
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

        let exn_stack_top_gva = hyperlight_common::layout::SCRATCH_TOP_GVA as u64
            - hyperlight_common::layout::SCRATCH_TOP_EXN_STACK_OFFSET
            + 1;

        let entrypoint_offset = entrypoint_va.checked_sub(base_va).ok_or_else(|| {
            crate::new_error!(
                "ELF entrypoint VA ({:#x}) is below base VA ({:#x})",
                entrypoint_va,
                base_va
            )
        })?;

        let entrypoint_gva = (layout.get_guest_code_gva() as u64)
            .checked_add(entrypoint_offset)
            .ok_or_else(|| crate::new_error!("ELF entrypoint GVA overflows"))?;

        // The page tables follow the data, which is padded to a host page.
        let host_page_size = self::memory::host_page_size();
        let data_len = layout.get_memory_size()?.next_multiple_of(host_page_size);
        let mut memory = ExclusiveSharedMemory::new(
            (data_len + pt_bytes.len()).next_multiple_of(host_page_size),
        )?;
        let data = &mut memory.as_mut_slice()[..data_len];

        let load_info = exe_info.load(
            layout.get_guest_code_gva() as u64,
            &mut data[layout.guest_code_offset()..],
        )?;

        layout.write_peb(data)?;

        blob.map(|x| layout.write_init_data(data, x.data))
            .transpose()?;
        memory.copy_from_slice(&pt_bytes, data_len)?;
        let memory = Arc::new(SnapshotMemory::from_flat(
            memory.freeze(data_len)?,
            SandboxMemoryLayout::BASE_ADDRESS as u64,
            pt_bytes.len(),
            scratch_base_gpa(layout.get_scratch_size()),
        )?);

        Ok(Self {
            state: Arc::new(SnapshotState {
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
                virtq: None,
            }),
            metadata: BTreeMap::new(),
        })
    }

    // It might be nice to consider moving at least stack_top_gva into
    // layout, and sharing (via RwLock or similar) the layout between
    // the (host-side) mem mgr (where it can be passed in here) and
    // the sandbox vm itself (which modifies it as it receives
    // requests from the sandbox).
    #[allow(clippy::too_many_arguments)]
    /// Capture memory with optional validated transport images.
    ///
    /// `layout` is the sandbox's own: the live page tables and scratch are
    /// read with it. The snapshot's page tables are built for
    /// `scratch_size`, which can differ from the sandbox's own. A larger
    /// scratch window must not cover a guest mapping or a snapshot layer.
    /// Page-table and snapshot sizes do not affect transport geometry.
    /// `root_pt_gpas` must be distinct.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn new(
        memory_view: &GuestPhysicalMemoryView<'_>,
        layout: SandboxMemoryLayout,
        load_info: LoadInfo,
        root_pt_gpas: &[u64],
        stack_top_gva: u64,
        sregs: CommonSpecialRegisters,
        #[cfg(target_arch = "x86_64")] msrs: Vec<MsrEntry>,
        next_action: NextAction,
        original_entrypoint: u64,
        snapshot_generation: u64,
        host_functions: HostFunctionDetails,
        virtq: Option<VirtqSnapshot>,
        scratch_size: usize,
    ) -> Result<Self> {
        if root_pt_gpas.is_empty() {
            return Err(crate::new_error!("snapshot has no page-table roots"));
        }
        let target = layout.with_scratch_size(scratch_size)?;
        let scratch_gva = scratch_base_gva(layout.get_scratch_size());
        // A larger scratch window also covers this band below the current
        // one, which `map_specials` would map over the guest's mappings.
        let grown_band = scratch_base_gva(scratch_size)..scratch_gva;
        // Unbacked roots fail through `PageTableReader::finish`.
        if let Some(root) = root_pt_gpas
            .iter()
            .find(|root| !root.is_multiple_of(PAGE_SIZE as u64))
        {
            return Err(crate::new_error!(
                "snapshot page-table root {root:#x} is not aligned"
            ));
        }
        // Phase 1: walk every PT root together. This detects
        // aliased intermediate tables (e.g. Nanvix's kernel-
        // half PTs, which multiple process PDs share by
        // pointing at the same PT page). The walker emits
        // `ThisSpace(leaf)` for private leaves and
        // `AnotherSpace(ref)` for sub-trees that were already
        // seen via an earlier root. Results are returned in
        // `root_pt_gpas` order — which is also the topological
        // order of the `AnotherSpace` references — so
        // processing in iteration order is safe.
        let op = PageTableReader::new(memory_view, root_pt_gpas[0]);
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
        op.finish()?;
        let source_layers = memory_view.snapshot().reusable_layers();
        let mut reused_layers = source_layers.map(|layers| vec![false; layers.len()]);
        let mut new_pages = Vec::new();
        for (_, mappings) in &walk {
            for mapping in mappings {
                let SpaceAwareMapping::ThisSpace(mapping) = mapping else {
                    continue;
                };
                if !grown_band.is_empty()
                    && mapping.virt_base < grown_band.end
                    && grown_band.start < mapping.virt_base.saturating_add(mapping.len)
                {
                    for_each_mapping_page(mapping, |_, virt_gva, _| {
                        if grown_band.contains(&virt_gva) && !skip_virt(virt_gva, scratch_gva) {
                            return Err(crate::new_error!(
                                "a scratch size of {scratch_size} would map scratch over the guest mapping at {virt_gva:#x}"
                            ));
                        }
                        Ok(())
                    })?;
                }
                if validate_mapping(mapping)? && !mapping_has_skipped_pages(mapping, scratch_gva)? {
                    if matches!(mapping.kind, MappingKind::ZeroInit(_)) {
                        continue;
                    }
                    let mapping_len = usize::try_from(mapping.len)?;
                    if let Some(backing) = memory_view.resolve(mapping.phys_base, mapping_len) {
                        record_backed_pages(
                            backing,
                            mapping.phys_base,
                            mapping_len,
                            reused_layers.as_deref_mut(),
                            &mut new_pages,
                        )?;
                        continue;
                    }
                }
                for_each_mapping_page(mapping, |source_gpa, virt_gva, kind| {
                    if skip_virt(virt_gva, scratch_gva) || matches!(kind, MappingKind::ZeroInit(_))
                    {
                        return Ok(());
                    }
                    let backing = memory_view.resolve(source_gpa, PAGE_SIZE).ok_or_else(|| {
                        crate::new_error!("snapshot leaf names unbacked GPA {source_gpa:#x}")
                    })?;
                    record_backed_pages(
                        backing,
                        source_gpa,
                        PAGE_SIZE,
                        reused_layers.as_deref_mut(),
                        &mut new_pages,
                    )
                })?;
            }
        }

        new_pages.sort_unstable_by_key(|page| page.source_gpa);
        new_pages.dedup_by_key(|page| page.source_gpa);

        let mut layers: Vec<Arc<SnapshotBlob>> = match (source_layers, reused_layers) {
            (Some(source_layers), Some(reused_layers)) => source_layers
                .iter()
                .zip(reused_layers)
                .filter(|(_, reused)| *reused)
                .map(|(layer, _)| layer.clone())
                .collect(),
            _ => Vec::new(),
        };
        let target_scratch_gpa = scratch_base_gpa(scratch_size);
        if let Some(layer) = layers
            .iter()
            .find(|layer| layer.gpa_range().end > target_scratch_gpa)
        {
            return Err(crate::new_error!(
                "a scratch size of {scratch_size} would map scratch over the snapshot layer at {:#x}",
                layer.gpa_start()
            ));
        }
        let host_page_size = self::memory::host_page_size();
        let data_len = packed_data_len(new_pages.len(), host_page_size)?;
        let new_blob_gpa = if data_len == 0 {
            None
        } else {
            Some(
                first_fit_blob_gpa(data_len, &layers, target_scratch_gpa).ok_or_else(|| {
                    crate::new_error!("snapshot has no address space for a new layer")
                })?,
            )
        };
        let new_page_runs = match new_blob_gpa {
            Some(destination_start) => new_page_runs(&new_pages, destination_start)?,
            None => Vec::new(),
        };

        // Phase 2: rebuild each space's page tables, compacting
        // `ThisSpace` leaves into a dense snapshot blob and
        // linking `AnotherSpace` entries to already-built
        // spaces' tables.
        // TODO: Look for opportunities to hugepage map
        let pt_buf = GuestPageTableBuffer::new(target.get_pt_base_gpa() as usize);
        // Allocate one root table per space and remember the
        // addresses returned by `alloc_table` instead of
        // assuming the buffer's physical layout.
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
                            // Drop the scratch region and (on
                            // amd64) the snapshot's own PT
                            // self-map; both are re-mapped
                            // freshly by `map_specials`.
                            if skip_virt(virt_gva, scratch_gva) {
                                flush_mapping(&mut pending_mapping);
                                return Ok(());
                            }
                            // Writable pages become CoW in the
                            // rebuilt snapshot; read-only pages
                            // stay read-only.
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
                        // Link to the owning space's already-
                        // rebuilt intermediate table — this
                        // is what preserves Nanvix's
                        // kernel-half-shared invariant across
                        // process PDs after relocation.
                        // SAFETY: The reference came from the source walk and
                        // `pt_buf` is local to this capture. The walk returns
                        // spaces in topological order, so the owner named by
                        // `reference` already has its root in `built_roots`.
                        unsafe { vmem::space_aware_map(&pt_buf, reference, &built_roots) };
                    }
                }
            }
            flush_mapping(&mut pending_mapping);
        }

        // Phase 3: Map the scratch region into each root.
        for &root_addr in &root_addrs {
            pt_buf.set_root(root_addr);
            map_specials(&pt_buf, scratch_size);
        }
        pt_buf.set_root(pt_buf.initial_root());
        // Phase 4: write the new blob, the new pages followed by the page
        // tables. A capture with no new pages still needs a blob for its
        // page tables.
        let page_tables = pt_buf.into_bytes();
        target.ensure_page_tables_fit(page_tables.len())?;
        let blob_len = data_len
            .checked_add(page_tables.len())
            .and_then(|len| len.checked_next_multiple_of(host_page_size))
            .ok_or_else(|| crate::new_error!("snapshot blob size overflows"))?;
        let mut allocation = ExclusiveSharedMemory::new(blob_len)?;
        for copy in new_page_copies(&new_pages)? {
            let destination = allocation
                .as_mut_slice()
                .get_mut(copy.destination)
                .ok_or_else(|| crate::new_error!("snapshot destination page is out of bounds"))?;
            memory_view.read_backing(copy.backing, destination)?;
        }
        allocation.copy_from_slice(&page_tables, data_len)?;
        let blob = Arc::new(SnapshotBlob::new(
            allocation.freeze(data_len)?,
            new_blob_gpa.unwrap_or_default(),
            page_tables.len(),
            target_scratch_gpa,
        )?);
        if data_len > 0 {
            layers.push(blob.clone());
        }
        // Validates the layer limit.
        let memory = Arc::new(SnapshotMemory::new(layers.into_boxed_slice(), blob)?);

        Ok(Self {
            state: Arc::new(SnapshotState {
                layout: target,
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
                virtq,
            }),
            metadata: BTreeMap::new(),
        })
    }

    /// Deserializes the metadata stored under `namespace` as `T`.
    ///
    /// Returns `None` if the namespace has no metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON metadata cannot be deserialized as `T`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use hyperlight_host::sandbox::snapshot::Snapshot;
    /// # use serde::{Deserialize, Serialize};
    /// #
    /// #[derive(Debug, PartialEq, Serialize, Deserialize)]
    /// struct Metadata {
    ///     version: u32,
    /// }
    ///
    /// # fn example(snapshot: Arc<Snapshot>) -> Result<(), Box<dyn std::error::Error>> {
    /// let snapshot =
    ///     snapshot.with_metadata("snapshot-metadata-namespace-v1", &Metadata { version: 1 })?;
    /// let metadata = snapshot
    ///     .metadata::<Metadata>("snapshot-metadata-namespace-v1")?
    ///     .expect("metadata should exist");
    /// assert_eq!(metadata, Metadata { version: 1 });
    /// # Ok(())
    /// # }
    /// ```
    pub fn metadata<T>(&self, namespace: &str) -> Result<Option<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        self.metadata
            .get(namespace)
            .map(serde::Deserialize::deserialize)
            .transpose()
            .map_err(Into::into)
    }

    /// Adds `metadata` to this snapshot and returns the result as a new
    /// snapshot. Metadata already stored under `namespace` is replaced.
    ///
    /// This snapshot remains unchanged.
    /// Metadata is saved and loaded with the snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if `metadata` cannot be serialized as JSON.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use hyperlight_host::sandbox::snapshot::Snapshot;
    /// # use serde::{Deserialize, Serialize};
    /// #
    /// #[derive(Debug, PartialEq, Serialize, Deserialize)]
    /// struct Metadata {
    ///     version: u32,
    /// }
    ///
    /// # fn example(snapshot: Arc<Snapshot>) -> Result<(), Box<dyn std::error::Error>> {
    /// let snapshot =
    ///     snapshot.with_metadata("snapshot-metadata-namespace-v1", &Metadata { version: 1 })?;
    /// let metadata = snapshot
    ///     .metadata::<Metadata>("snapshot-metadata-namespace-v1")?
    ///     .expect("metadata should exist");
    /// assert_eq!(metadata, Metadata { version: 1 });
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_metadata<T>(&self, namespace: impl Into<String>, metadata: &T) -> Result<Arc<Self>>
    where
        T: serde::Serialize,
    {
        let namespace = namespace.into();
        let metadata = serde_json::to_value(metadata)?;
        let mut metadata_by_namespace = self.metadata.clone();
        metadata_by_namespace.insert(namespace, metadata);
        Ok(Arc::new(Self {
            state: Arc::clone(&self.state),
            metadata: metadata_by_namespace,
        }))
    }

    /// Generation number assigned to this snapshot when it was taken.
    pub(crate) fn snapshot_generation(&self) -> u64 {
        self.state.snapshot_generation
    }

    /// Return the main memory contents of the snapshot
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn snapshot_memory(&self) -> &Arc<SnapshotMemory> {
        &self.state.memory
    }

    /// Return a copy of the load info for the exe in the snapshot
    pub(crate) fn load_info(&self) -> LoadInfo {
        self.state.load_info.clone()
    }

    pub(crate) fn layout(&self) -> &crate::mem::layout::SandboxMemoryLayout {
        &self.state.layout
    }

    pub(crate) fn root_pt_gpa(&self) -> u64 {
        self.state.layout.get_pt_base_gpa()
    }

    pub(crate) fn stack_top_gva(&self) -> u64 {
        self.state.stack_top_gva
    }

    /// Returns the special registers stored in this snapshot.
    /// Returns None for snapshots created directly from a binary (before preinitialisation).
    /// Returns Some for snapshots taken from a running sandbox.
    /// Note: The CR3 value in the returned struct should NOT be used for restore;
    /// use `root_pt_gpa()` instead since page tables are relocated during snapshot.
    pub(crate) fn sregs(&self) -> Option<&CommonSpecialRegisters> {
        self.state.sregs.as_ref()
    }

    /// The MSRs saved in this snapshot.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn msrs(&self) -> Option<&Vec<MsrEntry>> {
        self.state.msrs.as_ref()
    }

    pub(crate) fn next_action(&self) -> NextAction {
        self.state.next_action
    }

    pub(crate) fn virtq(&self) -> Option<&VirtqSnapshot> {
        self.state.virtq.as_ref()
    }

    /// Guest virtual address of the guest binary's ELF entry point,
    /// preserved across the `Initialise` -> `Call` transition. Used
    /// to fill `AT_ENTRY` in guest core dumps. 0 if unknown.
    pub(crate) fn original_entrypoint(&self) -> u64 {
        self.state.original_entrypoint
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
        let required = match &self.state.host_functions.host_functions {
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
        BackingSource, GuestBacking, GuestPageTableBuffer, GuestPhysicalMemoryView,
        SandboxMemoryManager,
    };
    use crate::mem::shared_mem::{ExclusiveSharedMemory, HostSharedMemory};

    fn default_sregs() -> CommonSpecialRegisters {
        CommonSpecialRegisters::default()
    }

    fn new_page(source_gpa: u64, offset: usize) -> super::NewPage {
        super::NewPage {
            source_gpa,
            backing: GuestBacking {
                source: BackingSource::Snapshot(0),
                offset,
            },
        }
    }

    #[test]
    fn page_runs_map_each_source_to_its_destination() {
        let base = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let page = PAGE_SIZE as u64;
        let destination = base + 0x10_0000;
        // Two contiguous pages, then a gap, then one more.
        let pages = [
            new_page(base, 0),
            new_page(base + page, PAGE_SIZE),
            new_page(base + 8 * page, 8 * PAGE_SIZE),
        ];

        let runs = super::new_page_runs(&pages, destination).unwrap();
        assert_eq!(runs.len(), 2);

        // Destinations are packed in index order regardless of source gaps.
        assert_eq!(super::page_destination(&runs, base), Some(destination));
        assert_eq!(
            super::page_destination(&runs, base + page),
            Some(destination + page)
        );
        assert_eq!(
            super::page_destination(&runs, base + 8 * page),
            Some(destination + 2 * page)
        );
        // An address in the source gap belongs to no run.
        assert_eq!(super::page_destination(&runs, base + 2 * page), None);
        assert_eq!(super::page_destination(&runs, base + 9 * page), None);
    }

    #[test]
    fn page_copies_merge_only_contiguous_backings() {
        let base = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let page = PAGE_SIZE as u64;
        // Contiguous source addresses, but the third page comes from a
        // backing offset that does not follow the second.
        let pages = [
            new_page(base, 0),
            new_page(base + page, PAGE_SIZE),
            new_page(base + 2 * page, 9 * PAGE_SIZE),
        ];

        let copies = super::new_page_copies(&pages).unwrap();
        assert_eq!(copies.len(), 2);
        assert_eq!(copies[0].destination, 0..2 * PAGE_SIZE);
        assert_eq!(copies[1].destination, 2 * PAGE_SIZE..3 * PAGE_SIZE);
    }

    #[test]
    fn blob_placement_respects_the_scratch_boundary() {
        let base = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let scratch_base = base + 2 * PAGE_SIZE as u64;

        // An empty delta needs no address.
        assert_eq!(super::first_fit_blob_gpa(0, &[], scratch_base), None);
        // With nothing to reuse the delta lands at the base.
        assert_eq!(
            super::first_fit_blob_gpa(PAGE_SIZE, &[], scratch_base),
            Some(base)
        );
        // Exactly filling the space below scratch is allowed.
        assert_eq!(
            super::first_fit_blob_gpa(2 * PAGE_SIZE, &[], scratch_base),
            Some(base)
        );
        // One page more is not.
        assert_eq!(
            super::first_fit_blob_gpa(3 * PAGE_SIZE, &[], scratch_base),
            None
        );
    }

    #[test]
    fn snapshot_page_policy_reuses_shared_and_copies_private_backings() {
        let source_gpa = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let backing = GuestBacking {
            source: BackingSource::Snapshot(0),
            offset: 0,
        };
        let mut reused = vec![false];
        let mut copied = Vec::new();

        super::record_backed_pages(
            backing,
            source_gpa,
            2 * PAGE_SIZE,
            Some(reused.as_mut_slice()),
            &mut copied,
        )
        .unwrap();
        assert_eq!(reused, [true]);
        assert!(copied.is_empty());

        reused[0] = false;
        super::record_backed_pages(backing, source_gpa, 2 * PAGE_SIZE, None, &mut copied).unwrap();
        assert_eq!(reused, [false]);
        assert_eq!(copied.len(), 2);
        assert_eq!(copied[0].source_gpa, source_gpa);
        assert_eq!(copied[0].backing, backing);
        assert_eq!(copied[1].source_gpa, source_gpa + PAGE_SIZE as u64);
        assert_eq!(
            copied[1].backing,
            GuestBacking {
                source: BackingSource::Snapshot(0),
                offset: PAGE_SIZE,
            }
        );
    }

    fn make_simple_pt_memory(contents: &[u8], pt_base: u64) -> super::SnapshotMemory {
        let base = SandboxMemoryLayout::BASE_ADDRESS as u64;
        make_pt_memory(contents, pt_base, base, &[base])
    }

    /// A one-layer snapshot at `data_gpa` whose page tables map its first
    /// page at each of `gvas`.
    fn make_pt_memory(
        contents: &[u8],
        pt_base: u64,
        data_gpa: u64,
        gvas: &[u64],
    ) -> super::SnapshotMemory {
        let pt_buf = GuestPageTableBuffer::new(pt_base as usize);
        for &virt_base in gvas {
            let mapping = Mapping {
                phys_base: data_gpa,
                virt_base,
                len: page_size::get() as u64,
                kind: MappingKind::Basic(BasicMapping {
                    readable: true,
                    writable: true,
                    executable: true,
                }),
            };
            unsafe { vmem::map(&pt_buf, mapping) };
        }
        super::map_specials(&pt_buf, PAGE_SIZE);
        let pt_bytes = pt_buf.into_bytes();

        super::memory::tests::flat_memory(
            contents,
            &pt_bytes,
            data_gpa,
            hyperlight_common::layout::scratch_base_gpa(PAGE_SIZE),
        )
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
        let base = SandboxMemoryLayout::BASE_ADDRESS as u64;
        make_pt_mgr(base, &[base])
    }

    /// A manager whose snapshot is one layer at `data_gpa`, with page tables
    /// that map its first page at each of `gvas`.
    fn make_pt_mgr(data_gpa: u64, gvas: &[u64]) -> (SandboxMemoryManager<HostSharedMemory>, u64) {
        let cfg = crate::sandbox::SandboxConfiguration::default();
        let scratch_mem = ExclusiveSharedMemory::new(cfg.get_scratch_size()).unwrap();
        let layout = SandboxMemoryLayout::new(cfg, 4096, 0x3000, None).unwrap();
        let pt_base = layout.get_pt_base_gpa();
        let memory = make_pt_memory(&vec![0u8; page_size::get()], pt_base, data_gpa, gvas);
        layout
            .ensure_page_tables_fit(memory.page_table_len())
            .unwrap();
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
    fn capture_and_restore_preserve_multiple_page_table_roots() {
        let cfg = crate::sandbox::SandboxConfiguration::default();
        let layout = SandboxMemoryLayout::new(cfg, 4096, 0x3000, None).unwrap();
        let pt_base = layout.get_pt_base_gpa();
        let base = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let pt_buf = GuestPageTableBuffer::new(pt_base as usize);
        let first_root = pt_buf.initial_root();
        // SAFETY: The local buffer owns its page tables and has no concurrent access.
        let second_root = unsafe { <GuestPageTableBuffer as vmem::TableOps>::alloc_table(&pt_buf) };
        let kind = MappingKind::Basic(BasicMapping {
            readable: true,
            writable: false,
            executable: false,
        });
        // SAFETY: Both roots belong to this local buffer and the mappings are page-aligned.
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
        let mut bytes = vec![0u8; data_len];
        bytes[..PAGE_SIZE].fill(0x11);
        bytes[PAGE_SIZE..2 * PAGE_SIZE].fill(0x22);
        let memory = super::memory::tests::flat_memory(
            &bytes,
            &page_tables,
            base,
            hyperlight_common::layout::scratch_base_gpa(layout.get_scratch_size()),
        );
        let manager = SandboxMemoryManager::new(
            layout,
            SnapshotMemoryBacking::from_snapshot(Arc::new(memory)).unwrap(),
            ExclusiveSharedMemory::new(layout.get_scratch_size()).unwrap(),
            super::NextAction::None,
        );
        let (mut manager, _) = manager.build().unwrap();

        let snapshot = manager
            .with_guest_memory(&[], |memory| {
                super::Snapshot::new(
                    memory,
                    manager.layout,
                    LoadInfo::dummy(),
                    &[first_root, second_root],
                    0,
                    default_sregs(),
                    #[cfg(target_arch = "x86_64")]
                    Vec::new(),
                    super::NextAction::None,
                    0,
                    1,
                    HostFunctionDetails::default(),
                    None,
                    manager.layout.get_scratch_size(),
                )
            })
            .unwrap();
        let rebuilt_first_root = snapshot.root_pt_gpa();
        let rebuilt_second_root = rebuilt_first_root + PAGE_TABLE_SIZE as u64;
        let roots = [rebuilt_first_root, rebuilt_second_root];
        // SAFETY: The immutable snapshot owns both roots throughout the walk.
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
        manager
            .with_guest_memory(&[], |memory| {
                for (root, gva, expected) in [
                    (rebuilt_first_root, base, 0x11),
                    (rebuilt_second_root, base + PAGE_SIZE as u64, 0x22),
                ] {
                    let reader = super::PageTableReader::new(memory, root);
                    // SAFETY: The reader borrows the stopped manager's mapped memory.
                    let mapping = unsafe { vmem::virt_to_phys(&reader, gva, 1) }
                        .next()
                        .unwrap();
                    let gpa = mapping.phys_base + gva - mapping.virt_base;
                    let mut byte = [0u8; 1];
                    memory.read(gpa, &mut byte).unwrap();
                    assert_eq!(byte, [expected]);
                }
                Ok(())
            })
            .unwrap();
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

        let result = manager.with_guest_memory(&[], |memory| {
            super::Snapshot::new(
                memory,
                manager.layout,
                LoadInfo::dummy(),
                &[pt_base],
                0,
                default_sregs(),
                Vec::new(),
                super::NextAction::None,
                0,
                1,
                HostFunctionDetails::default(),
                None,
                manager.layout.get_scratch_size(),
            )
        });
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
        let snapshot_a = GuestPhysicalMemoryView::with_memory(
            &pattern_a_memory,
            &mgr.scratch_mem,
            &[],
            mgr.layout,
            |memory| {
                super::Snapshot::new(
                    memory,
                    mgr.layout,
                    LoadInfo::dummy(),
                    &[pt_base],
                    0,
                    default_sregs(),
                    #[cfg(target_arch = "x86_64")]
                    Vec::new(),
                    super::NextAction::None,
                    0,
                    1,
                    HostFunctionDetails::default(),
                    None,
                    mgr.layout.get_scratch_size(),
                )
            },
        )
        .unwrap();
        assert_eq!(snapshot_a.snapshot_memory().layers().len(), 1);

        // Create second snapshot with pattern B
        let pattern_b = vec![0xBB; page_size::get()];
        let pattern_b_memory = make_simple_pt_host_mem(&pattern_b, pt_base);
        let snapshot_b = GuestPhysicalMemoryView::with_memory(
            &pattern_b_memory,
            &mgr.scratch_mem,
            &[],
            mgr.layout,
            |memory| {
                super::Snapshot::new(
                    memory,
                    mgr.layout,
                    LoadInfo::dummy(),
                    &[pt_base],
                    0,
                    default_sregs(),
                    #[cfg(target_arch = "x86_64")]
                    Vec::new(),
                    super::NextAction::None,
                    0,
                    2,
                    HostFunctionDetails::default(),
                    None,
                    mgr.layout.get_scratch_size(),
                )
            },
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
    fn page_table_reader_reports_unbacked_memory() {
        let (manager, pt_base) = make_simple_pt_mgr();
        manager
            .with_guest_memory(&[], |memory| {
                let reader = super::PageTableReader::new(memory, pt_base);
                assert!(reader.finish().is_ok());

                // A read off every backing is recorded rather than returned, so the
                // walk keeps going against not-present entries until finish() asks.
                // SAFETY: the reader borrows `memory`, which outlives this call.
                let entry = unsafe {
                    <super::PageTableReader as vmem::TableReadOps>::read_entry(
                        &reader,
                        !(PAGE_SIZE as u64 - 1),
                    )
                };
                assert_eq!(entry, 0);
                let error = reader.finish().unwrap_err().to_string();
                assert!(error.contains("accessed unbacked memory"), "{error}");
                Ok(())
            })
            .unwrap();
    }
    fn snapshot_with_scratch(
        data_gpa: u64,
        gvas: &[u64],
        scratch_size: usize,
    ) -> crate::Result<super::Snapshot> {
        let (mgr, pt_base) = make_pt_mgr(data_gpa, gvas);
        mgr.with_guest_memory(&[], |memory| {
            super::Snapshot::new(
                memory,
                mgr.layout,
                LoadInfo::dummy(),
                &[pt_base],
                0,
                default_sregs(),
                #[cfg(target_arch = "x86_64")]
                Vec::new(),
                super::NextAction::None,
                0,
                1,
                HostFunctionDetails::default(),
                None,
                scratch_size,
            )
        })
    }

    /// A snapshot can have more scratch than its sandbox, unless the larger
    /// window would cover a guest mapping below the current one.
    #[test]
    fn larger_scratch_must_not_cover_guest_mappings() {
        let scratch_size = crate::sandbox::SandboxConfiguration::default().get_scratch_size();
        let larger = scratch_size * 2;
        let base = SandboxMemoryLayout::BASE_ADDRESS as u64;

        let Ok(snapshot) = snapshot_with_scratch(base, &[base], larger) else {
            panic!("a larger scratch window over no guest mapping is rejected");
        };
        assert_eq!(snapshot.layout().get_scratch_size(), larger);

        let in_band = super::scratch_base_gva(scratch_size) - PAGE_SIZE as u64;
        let Err(err) = snapshot_with_scratch(base, &[base, in_band], larger) else {
            panic!("a larger scratch window covers a guest mapping");
        };
        assert!(err.to_string().contains(&format!("{in_band:#x}")), "{err}");

        // The same mapping is kept when the scratch window does not grow.
        assert!(snapshot_with_scratch(base, &[base, in_band], scratch_size).is_ok());
    }

    /// A larger scratch window must not cover a layer the capture keeps.
    #[test]
    #[cfg(not(unshared_snapshot_mem))]
    fn larger_scratch_must_not_cover_kept_layers() {
        let scratch_size = crate::sandbox::SandboxConfiguration::default().get_scratch_size();
        let base = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let high = super::scratch_base_gpa(scratch_size) - page_size::get() as u64;

        let Err(err) = snapshot_with_scratch(high, &[base], scratch_size * 2) else {
            panic!("a larger scratch window covers a kept layer");
        };
        assert!(err.to_string().contains(&format!("{high:#x}")), "{err}");

        let snapshot = snapshot_with_scratch(high, &[base], scratch_size).unwrap();
        assert_eq!(snapshot.snapshot_memory().layers()[0].gpa_start(), high);
    }

    #[test]
    fn page_table_reader_switches_cached_table_pages() {
        let (manager, pt_base) = make_simple_pt_mgr();
        let first = 8;
        let second = PAGE_SIZE + 16;
        manager.scratch_mem.write::<u64>(first, 0x1111).unwrap();
        manager.scratch_mem.write::<u64>(second, 0x2222).unwrap();
        let scratch_base =
            hyperlight_common::layout::scratch_base_gpa(manager.layout.get_scratch_size());
        manager
            .with_guest_memory(&[], |memory| {
                let reader = super::PageTableReader::new(memory, pt_base);
                // SAFETY: the reader borrows `memory`, which outlives these calls.
                let read = |offset: usize| unsafe {
                    <super::PageTableReader as vmem::TableReadOps>::read_entry(
                        &reader,
                        scratch_base + offset as u64,
                    )
                };

                assert_eq!(read(first), 0x1111);
                assert_eq!(read(second), 0x2222);
                assert_eq!(read(first), 0x1111);
                assert!(reader.finish().is_ok());
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn capture_rejects_invalid_page_table_roots() {
        let (manager, root) = make_simple_pt_mgr();
        for roots in [
            Vec::new(),
            vec![root + 1],
            vec![u64::MAX - (PAGE_SIZE as u64 - 1)],
        ] {
            let result = manager.with_guest_memory(&[], |memory| {
                super::Snapshot::new(
                    memory,
                    manager.layout,
                    LoadInfo::dummy(),
                    &roots,
                    0,
                    default_sregs(),
                    #[cfg(target_arch = "x86_64")]
                    Vec::new(),
                    super::NextAction::None,
                    0,
                    1,
                    HostFunctionDetails::default(),
                    None,
                    manager.layout.get_scratch_size(),
                )
            });
            assert!(result.is_err(), "invalid roots accepted: {roots:?}");
        }
    }

    #[test]
    fn capture_reuses_shared_pages_and_materializes_private_pages() {
        let host_page_size = page_size::get();
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
                    len: host_page_size as u64,
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
                    virt_base: base + (2 * host_page_size) as u64,
                    len: host_page_size as u64,
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
                    virt_base: base + host_page_size as u64,
                    len: host_page_size as u64,
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

        let mut source_bytes = vec![0u8; 2 * host_page_size];
        source_bytes[..host_page_size].fill(0x11);
        source_bytes[host_page_size..2 * host_page_size].fill(0x22);
        let source = super::memory::tests::flat_memory(
            &source_bytes,
            &page_tables,
            base,
            hyperlight_common::layout::scratch_base_gpa(layout.get_scratch_size()),
        );
        let source_blob = source.layers()[0].clone();
        let managed = SnapshotMemoryBacking::from_snapshot(Arc::new(source)).unwrap();
        let scratch = ExclusiveSharedMemory::new(layout.get_scratch_size()).unwrap();
        let manager = SandboxMemoryManager::new(layout, managed, scratch, super::NextAction::None);
        let (manager, _) = manager.build().unwrap();
        let reuses_source_layers = manager.shared_mem.reusable_layers().is_some();
        #[cfg(gdb)]
        {
            let (layer_index, offset) = manager.shared_mem.resolve(base, host_page_size).unwrap();
            manager
                .shared_mem
                .write_layer(layer_index, offset, &vec![0x44; host_page_size])
                .unwrap();
        }
        let mut source_page = vec![0u8; host_page_size];
        manager
            .shared_mem
            .read_snapshot_gpa(base, &mut source_page)
            .unwrap();
        manager
            .scratch_mem
            .copy_from_slice(&vec![0x33; host_page_size], scratch_offset)
            .unwrap();

        let captured = manager
            .with_guest_memory(&[], |memory| {
                super::Snapshot::new(
                    memory,
                    manager.layout,
                    LoadInfo::dummy(),
                    &[pt_base],
                    0,
                    default_sregs(),
                    #[cfg(target_arch = "x86_64")]
                    Vec::new(),
                    super::NextAction::None,
                    0,
                    1,
                    HostFunctionDetails::default(),
                    None,
                    manager.layout.get_scratch_size(),
                )
            })
            .unwrap();

        let layers = captured.snapshot_memory().layers();
        let delta_gpa = if reuses_source_layers {
            assert_eq!(layers.len(), 2);
            assert!(std::sync::Arc::ptr_eq(&layers[0], &source_blob));
            assert_eq!(layers[1].data_len(), host_page_size);
            assert_eq!(layers[1].gpa_start(), base + (2 * host_page_size) as u64);
            base + (2 * host_page_size) as u64
        } else {
            assert_eq!(layers.len(), 1);
            assert!(!std::sync::Arc::ptr_eq(&layers[0], &source_blob));
            assert_eq!(layers[0].data_len(), 2 * host_page_size);
            assert_eq!(layers[0].gpa_start(), base);
            base + host_page_size as u64
        };

        // SAFETY: `captured` is immutable for the duration of this walk.
        let mappings = unsafe { vmem::virt_to_phys(&captured, base, 3 * host_page_size as u64) }
            .step_by(host_page_size / PAGE_SIZE)
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
        let (delta_layer, delta_offset) = captured
            .snapshot_memory()
            .resolve(mappings[1].phys_base, host_page_size)
            .unwrap();
        assert_eq!(
            layers[delta_layer].memory().as_slice()[delta_offset..delta_offset + host_page_size],
            vec![0x33; host_page_size]
        );
        let (kept_layer, kept_offset) = captured
            .snapshot_memory()
            .resolve(base, host_page_size)
            .unwrap();
        assert_eq!(
            layers[kept_layer].memory().as_slice()[kept_offset..kept_offset + host_page_size],
            source_page
        );
        // The reused layer stays mapped whole, including the page the guest
        // replaced.
        let (replaced_layer, replaced_offset) = captured
            .snapshot_memory()
            .resolve(base + host_page_size as u64, host_page_size)
            .unwrap();
        let replaced = vec![if reuses_source_layers { 0x22 } else { 0x33 }; host_page_size];
        assert_eq!(
            layers[replaced_layer].memory().as_slice()
                [replaced_offset..replaced_offset + host_page_size],
            replaced
        );
    }

    #[test]
    fn capture_rejects_leaf_into_page_table_tail() {
        let host_page_size = page_size::get();
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
                    phys_base: base + host_page_size as u64,
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

        let bytes = vec![0u8; host_page_size];
        let source = super::memory::tests::flat_memory(
            &bytes,
            &page_tables,
            base,
            hyperlight_common::layout::scratch_base_gpa(layout.get_scratch_size()),
        );
        let manager = SandboxMemoryManager::new(
            layout,
            SnapshotMemoryBacking::from_snapshot(Arc::new(source)).unwrap(),
            ExclusiveSharedMemory::new(layout.get_scratch_size()).unwrap(),
            super::NextAction::None,
        );
        let (manager, _) = manager.build().unwrap();

        let result = manager.with_guest_memory(&[], |memory| {
            super::Snapshot::new(
                memory,
                manager.layout,
                LoadInfo::dummy(),
                &[pt_base],
                0,
                default_sregs(),
                #[cfg(target_arch = "x86_64")]
                Vec::new(),
                super::NextAction::None,
                0,
                1,
                HostFunctionDetails::default(),
                None,
                manager.layout.get_scratch_size(),
            )
        });
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
    #[cfg(not(unshared_snapshot_mem))]
    fn capture_rejects_delta_exceeding_layer_limit() {
        let host_page_size = page_size::get();
        let cfg = crate::sandbox::SandboxConfiguration::default();
        let layout = SandboxMemoryLayout::new(cfg, 4096, 0x3000, None).unwrap();
        let pt_base = layout.get_pt_base_gpa();
        let scratch_offset = layout.get_scratch_size() / 2;
        let scratch_gpa = hyperlight_common::layout::scratch_base_gpa(layout.get_scratch_size())
            + scratch_offset as u64;
        let base = SandboxMemoryLayout::BASE_ADDRESS as u64;
        let max_layers = super::memory::MAX_SNAPSHOT_LAYERS;

        let pt_buf = GuestPageTableBuffer::new(pt_base as usize);
        // One page in each of `max_layers` source layers, then one scratch page
        // that needs a new layer.
        for index in 0..=max_layers {
            let phys_base = if index < max_layers {
                base + (index * host_page_size) as u64
            } else {
                scratch_gpa
            };
            // SAFETY: The page-aligned mapping is written to a local page-table
            // buffer with no concurrent access.
            unsafe {
                vmem::map(
                    &pt_buf,
                    Mapping {
                        phys_base,
                        virt_base: base + (index * host_page_size) as u64,
                        len: host_page_size as u64,
                        kind: MappingKind::Basic(BasicMapping {
                            readable: true,
                            writable: index == max_layers,
                            executable: false,
                        }),
                    },
                );
            }
        }
        super::map_specials(&pt_buf, layout.get_scratch_size());
        let page_tables = pt_buf.into_bytes();
        layout.ensure_page_tables_fit(page_tables.len()).unwrap();

        let scratch_base = hyperlight_common::layout::scratch_base_gpa(layout.get_scratch_size());
        let source_layers = (0..max_layers)
            .map(|index| {
                let storage = crate::mem::shared_mem::ReadonlySharedMemory::from_bytes(
                    &vec![index as u8; host_page_size],
                    host_page_size,
                )
                .unwrap();
                Arc::new(
                    super::SnapshotBlob::new(
                        storage,
                        base + (index * host_page_size) as u64,
                        0,
                        scratch_base,
                    )
                    .unwrap(),
                )
            })
            .collect::<Box<[_]>>();
        let source = super::SnapshotMemory::new(
            source_layers.clone(),
            super::memory::tests::page_tables_from_bytes(&page_tables),
        )
        .unwrap();
        let managed = SnapshotMemoryBacking::from_snapshot(Arc::new(source)).unwrap();
        let scratch = ExclusiveSharedMemory::new(layout.get_scratch_size()).unwrap();
        let manager = SandboxMemoryManager::new(layout, managed, scratch, super::NextAction::None);
        let (mut manager, _) = manager.build().unwrap();
        manager
            .scratch_mem
            .copy_from_slice(&vec![0x55; host_page_size], scratch_offset)
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
            manager.layout.get_scratch_size(),
        );
        let error = match result {
            Ok(_) => panic!("capture unexpectedly exceeded the layer limit"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("layer count 31 exceeds 30"));
        assert_eq!(manager.snapshot_count, 0);
        assert!(
            manager
                .shared_mem
                .layers()
                .iter()
                .zip(&source_layers)
                .all(|(layer, source)| Arc::ptr_eq(layer, source))
        );
        assert_eq!(
            manager.scratch_mem.read::<u8>(scratch_offset).unwrap(),
            0x55
        );
    }
}
