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

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};

use hyperlight_common::layout::{scratch_base_gpa, scratch_base_gva};
use hyperlight_common::vmem;
use hyperlight_common::vmem::{
    BasicMapping, CowMapping, Mapping, MappingKind, PAGE_SIZE, SpaceAwareMapping, SpaceId, TableOps,
};
use tracing::{Span, instrument};

use crate::HyperlightError::MemoryRegionSizeMismatch;
use crate::Result;
use crate::hypervisor::regs::CommonSpecialRegisters;
use crate::mem::exe::{ExeInfo, LoadInfo};
use crate::mem::layout::SandboxMemoryLayout;
use crate::mem::memory_region::{GuestMemoryRegion, MemoryRegion, MemoryRegionFlags};
use crate::mem::mgr::{GuestPageTableBuffer, SnapshotSharedMemory};
use crate::mem::shared_mem::{ReadonlySharedMemory, SharedMemory};
use crate::sandbox::SandboxConfiguration;
use crate::sandbox::uninitialized::{GuestBinary, GuestEnvironment};

pub(super) static SANDBOX_CONFIGURATION_COUNTER: AtomicU64 = AtomicU64::new(0);

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

/// A wrapper around a `SharedMemory` reference and a snapshot
/// of the memory therein
pub struct Snapshot {
    /// Unique ID of the sandbox configuration for sandboxes where
    /// this snapshot may be restored.
    sandbox_id: u64,
    /// Layout object for the sandbox. TODO: get rid of this and
    /// replace with something saner and set up from the guest (early
    /// on?).
    ///
    /// Not checked on restore, since any sandbox with the same
    /// configuration id will share the same layout
    layout: crate::mem::layout::SandboxMemoryLayout,
    /// Memory of the sandbox at the time this snapshot was taken
    memory: ReadonlySharedMemory,
    /// The memory regions that were mapped when this snapshot was
    /// taken (excluding initial sandbox regions)
    regions: Vec<MemoryRegion>,
    /// Extra debug information about the binary in this snapshot,
    /// from when the binary was first loaded into the snapshot.
    ///
    /// This information is provided on a best-effort basis, and there
    /// is a pretty good chance that it does not exist; generally speaking,
    /// things like persisting a snapshot and reloading it are likely
    /// to destroy this information.
    load_info: LoadInfo,
    /// The hash of the other portions of the snapshot. Morally, this
    /// is just a memoization cache for [`hash`], below, but it is not
    /// a [`std::sync::OnceLock`] because it may be persisted to disk
    /// without being recomputed on load.
    ///
    /// It is not a [`blake3::Hash`] because we do not presently
    /// require constant-time equality checking
    hash: [u8; 32],
    /// The address of the top of the guest stack
    stack_top_gva: u64,

    /// Special register state captured from the vCPU during snapshot.
    /// None for snapshots created directly from a binary (before
    /// guest runs).  Some for snapshots taken from a running sandbox.
    /// Note: CR3 in this struct is NOT used on restore, since page
    /// tables are relocated during snapshot.
    sregs: Option<CommonSpecialRegisters>,

    /// The next action that should be performed on this snapshot
    entrypoint: NextAction,
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
        let addr = addr as usize;
        let Some(pte_bytes) = self.memory.as_slice().get(addr..addr + PTE_SIZE) else {
            // Attacker-controlled data pointed out-of-bounds. We'll
            // default to returning 0 in this case, which, for most
            // architectures (including x86-64 and arm64, the ones we
            // care about presently) will be a not-present entry.
            return 0;
        };
        // The `get()` above ensures exactly PTE_SIZE bytes.
        #[allow(clippy::unwrap_used)]
        vmem::PageTableEntry::from_le_bytes(pte_bytes.try_into().unwrap())
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

/// Compute a deterministic hash of a snapshot.
///
/// This does not include the load info from the snapshot, because
/// that is only used for debugging builds.
fn hash(memory: &[u8], regions: &[MemoryRegion]) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(memory);
    for rgn in regions {
        hasher.update(&usize::to_le_bytes(rgn.guest_region.start));
        let guest_len = rgn.guest_region.end - rgn.guest_region.start;
        #[allow(clippy::useless_conversion)]
        let host_start_addr: usize = rgn.host_region.start.into();
        #[allow(clippy::useless_conversion)]
        let host_end_addr: usize = rgn.host_region.end.into();
        hasher.update(&usize::to_le_bytes(host_start_addr));
        let host_len = host_end_addr - host_start_addr;
        if guest_len != host_len {
            return Err(MemoryRegionSizeMismatch(
                host_len,
                guest_len,
                format!("{:?}", rgn),
            ));
        }
        // Ignore [`MemoryRegion::region_type`], since it is extra
        // information for debugging rather than a core part of the
        // identity of the snapshot/workload.
        hasher.update(&usize::to_le_bytes(guest_len));
        hasher.update(&u32::to_le_bytes(rgn.flags.bits()));
    }
    // Ignore [`load_info`], since it is extra information for
    // debugging rather than a core part of the identity of the
    // snapshot/workload.
    Ok(hasher.finalize().into())
}

pub(crate) fn access_gpa<'a>(
    snap: &'a [u8],
    scratch: &'a [u8],
    layout: SandboxMemoryLayout,
    gpa: u64,
) -> Option<(&'a [u8], usize)> {
    let resolved = layout.resolve_gpa(gpa, &[])?.with_memories(snap, scratch);
    Some((resolved.base.as_ref(), resolved.offset))
}

pub(crate) struct SharedMemoryPageTableBuffer<'a> {
    snap: &'a [u8],
    scratch: &'a [u8],
    layout: SandboxMemoryLayout,
    root: u64,
}
impl<'a> SharedMemoryPageTableBuffer<'a> {
    pub(crate) fn new(
        snap: &'a [u8],
        scratch: &'a [u8],
        layout: SandboxMemoryLayout,
        root: u64,
    ) -> Self {
        Self {
            snap,
            scratch,
            layout,
            root,
        }
    }
}
impl<'a> hyperlight_common::vmem::TableReadOps for SharedMemoryPageTableBuffer<'a> {
    type TableAddr = u64;
    fn entry_addr(addr: u64, offset: u64) -> u64 {
        addr + offset
    }
    unsafe fn read_entry(&self, addr: u64) -> vmem::PageTableEntry {
        let memoff = access_gpa(self.snap, self.scratch, self.layout, addr);
        let Some(pte_bytes) = memoff.and_then(|(mem, off)| mem.get(off..off + PTE_SIZE)) else {
            // Attacker-controlled data pointed out-of-bounds. We'll
            // default to returning 0 in this case, which, for most
            // architectures (including x86-64 and arm64, the ones we
            // care about presently) will be a not-present entry.
            return 0;
        };
        // The `get()` above ensures exactly PTE_SIZE bytes.
        #[allow(clippy::unwrap_used)]
        vmem::PageTableEntry::from_le_bytes(pte_bytes.try_into().unwrap())
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
impl<'a> core::convert::AsRef<SharedMemoryPageTableBuffer<'a>> for SharedMemoryPageTableBuffer<'a> {
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
    #[cfg(not(feature = "i686-guest"))]
    if virt_base >= hyperlight_common::layout::SNAPSHOT_PT_GVA_MIN as u64
        && virt_base <= hyperlight_common::layout::SNAPSHOT_PT_GVA_MAX as u64
    {
        return true;
    }
    #[cfg(feature = "i686-guest")]
    let _ = virt_base;
    false
}

/// Find the contents of the page which starts at gpa in guest physical
/// memory, taking into account excess host->guest regions
///
/// # Safety
/// The host side of the regions identified by MemoryRegion must be
/// alive and must not be mutated by any other thread: references to
/// these regions may be created and live for `'a`.
unsafe fn guest_page<'a>(
    snap: &'a [u8],
    scratch: &'a [u8],
    regions: &[MemoryRegion],
    layout: SandboxMemoryLayout,
    gpa: u64,
) -> Option<&'a [u8]> {
    let resolved = layout
        .resolve_gpa(gpa, regions)?
        .with_memories(snap, scratch);
    if resolved.as_ref().len() < PAGE_SIZE {
        return None;
    }
    Some(&resolved.as_ref()[..PAGE_SIZE])
}

fn map_specials(pt_buf: &GuestPageTableBuffer, scratch_size: usize) {
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
        user_accessible: false,
    };
    unsafe { vmem::map(pt_buf, mapping) };
}

impl Snapshot {
    /// Create a new snapshot from the guest binary identified by `env`. With the configuration
    /// specified in `cfg`.
    pub(crate) fn from_env<'a, 'b>(
        env: impl Into<GuestEnvironment<'a, 'b>>,
        cfg: SandboxConfiguration,
    ) -> Result<Self> {
        let env = env.into();
        let mut bin = env.guest_binary;
        bin.canonicalize()?;
        let blob = env.init_data;

        let exe_info = match bin {
            GuestBinary::FilePath(bin_path_str) => ExeInfo::from_file(&bin_path_str)?,
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

        #[cfg_attr(feature = "i686-guest", allow(unused_mut))]
        let mut layout = crate::mem::layout::SandboxMemoryLayout::new(
            cfg,
            exe_info.loaded_size(),
            guest_blob_size,
            guest_blob_mem_flags,
        )?;

        let load_addr = layout.get_guest_code_address() as u64;
        let base_va = exe_info.base_va();
        let entrypoint_va: u64 = exe_info.entrypoint().into();

        let mut memory = vec![0; layout.get_memory_size()?];

        let load_info = exe_info.load(
            load_addr.try_into()?,
            &mut memory[layout.get_guest_code_offset()..],
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
                user_accessible: false,
            };
            unsafe { vmem::map(&pt_buf, mapping) };
        }

        // 2. Map the special mappings
        map_specials(&pt_buf, layout.get_scratch_size());

        let pt_bytes = pt_buf.into_bytes();
        layout.set_pt_size(pt_bytes.len())?;
        memory.extend(&pt_bytes);

        let exn_stack_top_gva = hyperlight_common::layout::MAX_GVA as u64
            - hyperlight_common::layout::SCRATCH_TOP_EXN_STACK_OFFSET
            + 1;

        let extra_regions = Vec::new();
        let hash = hash(&memory, &extra_regions)?;

        Ok(Self {
            sandbox_id: SANDBOX_CONFIGURATION_COUNTER.fetch_add(1, Ordering::Relaxed),
            memory: ReadonlySharedMemory::from_bytes(&memory)?,
            layout,
            regions: extra_regions,
            load_info,
            hash,
            stack_top_gva: exn_stack_top_gva,
            sregs: None,
            entrypoint: NextAction::Initialise(load_addr + entrypoint_va - base_va),
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
    pub(crate) fn new<S: SharedMemory>(
        shared_mem: &mut SnapshotSharedMemory<S>,
        scratch_mem: &mut S,
        sandbox_id: u64,
        mut layout: SandboxMemoryLayout,
        load_info: LoadInfo,
        regions: Vec<MemoryRegion>,
        root_pt_gpas: &[u64],
        stack_top_gva: u64,
        sregs: CommonSpecialRegisters,
        entrypoint: NextAction,
    ) -> Result<Self> {
        let mut phys_seen = HashMap::<u64, usize>::new();
        let scratch_gva = scratch_base_gva(layout.get_scratch_size());
        let memory = shared_mem.with_contents(|snap_c| {
            scratch_mem.with_contents(|scratch_c| {
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
                let op = SharedMemoryPageTableBuffer::new(
                    snap_c,
                    scratch_c,
                    layout,
                    root_pt_gpas.first().copied().unwrap_or(0),
                );
                let walk = unsafe {
                    vmem::walk_va_spaces(
                        &op,
                        root_pt_gpas,
                        0,
                        hyperlight_common::layout::MAX_GVA as u64,
                    )
                };

                // Phase 2: rebuild each space's page tables, compacting
                // `ThisSpace` leaves into a dense snapshot blob and
                // linking `AnotherSpace` entries to already-built
                // spaces' tables.
                // TODO: Look for opportunities to hugepage map
                let mut snapshot_memory: Vec<u8> = Vec::new();
                let pt_buf = GuestPageTableBuffer::new(layout.get_pt_base_gpa() as usize);
                for _ in 1..root_pt_gpas.len() {
                    unsafe { pt_buf.alloc_table() };
                }

                let mut built_roots: BTreeMap<SpaceId, u64> = BTreeMap::new();
                for (root_idx, (space_id, mappings)) in walk.into_iter().enumerate() {
                    pt_buf.set_root_offset(root_idx * PAGE_SIZE);
                    built_roots.insert(
                        space_id,
                        (layout.get_pt_base_gpa() as usize + root_idx * PAGE_SIZE) as u64,
                    );

                    for sam in mappings {
                        match sam {
                            SpaceAwareMapping::ThisSpace(mapping) => {
                                // Drop the scratch region and (on
                                // amd64) the snapshot's own PT
                                // self-map; both are re-mapped
                                // freshly by `map_specials`.
                                if skip_virt(mapping.virt_base, scratch_gva) {
                                    continue;
                                }
                                let Some(contents) = (unsafe {
                                    guest_page(
                                        snap_c,
                                        scratch_c,
                                        &regions,
                                        layout,
                                        mapping.phys_base,
                                    )
                                }) else {
                                    continue;
                                };

                                // Writable pages become CoW in the
                                // rebuilt snapshot; read-only pages
                                // stay read-only.
                                let kind = match mapping.kind {
                                    MappingKind::Cow(cm) => MappingKind::Cow(cm),
                                    MappingKind::Basic(bm) if bm.writable => {
                                        MappingKind::Cow(CowMapping {
                                            readable: bm.readable,
                                            executable: bm.executable,
                                        })
                                    }
                                    MappingKind::Basic(bm) => MappingKind::Basic(BasicMapping {
                                        readable: bm.readable,
                                        writable: false,
                                        executable: bm.executable,
                                    }),
                                    MappingKind::Unmapped => continue,
                                };
                                let new_gpa =
                                    phys_seen.entry(mapping.phys_base).or_insert_with(|| {
                                        let new_offset = snapshot_memory.len();
                                        snapshot_memory.extend(contents);
                                        new_offset + SandboxMemoryLayout::BASE_ADDRESS
                                    });

                                let compacted = Mapping {
                                    phys_base: *new_gpa as u64,
                                    virt_base: mapping.virt_base,
                                    len: PAGE_SIZE as u64,
                                    kind,
                                    user_accessible: mapping.user_accessible,
                                };
                                unsafe { vmem::map(&pt_buf, compacted) };
                            }
                            SpaceAwareMapping::AnotherSpace(ref_map) => {
                                // Link to the owning space's already-
                                // rebuilt intermediate table — this
                                // is what preserves Nanvix's
                                // kernel-half-shared invariant across
                                // process PDs after relocation.
                                unsafe {
                                    vmem::space_aware_map(&pt_buf, ref_map, &built_roots);
                                }
                            }
                        }
                    }
                }

                // Phase 3: Map the scratch region into each root.
                for root_idx in 0..root_pt_gpas.len() {
                    pt_buf.set_root_offset(root_idx * PAGE_SIZE);
                    map_specials(&pt_buf, layout.get_scratch_size());
                }
                pt_buf.set_root_offset(0);

                // Phase 4: finalize PT bytes.
                let pt_data = pt_buf.into_bytes();
                layout.set_pt_size(pt_data.len())?;
                snapshot_memory.extend(&pt_data);
                Ok::<_, crate::HyperlightError>(snapshot_memory)
            })
        })???;
        // Only map the data portion into guest PA space. The PT tail
        // must stay out of the KVM slot to avoid overlapping with
        // map_file_cow regions that sit right after the snapshot.
        let guest_visible_size = memory.len() - layout.get_pt_size();
        debug_assert!(guest_visible_size.is_multiple_of(PAGE_SIZE));
        layout.set_snapshot_size(guest_visible_size);

        // On amd64 we currently don't persist the embedder-provided
        // regions (`map_file_cow` etc.) into the snapshot — the
        // existing behaviour predates this PR and mirrors what the old
        // non-relocated path did. On i686 we do keep them: Nanvix uses
        // `map_file_cow` regions for its ramfs image, which must
        // survive into the snapshot identity so that restore produces
        // the same guest state.
        #[cfg(not(feature = "i686-guest"))]
        let regions = Vec::new();

        let hash = hash(&memory, &regions)?;
        Ok(Self {
            sandbox_id,
            layout,
            memory: ReadonlySharedMemory::from_bytes_with_mapped_size(&memory, guest_visible_size)?,
            regions,
            load_info,
            hash,
            stack_top_gva,
            sregs: Some(sregs),
            entrypoint,
        })
    }

    /// The id of the sandbox this snapshot was taken from.
    pub(crate) fn sandbox_id(&self) -> u64 {
        self.sandbox_id
    }

    /// Get the mapped regions from this snapshot
    pub(crate) fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    /// Return the main memory contents of the snapshot
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn memory(&self) -> &ReadonlySharedMemory {
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

    pub(crate) fn entrypoint(&self) -> NextAction {
        self.entrypoint
    }
}

impl PartialEq for Snapshot {
    fn eq(&self, other: &Snapshot) -> bool {
        self.hash == other.hash
    }
}

#[cfg(test)]
#[cfg(not(feature = "i686-guest"))]
mod tests {
    use hyperlight_common::vmem::{self, BasicMapping, Mapping, MappingKind, PAGE_SIZE};

    use crate::hypervisor::regs::CommonSpecialRegisters;
    use crate::mem::exe::LoadInfo;
    use crate::mem::layout::SandboxMemoryLayout;
    use crate::mem::mgr::{GuestPageTableBuffer, SandboxMemoryManager, SnapshotSharedMemory};
    use crate::mem::shared_mem::{
        ExclusiveSharedMemory, HostSharedMemory, ReadonlySharedMemory, SharedMemory,
    };

    fn default_sregs() -> CommonSpecialRegisters {
        CommonSpecialRegisters::default()
    }

    const SIMPLE_PT_BASE: usize = PAGE_SIZE + SandboxMemoryLayout::BASE_ADDRESS;

    fn make_simple_pt_mem(contents: &[u8]) -> SnapshotSharedMemory<ExclusiveSharedMemory> {
        let pt_buf = GuestPageTableBuffer::new(SIMPLE_PT_BASE);
        let mapping = Mapping {
            phys_base: SandboxMemoryLayout::BASE_ADDRESS as u64,
            virt_base: SandboxMemoryLayout::BASE_ADDRESS as u64,
            len: PAGE_SIZE as u64,
            kind: MappingKind::Basic(BasicMapping {
                readable: true,
                writable: true,
                executable: true,
            }),
            user_accessible: false,
        };
        unsafe { vmem::map(&pt_buf, mapping) };
        super::map_specials(&pt_buf, PAGE_SIZE);
        let pt_bytes = pt_buf.into_bytes();

        let mut snapshot_mem = vec![0u8; PAGE_SIZE + pt_bytes.len()];
        snapshot_mem[0..PAGE_SIZE].copy_from_slice(contents);
        snapshot_mem[PAGE_SIZE..].copy_from_slice(&pt_bytes);
        ReadonlySharedMemory::from_bytes(&snapshot_mem)
            .unwrap()
            .to_mgr_snapshot_mem()
            .unwrap()
    }

    fn make_simple_pt_mgr() -> (SandboxMemoryManager<HostSharedMemory>, u64) {
        let cfg = crate::sandbox::SandboxConfiguration::default();
        let scratch_mem = ExclusiveSharedMemory::new(cfg.get_scratch_size()).unwrap();
        let mgr = SandboxMemoryManager::new(
            SandboxMemoryLayout::new(cfg, 4096, 0x3000, None).unwrap(),
            make_simple_pt_mem(&[0u8; PAGE_SIZE]),
            scratch_mem,
            super::NextAction::None,
        );
        let (mgr, _) = mgr.build().unwrap();
        (mgr, SIMPLE_PT_BASE as u64)
    }

    #[test]
    fn multiple_snapshots_independent() {
        let (mut mgr, pt_base) = make_simple_pt_mgr();

        // Create first snapshot with pattern A
        let pattern_a = vec![0xAA; PAGE_SIZE];
        let snapshot_a = super::Snapshot::new(
            &mut make_simple_pt_mem(&pattern_a).build().0,
            &mut mgr.scratch_mem,
            1,
            mgr.layout,
            LoadInfo::dummy(),
            Vec::new(),
            &[pt_base],
            0,
            default_sregs(),
            super::NextAction::None,
        )
        .unwrap();

        // Create second snapshot with pattern B
        let pattern_b = vec![0xBB; PAGE_SIZE];
        let snapshot_b = super::Snapshot::new(
            &mut make_simple_pt_mem(&pattern_b).build().0,
            &mut mgr.scratch_mem,
            2,
            mgr.layout,
            LoadInfo::dummy(),
            Vec::new(),
            &[pt_base],
            0,
            default_sregs(),
            super::NextAction::None,
        )
        .unwrap();

        // Restore snapshot A
        mgr.restore_snapshot(&snapshot_a).unwrap();
        mgr.shared_mem
            .with_contents(|contents| assert_eq!(&contents[0..pattern_a.len()], &pattern_a[..]))
            .unwrap();

        // Restore snapshot B
        mgr.restore_snapshot(&snapshot_b).unwrap();
        mgr.shared_mem
            .with_contents(|contents| assert_eq!(&contents[0..pattern_b.len()], &pattern_b[..]))
            .unwrap();
    }
}

#[cfg(test)]
#[cfg(feature = "i686-guest")]
mod i686_tests {
    use hyperlight_common::vmem::{
        self, BasicMapping, CowMapping, Mapping, MappingKind, PAGE_SIZE,
    };

    use crate::mem::mgr::GuestPageTableBuffer;

    const PT_BASE: usize = 0x10_0000;

    #[test]
    fn map_single_page() {
        let pt = GuestPageTableBuffer::new(PT_BASE);
        let mapping = Mapping {
            phys_base: 0x2000,
            virt_base: 0x1000,
            len: PAGE_SIZE as u64,
            kind: MappingKind::Basic(BasicMapping {
                readable: true,
                writable: true,
                executable: true,
            }),
            user_accessible: false,
        };
        unsafe { vmem::map(&pt, mapping) };

        let results: Vec<_> =
            unsafe { vmem::virt_to_phys(&pt, 0x1000, PAGE_SIZE as u64) }.collect();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].phys_base, 0x2000);
        assert_eq!(results[0].virt_base, 0x1000);
        assert!(matches!(
            results[0].kind,
            MappingKind::Basic(BasicMapping { writable: true, .. })
        ));
    }

    #[test]
    fn map_cow_page() {
        let pt = GuestPageTableBuffer::new(PT_BASE);
        let mapping = Mapping {
            phys_base: 0x3000,
            virt_base: 0x2000,
            len: PAGE_SIZE as u64,
            kind: MappingKind::Cow(CowMapping {
                readable: true,
                executable: true,
            }),
            user_accessible: false,
        };
        unsafe { vmem::map(&pt, mapping) };

        let results: Vec<_> =
            unsafe { vmem::virt_to_phys(&pt, 0x2000, PAGE_SIZE as u64) }.collect();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].phys_base, 0x3000);
        assert!(matches!(results[0].kind, MappingKind::Cow(_)));
    }

    #[test]
    fn map_multiple_pages_across_pd_boundary() {
        let pt = GuestPageTableBuffer::new(PT_BASE);
        // Map pages spanning a 4MB PD boundary (PD[0] -> PD[1])
        let va_start = 0x003F_F000u64; // last page of PD[0]
        let pa_start = 0x5000u64;
        let mapping = Mapping {
            phys_base: pa_start,
            virt_base: va_start,
            len: 2 * PAGE_SIZE as u64,
            kind: MappingKind::Basic(BasicMapping {
                readable: true,
                writable: false,
                executable: true,
            }),
            user_accessible: false,
        };
        unsafe { vmem::map(&pt, mapping) };

        let results: Vec<_> =
            unsafe { vmem::virt_to_phys(&pt, va_start, 2 * PAGE_SIZE as u64) }.collect();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].phys_base, pa_start);
        assert_eq!(results[0].virt_base, va_start);
        assert_eq!(results[1].phys_base, pa_start + PAGE_SIZE as u64);
        assert_eq!(results[1].virt_base, va_start + PAGE_SIZE as u64);
    }

    #[test]
    fn virt_to_phys_unmapped_returns_empty() {
        let pt = GuestPageTableBuffer::new(PT_BASE);
        let results: Vec<_> =
            unsafe { vmem::virt_to_phys(&pt, 0x1000, PAGE_SIZE as u64) }.collect();
        assert!(results.is_empty());
    }

    #[test]
    fn map_reuses_existing_page_table() {
        let pt = GuestPageTableBuffer::new(PT_BASE);
        // Map two pages in the same 4MB region (same PD entry)
        unsafe {
            vmem::map(
                &pt,
                Mapping {
                    phys_base: 0x1000,
                    virt_base: 0x1000,
                    len: PAGE_SIZE as u64,
                    kind: MappingKind::Basic(BasicMapping {
                        readable: true,
                        writable: true,
                        executable: true,
                    }),
                    user_accessible: false,
                },
            );
            vmem::map(
                &pt,
                Mapping {
                    phys_base: 0x5000,
                    virt_base: 0x5000,
                    len: PAGE_SIZE as u64,
                    kind: MappingKind::Basic(BasicMapping {
                        readable: true,
                        writable: true,
                        executable: true,
                    }),
                    user_accessible: false,
                },
            );
        }
        // Both should be visible
        let r1: Vec<_> = unsafe { vmem::virt_to_phys(&pt, 0x1000, PAGE_SIZE as u64) }.collect();
        let r2: Vec<_> = unsafe { vmem::virt_to_phys(&pt, 0x5000, PAGE_SIZE as u64) }.collect();
        assert_eq!(r1.len(), 1);
        assert_eq!(r2.len(), 1);
        assert_eq!(r1[0].phys_base, 0x1000);
        assert_eq!(r2[0].phys_base, 0x5000);
        // Should have allocated: 1 PD (pre-existing) + 1 PT = 2 pages total
        assert_eq!(pt.size(), 2 * PAGE_SIZE);
    }
}
