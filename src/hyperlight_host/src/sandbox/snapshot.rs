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

    /// The generation number assigned to this snapshot when it was
    /// taken — i.e. "this is the Nth snapshot taken from the sandbox's
    /// execution path from init to here". Propagated into the
    /// restored sandbox's guest-visible counter so the guest can tell
    /// which snapshot it is currently a clone of.
    snapshot_generation: u64,
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
            snapshot_generation: 0,
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
        snapshot_generation: u64,
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
                // Allocate one root table per space and remember the
                // addresses returned by `alloc_table` instead of
                // assuming the buffer's physical layout.
                let mut root_addrs: Vec<u64> = Vec::with_capacity(root_pt_gpas.len());
                root_addrs.push(pt_buf.initial_root());
                for _ in 1..root_pt_gpas.len() {
                    root_addrs.push(unsafe { pt_buf.alloc_table() });
                }

                let mut built_roots: BTreeMap<SpaceId, u64> = BTreeMap::new();
                for (root_idx, (space_id, mappings)) in walk.into_iter().enumerate() {
                    pt_buf.set_root(root_addrs[root_idx]);
                    built_roots.insert(space_id, root_addrs[root_idx]);

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
                for &root_addr in &root_addrs {
                    pt_buf.set_root(root_addr);
                    map_specials(&pt_buf, layout.get_scratch_size());
                }
                pt_buf.set_root(pt_buf.initial_root());

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

        // Drop the embedder-provided regions: post-compaction every
        // VA that used to map into a `map_file_cow` region has been
        // rewritten to point at the new copy inside the snapshot blob
        // (see the `guest_page` walk above). Re-mapping the originals
        // on restore is unnecessary for the translation to work and
        // actively risks corrupting the snapshot if the new snapshot
        // PAs overlap the old region PAs.
        let regions: Vec<MemoryRegion> = Vec::new();

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
            snapshot_generation,
        })
    }

    /// Generation number assigned to this snapshot when it was taken.
    pub(crate) fn snapshot_generation(&self) -> u64 {
        self.snapshot_generation
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

// --- Snapshot file format ---
//
// All multi-byte integers are little-endian. The header is zero-padded
// to 4096 bytes so the memory blob is page-aligned for direct mmap.
//
// Preamble (fixed across all format versions):
//
//   Offset  Size  Field
//   ------  ----  -----
//   0       4     Magic ("HLS\0")
//   4       4     Format version (u32: 1 = V1)
//
// V1 header (starts at offset 8):
//
//   Offset  Size  Field
//   ------  ----  -----
//   8       4     Architecture tag (u32: 1=x86_64, 2=aarch64)
//   12      4     ABI version (u32: must match SNAPSHOT_ABI_VERSION)
//   16      32    Content hash (blake3, over memory blob only)
//   48      8     stack_top_gva (u64)
//   56      8     Entrypoint tag (u64: 0=Initialise, 1=Call)
//   64      8     Entrypoint address (u64)
//   72      8     input_data_size (u64)
//   80      8     output_data_size (u64)
//   88      8     heap_size (u64)
//   96      8     code_size (u64)
//   104     8     init_data_size (u64)
//   112     8     init_data_permissions (u64: 0=None, else MemoryRegionFlags bits)
//   120     8     scratch_size (u64)
//   128     8     snapshot_size (u64)
//   136     8     pt_size (u64: 0=None)
//   144     8     memory_size (u64, byte length of memory blob)
//                   Currently derivable from layout fields, but stored
//                   explicitly for forward compatibility (e.g. compression
//                   could make the on-disk size differ from the layout size).
//   152     8     memory_offset (u64, byte offset of memory blob from file start)
//                   Currently always SNAPSHOT_HEADER_SIZE (4096), but stored
//                   explicitly so a future format version can relocate the
//                   blob (e.g. for 2 MB huge page alignment) without a
//                   breaking change.
//   160     8     has_sregs (u64: 0=no, 1=yes)
//   168     8     hypervisor_tag (u64: 1=KVM, 2=MSHV, 3=WHP)
//
// Special registers (offset 176, always written; ignored on load if has_sregs=0):
//
//   176     832   8 segment registers (cs,ds,es,fs,gs,ss,tr,ldt)
//                   each: 13 fields x u64 (base, limit, selector, type,
//                   present, dpl, db, s, l, g, avl, unusable, padding)
//   1008    32    2 table registers (gdt, idt), each: base(u64) + limit(u64)
//   1040    56    7 control values: cr0, cr2, cr3, cr4, cr8, efer, apic_base
//   1096    32    interrupt_bitmap (4 x u64)
//
// Padding and memory blob:
//
//   1128    2968  Zero padding (to align memory blob to page boundary)
//   4096    *     Memory blob (snapshot memory contents, mmap target)

const SNAPSHOT_MAGIC: &[u8; 4] = b"HLS\0";
const SNAPSHOT_HEADER_SIZE: usize = 4096;

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
const SNAPSHOT_ABI_VERSION: u32 = 1;

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
}

impl ArchTag {
    fn current() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self::X86_64
        }
        #[cfg(target_arch = "aarch64")]
        {
            Self::Aarch64
        }
    }

    fn from_u32(v: u32) -> crate::Result<Self> {
        match v {
            1 => Ok(Self::X86_64),
            2 => Ok(Self::Aarch64),
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
enum HypervisorTag {
    Kvm = 1,
    Mshv = 2,
    Whp = 3,
}

impl HypervisorTag {
    fn current() -> Option<Self> {
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

/// Memory layout fields stored in the snapshot file.
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

/// Fixed preamble at the start of every snapshot file.
/// This never changes across format versions so it can always be read
/// to determine which version-specific header follows.
struct SnapshotPreamble {
    magic: [u8; 4],
    format_version: FormatVersion,
}

/// Version-specific header content.
enum SnapshotHeader {
    V1(SnapshotHeaderV1),
}

/// V1 snapshot header.
struct SnapshotHeaderV1 {
    arch: ArchTag,
    abi_version: u32,
    hash: [u8; 32],
    stack_top_gva: u64,
    entrypoint: NextAction,
    layout: LayoutFields,
    memory_size: usize,
    memory_offset: u64,
    has_sregs: bool,
    hypervisor: HypervisorTag,
}

// --- Low-level I/O helpers ---

fn write_u32(w: &mut impl std::io::Write, v: u32) -> crate::Result<()> {
    w.write_all(&v.to_le_bytes())
        .map_err(|e| crate::new_error!("snapshot write error: {}", e))
}

fn write_u64(w: &mut impl std::io::Write, v: u64) -> crate::Result<()> {
    w.write_all(&v.to_le_bytes())
        .map_err(|e| crate::new_error!("snapshot write error: {}", e))
}

fn read_u32(r: &mut (impl std::io::Read + ?Sized)) -> crate::Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)
        .map_err(|e| crate::new_error!("snapshot read error: {}", e))?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64(r: &mut (impl std::io::Read + ?Sized)) -> crate::Result<u64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)
        .map_err(|e| crate::new_error!("snapshot read error: {}", e))?;
    Ok(u64::from_le_bytes(buf))
}

fn read_bytes<const N: usize>(r: &mut (impl std::io::Read + ?Sized)) -> crate::Result<[u8; N]> {
    let mut buf = [0u8; N];
    r.read_exact(&mut buf)
        .map_err(|e| crate::new_error!("snapshot file truncated: {}", e))?;
    Ok(buf)
}

// --- Preamble serialization ---

impl SnapshotPreamble {
    fn write_to(&self, w: &mut impl std::io::Write) -> crate::Result<()> {
        w.write_all(&self.magic)
            .map_err(|e| crate::new_error!("snapshot write error: {}", e))?;
        write_u32(w, self.format_version as u32)
    }

    fn read_from(r: &mut (impl std::io::Read + ?Sized)) -> crate::Result<Self> {
        Ok(Self {
            magic: read_bytes(r)?,
            format_version: FormatVersion::from_u32(read_u32(r)?)?,
        })
    }
}

// --- V1 header serialization ---

impl SnapshotHeaderV1 {
    fn write_to(&self, w: &mut impl std::io::Write) -> crate::Result<()> {
        write_u32(w, self.arch as u32)?;
        write_u32(w, self.abi_version)?;
        w.write_all(&self.hash)
            .map_err(|e| crate::new_error!("snapshot write error: {}", e))?;
        write_u64(w, self.stack_top_gva)?;
        let (tag, addr) = match self.entrypoint {
            NextAction::Initialise(a) => (0u64, a),
            NextAction::Call(a) => (1u64, a),
            #[cfg(test)]
            NextAction::None => (u64::MAX, 0),
        };
        write_u64(w, tag)?;
        write_u64(w, addr)?;

        // Layout fields
        let l = &self.layout;
        write_u64(w, l.input_data_size as u64)?;
        write_u64(w, l.output_data_size as u64)?;
        write_u64(w, l.heap_size as u64)?;
        write_u64(w, l.code_size as u64)?;
        write_u64(w, l.init_data_size as u64)?;
        write_u64(w, l.init_data_permissions.map_or(0, |f| f.bits() as u64))?;
        write_u64(w, l.scratch_size as u64)?;
        write_u64(w, l.snapshot_size as u64)?;
        write_u64(w, l.pt_size.map_or(0, |v| v as u64))?;

        write_u64(w, self.memory_size as u64)?;
        write_u64(w, self.memory_offset)?;
        write_u64(w, if self.has_sregs { 1 } else { 0 })?;
        write_u64(w, self.hypervisor as u64)?;
        Ok(())
    }

    fn read_from(r: &mut (impl std::io::Read + ?Sized)) -> crate::Result<Self> {
        use crate::mem::memory_region::MemoryRegionFlags;

        let arch = ArchTag::from_u32(read_u32(r)?)?;
        let abi_version = read_u32(r)?;
        let hash = read_bytes(r)?;
        let stack_top_gva = read_u64(r)?;
        let entrypoint_tag = read_u64(r)?;
        let entrypoint_addr = read_u64(r)?;
        let entrypoint = match entrypoint_tag {
            0 => NextAction::Initialise(entrypoint_addr),
            1 => NextAction::Call(entrypoint_addr),
            _ => {
                return Err(crate::new_error!(
                    "invalid entrypoint tag in snapshot: {}",
                    entrypoint_tag
                ));
            }
        };

        let input_data_size = read_u64(r)? as usize;
        let output_data_size = read_u64(r)? as usize;
        let heap_size = read_u64(r)? as usize;
        let code_size = read_u64(r)? as usize;
        let init_data_size = read_u64(r)? as usize;
        let perms_raw = read_u64(r)?;
        let init_data_permissions = if perms_raw == 0 {
            None
        } else {
            Some(
                MemoryRegionFlags::from_bits(perms_raw as u32).ok_or_else(|| {
                    crate::new_error!(
                        "snapshot contains unknown memory region flags: {:#x}",
                        perms_raw
                    )
                })?,
            )
        };
        let scratch_size = read_u64(r)? as usize;
        let snapshot_size = read_u64(r)? as usize;
        let pt_raw = read_u64(r)?;
        let pt_size = if pt_raw == 0 {
            None
        } else {
            Some(pt_raw as usize)
        };

        let memory_size = read_u64(r)? as usize;
        let memory_offset = read_u64(r)?;
        let has_sregs = read_u64(r)? != 0;
        let hypervisor = HypervisorTag::from_u64(read_u64(r)?)?;

        Ok(Self {
            arch,
            abi_version,
            hash,
            stack_top_gva,
            entrypoint,
            layout: LayoutFields {
                input_data_size,
                output_data_size,
                heap_size,
                code_size,
                init_data_size,
                init_data_permissions,
                scratch_size,
                snapshot_size,
                pt_size,
            },
            memory_size,
            memory_offset,
            has_sregs,
            hypervisor,
        })
    }
}

fn write_sregs(w: &mut impl std::io::Write, sregs: &CommonSpecialRegisters) -> crate::Result<()> {
    // Segment registers: cs, ds, es, fs, gs, ss, tr, ldt (13 fields each)
    for seg in [
        &sregs.cs, &sregs.ds, &sregs.es, &sregs.fs, &sregs.gs, &sregs.ss, &sregs.tr, &sregs.ldt,
    ] {
        for v in [
            seg.base,
            seg.limit as u64,
            seg.selector as u64,
            seg.type_ as u64,
            seg.present as u64,
            seg.dpl as u64,
            seg.db as u64,
            seg.s as u64,
            seg.l as u64,
            seg.g as u64,
            seg.avl as u64,
            seg.unusable as u64,
            seg.padding as u64,
        ] {
            write_u64(w, v)?;
        }
    }
    // Table registers: gdt, idt (2 fields each)
    for tab in [&sregs.gdt, &sregs.idt] {
        write_u64(w, tab.base)?;
        write_u64(w, tab.limit as u64)?;
    }
    // Control registers + bitmap
    for v in [
        sregs.cr0,
        sregs.cr2,
        sregs.cr3,
        sregs.cr4,
        sregs.cr8,
        sregs.efer,
        sregs.apic_base,
    ] {
        write_u64(w, v)?;
    }
    for &v in &sregs.interrupt_bitmap {
        write_u64(w, v)?;
    }
    Ok(())
}

fn read_sregs(r: &mut impl std::io::Read) -> crate::Result<CommonSpecialRegisters> {
    use crate::hypervisor::regs::{CommonSegmentRegister, CommonTableRegister};

    let read_seg = |r: &mut dyn std::io::Read| -> crate::Result<CommonSegmentRegister> {
        Ok(CommonSegmentRegister {
            base: read_u64(r)?,
            limit: read_u64(r)? as u32,
            selector: read_u64(r)? as u16,
            type_: read_u64(r)? as u8,
            present: read_u64(r)? as u8,
            dpl: read_u64(r)? as u8,
            db: read_u64(r)? as u8,
            s: read_u64(r)? as u8,
            l: read_u64(r)? as u8,
            g: read_u64(r)? as u8,
            avl: read_u64(r)? as u8,
            unusable: read_u64(r)? as u8,
            padding: read_u64(r)? as u8,
        })
    };
    let read_tab = |r: &mut dyn std::io::Read| -> crate::Result<CommonTableRegister> {
        Ok(CommonTableRegister {
            base: read_u64(r)?,
            limit: read_u64(r)? as u16,
        })
    };
    Ok(CommonSpecialRegisters {
        cs: read_seg(r)?,
        ds: read_seg(r)?,
        es: read_seg(r)?,
        fs: read_seg(r)?,
        gs: read_seg(r)?,
        ss: read_seg(r)?,
        tr: read_seg(r)?,
        ldt: read_seg(r)?,
        gdt: read_tab(r)?,
        idt: read_tab(r)?,
        cr0: read_u64(r)?,
        cr2: read_u64(r)?,
        cr3: read_u64(r)?,
        cr4: read_u64(r)?,
        cr8: read_u64(r)?,
        efer: read_u64(r)?,
        apic_base: read_u64(r)?,
        interrupt_bitmap: [read_u64(r)?, read_u64(r)?, read_u64(r)?, read_u64(r)?],
    })
}

impl Snapshot {
    /// Save this snapshot to a file on disk.
    ///
    /// The file format uses a page-aligned memory blob that can be
    /// mmapped directly on load for zero-copy instantiation.
    ///
    /// Note: extra memory regions added via
    /// [`map_region`](crate::MultiUseSandbox::map_region) or
    /// [`map_file_cow`](crate::MultiUseSandbox::map_file_cow) are
    /// **not** persisted. Only the primary sandbox memory is saved.
    /// Regions that were folded into the snapshot memory (by taking
    /// a snapshot after mapping) are included since they become part
    /// of the memory blob.
    pub fn to_file(&self, path: impl AsRef<std::path::Path>) -> crate::Result<()> {
        use std::io::{BufWriter, Write};

        let file = std::fs::File::create(path.as_ref())
            .map_err(|e| crate::new_error!("failed to create snapshot file: {}", e))?;
        let mut w = BufWriter::new(file);

        let layout = &self.layout;

        let preamble = SnapshotPreamble {
            magic: *SNAPSHOT_MAGIC,
            format_version: FormatVersion::V1,
        };

        let v1 = SnapshotHeaderV1 {
            arch: ArchTag::current(),
            abi_version: SNAPSHOT_ABI_VERSION,
            hash: self.hash,
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
            memory_offset: SNAPSHOT_HEADER_SIZE as u64,
            has_sregs: self.sregs.is_some(),
            hypervisor: HypervisorTag::current()
                .ok_or_else(|| crate::new_error!("no hypervisor available to tag snapshot"))?,
        };

        preamble.write_to(&mut w)?;
        v1.write_to(&mut w)?;
        write_sregs(&mut w, &self.sregs.unwrap_or_default())?;

        // Pad header to SNAPSHOT_HEADER_SIZE and write memory blob
        // Use a Cursor to track position instead of manual size calculation
        let pos = std::io::Seek::stream_position(&mut w)
            .map_err(|e| crate::new_error!("snapshot seek error: {}", e))?
            as usize;
        if pos > SNAPSHOT_HEADER_SIZE {
            return Err(crate::new_error!(
                "snapshot header exceeded {} bytes (wrote {})",
                SNAPSHOT_HEADER_SIZE,
                pos
            ));
        }
        w.write_all(&vec![0u8; SNAPSHOT_HEADER_SIZE - pos])
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
    /// Note: ELF unwind info (`LoadInfo`) is not persisted in the
    /// snapshot file, so the `mem_profile` feature will not have
    /// accurate profiling data for sandboxes created from disk
    /// snapshots.
    pub fn from_file(path: impl AsRef<std::path::Path>) -> crate::Result<Self> {
        Self::from_file_impl(path, true)
    }

    /// Load a snapshot from a file on disk without verifying the
    /// content hash. This is faster for large snapshots in trusted
    /// environments where file integrity is guaranteed by other means.
    pub fn from_file_unchecked(path: impl AsRef<std::path::Path>) -> crate::Result<Self> {
        Self::from_file_impl(path, false)
    }

    fn from_file_impl(path: impl AsRef<std::path::Path>, verify_hash: bool) -> crate::Result<Self> {
        use std::io::BufReader;

        let file = std::fs::File::open(path.as_ref())
            .map_err(|e| crate::new_error!("failed to open snapshot file: {}", e))?;
        let mut r = BufReader::new(&file);

        // Read preamble first to determine version
        let preamble = SnapshotPreamble::read_from(&mut r)?;
        if &preamble.magic != SNAPSHOT_MAGIC {
            return Err(crate::new_error!(
                "invalid snapshot file: bad magic bytes (expected {:?}, got {:?})",
                SNAPSHOT_MAGIC,
                preamble.magic
            ));
        }

        // Dispatch to version-specific reader
        let header = match preamble.format_version {
            FormatVersion::V1 => SnapshotHeader::V1(SnapshotHeaderV1::read_from(&mut r)?),
        };

        let SnapshotHeader::V1(hdr) = header;

        // Validate
        if hdr.arch != ArchTag::current() {
            return Err(crate::new_error!(
                "snapshot architecture mismatch: expected {:?}, got {:?}",
                ArchTag::current(),
                hdr.arch
            ));
        }
        if hdr.abi_version != SNAPSHOT_ABI_VERSION {
            return Err(crate::new_error!(
                "snapshot ABI version mismatch: file has ABI version {}, \
                 but this build expects {}. The snapshot must be regenerated \
                 from the guest binary.",
                hdr.abi_version,
                SNAPSHOT_ABI_VERSION
            ));
        }
        let current_hv = HypervisorTag::current()
            .ok_or_else(|| crate::new_error!("no hypervisor available to load snapshot"))?;
        if hdr.hypervisor != current_hv {
            return Err(crate::new_error!(
                "snapshot hypervisor mismatch: file was created on {} but the current hypervisor is {}.",
                hdr.hypervisor.name(),
                current_hv.name()
            ));
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
        layout.set_snapshot_size(l.snapshot_size);
        if let Some(pt) = l.pt_size {
            layout.set_pt_size(pt)?;
        }

        // Read sregs
        let sregs_data = read_sregs(&mut r)?;
        let sregs = if hdr.has_sregs {
            Some(sregs_data)
        } else {
            None
        };

        // Map the memory blob directly from the file (zero-copy CoW)
        let memory = ReadonlySharedMemory::from_file(&file, hdr.memory_offset, hdr.memory_size)?;

        // Verify hash
        if verify_hash {
            let computed: [u8; 32] = blake3::hash(memory.as_slice()).into();
            if computed != hdr.hash {
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
            hash: hdr.hash,
            stack_top_gva: hdr.stack_top_gva,
            sregs,
            entrypoint: hdr.entrypoint,
            snapshot_generation: 0,
        })
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
            1,
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
            2,
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

#[cfg(test)]
mod snapshot_file_tests {
    use std::sync::Arc;

    use hyperlight_testing::simple_guest_as_string;

    use crate::sandbox::snapshot::Snapshot;
    use crate::{GuestBinary, MultiUseSandbox, UninitializedSandbox};

    fn create_test_sandbox() -> MultiUseSandbox {
        let path = simple_guest_as_string().unwrap();
        UninitializedSandbox::new(GuestBinary::FilePath(path), None)
            .unwrap()
            .evolve()
            .unwrap()
    }

    fn create_snapshot_from_binary() -> Snapshot {
        let path = simple_guest_as_string().unwrap();
        Snapshot::from_env(
            GuestBinary::FilePath(path),
            crate::sandbox::SandboxConfiguration::default(),
        )
        .unwrap()
    }

    #[test]
    fn from_snapshot_already_initialized_in_memory() {
        // Test from_snapshot with a snapshot taken from an already-initialized
        // sandbox (NextAction::Call), directly from memory without file I/O
        let mut sbox = create_test_sandbox();
        let snapshot = sbox.snapshot().unwrap();

        let new_snap = Snapshot {
            sandbox_id: super::SANDBOX_CONFIGURATION_COUNTER
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            layout: *snapshot.layout(),
            memory: snapshot.memory().clone(),
            regions: snapshot.regions().to_vec(),
            load_info: snapshot.load_info(),
            hash: snapshot.hash,
            stack_top_gva: snapshot.stack_top_gva(),
            sregs: snapshot.sregs().cloned(),
            entrypoint: snapshot.entrypoint(),
        };

        let mut sbox2 = MultiUseSandbox::from_snapshot(Arc::new(new_snap)).unwrap();
        let result: i32 = sbox2.call("GetStatic", ()).unwrap();
        assert_eq!(result, 0);
    }

    #[test]
    fn from_snapshot_in_memory() {
        // Test from_snapshot pathway using the existing Snapshot::from_env
        let path = simple_guest_as_string().unwrap();
        let snap = Snapshot::from_env(
            GuestBinary::FilePath(path),
            crate::sandbox::SandboxConfiguration::default(),
        )
        .unwrap();

        let mut sbox = MultiUseSandbox::from_snapshot(Arc::new(snap)).unwrap();

        // from_env creates a snapshot with NextAction::Initialise,
        // so from_snapshot will run the init code via vm.initialise()
        let result: i32 = sbox.call("GetStatic", ()).unwrap();
        assert_eq!(result, 0);
    }

    #[test]
    fn round_trip_save_load_call() {
        let mut sbox = create_test_sandbox();
        let snapshot = sbox.snapshot().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let snap_path = dir.path().join("test.hls");
        snapshot.to_file(&snap_path).unwrap();

        let loaded = Snapshot::from_file(&snap_path).unwrap();
        let mut sbox2 = MultiUseSandbox::from_snapshot(Arc::new(loaded)).unwrap();

        let result: String = sbox2.call("Echo", "hello\n".to_string()).unwrap();
        assert_eq!(result, "hello\n");
    }

    #[test]
    fn hash_verification_detects_corruption() {
        let snapshot = create_snapshot_from_binary();

        let dir = tempfile::tempdir().unwrap();
        let snap_path = dir.path().join("corrupted.hls");
        snapshot.to_file(&snap_path).unwrap();

        // Corrupt a byte in the memory blob (after the 4096-byte header)
        {
            use std::io::{Read, Seek, SeekFrom, Write};
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&snap_path)
                .unwrap();
            file.seek(SeekFrom::Start(4096 + 100)).unwrap();
            let mut byte = [0u8; 1];
            file.read_exact(&mut byte).unwrap();
            byte[0] ^= 0xFF;
            file.seek(SeekFrom::Start(4096 + 100)).unwrap();
            file.write_all(&byte).unwrap();
        }

        let result = Snapshot::from_file(&snap_path);
        let err_msg = match result {
            Err(e) => format!("{}", e),
            Ok(_) => panic!("expected load to fail with hash mismatch"),
        };
        assert!(
            err_msg.contains("hash mismatch"),
            "expected hash mismatch error, got: {}",
            err_msg
        );
    }

    #[test]
    fn arch_mismatch_rejected() {
        let snapshot = create_snapshot_from_binary();

        let dir = tempfile::tempdir().unwrap();
        let snap_path = dir.path().join("wrong_arch.hls");
        snapshot.to_file(&snap_path).unwrap();

        // Overwrite the architecture tag (offset 8, 4 bytes)
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&snap_path)
                .unwrap();
            file.seek(SeekFrom::Start(8)).unwrap();
            file.write_all(&99u32.to_le_bytes()).unwrap();
        }

        let result = Snapshot::from_file(&snap_path);
        let err_msg = match result {
            Err(e) => format!("{}", e),
            Ok(_) => panic!("expected load to fail with arch mismatch"),
        };
        assert!(
            err_msg.contains("architecture"),
            "expected arch-related error, got: {}",
            err_msg
        );
    }

    #[test]
    fn format_version_mismatch_rejected() {
        let snapshot = create_snapshot_from_binary();

        let dir = tempfile::tempdir().unwrap();
        let snap_path = dir.path().join("wrong_version.hls");
        snapshot.to_file(&snap_path).unwrap();

        // Overwrite the format version (offset 4, 4 bytes)
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&snap_path)
                .unwrap();
            file.seek(SeekFrom::Start(4)).unwrap();
            file.write_all(&999u32.to_le_bytes()).unwrap();
        }

        let result = Snapshot::from_file(&snap_path);
        let err_msg = match result {
            Err(e) => format!("{}", e),
            Ok(_) => panic!("expected load to fail with version mismatch"),
        };
        assert!(
            err_msg.contains("format version"),
            "expected version mismatch error, got: {}",
            err_msg
        );
        assert!(
            err_msg.contains("convertible"),
            "expected hint about convertibility, got: {}",
            err_msg
        );
    }

    #[test]
    fn abi_version_mismatch_rejected() {
        let snapshot = create_snapshot_from_binary();

        let dir = tempfile::tempdir().unwrap();
        let snap_path = dir.path().join("wrong_abi.hls");
        snapshot.to_file(&snap_path).unwrap();

        // Overwrite the ABI version (offset 12, 4 bytes)
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&snap_path)
                .unwrap();
            file.seek(SeekFrom::Start(12)).unwrap();
            file.write_all(&999u32.to_le_bytes()).unwrap();
        }

        let result = Snapshot::from_file(&snap_path);
        let err_msg = match result {
            Err(e) => format!("{}", e),
            Ok(_) => panic!("expected load to fail with ABI version mismatch"),
        };
        assert!(
            err_msg.contains("ABI version mismatch"),
            "expected ABI version mismatch error, got: {}",
            err_msg
        );
        assert!(
            err_msg.contains("regenerated"),
            "expected hint about regeneration, got: {}",
            err_msg
        );
    }

    #[test]
    fn hypervisor_mismatch_rejected() {
        let snapshot = create_snapshot_from_binary();

        let dir = tempfile::tempdir().unwrap();
        let snap_path = dir.path().join("wrong_hv.hls");
        snapshot.to_file(&snap_path).unwrap();

        // Overwrite the hypervisor tag (offset 168, 8 bytes) with a
        // valid but wrong hypervisor tag.
        use super::HypervisorTag;
        let current = HypervisorTag::current().unwrap();
        let wrong_tag = match current {
            HypervisorTag::Whp => HypervisorTag::Kvm,
            _ => HypervisorTag::Whp,
        };
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&snap_path)
                .unwrap();
            file.seek(SeekFrom::Start(168)).unwrap();
            file.write_all(&(wrong_tag as u64).to_le_bytes()).unwrap();
        }

        let result = Snapshot::from_file(&snap_path);
        let err_msg = match result {
            Err(e) => format!("{}", e),
            Ok(_) => panic!("expected load to fail with hypervisor mismatch"),
        };
        assert!(
            err_msg.contains("hypervisor mismatch"),
            "expected hypervisor mismatch error, got: {}",
            err_msg
        );
    }

    #[test]
    fn restore_from_loaded_snapshot() {
        let mut sbox = create_test_sandbox();
        let snapshot = sbox.snapshot().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let snap_path = dir.path().join("restore.hls");
        snapshot.to_file(&snap_path).unwrap();

        let loaded = Snapshot::from_file(&snap_path).unwrap();
        let mut sbox = MultiUseSandbox::from_snapshot(Arc::new(loaded)).unwrap();

        // Mutate state
        sbox.call::<i32>("AddToStatic", 42i32).unwrap();
        let val: i32 = sbox.call("GetStatic", ()).unwrap();
        assert_eq!(val, 42);

        // Take a new snapshot and restore to it
        let snap2 = sbox.snapshot().unwrap();
        sbox.call::<i32>("AddToStatic", 10i32).unwrap();
        let val: i32 = sbox.call("GetStatic", ()).unwrap();
        assert_eq!(val, 52);

        sbox.restore(snap2).unwrap();
        let val: i32 = sbox.call("GetStatic", ()).unwrap();
        assert_eq!(val, 42);
    }

    #[test]
    fn multiple_sandboxes_from_same_file() {
        let mut sbox = create_test_sandbox();
        let snapshot = sbox.snapshot().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let snap_path = dir.path().join("shared.hls");
        snapshot.to_file(&snap_path).unwrap();

        let loaded1 = Snapshot::from_file(&snap_path).unwrap();
        let loaded2 = Snapshot::from_file(&snap_path).unwrap();

        let mut sbox1 = MultiUseSandbox::from_snapshot(Arc::new(loaded1)).unwrap();
        let mut sbox2 = MultiUseSandbox::from_snapshot(Arc::new(loaded2)).unwrap();

        // Mutate one, verify the other is unaffected
        sbox1.call::<i32>("AddToStatic", 100i32).unwrap();
        let val1: i32 = sbox1.call("GetStatic", ()).unwrap();
        let val2: i32 = sbox2.call("GetStatic", ()).unwrap();
        assert_eq!(val1, 100);
        assert_eq!(val2, 0);
    }

    #[test]
    fn snapshot_then_save_round_trip() {
        let mut sbox = create_test_sandbox();
        let snapshot = sbox.snapshot().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let snap_path1 = dir.path().join("first.hls");
        snapshot.to_file(&snap_path1).unwrap();

        // Load, create sandbox, mutate, take snapshot, save again
        let loaded = Snapshot::from_file(&snap_path1).unwrap();
        let mut sbox2 = MultiUseSandbox::from_snapshot(Arc::new(loaded)).unwrap();

        sbox2.call::<i32>("AddToStatic", 77i32).unwrap();
        let snap2 = sbox2.snapshot().unwrap();

        let snap_path2 = dir.path().join("second.hls");
        snap2.to_file(&snap_path2).unwrap();

        // Load the second snapshot and verify mutated state
        let loaded2 = Snapshot::from_file(&snap_path2).unwrap();
        let mut sbox3 = MultiUseSandbox::from_snapshot(Arc::new(loaded2)).unwrap();

        let val: i32 = sbox3.call("GetStatic", ()).unwrap();
        assert_eq!(val, 77);
    }

    /// `MultiUseSandbox::from_snapshot` should register the default
    /// `HostPrint` host function, just like the regular codepath.
    #[test]
    fn from_snapshot_has_default_host_print() {
        let mut sbox = create_test_sandbox();
        let snapshot = sbox.snapshot().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let snap_path = dir.path().join("test.hls");
        snapshot.to_file(&snap_path).unwrap();

        let loaded = Snapshot::from_file(&snap_path).unwrap();
        let mut sbox2 = MultiUseSandbox::from_snapshot(Arc::new(loaded)).unwrap();

        let result = sbox2.call::<i32>("PrintOutput", "hello from snapshot".to_string());
        assert!(
            result.is_ok(),
            "PrintOutput should succeed because HostPrint is registered by from_snapshot: {:?}",
            result.unwrap_err()
        );
    }

    #[test]
    fn from_file_unchecked_skips_hash_verification() {
        let mut sbox = create_test_sandbox();
        let snapshot = sbox.snapshot().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let snap_path = dir.path().join("unchecked.hls");
        snapshot.to_file(&snap_path).unwrap();

        // Corrupt a byte in the memory blob (past the header)
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&snap_path)
                .unwrap();
            // Write garbage into the memory blob region
            file.seek(SeekFrom::Start(4096 + 64)).unwrap();
            file.write_all(&[0xFF; 16]).unwrap();
        }

        // from_file (with hash check) should fail
        let result = Snapshot::from_file(&snap_path);
        assert!(result.is_err(), "from_file should detect corruption");

        // from_file_unchecked should succeed despite corruption
        let loaded = Snapshot::from_file_unchecked(&snap_path);
        assert!(loaded.is_ok(), "from_file_unchecked should skip hash check");
    }
}
