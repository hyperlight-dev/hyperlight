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

use std::sync::atomic::{AtomicU64, Ordering};

use hyperlight_common::layout::scratch_base_gva;
#[cfg(not(feature = "i686-guest"))]
use hyperlight_common::vmem;
#[cfg(feature = "i686-guest")]
use hyperlight_common::vmem::TableOps;
use hyperlight_common::vmem::{BasicMapping, CowMapping, Mapping, MappingKind, PAGE_SIZE};
use tracing::{Span, instrument};

use crate::HyperlightError::MemoryRegionSizeMismatch;
use crate::Result;
use crate::hypervisor::regs::CommonSpecialRegisters;
use crate::mem::exe::LoadInfo;
use crate::mem::layout::SandboxMemoryLayout;
use crate::mem::memory_region::MemoryRegion;
use crate::mem::mgr::{GuestPageTableBuffer, SnapshotSharedMemory};
use crate::mem::shared_mem::{ReadonlySharedMemory, SharedMemory};
use crate::sandbox::SandboxConfiguration;
use crate::sandbox::uninitialized::{GuestBinary, GuestEnvironment};

pub(super) static SANDBOX_CONFIGURATION_COUNTER: AtomicU64 = AtomicU64::new(0);

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
    /// Separate PT storage for i686 snapshots. On x86_64, PTs are
    /// appended to `memory` and the snapshot region's GPA range grows
    /// to include them. On i686, that would cause the snapshot KVM
    /// memory slot to overlap with map_file_cow regions (e.g. RAMFS)
    /// placed at GPAs just above the original snapshot end. Storing
    /// PTs separately avoids the conflict; they are copied directly
    /// to scratch during restore.
    #[cfg(feature = "i686-guest")]
    separate_pt_bytes: Vec<u8>,
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
    unsafe fn read_entry(&self, addr: u64) -> u64 {
        let addr = addr as usize;
        let Some(pte_bytes) = self.memory.as_slice().get(addr..addr + 8) else {
            // Attacker-controlled data pointed out-of-bounds. We'll
            // default to returning 0 in this case, which, for most
            // architectures (including x86-64 and arm64, the ones we
            // care about presently) will be a not-present entry.
            return 0;
        };
        // this is statically the correct size, so using unwrap() here
        // doesn't make this any more panic-y.
        #[allow(clippy::unwrap_used)]
        let n: [u8; 8] = pte_bytes.try_into().unwrap();
        u64::from_ne_bytes(n)
    }
    fn to_phys(addr: u64) -> u64 {
        addr
    }
    fn from_phys(addr: u64) -> u64 {
        addr
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
    /// CoW resolution map: maps snapshot GPAs to their CoW'd scratch GPAs.
    /// Built by walking the kernel PD to find pages that were CoW'd during boot.
    #[cfg(feature = "i686-guest")]
    cow_map: Option<&'a std::collections::HashMap<u64, u64>>,
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
            #[cfg(feature = "i686-guest")]
            cow_map: None,
        }
    }

    #[cfg(feature = "i686-guest")]
    fn with_cow_map(mut self, cow_map: &'a std::collections::HashMap<u64, u64>) -> Self {
        self.cow_map = Some(cow_map);
        self
    }
}
impl<'a> hyperlight_common::vmem::TableReadOps for SharedMemoryPageTableBuffer<'a> {
    type TableAddr = u64;
    fn entry_addr(addr: u64, offset: u64) -> u64 {
        addr + offset
    }
    unsafe fn read_entry(&self, addr: u64) -> u64 {
        // For i686: if the GPA was CoW'd, read from the scratch copy instead.
        #[cfg(feature = "i686-guest")]
        let addr = {
            let page_gpa = addr & 0xFFFFF000;
            if let Some(map) = self.cow_map {
                if let Some(&scratch_gpa) = map.get(&page_gpa) {
                    scratch_gpa + (addr & 0xFFF)
                } else {
                    addr
                }
            } else {
                addr
            }
        };
        let memoff = access_gpa(self.snap, self.scratch, self.layout, addr);
        // For i686 guests, page table entries are 4 bytes; for x86_64 they
        // are 8 bytes. Read the correct size based on the feature flag.
        #[cfg(feature = "i686-guest")]
        {
            let Some(pte_bytes) = memoff.and_then(|(mem, off)| mem.get(off..off + 4)) else {
                // Out-of-bounds: return 0, which is a not-present entry.
                return 0;
            };
            #[allow(clippy::unwrap_used)]
            let n: [u8; 4] = pte_bytes.try_into().unwrap();
            // Page-table entries are little-endian by arch spec;
            // use `from_le_bytes` so host endianness doesn't leak in.
            u32::from_le_bytes(n) as u64
        }
        #[cfg(not(feature = "i686-guest"))]
        {
            let Some(pte_bytes) = memoff.and_then(|(mem, off)| mem.get(off..off + 8)) else {
                // Attacker-controlled data pointed out-of-bounds. We'll
                // default to returning 0 in this case, which, for most
                // architectures (including x86-64 and arm64, the ones we
                // care about presently) will be a not-present entry.
                return 0;
            };
            // this is statically the correct size, so using unwrap() here
            // doesn't make this any more panic-y.
            #[allow(clippy::unwrap_used)]
            let n: [u8; 8] = pte_bytes.try_into().unwrap();
            u64::from_ne_bytes(n)
        }
    }
    fn to_phys(addr: u64) -> u64 {
        addr
    }
    fn from_phys(addr: u64) -> u64 {
        addr
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

/// Build a CoW resolution map by walking a kernel PD.
/// For each PTE that maps a VA in [0, MEMORY_SIZE) to a PA in scratch,
/// record: original_gpa -> scratch_gpa.
#[cfg(feature = "i686-guest")]
fn build_cow_map(
    snap: &[u8],
    scratch: &[u8],
    layout: SandboxMemoryLayout,
    kernel_root: u64,
) -> crate::Result<std::collections::HashMap<u64, u64>> {
    use hyperlight_common::layout::scratch_base_gpa;
    let mut cow_map = std::collections::HashMap::new();
    let scratch_base = scratch_base_gpa(layout.get_scratch_size());
    let scratch_end = scratch_base + layout.get_scratch_size() as u64;
    let mem_size = layout.get_memory_size()? as u64;

    let op = SharedMemoryPageTableBuffer::new(snap, scratch, layout, kernel_root);
    let mappings = unsafe {
        hyperlight_common::vmem::i686_guest::virt_to_phys(
            &op,
            0,
            hyperlight_common::layout::MAX_GVA as u64,
        )
    };
    for m in mappings {
        if m.virt_base < mem_size && m.phys_base >= scratch_base && m.phys_base < scratch_end {
            cow_map.insert(m.virt_base, m.phys_base);
        }
    }
    Ok(cow_map)
}

/// On i686, PDE index where user-space begins. Kernel occupies PDEs
/// 0..256 (VA 0x00000000..0x40000000), user-space occupies 256+.
#[cfg(feature = "i686-guest")]
const I686_USER_PDE_START: usize = 256;

/// On i686, VA where user-space begins (derived from [`I686_USER_PDE_START`]).
#[cfg(feature = "i686-guest")]
const I686_USER_VA_START: u64 = (I686_USER_PDE_START as u64) << 22;

/// Convert a snapshot mapping kind for compaction: writable pages
/// become CoW, read-only pages stay read-only.
fn compaction_kind(kind: &MappingKind) -> MappingKind {
    match kind {
        MappingKind::Cow(cm) => MappingKind::Cow(*cm),
        MappingKind::Basic(bm) if bm.writable => MappingKind::Cow(CowMapping {
            readable: bm.readable,
            executable: bm.executable,
        }),
        MappingKind::Basic(bm) => MappingKind::Basic(BasicMapping {
            readable: bm.readable,
            writable: false,
            executable: bm.executable,
        }),
        MappingKind::Unmapped => MappingKind::Unmapped,
    }
}

fn filtered_mappings<'a>(
    snap: &'a [u8],
    scratch: &'a [u8],
    regions: &[MemoryRegion],
    layout: SandboxMemoryLayout,
    root_pts: &[u64],
    #[cfg(feature = "i686-guest")] cow_map: &std::collections::HashMap<u64, u64>,
) -> Vec<(usize, Mapping, &'a [u8])> {
    use std::collections::HashSet;
    let mut all_mappings = Vec::new();
    let mut seen_phys = HashSet::new();
    let scratch_gva = scratch_base_gva(layout.get_scratch_size());

    #[cfg_attr(not(feature = "i686-guest"), allow(unused_variables))]
    for (root_idx, &root_pt) in root_pts.iter().enumerate() {
        #[cfg(feature = "i686-guest")]
        let op =
            SharedMemoryPageTableBuffer::new(snap, scratch, layout, root_pt).with_cow_map(cow_map);
        #[cfg(not(feature = "i686-guest"))]
        let op = SharedMemoryPageTableBuffer::new(snap, scratch, layout, root_pt);

        #[cfg(not(feature = "i686-guest"))]
        let iter = unsafe {
            hyperlight_common::vmem::virt_to_phys(&op, 0, hyperlight_common::layout::MAX_GVA as u64)
        };
        #[cfg(feature = "i686-guest")]
        let iter = unsafe {
            hyperlight_common::vmem::i686_guest::virt_to_phys(
                &op,
                0,
                hyperlight_common::layout::MAX_GVA as u64,
            )
        };

        for m in iter {
            if m.virt_base >= scratch_gva {
                continue;
            }
            #[cfg(not(feature = "i686-guest"))]
            if m.virt_base >= hyperlight_common::layout::SNAPSHOT_PT_GVA_MIN as u64
                && m.virt_base <= hyperlight_common::layout::SNAPSHOT_PT_GVA_MAX as u64
            {
                continue;
            }
            // On i686, kernel pages (shared across roots) are only
            // collected from root 0. User pages are collected per-root
            // with their root index for per-process PD isolation.
            #[cfg(feature = "i686-guest")]
            let effective_root = if m.virt_base < I686_USER_VA_START {
                if root_idx != 0 {
                    continue;
                }
                0
            } else {
                root_idx
            };
            #[cfg(not(feature = "i686-guest"))]
            let effective_root = 0;

            if seen_phys.insert(m.phys_base) {
                all_mappings.push((effective_root, m));
            }
        }
    }

    all_mappings
        .into_iter()
        .filter_map(move |(root_idx, mapping)| {
            let contents =
                unsafe { guest_page(snap, scratch, regions, layout, mapping.phys_base) }?;
            Some((root_idx, mapping, contents))
        })
        .collect()
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

        use crate::mem::exe::ExeInfo;
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

        #[cfg(not(feature = "i686-guest"))]
        use hyperlight_common::vmem;

        {
            use hyperlight_common::layout::scratch_base_gpa;

            use crate::mem::memory_region::{GuestMemoryRegion, MemoryRegionFlags};
            use crate::mem::mgr::GuestPageTableBuffer;

            #[cfg(not(feature = "i686-guest"))]
            let pt_buf = GuestPageTableBuffer::<8>::new(layout.get_pt_base_gpa() as usize);
            #[cfg(feature = "i686-guest")]
            let pt_buf = GuestPageTableBuffer::<4>::new(layout.get_pt_base_gpa() as usize);

            // Map snapshot memory regions (writable -> CoW, read-only -> Basic)
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
                unsafe {
                    #[cfg(not(feature = "i686-guest"))]
                    vmem::map(&pt_buf, mapping);
                    #[cfg(feature = "i686-guest")]
                    hyperlight_common::vmem::i686_guest::map(&pt_buf, mapping);
                }
            }

            // Map the scratch region
            let scratch_mapping = Mapping {
                phys_base: scratch_base_gpa(layout.get_scratch_size()),
                virt_base: scratch_base_gva(layout.get_scratch_size()),
                len: layout.get_scratch_size() as u64,
                kind: MappingKind::Basic(BasicMapping {
                    readable: true,
                    writable: true,
                    executable: false,
                }),
            };
            unsafe {
                #[cfg(not(feature = "i686-guest"))]
                vmem::map(&pt_buf, scratch_mapping);
                #[cfg(feature = "i686-guest")]
                hyperlight_common::vmem::i686_guest::map(&pt_buf, scratch_mapping);
            }

            let pt_bytes = pt_buf.into_bytes();
            layout.set_pt_size(pt_bytes.len())?;
            memory.extend(&pt_bytes);
        };

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
            #[cfg(feature = "i686-guest")]
            separate_pt_bytes: Vec::new(),
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
        use std::collections::HashMap;
        let mut phys_seen = HashMap::<u64, usize>::new();
        let memory = shared_mem.with_contents(|snap_c| {
            scratch_mem.with_contents(|scratch_c| {
                // Phase 0 (i686 only): build a CoW resolution map so the
                // PT walker reads CoW'd pages from scratch, not stale
                // snapshot copies.
                #[cfg(feature = "i686-guest")]
                let cow_map = {
                    let kernel_root = root_pt_gpas.first().copied().ok_or_else(|| {
                        crate::new_error!("snapshot requires at least one page directory root")
                    })?;
                    build_cow_map(snap_c, scratch_c, layout, kernel_root)?
                };

                // Phase 1: walk every PT root and collect live pages,
                // tagged with which root they belong to (for per-process
                // PD isolation on i686).
                let live_pages = filtered_mappings(
                    snap_c,
                    scratch_c,
                    &regions,
                    layout,
                    root_pt_gpas,
                    #[cfg(feature = "i686-guest")]
                    &cow_map,
                );

                // Phase 2: compact live pages into a dense snapshot blob
                // and build new page tables with compacted GPAs.
                // TODO: Look for opportunities to hugepage map
                let mut snapshot_memory: Vec<u8> = Vec::new();
                #[cfg(not(feature = "i686-guest"))]
                let pt_buf = GuestPageTableBuffer::<8>::new(layout.get_pt_base_gpa() as usize);
                #[cfg(feature = "i686-guest")]
                let pt_buf = {
                    let buf = GuestPageTableBuffer::<4>::new(layout.get_pt_base_gpa() as usize);
                    for _ in 1..root_pt_gpas.len() {
                        unsafe { buf.alloc_table() };
                    }
                    buf
                };

                for (_root_idx, mapping, contents) in live_pages {
                    let kind = compaction_kind(&mapping.kind);
                    if matches!(kind, MappingKind::Unmapped) {
                        continue;
                    }
                    let new_gpa = phys_seen.entry(mapping.phys_base).or_insert_with(|| {
                        let new_offset = snapshot_memory.len();
                        snapshot_memory.extend(contents);
                        new_offset + SandboxMemoryLayout::BASE_ADDRESS
                    });

                    #[cfg(feature = "i686-guest")]
                    pt_buf.set_root_offset(_root_idx * PAGE_SIZE);

                    let new_mapping = Mapping {
                        phys_base: *new_gpa as u64,
                        virt_base: mapping.virt_base,
                        len: PAGE_SIZE as u64,
                        kind,
                    };
                    unsafe {
                        #[cfg(not(feature = "i686-guest"))]
                        vmem::map(&pt_buf, new_mapping);
                        #[cfg(feature = "i686-guest")]
                        hyperlight_common::vmem::i686_guest::map(&pt_buf, new_mapping);
                    }
                }
                #[cfg(feature = "i686-guest")]
                pt_buf.set_root_offset(0);

                // Phase 3: map the scratch region into the page tables.
                let scratch_gpa =
                    hyperlight_common::layout::scratch_base_gpa(layout.get_scratch_size());
                let scratch_gva = scratch_base_gva(layout.get_scratch_size());
                let scratch_len = layout.get_scratch_size() as u64;
                unsafe {
                    #[cfg(not(feature = "i686-guest"))]
                    vmem::map(
                        &pt_buf,
                        Mapping {
                            phys_base: scratch_gpa,
                            virt_base: scratch_gva,
                            len: scratch_len,
                            kind: MappingKind::Basic(BasicMapping {
                                readable: true,
                                writable: true,
                                executable: false,
                            }),
                        },
                    );
                    #[cfg(feature = "i686-guest")]
                    hyperlight_common::vmem::i686_guest::map(
                        &pt_buf,
                        Mapping {
                            phys_base: scratch_gpa,
                            virt_base: scratch_gva,
                            len: scratch_len,
                            kind: MappingKind::Basic(BasicMapping {
                                readable: true,
                                writable: true,
                                executable: false,
                            }),
                        },
                    );
                }

                // Phase 4 (i686 only): replicate kernel PDEs and scratch
                // into all other PD roots, then mark user PDEs with
                // PAGE_USER for ring-3 accessibility.
                #[cfg(feature = "i686-guest")]
                unsafe {
                    pt_buf.finalize_multi_root(
                        root_pt_gpas.len(),
                        I686_USER_PDE_START,
                        scratch_gpa,
                        scratch_gva,
                        scratch_len,
                    );
                }

                // Phase 5: finalize PT bytes.
                let pt_data = pt_buf.into_bytes();
                layout.set_pt_size(pt_data.len())?;

                #[cfg(feature = "i686-guest")]
                {
                    Ok::<_, crate::HyperlightError>((snapshot_memory, pt_data.into_vec()))
                }
                #[cfg(not(feature = "i686-guest"))]
                {
                    snapshot_memory.extend(&pt_data);
                    Ok::<_, crate::HyperlightError>(snapshot_memory)
                }
            })
        })???;
        #[cfg(feature = "i686-guest")]
        let (memory, separate_pt_bytes) = memory;
        layout.set_snapshot_size(memory.len());

        #[cfg(not(feature = "i686-guest"))]
        let regions = Vec::new();

        let hash = hash(&memory, &regions)?;
        Ok(Self {
            sandbox_id,
            layout,
            memory: ReadonlySharedMemory::from_bytes(&memory)?,
            regions,
            load_info,
            hash,
            stack_top_gva,
            sregs: Some(sregs),
            #[cfg(feature = "i686-guest")]
            separate_pt_bytes,
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

    #[cfg(feature = "i686-guest")]
    pub(crate) fn separate_pt_bytes(&self) -> &[u8] {
        &self.separate_pt_bytes
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
        let pt_buf = GuestPageTableBuffer::<8>::new(SIMPLE_PT_BASE);
        let mapping = Mapping {
            phys_base: SandboxMemoryLayout::BASE_ADDRESS as u64,
            virt_base: SandboxMemoryLayout::BASE_ADDRESS as u64,
            len: PAGE_SIZE as u64,
            kind: MappingKind::Basic(BasicMapping {
                readable: true,
                writable: true,
                executable: true,
            }),
        };
        unsafe { vmem::map(&pt_buf, mapping) };
        // Map the scratch region
        let scratch_mapping = Mapping {
            phys_base: hyperlight_common::layout::scratch_base_gpa(PAGE_SIZE),
            virt_base: hyperlight_common::layout::scratch_base_gva(PAGE_SIZE),
            len: PAGE_SIZE as u64,
            kind: MappingKind::Basic(BasicMapping {
                readable: true,
                writable: true,
                executable: false,
            }),
        };
        unsafe { vmem::map(&pt_buf, scratch_mapping) };
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
        BasicMapping, CowMapping, Mapping, MappingKind, PAGE_SIZE, i686_guest,
    };

    use crate::mem::mgr::GuestPageTableBuffer;

    const PT_BASE: usize = 0x10_0000;

    #[test]
    fn map_single_page() {
        let pt = GuestPageTableBuffer::<4>::new(PT_BASE);
        let mapping = Mapping {
            phys_base: 0x2000,
            virt_base: 0x1000,
            len: PAGE_SIZE as u64,
            kind: MappingKind::Basic(BasicMapping {
                readable: true,
                writable: true,
                executable: true,
            }),
        };
        unsafe { i686_guest::map(&pt, mapping) };

        let results: Vec<_> =
            unsafe { i686_guest::virt_to_phys(&pt, 0x1000, PAGE_SIZE as u64) }.collect();
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
        let pt = GuestPageTableBuffer::<4>::new(PT_BASE);
        let mapping = Mapping {
            phys_base: 0x3000,
            virt_base: 0x2000,
            len: PAGE_SIZE as u64,
            kind: MappingKind::Cow(CowMapping {
                readable: true,
                executable: true,
            }),
        };
        unsafe { i686_guest::map(&pt, mapping) };

        let results: Vec<_> =
            unsafe { i686_guest::virt_to_phys(&pt, 0x2000, PAGE_SIZE as u64) }.collect();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].phys_base, 0x3000);
        assert!(matches!(results[0].kind, MappingKind::Cow(_)));
    }

    #[test]
    fn map_multiple_pages_across_pd_boundary() {
        let pt = GuestPageTableBuffer::<4>::new(PT_BASE);
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
        };
        unsafe { i686_guest::map(&pt, mapping) };

        let results: Vec<_> =
            unsafe { i686_guest::virt_to_phys(&pt, va_start, 2 * PAGE_SIZE as u64) }.collect();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].phys_base, pa_start);
        assert_eq!(results[0].virt_base, va_start);
        assert_eq!(results[1].phys_base, pa_start + PAGE_SIZE as u64);
        assert_eq!(results[1].virt_base, va_start + PAGE_SIZE as u64);
    }

    #[test]
    fn virt_to_phys_unmapped_returns_empty() {
        let pt = GuestPageTableBuffer::<4>::new(PT_BASE);
        let results: Vec<_> =
            unsafe { i686_guest::virt_to_phys(&pt, 0x1000, PAGE_SIZE as u64) }.collect();
        assert!(results.is_empty());
    }

    #[test]
    fn map_reuses_existing_page_table() {
        let pt = GuestPageTableBuffer::<4>::new(PT_BASE);
        // Map two pages in the same 4MB region (same PD entry)
        unsafe {
            i686_guest::map(
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
                },
            );
            i686_guest::map(
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
                },
            );
        }
        // Both should be visible
        let r1: Vec<_> =
            unsafe { i686_guest::virt_to_phys(&pt, 0x1000, PAGE_SIZE as u64) }.collect();
        let r2: Vec<_> =
            unsafe { i686_guest::virt_to_phys(&pt, 0x5000, PAGE_SIZE as u64) }.collect();
        assert_eq!(r1.len(), 1);
        assert_eq!(r2.len(), 1);
        assert_eq!(r1[0].phys_base, 0x1000);
        assert_eq!(r2[0].phys_base, 0x5000);
        // Should have allocated: 1 PD (pre-existing) + 1 PT = 2 pages total
        assert_eq!(pt.size(), 2 * PAGE_SIZE);
    }
}
