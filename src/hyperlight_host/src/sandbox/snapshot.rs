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

use tracing::{Span, instrument};

use crate::Result;
use crate::mem::exe::LoadInfo;
use crate::mem::layout::SandboxMemoryLayout;
use crate::mem::memory_region::MemoryRegion;
use crate::mem::mgr::GuestPageTableBuffer;
use crate::mem::shared_mem::{ExclusiveSharedMemory, SharedMemory};
use crate::sandbox::SandboxConfiguration;
use crate::sandbox::uninitialized::{GuestBinary, GuestEnvironment};

use hyperlight_common::layout::{scratch_base_gpa, scratch_base_gva};
use hyperlight_common::vm::{self, Mapping, MappingKind, BasicMapping, PAGE_SIZE};

use std::sync::atomic::{AtomicU64, Ordering};
pub(super) static SANDBOX_CONFIGURATION_COUNTER: AtomicU64 = AtomicU64::new(0);

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
    layout: SandboxMemoryLayout,
    /// Memory of the sandbox at the time this snapshot was taken
    memory: Vec<u8>,
    /// The memory regions that were mapped when this snapshot was
    /// taken (excluding initial sandbox regions)
    regions: Vec<MemoryRegion>,
    /// Extra debug information about the binary in this snapshot,
    /// from when the binary was first loaded into the snapshot.
    ///
    /// This information is provided on a best-effort basis, and there
    /// is a pretty good chance that it does not exist, even when
    /// build with the unwind_guest feature; generally speaking,
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
    /// The address of the root page table
    root_pt_gpa: u64,

    /// TODO: this should not necessarily be around in the long term...
    ///
    /// When creating a snapshot directly from a guest binary, this
    /// tracks the address that we need to call into before actually
    /// using a sandbox from this snapshot in order to do
    /// preinitialisation. Ideally we would either not need to do this
    /// at all, or do it as part of the snapshot creation process and
    /// never need this.
    preinitialise: Option<u64>,
}

/// Compute a deterministic hash of a snapshot.
///
/// This does not include the load info from the snapshot, because
/// that is only used for debugging builds.
fn hash(memory: &[u8], regions: &[MemoryRegion]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(memory);
    for rgn in regions {
        hasher.update(&usize::to_le_bytes(rgn.guest_region.start));
        let guest_len = rgn.guest_region.end - rgn.guest_region.start;
        hasher.update(&usize::to_le_bytes(rgn.guest_region.start));
        let host_len = rgn.host_region.end - rgn.host_region.start;
        assert!(guest_len == host_len);
        hasher.update(&usize::to_le_bytes(guest_len));
        hasher.update(&u32::to_le_bytes(rgn.flags.bits()));
        // Ignore [`MemoryRegion::region_type`], since it is extra
        // information for debugging rather than a core part of the
        // identity of the snapshot/workload.
    }
    // Ignore [`load_info`], since it is extra information for
    // debugging rather than a core part of the identity of the
    // snapshot/workload.
    hasher.finalize().into()
}

fn access_gpa<'a>(snap: &'a ExclusiveSharedMemory, scratch: &'a ExclusiveSharedMemory, scratch_size: usize, gpa: u64) -> (&'a ExclusiveSharedMemory, usize) {
    let scratch_base = scratch_base_gpa(scratch_size);
    if gpa >= scratch_base {
        (scratch, (gpa - scratch_base) as usize)
    } else {
        (snap, gpa as usize - SandboxMemoryLayout::BASE_ADDRESS)
    }
}

pub(crate) struct SharedMemoryPageTableBuffer<'a> {
    snap: &'a ExclusiveSharedMemory,
    scratch: &'a ExclusiveSharedMemory,
    scratch_size: usize,
    root: u64,
}
impl<'a> SharedMemoryPageTableBuffer<'a> {
    fn new(
        snap: &'a ExclusiveSharedMemory,
        scratch: &'a ExclusiveSharedMemory,
        scratch_size: usize,
        root: u64,
    ) -> Self {
        Self { snap, scratch, scratch_size, root }
    }
}
impl<'a> hyperlight_common::vm::TableOps for SharedMemoryPageTableBuffer<'a> {
    type TableAddr = u64;
    unsafe fn alloc_table(&self) -> u64 {
        panic!("SMPTB is never used to mutate");
    }
    fn entry_addr(addr: u64, offset: u64) -> u64 {
        addr + offset
    }
    unsafe fn read_entry(&self, addr: u64) -> u64 {
        let (mem, off) = access_gpa(self.snap, self.scratch, self.scratch_size, addr);
        let n: [u8; 8] = mem.as_slice()[off..off+8].try_into().unwrap();
        u64::from_ne_bytes(n)
    }
    unsafe fn write_entry(&self, addr: u64, x: u64) -> Option<u64> {
        panic!("SMPTB is never used to mutate");
    }
    fn to_phys(addr: u64) -> u64 { addr }
    fn from_phys(addr: u64) -> u64 { addr }
    fn root_table(&self) -> u64 { self.root }
}
fn filtered_mappings<'a>(
    snap: &'a ExclusiveSharedMemory,
    scratch: &'a ExclusiveSharedMemory,
    regions: &[MemoryRegion],
    scratch_size: usize,
    root_pt: u64,
) -> Vec<(u64, u64, &'a [u8])> {
    let op = SharedMemoryPageTableBuffer::new(
        snap,
        scratch,
        scratch_size,
        root_pt,
    );
    unsafe { hyperlight_common::vm::vtops(&op, 0, hyperlight_common::layout::MAX_GVA as u64) }
        .filter_map(move |(gva, gpa)| {
            // the scratch map doesn't count
            if gva > scratch_base_gva(scratch_size) { return None; }
            // neither does the mapping of the snapshot's own page tables
            if gva >= hyperlight_common::layout::SNAPSHOT_PT_GVA_MIN as u64 &&
                gva <= hyperlight_common::layout::SNAPSHOT_PT_GVA_MAX as u64 {
                    return None;
                }
            // todo: is it useful to warn if we can't resolve this?
            let contents = unsafe { guest_page(snap, scratch, regions, scratch_size, gpa) }?;
            Some((gva, gpa, contents))
        })
        .collect()
}

/// Find the contents of the page which starts at gpa in guest physical
/// memory, taking into account excess host->guest regions
///
/// # Safety
/// The host side of the regions identified by MemoryRegion must be
/// alive and must not be mutated by any other thread: referecnes to
/// these regions may be created and live for `'a`.
unsafe fn guest_page<'a>(
    snap: &'a ExclusiveSharedMemory,
    scratch: &'a ExclusiveSharedMemory,
    regions: &[MemoryRegion],
    scratch_size: usize,
    gpa: u64
) -> Option<&'a [u8]> {
    let gpa_u = gpa as usize;
    for rgn in regions {
        if gpa_u >= rgn.guest_region.start && gpa_u < rgn.guest_region.end {
            let off = gpa_u - rgn.guest_region.start;
            return Some(unsafe { std::slice::from_raw_parts((rgn.host_region.start + off) as *const u8, PAGE_SIZE) });
        }
    }
    let (mem, off) = access_gpa(snap, scratch, scratch_size, gpa);
    if off + PAGE_SIZE <= mem.as_slice().len() {
        Some(&mem.as_slice()[off..off+PAGE_SIZE])
    } else {
        None
    }
}

fn map_specials(pt_buf: &GuestPageTableBuffer, scratch_size: usize) {
    // Map the scratch region
    let mapping = Mapping {
        phys_base: scratch_base_gpa(scratch_size),
        virt_base: scratch_base_gva(scratch_size),
        len: scratch_size as u64,
        kind: MappingKind::BasicMapping(BasicMapping {
            readable: true,
            writable: true,
            executable: true,
        }),
    };
    unsafe { vm::map(pt_buf, mapping) };
    // Map the page tables themselves, in order to allow the
    // guest to update them easily
    let mut pt_size_mapped = 0;
    while pt_buf.size() > pt_size_mapped {
        let mapping = Mapping {
            phys_base: (pt_buf.phys_base() + pt_size_mapped) as u64,
            virt_base: (hyperlight_common::layout::SNAPSHOT_PT_GVA_MIN + pt_size_mapped) as u64,
            len: (pt_buf.size() - pt_size_mapped) as u64,
            kind: MappingKind::BasicMapping(BasicMapping {
                readable: true,
                writable: false,
                executable: false,
            }),
        };
        pt_size_mapped = pt_buf.size();
        unsafe { vm::map(pt_buf, mapping) };
    }
}

impl Snapshot {
    /// Create a new snapshot that runs the guest binary identified by env
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

        let guest_blob_size = blob.as_ref().map(|b| b.data.len()).unwrap_or(0);
        let guest_blob_mem_flags = blob.as_ref().map(|b| b.permissions);

        let mut layout = SandboxMemoryLayout::new(
            cfg,
            exe_info.loaded_size(),
            usize::try_from(cfg.get_heap_size())?,
            cfg.get_scratch_size(),
            guest_blob_size,
            guest_blob_mem_flags,
        )?;

        let load_addr = layout.get_guest_code_address() as u64;
        let entrypoint_offset: u64 = exe_info.entrypoint().into();

        let mut memory = vec![0; layout.get_memory_size()?];

        let load_info = exe_info.load(
            load_addr.clone().try_into()?,
            &mut memory[layout.get_guest_code_offset()..]
        )?;

        blob.map(|x| layout.write_init_data(&mut memory, x.data)).transpose()?;

        // Set up page table entries for the snapshot
        let pt_base_gpa = SandboxMemoryLayout::BASE_ADDRESS + layout.get_pt_offset();
        let pt_buf = GuestPageTableBuffer::new(pt_base_gpa);
        use crate::mem::memory_region::{GuestMemoryRegion, MemoryRegionFlags};
        // 1. Map the (ideally readonly) pages of snapshot data
        for rgn in layout.get_memory_regions_::<GuestMemoryRegion>(())?.iter() {
            let readable = rgn.flags.contains(MemoryRegionFlags::READ);
            let writable = rgn.flags.contains(MemoryRegionFlags::WRITE)
                // Temporary hack: the stack guard page is
                // currently checked for in the host, rather than
                // the guest, so we need to mark it writable in
                // the Stage 1 translation so that the fault
                // exception on a write is taken to the
                // hypervisor, rather than the guest kernel
                || rgn.flags.contains(MemoryRegionFlags::STACK_GUARD);
            let executable = rgn.flags.contains(MemoryRegionFlags::EXECUTE);
            let mapping = Mapping {
                phys_base: rgn.guest_region.start as u64,
                virt_base: rgn.guest_region.start as u64,
                len: rgn.guest_region.len() as u64,
                kind: MappingKind::BasicMapping(BasicMapping {
                    readable,
                    writable,
                    executable,
                }),
            };
            unsafe { vm::map(&pt_buf, mapping) };
        }
        // 2. Map the special mappings
        map_specials(&pt_buf, layout.get_scratch_size());
        let pt_bytes = pt_buf.into_bytes();
        layout.set_pt_size(pt_bytes.len());
        memory.extend(&pt_bytes);

        let extra_regions = Vec::new();
        let hash = hash(&memory, &extra_regions);

        Ok(Self {
            sandbox_id: SANDBOX_CONFIGURATION_COUNTER.fetch_add(1, Ordering::Relaxed),
            memory,
            layout,
            regions: extra_regions,
            load_info,
            hash,
            root_pt_gpa: pt_base_gpa as u64,
            preinitialise: Some(load_addr + entrypoint_offset),
        })
    }

    /// Take a snapshot of the memory in `shared_mem`, then create a new
    /// instance of `Self` with the snapshot stored therein.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn new<S: SharedMemory>(
        shared_mem: &mut S,
        scratch_mem: &mut S,
        sandbox_id: u64,
        mut layout: SandboxMemoryLayout,
        load_info: LoadInfo,
        regions: Vec<MemoryRegion>,
        root_pt: u64,
    ) -> Result<Self> {
        let (new_root_pt_gpa, memory) = shared_mem.with_exclusivity(|snap_e| {
            scratch_mem.with_exclusivity(|scratch_e| {
                let scratch_size = layout.get_scratch_size();

                // Pass 1: count how many pages need to live
                let mut live_pages = filtered_mappings(&snap_e, &scratch_e, &regions, scratch_size, root_pt);

                // Pass 2: copy them, and map them
                // TODO: Look for opportunities to hugepage map
                let pt_base_gpa = SandboxMemoryLayout::BASE_ADDRESS + live_pages.len() * PAGE_SIZE;
                let pt_buf = GuestPageTableBuffer::new(pt_base_gpa);
                let mut snapshot_memory: Vec<u8> = Vec::new();
                let mut snapshot_offset = 0;
                for (gva, gpa, contents) in live_pages {
                    let new_offset = snapshot_memory.len();
                    snapshot_memory.extend(contents);
                    let new_gpa = new_offset + SandboxMemoryLayout::BASE_ADDRESS;
                    let mapping = Mapping {
                        phys_base: new_gpa as u64,
                        virt_base: gva,
                        len: PAGE_SIZE as u64,
                        kind: MappingKind::BasicMapping(BasicMapping {
                            // TODO: copy the permission flags from
                            // the previous mapping
                            readable: true,
                            writable: true,
                            executable: true,
                        })
                    };
                    unsafe { vm::map(&pt_buf, mapping) };
                }
                // Phase 3: Map the special mappings
                map_specials(&pt_buf, layout.get_scratch_size());
                let pt_bytes = pt_buf.into_bytes();
                layout.set_pt_size(pt_bytes.len());
                snapshot_memory.extend(&pt_bytes);
                (pt_base_gpa, snapshot_memory)
            })
        })??;

        // We do not need the original regions anymore, as any uses of
        // the min the guest have been incorporated into the snapshot
        // properly.
        let regions = Vec::new();
        let hash = hash(&memory, &regions);
        Ok(Self {
            sandbox_id,
            layout,
            memory,
            regions,
            load_info,
            hash,
            root_pt_gpa: new_root_pt_gpa as u64,
            preinitialise: None,
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

    /// Return the size of the snapshot in bytes.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn mem_size(&self) -> usize {
        self.memory.len()
    }

    /// Return the main memory contents of the snapshot
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn memory(&self) -> &[u8] {
        &self.memory
    }

    /// Return a copy of the load info for the exe in the snapshot
    pub(crate) fn load_info(&self) -> LoadInfo {
        self.load_info.clone()
    }

    pub(crate) fn layout(&self) -> &SandboxMemoryLayout {
        &self.layout
    }

    pub(crate) fn root_pt_gpa(&self) -> u64 {
        self.root_pt_gpa
    }

    pub(crate) fn preinitialise(&self) -> Option<u64> {
        self.preinitialise
    }
}

impl PartialEq for Snapshot {
    fn eq(&self, other: &Snapshot) -> bool {
        self.hash == other.hash
    }
}

// todo: these need to become much more sophisticated, since data which is not mapped by an evident page table in the guest will not be copied...
// #[cfg(test)]
// mod tests {
//     use hyperlight_common::mem::PAGE_SIZE_USIZE;

//     use crate::mem::exe::LoadInfo;
//     use crate::mem::layout::SandboxMemoryLayout;
//     use crate::mem::shared_mem::{ExclusiveSharedMemory, SharedMemory};

//     #[test]
//     fn restore() {
//         // Simplified version of the original test
//         let data1 = vec![b'a'; PAGE_SIZE_USIZE];
//         let data2 = vec![b'b'; PAGE_SIZE_USIZE];

//         let mut gm = ExclusiveSharedMemory::new(PAGE_SIZE_USIZE).unwrap();
//         gm.copy_from_slice(&data1, 0).unwrap();
//         let mut gsm = ExclusiveSharedMemory::new(PAGE_SIZE_USIZE).unwrap();

//         let cfg = crate::sandbox::SandboxConfiguration::default();
//         let layout = SandboxMemoryLayout::new(cfg, 4096, 4096, 0x3000, 0, None).unwrap();

//         // Take snapshot of data1
//         let snapshot =
//             super::Snapshot::new(&mut gm, gsm, 0, layout, crate::mem::exe::LoadInfo::dummy(), Vec::new())
//                 .unwrap();

//         // Modify memory to data2
//         gm.copy_from_slice(&data2, 0).unwrap();
//         assert_eq!(gm.as_slice(), &data2[..]);

//         // Restore should bring back data1
//         gm.restore_from_snapshot(&snapshot).unwrap();
//         assert_eq!(gm.as_slice(), &data1[..]);
//     }

//     #[test]
//     fn snapshot_mem_size() {
//         let size = PAGE_SIZE_USIZE * 2;
//         let mut gm = ExclusiveSharedMemory::new(size).unwrap();
//         let mut gsm = ExclusiveSharedMemory::new(size).unwrap();

//         let cfg = crate::sandbox::SandboxConfiguration::default();
//         let layout = SandboxMemoryLayout::new(cfg, 4096, 4096, 0x3000, 0, None).unwrap();

//         let snapshot =
//             super::Snapshot::new(&mut gm, 0, layout, crate::mem::exe::LoadInfo::dummy(), Vec::new())
//                 .unwrap();
//         assert_eq!(snapshot.mem_size(), size);
//     }

//     #[test]
//     fn multiple_snapshots_independent() {
//         let mut gm = ExclusiveSharedMemory::new(PAGE_SIZE_USIZE).unwrap();

//         let cfg = crate::sandbox::SandboxConfiguration::default();
//         let layout = SandboxMemoryLayout::new(cfg, 4096, 4096, 0x3000, 0, None).unwrap();

//         // Create first snapshot with pattern A
//         let pattern_a = vec![0xAA; PAGE_SIZE_USIZE];
//         gm.copy_from_slice(&pattern_a, 0).unwrap();
//         let snapshot_a = super::Snapshot::new(&mut gm, 1, layout, LoadInfo::dummy(), Vec::new()).unwrap();

//         // Create second snapshot with pattern B
//         let pattern_b = vec![0xBB; PAGE_SIZE_USIZE];
//         gm.copy_from_slice(&pattern_b, 0).unwrap();
//         let snapshot_b = super::Snapshot::new(&mut gm, 2, layout, LoadInfo::dummy(), Vec::new()).unwrap();

//         // Clear memory
//         gm.copy_from_slice(&[0; PAGE_SIZE_USIZE], 0).unwrap();

//         // Restore snapshot A
//         gm.restore_from_snapshot(&snapshot_a).unwrap();
//         assert_eq!(gm.as_slice(), &pattern_a[..]);

//         // Restore snapshot B
//         gm.restore_from_snapshot(&snapshot_b).unwrap();
//         assert_eq!(gm.as_slice(), &pattern_b[..]);
//     }
// }
