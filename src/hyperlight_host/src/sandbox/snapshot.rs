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
use crate::mem::memory_region::MemoryRegion;
use crate::mem::shared_mem::SharedMemory;
use crate::sandbox::SandboxConfiguration;
use crate::sandbox::uninitialized::{GuestBinary, GuestEnvironment};

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
    layout: crate::mem::layout::SandboxMemoryLayout,
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

        let mut layout = crate::mem::layout::SandboxMemoryLayout::new(
            cfg,
            exe_info.loaded_size(),
            usize::try_from(cfg.get_stack_size())?,
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
        let pt_base_gpa = crate::mem::layout::SandboxMemoryLayout::BASE_ADDRESS + layout.get_pt_offset();
        let pt_buf = crate::mem::mgr::GuestPageTableBuffer::new(pt_base_gpa);
        use crate::mem::memory_region::{GuestMemoryRegion, MemoryRegionFlags};
        use hyperlight_common::vm::{self, Mapping, MappingKind, BasicMapping};
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
        // 2. Map the scratch region
        let scratch_size = cfg.get_scratch_size();
        let mapping = Mapping {
            phys_base: hyperlight_common::layout::scratch_base_gpa(scratch_size),
            virt_base: hyperlight_common::layout::scratch_base_gva(scratch_size),
            len: scratch_size as u64,
            kind: MappingKind::BasicMapping(BasicMapping {
                readable: true,
                writable: true,
                executable: true,
            }),
        };
        unsafe { vm::map(&pt_buf, mapping) };
        // 3. Map the page tables themselves, in order to allow the
        // guest to update them easily
        let mut pt_size_mapped = 0;
        while pt_buf.size() > pt_size_mapped {
            let mapping = Mapping {
                phys_base: (pt_base_gpa + pt_size_mapped) as u64,
                virt_base: (hyperlight_common::layout::SNAPSHOT_PT_GVA + pt_size_mapped) as u64,
                len: (pt_buf.size() - pt_size_mapped) as u64,
                kind: MappingKind::BasicMapping(BasicMapping {
                    readable: true,
                    writable: true,
                    executable: false,
                }),
            };
            unsafe { vm::map(&pt_buf, mapping) };
            pt_size_mapped = pt_buf.size();
        }
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
            preinitialise: Some(load_addr + entrypoint_offset),
        })
    }

    /// Take a snapshot of the memory in `shared_mem`, then create a new
    /// instance of `Self` with the snapshot stored therein.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn new<S: SharedMemory>(
        shared_mem: &mut S,
        sandbox_id: u64,
        layout: crate::mem::layout::SandboxMemoryLayout,
        load_info: LoadInfo,
        regions: Vec<MemoryRegion>,
    ) -> Result<Self> {
        // TODO: Track dirty pages instead of copying entire memory
        let memory = shared_mem.with_exclusivity(|e| e.copy_all_to_vec())??;
        let hash = hash(&memory, &regions);
        Ok(Self {
            sandbox_id,
            layout,
            memory,
            regions,
            load_info,
            hash,
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

    pub(crate) fn layout(&self) -> &crate::mem::layout::SandboxMemoryLayout {
        &self.layout
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

#[cfg(test)]
mod tests {
    use hyperlight_common::mem::PAGE_SIZE_USIZE;

    use crate::mem::exe::LoadInfo;
    use crate::mem::shared_mem::{ExclusiveSharedMemory, SharedMemory};

    #[test]
    fn restore() {
        // Simplified version of the original test
        let data1 = vec![b'a'; PAGE_SIZE_USIZE];
        let data2 = vec![b'b'; PAGE_SIZE_USIZE];

        let mut gm = ExclusiveSharedMemory::new(PAGE_SIZE_USIZE).unwrap();
        gm.copy_from_slice(&data1, 0).unwrap();

        let cfg = crate::sandbox::SandboxConfiguration::default();
        let layout = crate::mem::layout::SandboxMemoryLayout::new(cfg, 4096, 2048, 4096, 0x3000, 0, None).unwrap();

        // Take snapshot of data1
        let snapshot =
            super::Snapshot::new(&mut gm, 0, layout, crate::mem::exe::LoadInfo::dummy(), Vec::new())
                .unwrap();

        // Modify memory to data2
        gm.copy_from_slice(&data2, 0).unwrap();
        assert_eq!(gm.as_slice(), &data2[..]);

        // Restore should bring back data1
        gm.restore_from_snapshot(&snapshot).unwrap();
        assert_eq!(gm.as_slice(), &data1[..]);
    }

    #[test]
    fn snapshot_mem_size() {
        let size = PAGE_SIZE_USIZE * 2;
        let mut gm = ExclusiveSharedMemory::new(size).unwrap();

        let cfg = crate::sandbox::SandboxConfiguration::default();
        let layout = crate::mem::layout::SandboxMemoryLayout::new(cfg, 4096, 2048, 4096, 0x3000, 0, None).unwrap();

        let snapshot =
            super::Snapshot::new(&mut gm, 0, layout, crate::mem::exe::LoadInfo::dummy(), Vec::new())
                .unwrap();
        assert_eq!(snapshot.mem_size(), size);
    }

    #[test]
    fn multiple_snapshots_independent() {
        let mut gm = ExclusiveSharedMemory::new(PAGE_SIZE_USIZE).unwrap();

        let cfg = crate::sandbox::SandboxConfiguration::default();
        let layout = crate::mem::layout::SandboxMemoryLayout::new(cfg, 4096, 2048, 4096, 0x3000, 0, None).unwrap();

        // Create first snapshot with pattern A
        let pattern_a = vec![0xAA; PAGE_SIZE_USIZE];
        gm.copy_from_slice(&pattern_a, 0).unwrap();
        let snapshot_a = super::Snapshot::new(&mut gm, 1, layout, LoadInfo::dummy(), Vec::new()).unwrap();

        // Create second snapshot with pattern B
        let pattern_b = vec![0xBB; PAGE_SIZE_USIZE];
        gm.copy_from_slice(&pattern_b, 0).unwrap();
        let snapshot_b = super::Snapshot::new(&mut gm, 2, layout, LoadInfo::dummy(), Vec::new()).unwrap();

        // Clear memory
        gm.copy_from_slice(&[0; PAGE_SIZE_USIZE], 0).unwrap();

        // Restore snapshot A
        gm.restore_from_snapshot(&snapshot_a).unwrap();
        assert_eq!(gm.as_slice(), &pattern_a[..]);

        // Restore snapshot B
        gm.restore_from_snapshot(&snapshot_b).unwrap();
        assert_eq!(gm.as_slice(), &pattern_b[..]);
    }
}
