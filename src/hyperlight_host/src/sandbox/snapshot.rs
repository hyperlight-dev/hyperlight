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

use tracing::{Span, instrument};

use crate::HyperlightError::MemoryRegionSizeMismatch;
use crate::Result;
use crate::mem::exe::LoadInfo;
use crate::mem::memory_region::MemoryRegion;
use crate::mem::shared_mem::SharedMemory;
use crate::sandbox::SandboxConfiguration;
use crate::sandbox::uninitialized::{GuestBinary, GuestEnvironment};
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

    /// Preinitialisation entry point for snapshots created directly from a
    /// guest binary.
    ///
    /// When creating a snapshot directly from a guest binary, this tracks
    /// the address that we need to call into before actually using a
    /// sandbox from this snapshot in order to perform guest-side
    /// preinitialisation.
    ///
    /// Long-term, the intention is to run this preinitialisation eagerly as
    /// part of the snapshot creation process so that restored sandboxes can
    /// begin executing from their normal entry point without requiring this
    /// field. Until that refactoring happens, this remains part of the
    /// snapshot format and must be preserved.
    preinitialise: Option<u64>,
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
        hasher.update(&usize::to_le_bytes(guest_len));
        hasher.update(&u32::to_le_bytes(rgn.flags.bits()));
        // Ignore [`MemoryRegion::region_type`], since it is extra
        // information for debugging rather than a core part of the
        // identity of the snapshot/workload.
    }
    // Ignore [`load_info`], since it is extra information for
    // debugging rather than a core part of the identity of the
    // snapshot/workload.
    Ok(hasher.finalize().into())
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

        let guest_blob_size = blob.as_ref().map(|b| b.data.len()).unwrap_or(0);
        let guest_blob_mem_flags = blob.as_ref().map(|b| b.permissions);

        #[cfg_attr(not(feature = "init-paging"), allow(unused_mut))]
        let mut layout = crate::mem::layout::SandboxMemoryLayout::new(
            cfg,
            exe_info.loaded_size(),
            usize::try_from(cfg.get_stack_size())?,
            usize::try_from(cfg.get_heap_size())?,
            guest_blob_size,
            guest_blob_mem_flags,
        )?;

        let load_addr = layout.get_guest_code_address() as u64;
        let entrypoint_offset: u64 = exe_info.entrypoint().into();

        let mut memory = vec![0; layout.get_memory_size()?];

        let load_info = exe_info.load(
            load_addr.try_into()?,
            &mut memory[layout.get_guest_code_offset()..],
        )?;

        blob.map(|x| layout.write_init_data(&mut memory, x.data))
            .transpose()?;

        #[cfg(feature = "init-paging")]
        {
            let pt_base_gpa =
                crate::mem::layout::SandboxMemoryLayout::BASE_ADDRESS + layout.get_pt_offset();
            let pt_buf = crate::mem::mgr::GuestPageTableBuffer::new(pt_base_gpa);
            use hyperlight_common::vmem::{self, BasicMapping, Mapping, MappingKind};

            use crate::mem::memory_region::{GuestMemoryRegion, MemoryRegionFlags};
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
                unsafe { vmem::map(&pt_buf, mapping) };
            }
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
                unsafe { vmem::map(&pt_buf, mapping) };
                pt_size_mapped = pt_buf.size();
            }
            let pt_bytes = pt_buf.into_bytes();
            layout.set_pt_size(pt_bytes.len());
            memory.extend(&pt_bytes);
        }

        let extra_regions = Vec::new();
        let hash = hash(&memory, &extra_regions)?;

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
        let hash = hash(&memory, &regions)?;
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
        let layout =
            crate::mem::layout::SandboxMemoryLayout::new(cfg, 4096, 2048, 4096, 0, None).unwrap();

        // Take snapshot of data1
        let snapshot = super::Snapshot::new(
            &mut gm,
            0,
            layout,
            crate::mem::exe::LoadInfo::dummy(),
            Vec::new(),
        )
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
        let layout =
            crate::mem::layout::SandboxMemoryLayout::new(cfg, 4096, 2048, 4096, 0, None).unwrap();

        let snapshot = super::Snapshot::new(
            &mut gm,
            0,
            layout,
            crate::mem::exe::LoadInfo::dummy(),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(snapshot.mem_size(), size);
    }

    #[test]
    fn multiple_snapshots_independent() {
        let mut gm = ExclusiveSharedMemory::new(PAGE_SIZE_USIZE).unwrap();

        let cfg = crate::sandbox::SandboxConfiguration::default();
        let layout =
            crate::mem::layout::SandboxMemoryLayout::new(cfg, 4096, 2048, 4096, 0, None).unwrap();

        // Create first snapshot with pattern A
        let pattern_a = vec![0xAA; PAGE_SIZE_USIZE];
        gm.copy_from_slice(&pattern_a, 0).unwrap();
        let snapshot_a =
            super::Snapshot::new(&mut gm, 1, layout, LoadInfo::dummy(), Vec::new()).unwrap();

        // Create second snapshot with pattern B
        let pattern_b = vec![0xBB; PAGE_SIZE_USIZE];
        gm.copy_from_slice(&pattern_b, 0).unwrap();
        let snapshot_b =
            super::Snapshot::new(&mut gm, 2, layout, LoadInfo::dummy(), Vec::new()).unwrap();

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
