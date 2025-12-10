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

use crate::HyperlightError::MemoryRegionSizeMismatch;
use crate::Result;
use crate::mem::memory_region::MemoryRegion;
use crate::mem::shared_mem::SharedMemory;

/// A wrapper around a `SharedMemory` reference and a snapshot
/// of the memory therein
pub struct Snapshot {
    // Unique ID of the sandbox this snapshot was taken from
    sandbox_id: u64,
    // Memory of the sandbox at the time this snapshot was taken
    memory: Vec<u8>,
    /// The memory regions that were mapped when this snapshot was taken (excluding initial sandbox regions)
    regions: Vec<MemoryRegion>,
    /// The hash of the other portions of the snapshot. Morally, this
    /// is just a memoization cache for [`hash`], below, but it is not
    /// a [`std::sync::OnceLock`] because it may be persisted to disk
    /// without being recomputed on load.
    ///
    /// It is not a [`blake3::Hash`] because we do not presently
    /// require constant-time equality checking
    hash: [u8; 32],
}

fn hash(memory: &[u8], regions: &[MemoryRegion]) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(memory);
    for rgn in regions {
        hasher.update(&usize::to_le_bytes(rgn.guest_region.start));
        let guest_len = rgn.guest_region.end - rgn.guest_region.start;
        hasher.update(&usize::to_le_bytes(rgn.host_region.start));
        let host_len = rgn.host_region.end - rgn.host_region.start;
        if guest_len != host_len {
            return Err(MemoryRegionSizeMismatch(host_len, guest_len, rgn.clone()));
        }
        hasher.update(&usize::to_le_bytes(guest_len));
        hasher.update(&u32::to_le_bytes(rgn.flags.bits()));
    }
    Ok(hasher.finalize().into())
}

impl Snapshot {
    /// Take a snapshot of the memory in `shared_mem`, then create a new
    /// instance of `Self` with the snapshot stored therein.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn new<S: SharedMemory>(
        shared_mem: &mut S,
        sandbox_id: u64,
        regions: Vec<MemoryRegion>,
    ) -> Result<Self> {
        // TODO: Track dirty pages instead of copying entire memory
        let memory = shared_mem.with_exclusivity(|e| e.copy_all_to_vec())??;
        let hash = hash(&memory, &regions)?;
        Ok(Self {
            sandbox_id,
            memory,
            regions,
            hash,
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
}

impl PartialEq for Snapshot {
    fn eq(&self, other: &Snapshot) -> bool {
        self.hash == other.hash
    }
}

#[cfg(test)]
mod tests {
    use hyperlight_common::mem::PAGE_SIZE_USIZE;

    use crate::mem::shared_mem::{ExclusiveSharedMemory, SharedMemory};

    #[test]
    fn restore() {
        // Simplified version of the original test
        let data1 = vec![b'a'; PAGE_SIZE_USIZE];
        let data2 = vec![b'b'; PAGE_SIZE_USIZE];

        let mut gm = ExclusiveSharedMemory::new(PAGE_SIZE_USIZE).unwrap();
        gm.copy_from_slice(&data1, 0).unwrap();

        // Take snapshot of data1
        let snapshot = super::Snapshot::new(&mut gm, 0, Vec::new()).unwrap();

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

        let snapshot = super::Snapshot::new(&mut gm, 0, Vec::new()).unwrap();
        assert_eq!(snapshot.mem_size(), size);
    }

    #[test]
    fn multiple_snapshots_independent() {
        let mut gm = ExclusiveSharedMemory::new(PAGE_SIZE_USIZE).unwrap();

        // Create first snapshot with pattern A
        let pattern_a = vec![0xAA; PAGE_SIZE_USIZE];
        gm.copy_from_slice(&pattern_a, 0).unwrap();
        let snapshot_a = super::Snapshot::new(&mut gm, 1, Vec::new()).unwrap();

        // Create second snapshot with pattern B
        let pattern_b = vec![0xBB; PAGE_SIZE_USIZE];
        gm.copy_from_slice(&pattern_b, 0).unwrap();
        let snapshot_b = super::Snapshot::new(&mut gm, 2, Vec::new()).unwrap();

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
