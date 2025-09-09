/*
Copyright 2025  The Hyperlight Authors.

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

use super::memory_region::MemoryRegion;
use super::shared_mem::SharedMemory;
use crate::Result;

/// A wrapper around a `SharedMemory` reference and a snapshot
/// of the memory therein
#[derive(Clone)]
pub(crate) struct SharedMemorySnapshot {
    // Unique ID of the sandbox this snapshot was taken from
    sandbox_id: u64,
    // Memory of the sandbox at the time this snapshot was taken
    snapshot: Vec<u8>,
    /// The memory regions that were mapped when this snapshot was taken (excluding initial sandbox regions)
    regions: Vec<MemoryRegion>,
}

impl SharedMemorySnapshot {
    /// Take a snapshot of the memory in `shared_mem`, then create a new
    /// instance of `Self` with the snapshot stored therein.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn new<S: SharedMemory>(
        shared_mem: &mut S,
        sandbox_id: u64,
        regions: Vec<MemoryRegion>,
    ) -> Result<Self> {
        // TODO: Track dirty pages instead of copying entire memory
        let snapshot = shared_mem.with_exclusivity(|e| e.copy_all_to_vec())??;
        Ok(Self {
            sandbox_id,
            snapshot,
            regions,
        })
    }

    /// Copy the memory from the internally-stored memory snapshot
    /// into the internally-stored `SharedMemory`.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn restore_from_snapshot<S: SharedMemory>(&self, shared_mem: &mut S) -> Result<()> {
        shared_mem.with_exclusivity(|e| e.copy_from_slice(self.snapshot.as_slice(), 0))??;
        Ok(())
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
    pub(super) fn mem_size(&self) -> usize {
        self.snapshot.len()
    }
}

#[cfg(test)]
mod tests {
    use hyperlight_common::mem::PAGE_SIZE_USIZE;

    use crate::mem::shared_mem::ExclusiveSharedMemory;

    #[test]
    fn restore() {
        // Simplified version of the original test
        let data1 = vec![b'a'; PAGE_SIZE_USIZE];
        let data2 = vec![b'b'; PAGE_SIZE_USIZE];

        let mut gm = ExclusiveSharedMemory::new(PAGE_SIZE_USIZE).unwrap();
        gm.copy_from_slice(&data1, 0).unwrap();

        // Take snapshot of data1
        let snapshot = super::SharedMemorySnapshot::new(&mut gm, 0, Vec::new()).unwrap();

        // Modify memory to data2
        gm.copy_from_slice(&data2, 0).unwrap();
        assert_eq!(gm.as_slice(), &data2[..]);

        // Restore should bring back data1
        snapshot.restore_from_snapshot(&mut gm).unwrap();
        assert_eq!(gm.as_slice(), &data1[..]);
    }

    #[test]
    fn snapshot_mem_size() {
        let size = PAGE_SIZE_USIZE * 2;
        let mut gm = ExclusiveSharedMemory::new(size).unwrap();

        let snapshot = super::SharedMemorySnapshot::new(&mut gm, 0, Vec::new()).unwrap();
        assert_eq!(snapshot.mem_size(), size);
    }

    #[test]
    fn multiple_snapshots_independent() {
        let mut gm = ExclusiveSharedMemory::new(PAGE_SIZE_USIZE).unwrap();

        // Create first snapshot with pattern A
        let pattern_a = vec![0xAA; PAGE_SIZE_USIZE];
        gm.copy_from_slice(&pattern_a, 0).unwrap();
        let snapshot_a = super::SharedMemorySnapshot::new(&mut gm, 1, Vec::new()).unwrap();

        // Create second snapshot with pattern B
        let pattern_b = vec![0xBB; PAGE_SIZE_USIZE];
        gm.copy_from_slice(&pattern_b, 0).unwrap();
        let snapshot_b = super::SharedMemorySnapshot::new(&mut gm, 2, Vec::new()).unwrap();

        // Clear memory
        gm.copy_from_slice(&[0; PAGE_SIZE_USIZE], 0).unwrap();

        // Restore snapshot A
        snapshot_a.restore_from_snapshot(&mut gm).unwrap();
        assert_eq!(gm.as_slice(), &pattern_a[..]);

        // Restore snapshot B
        snapshot_b.restore_from_snapshot(&mut gm).unwrap();
        assert_eq!(gm.as_slice(), &pattern_b[..]);
    }
}
