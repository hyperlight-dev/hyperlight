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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use hyperlight_common::mem::PAGE_SIZE_USIZE;
use tracing::{Span, instrument};

use super::bitmap::bit_index_iterator;
use super::memory_region::MemoryRegion;
use super::shared_mem::SharedMemory;
use crate::Result;

/// A wrapper around a `SharedMemory` reference and a snapshot
/// of the memory therein
#[derive(Clone)]
pub(crate) struct SharedMemorySnapshot {
    // Unique ID of the sandbox this snapshot was taken from
    sandbox_id: u64,
    /// The memory regions that were mapped when this snapshot was taken (excluding initial sandbox regions)
    regions: Vec<MemoryRegion>,
    /// Data (pages) in this snapshot
    data: HashMap<usize, Vec<u8>>, // page_number -> page_data. Each entry is 1 page
    /// Parent snapshot (or None if root)
    parent: Option<Arc<SharedMemorySnapshot>>,
}

impl SharedMemorySnapshot {
    /// Take a snapshot of memory in `shared_mem` assuming `dirty_pages_bitmap` are the only
    /// changed pages since `parent` snapshot was taken.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn new<S: SharedMemory>(
        shared_mem: &mut S,
        sandbox_id: u64,
        regions: Vec<MemoryRegion>,
        dirty_pages_bitmap: &[u64],
        parent: Option<Arc<SharedMemorySnapshot>>,
    ) -> Result<Self> {
        let data = shared_mem.with_exclusivity(|e| -> Result<HashMap<usize, Vec<u8>>> {
            let mut snapshot = HashMap::new();
            bit_index_iterator(dirty_pages_bitmap).try_for_each(|idx| {
                let mut page = vec![0u8; PAGE_SIZE_USIZE];
                e.copy_to_slice(&mut page, idx * PAGE_SIZE_USIZE)?;
                snapshot.insert(idx, page);
                crate::Result::Ok(())
            })?;
            Ok(snapshot)
        })??;
        Ok(Self {
            sandbox_id,
            regions,
            data,
            parent,
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

    pub(super) fn restore_from_snapshot<S: SharedMemory>(
        self: &Arc<Self>,
        shared_mem: &mut S,
        current_dirty_pages: &[u64],
        most_recent_snapshot: &Option<Arc<SharedMemorySnapshot>>,
    ) -> Result<()> {
        let mut pages_to_restore = HashSet::new();

        // Unconditionally restore all current dirty pages
        for page_num in bit_index_iterator(current_dirty_pages) {
            pages_to_restore.insert(page_num);
        }

        if let Some(most_recent) = most_recent_snapshot {
            if Arc::ptr_eq(self, most_recent) {
                // Restoring to same snapshot sandbox was most recently in: only restore current dirty pages
            } else if self.is_ancestor_of(most_recent) {
                // Rolling back: collect pages from most_recent back to self (exclusive)
                Self::collect_pages_from_chain(most_recent, Some(self), &mut pages_to_restore);
            } else if most_recent.is_ancestor_of(self) {
                // Fast-forwarding: collect pages from self back to most_recent (exclusive)
                Self::collect_pages_from_chain(self, Some(most_recent), &mut pages_to_restore);
            } else {
                // Different branches not supported for now
                return Err(crate::new_error!(
                    "Cannot restore between snapshots on different branches"
                ));
            }
        } else {
            // Sandbox has no previous snapshots: restore all pages from this snapshot and its ancestors
            Self::collect_pages_from_chain(self, None, &mut pages_to_restore);
        }

        // Restore all collected pages
        shared_mem.with_exclusivity(|e| -> Result<()> {
            for page_num in pages_to_restore {
                let offset = page_num * PAGE_SIZE_USIZE;

                // Search backward through snapshots to find the page
                if let Some(page_data) = self.find_page_in_snapshots(page_num) {
                    // Restore from snapshot
                    // # Safety: We don't want to dirty the pages we restore
                    unsafe { e.copy_from_slice_no_dirty(page_data, offset)? };
                } else {
                    // Zero the page (return to initial state)
                    // # Safety: We don't want to dirty the pages we restore
                    unsafe { e.zero_fill_no_dirty(offset, PAGE_SIZE_USIZE)? };
                }
            }
            Ok(())
        })??;

        Ok(())
    }

    /// Check if this snapshot is an ancestor of the other snapshot
    /// (i.e. the other snapshot was taken after this one in the same chain)
    fn is_ancestor_of(self: &Arc<Self>, other: &Arc<SharedMemorySnapshot>) -> bool {
        let mut current = other.parent.as_ref();

        while let Some(snapshot) = current {
            if Arc::ptr_eq(self, snapshot) {
                return true;
            }
            current = snapshot.parent.as_ref();
        }

        false
    }

    /// Search backward through the snapshot chain to find a page
    fn find_page_in_snapshots(&self, page_num: usize) -> Option<&Vec<u8>> {
        // Check this snapshot first
        if let Some(page_data) = self.data.get(&page_num) {
            return Some(page_data);
        }

        // Check parent snapshots recursively
        if let Some(parent) = &self.parent {
            return parent.find_page_in_snapshots(page_num);
        }

        None
    }

    /// Collect all page numbers from snapshots in a chain, starting from `start_snapshot`
    /// and stopping when `stop_snapshot` is reached (exclusive) or when the chain ends.
    fn collect_pages_from_chain(
        start_snapshot: &Arc<SharedMemorySnapshot>,
        stop_snapshot: Option<&Arc<SharedMemorySnapshot>>,
        pages_to_restore: &mut HashSet<usize>,
    ) {
        let mut current_snapshot = Some(start_snapshot);

        while let Some(snapshot) = current_snapshot {
            if let Some(stop) = stop_snapshot {
                if Arc::ptr_eq(snapshot, stop) {
                    break;
                }
            }

            for page_num in snapshot.data.keys() {
                pages_to_restore.insert(*page_num);
            }

            current_snapshot = snapshot.parent.as_ref();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperlight_common::mem::PAGE_SIZE_USIZE;

    use crate::mem::shared_mem::ExclusiveSharedMemory;

    #[test]
    fn test_fresh_sandbox_restoration() {
        // Test restoring a fresh sandbox to a given snapshot
        let mut gm = ExclusiveSharedMemory::new(PAGE_SIZE_USIZE * 3).unwrap();

        // Set up initial data in three pages
        let page0_data = vec![b'A'; PAGE_SIZE_USIZE];
        let page1_data = vec![b'B'; PAGE_SIZE_USIZE];
        let page2_data = vec![b'C'; PAGE_SIZE_USIZE];

        gm.copy_from_slice(&page0_data, 0).unwrap();
        gm.copy_from_slice(&page1_data, PAGE_SIZE_USIZE).unwrap();
        gm.copy_from_slice(&page2_data, PAGE_SIZE_USIZE * 2)
            .unwrap();

        // Take snapshot with pages 0 and 2 dirty
        let dirty_bitmap = [0b101];
        let snapshot = Arc::new(
            super::SharedMemorySnapshot::new(&mut gm, 0, vec![], &dirty_bitmap, None).unwrap(),
        );
        assert_eq!(snapshot.data.len(), 2);
        assert!(snapshot.data.contains_key(&0));
        assert!(!snapshot.data.contains_key(&1));
        assert!(snapshot.data.contains_key(&2));

        // Create fresh sandbox
        let mut fresh_gm = ExclusiveSharedMemory::new(PAGE_SIZE_USIZE * 3).unwrap();

        // Restore fresh sandbox to snapshot state
        snapshot
            .restore_from_snapshot(&mut fresh_gm, &[], &None)
            .unwrap();

        // Verify only pages 0 and 2 were restored, page 1 remains zero
        let restored_data = fresh_gm.copy_all_to_vec().unwrap();
        assert_eq!(&restored_data[0..PAGE_SIZE_USIZE], &page0_data);
        assert_eq!(
            &restored_data[PAGE_SIZE_USIZE..PAGE_SIZE_USIZE * 2],
            &vec![0u8; PAGE_SIZE_USIZE]
        );
        assert_eq!(
            &restored_data[PAGE_SIZE_USIZE * 2..PAGE_SIZE_USIZE * 3],
            &page2_data
        );
    }

    #[test]
    fn test_rollback_to_ancestor() {
        let mut gm = ExclusiveSharedMemory::new(PAGE_SIZE_USIZE * 4).unwrap();

        // Initial state - modify page 0
        let page0_v1 = vec![b'1'; PAGE_SIZE_USIZE];
        gm.copy_from_slice(&page0_v1, 0).unwrap();
        let snapshot1 =
            Arc::new(super::SharedMemorySnapshot::new(&mut gm, 0, vec![], &[0b10], None).unwrap());
        assert_eq!(snapshot1.data.len(), 1);

        // Modify page 1, take snapshot 2
        let page1_v1 = vec![b'2'; PAGE_SIZE_USIZE];
        gm.copy_from_slice(&page1_v1, PAGE_SIZE_USIZE).unwrap();
        let snapshot2 = Arc::new(
            super::SharedMemorySnapshot::new(&mut gm, 0, vec![], &[0b10], Some(snapshot1.clone()))
                .unwrap(),
        );
        assert_eq!(snapshot2.data.len(), 1);

        // Modify page 2, take snapshot 3
        let page2_v1 = vec![b'3'; PAGE_SIZE_USIZE];
        gm.copy_from_slice(&page2_v1, PAGE_SIZE_USIZE * 2).unwrap();
        let snapshot3 = Arc::new(
            super::SharedMemorySnapshot::new(&mut gm, 0, vec![], &[0b100], Some(snapshot2.clone()))
                .unwrap(),
        );
        assert_eq!(snapshot3.data.len(), 1);

        // Make additional changes to page 3 (current dirty)
        let page3_v1 = vec![b'4'; PAGE_SIZE_USIZE];
        gm.copy_from_slice(&page3_v1, PAGE_SIZE_USIZE * 3).unwrap();
        let current_dirty = [0b1000]; // page 3 is dirty

        // Rollback to snapshot1 (most recent is snapshot3)
        snapshot1
            .restore_from_snapshot(&mut gm, &current_dirty, &Some(snapshot3))
            .unwrap();

        let restored_data = gm.copy_all_to_vec().unwrap();

        // Page 0 should be restored to snapshot1's value
        assert_eq!(&restored_data[0..PAGE_SIZE_USIZE], &page0_v1);
        // Pages 1, 2, 3 should be zeroed (not in snapshot1 or its ancestors)
        assert_eq!(
            &restored_data[PAGE_SIZE_USIZE..PAGE_SIZE_USIZE * 2],
            &vec![0u8; PAGE_SIZE_USIZE]
        );
        assert_eq!(
            &restored_data[PAGE_SIZE_USIZE * 2..PAGE_SIZE_USIZE * 3],
            &vec![0u8; PAGE_SIZE_USIZE]
        );
        assert_eq!(
            &restored_data[PAGE_SIZE_USIZE * 3..PAGE_SIZE_USIZE * 4],
            &vec![0u8; PAGE_SIZE_USIZE]
        );
    }

    #[test]
    fn test_rollback_then_rollforward() {
        let mut gm = ExclusiveSharedMemory::new(PAGE_SIZE_USIZE * 4).unwrap();

        // Helper function to verify page contents
        let verify_page = |gm: &ExclusiveSharedMemory, page_idx: usize, expected: u8| {
            let data = gm.copy_all_to_vec().unwrap();
            let page_start = page_idx * PAGE_SIZE_USIZE;
            let page_end = page_start + PAGE_SIZE_USIZE;
            assert_eq!(data[page_start..page_end], vec![expected; PAGE_SIZE_USIZE]);
        };

        let verify_page_zero = |gm: &ExclusiveSharedMemory, page_idx: usize| {
            let data = gm.copy_all_to_vec().unwrap();
            let page_start = page_idx * PAGE_SIZE_USIZE;
            let page_end = page_start + PAGE_SIZE_USIZE;
            assert_eq!(data[page_start..page_end], vec![0u8; PAGE_SIZE_USIZE]);
        };

        // Initial state: all pages zero
        verify_page_zero(&gm, 0);
        verify_page_zero(&gm, 1);
        verify_page_zero(&gm, 2);
        verify_page_zero(&gm, 3);

        // === SNAPSHOT 1 ===
        // Modify page 0 to 'A' and take snapshot1
        let page0_data = vec![b'A'; PAGE_SIZE_USIZE];
        gm.copy_from_slice(&page0_data, 0).unwrap();
        let snapshot1 =
            Arc::new(super::SharedMemorySnapshot::new(&mut gm, 0, vec![], &[0b1], None).unwrap());

        // Verify snapshot1 contains only page 0
        assert_eq!(snapshot1.data.len(), 1);
        assert!(snapshot1.data.contains_key(&0));
        assert_eq!(snapshot1.data[&0], page0_data);

        // Verify current memory state
        verify_page(&gm, 0, b'A');
        verify_page_zero(&gm, 1);
        verify_page_zero(&gm, 2);
        verify_page_zero(&gm, 3);

        // === SNAPSHOT 2 ===
        // Modify page 1 to 'B' and take snapshot2
        let page1_data = vec![b'B'; PAGE_SIZE_USIZE];
        gm.copy_from_slice(&page1_data, PAGE_SIZE_USIZE).unwrap();
        let snapshot2 = Arc::new(
            super::SharedMemorySnapshot::new(&mut gm, 0, vec![], &[0b10], Some(snapshot1.clone()))
                .unwrap(),
        );

        // Verify snapshot2 contains only page 1 (page 0 unchanged)
        assert_eq!(snapshot2.data.len(), 1);
        assert!(snapshot2.data.contains_key(&1));
        assert_eq!(snapshot2.data[&1], page1_data);

        // Verify current memory state
        verify_page(&gm, 0, b'A');
        verify_page(&gm, 1, b'B');
        verify_page_zero(&gm, 2);
        verify_page_zero(&gm, 3);

        // === SNAPSHOT 3 ===
        // Modify page 2 to 'C' and take snapshot3
        let page2_data = vec![b'C'; PAGE_SIZE_USIZE];
        gm.copy_from_slice(&page2_data, PAGE_SIZE_USIZE * 2)
            .unwrap();
        let snapshot3 = Arc::new(
            super::SharedMemorySnapshot::new(&mut gm, 0, vec![], &[0b100], Some(snapshot2.clone()))
                .unwrap(),
        );

        // Verify snapshot3 contains only page 2
        assert_eq!(snapshot3.data.len(), 1);
        assert!(snapshot3.data.contains_key(&2));
        assert_eq!(snapshot3.data[&2], page2_data);

        // Verify current memory state
        verify_page(&gm, 0, b'A');
        verify_page(&gm, 1, b'B');
        verify_page(&gm, 2, b'C');
        verify_page_zero(&gm, 3);

        // Make some additional changes (dirty page 3 to 'D')
        let page3_data = vec![b'D'; PAGE_SIZE_USIZE];
        gm.copy_from_slice(&page3_data, PAGE_SIZE_USIZE * 3)
            .unwrap();
        let current_dirty = [0b1000]; // page 3 is dirty

        // Verify current memory state before restoration
        verify_page(&gm, 0, b'A');
        verify_page(&gm, 1, b'B');
        verify_page(&gm, 2, b'C');
        verify_page(&gm, 3, b'D');

        // === RESTORE TO SNAPSHOT 2 (rollback) ===
        snapshot2
            .restore_from_snapshot(&mut gm, &current_dirty, &Some(snapshot3.clone()))
            .unwrap();

        // After rollback to snapshot2:
        // - Page 0: 'A' (from snapshot1, ancestor of snapshot2)
        // - Page 1: 'B' (from snapshot2)
        // - Page 2: zeroed (was dirty after snapshot2, not in snapshot2 or ancestors)
        // - Page 3: zeroed (was dirty, not in snapshot2 or ancestors)
        verify_page(&gm, 0, b'A');
        verify_page(&gm, 1, b'B');
        verify_page_zero(&gm, 2);
        verify_page_zero(&gm, 3);

        // === RESTORE TO SNAPSHOT 1 (further rollback) ===
        snapshot1
            .restore_from_snapshot(&mut gm, &[], &Some(snapshot2.clone()))
            .unwrap();

        // After rollback to snapshot1:
        // - Page 0: 'A' (from snapshot1)
        // - Page 1: zeroed (was dirty after snapshot1, not in snapshot1 or ancestors)
        // - Page 2: remains zero
        // - Page 3: remains zero
        verify_page(&gm, 0, b'A');
        verify_page_zero(&gm, 1);
        verify_page_zero(&gm, 2);
        verify_page_zero(&gm, 3);

        // === RESTORE TO SNAPSHOT 2 (forward) ===
        snapshot2
            .restore_from_snapshot(&mut gm, &[], &Some(snapshot1.clone()))
            .unwrap();

        // After fast-forward to snapshot2:
        // - Page 0: 'A' (from snapshot1, ancestor)
        // - Page 1: 'B' (from snapshot2)
        // - Page 2: remains zero
        // - Page 3: remains zero
        verify_page(&gm, 0, b'A');
        verify_page(&gm, 1, b'B');
        verify_page_zero(&gm, 2);
        verify_page_zero(&gm, 3);

        // === RESTORE TO SNAPSHOT 3 (forward) ===
        snapshot3
            .restore_from_snapshot(&mut gm, &[], &Some(snapshot2.clone()))
            .unwrap();

        // After fast-forward to snapshot3:
        // - Page 0: 'A' (from snapshot1, ancestor)
        // - Page 1: 'B' (from snapshot2, ancestor)
        // - Page 2: 'C' (from snapshot3)
        // - Page 3: remains zero
        verify_page(&gm, 0, b'A');
        verify_page(&gm, 1, b'B');
        verify_page(&gm, 2, b'C');
        verify_page_zero(&gm, 3);
    }

    #[test]
    fn test_current_dirty_pages_restoration() {
        // Test that current dirty pages are properly restored
        let mut gm = ExclusiveSharedMemory::new(PAGE_SIZE_USIZE * 2).unwrap();

        // Set up page 0 and take snapshot
        let page0_snapshot_data = vec![b'S'; PAGE_SIZE_USIZE];
        gm.copy_from_slice(&page0_snapshot_data, 0).unwrap();
        let snapshot =
            Arc::new(super::SharedMemorySnapshot::new(&mut gm, 0, vec![], &[1], None).unwrap());

        // Modify both pages after snapshot
        let page0_modified = vec![b'M'; PAGE_SIZE_USIZE];
        let page1_modified = vec![b'N'; PAGE_SIZE_USIZE];
        gm.copy_from_slice(&page0_modified, 0).unwrap();
        gm.copy_from_slice(&page1_modified, PAGE_SIZE_USIZE)
            .unwrap();

        // Current dirty pages: both page 0 and 1
        let current_dirty = [3u64]; // pages 0 and 1 are dirty

        // Restore to snapshot
        snapshot
            .restore_from_snapshot(&mut gm, &current_dirty, &None)
            .unwrap();

        let restored_data = gm.copy_all_to_vec().unwrap();

        // Page 0 should be restored to snapshot value
        assert_eq!(&restored_data[0..PAGE_SIZE_USIZE], &page0_snapshot_data);
        // Page 1 should be zeroed (wasn't in snapshot)
        assert_eq!(
            &restored_data[PAGE_SIZE_USIZE..PAGE_SIZE_USIZE * 2],
            &vec![0u8; PAGE_SIZE_USIZE]
        );
    }

    #[test]
    fn test_snapshot_chain_search() {
        // Test that page search works through snapshot chain
        let mut gm = ExclusiveSharedMemory::new(PAGE_SIZE_USIZE * 2).unwrap();

        // Snapshot 1: page 0 = 'A'
        let page0_v1 = vec![b'A'; PAGE_SIZE_USIZE];
        gm.copy_from_slice(&page0_v1, 0).unwrap();
        let snapshot1 =
            Arc::new(super::SharedMemorySnapshot::new(&mut gm, 0, vec![], &[1], None).unwrap());

        // Snapshot 2: page 1 = 'B' (page 0 unchanged, not stored again)
        let page1_v1 = vec![b'B'; PAGE_SIZE_USIZE];
        gm.copy_from_slice(&page1_v1, PAGE_SIZE_USIZE).unwrap();
        let snapshot2 = Arc::new(
            super::SharedMemorySnapshot::new(&mut gm, 0, vec![], &[2], Some(snapshot1.clone()))
                .unwrap(),
        );

        // Snapshot 3: page 0 = 'C' (overwrites page 0)
        let page0_v2 = vec![b'C'; PAGE_SIZE_USIZE];
        gm.copy_from_slice(&page0_v2, 0).unwrap();
        let snapshot3 = Arc::new(
            super::SharedMemorySnapshot::new(&mut gm, 0, vec![], &[1], Some(snapshot2.clone()))
                .unwrap(),
        );

        // Clear memory and restore to snapshot3
        gm = ExclusiveSharedMemory::new(PAGE_SIZE_USIZE * 2).unwrap();
        snapshot3
            .restore_from_snapshot(&mut gm, &[], &None)
            .unwrap();

        let restored_data = gm.copy_all_to_vec().unwrap();

        // Page 0 should have snapshot3's value (most recent)
        assert_eq!(&restored_data[0..PAGE_SIZE_USIZE], &page0_v2);
        // Page 1 should have snapshot2's value (found in parent)
        assert_eq!(
            &restored_data[PAGE_SIZE_USIZE..PAGE_SIZE_USIZE * 2],
            &page1_v1
        );
    }

    #[test]
    fn test_ancestor_relationship() {
        let mut gm = ExclusiveSharedMemory::new(PAGE_SIZE_USIZE).unwrap();

        let snapshot1 =
            Arc::new(super::SharedMemorySnapshot::new(&mut gm, 0, vec![], &[], None).unwrap());
        let snapshot2 = Arc::new(
            super::SharedMemorySnapshot::new(&mut gm, 0, vec![], &[], Some(snapshot1.clone()))
                .unwrap(),
        );
        let snapshot3 = Arc::new(
            super::SharedMemorySnapshot::new(&mut gm, 0, vec![], &[], Some(snapshot2.clone()))
                .unwrap(),
        );

        // Test ancestor relationships
        assert!(snapshot1.is_ancestor_of(&snapshot2));
        assert!(snapshot1.is_ancestor_of(&snapshot3));
        assert!(snapshot2.is_ancestor_of(&snapshot3));

        // Test non-ancestor relationships
        assert!(!snapshot2.is_ancestor_of(&snapshot1));
        assert!(!snapshot3.is_ancestor_of(&snapshot1));
        assert!(!snapshot3.is_ancestor_of(&snapshot2));

        // Test self-relationship
        assert!(!snapshot1.is_ancestor_of(&snapshot1));
    }

    #[test]
    fn test_different_branches_error() {
        // Test error when trying to restore between snapshots on different branches
        let mut gm = ExclusiveSharedMemory::new(PAGE_SIZE_USIZE).unwrap();

        // Common ancestor
        let ancestor =
            Arc::new(super::SharedMemorySnapshot::new(&mut gm, 0, vec![], &[], None).unwrap());

        // Two different branches
        let branch1 = Arc::new(
            super::SharedMemorySnapshot::new(&mut gm, 0, vec![], &[], Some(ancestor.clone()))
                .unwrap(),
        );
        let branch2 = Arc::new(
            super::SharedMemorySnapshot::new(&mut gm, 0, vec![], &[], Some(ancestor.clone()))
                .unwrap(),
        );

        // Trying to restore between different branches should error
        let result = branch1.restore_from_snapshot(&mut gm, &[], &Some(branch2));
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("different branches")
        );
    }

    #[test]
    fn test_restore_to_same_snapshot() {
        // Test restoring to the same snapshot that is currently the most recent
        let mut gm = ExclusiveSharedMemory::new(PAGE_SIZE_USIZE * 2).unwrap();

        let page0_data = vec![b'X'; PAGE_SIZE_USIZE];
        gm.copy_from_slice(&page0_data, 0).unwrap();

        // Take a snapshot
        let snapshot =
            Arc::new(super::SharedMemorySnapshot::new(&mut gm, 0, vec![], &[1], None).unwrap());

        // Modify memory after snapshot
        let page1_data = vec![b'Y'; PAGE_SIZE_USIZE];
        gm.copy_from_slice(&page1_data, PAGE_SIZE_USIZE).unwrap();

        // Current dirty pages: page 1 is dirty
        let current_dirty = [2u64]; // page 1 is dirty

        // Restore to the same snapshot that is the most recent
        snapshot
            .restore_from_snapshot(&mut gm, &current_dirty, &Some(snapshot.clone()))
            .unwrap();

        let restored_data = gm.copy_all_to_vec().unwrap();

        // Page 0 should remain unchanged (it was the snapshot data)
        assert_eq!(&restored_data[0..PAGE_SIZE_USIZE], &page0_data);
        // Page 1 should be zeroed (it was dirty but not in the snapshot)
        assert_eq!(
            &restored_data[PAGE_SIZE_USIZE..PAGE_SIZE_USIZE * 2],
            &vec![0u8; PAGE_SIZE_USIZE]
        );
    }
}
