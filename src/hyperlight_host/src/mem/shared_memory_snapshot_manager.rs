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

use hyperlight_common::mem::{PAGE_SIZE_USIZE, PAGES_IN_BLOCK};
use tracing::{Span, instrument};

use super::page_snapshot::PageSnapshot;
use super::shared_mem::SharedMemory;
use crate::Result;
use crate::mem::bitmap::{bit_index_iterator, bitmap_union};
use crate::mem::layout::SandboxMemoryLayout;

/// A wrapper around a `SharedMemory` reference and a snapshot
/// of the memory therein
pub(super) struct SharedMemorySnapshotManager {
    /// A vector of snapshots, each snapshot contains only the dirty pages in a compact format
    /// The first snapshot is the initial state of the memory, subsequent snapshots after initialization
    /// snapshots are deltas from the previous state (i.e. only the dirty pages are stored)
    /// The initial snapshot is a delta from zeroing the memory on allocation
    snapshots: Vec<PageSnapshot>,
    /// The offsets of the input and output data buffers in the memory layout are stored
    /// this allows us to reset the input and output buffers to their initial state (i.e. zeroed)
    /// each time we restore from a snapshot
    input_data_size: usize,
    output_data_size: usize,
    output_data_buffer_offset: usize,
    input_data_buffer_offset: usize,
}

impl SharedMemorySnapshotManager {
    /// Take a snapshot of the memory in `shared_mem`, then create a new
    /// instance of `Self` with the snapshot stored therein.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn new<S: SharedMemory>(
        shared_mem: &mut S,
        dirty_page_map: Option<&Vec<u64>>,
        layout: &SandboxMemoryLayout,
    ) -> Result<Self> {
        // Build a snapshot of memory from the dirty_page_map

        let diff = Self::build_snapshot_from_dirty_page_map(shared_mem, dirty_page_map)?;

        // Get the input output buffer details from the layout so that they can be reset to their initial state
        let input_data_size_offset = layout.get_input_data_size_offset();
        let output_data_size_offset = layout.get_output_data_size_offset();
        let output_data_buffer_offset = layout.get_output_data_pointer_offset();
        let input_data_buffer_offset = layout.get_input_data_pointer_offset();

        // Read the input and output data sizes and pointers from memory
        let (
            input_data_size,
            output_data_size,
            output_data_buffer_offset,
            input_data_buffer_offset,
        ) = shared_mem.with_exclusivity(|e| -> Result<(usize, usize, usize, usize)> {
            Ok((
                e.read_usize(input_data_size_offset)?,
                e.read_usize(output_data_size_offset)?,
                e.read_usize(output_data_buffer_offset)?,
                e.read_usize(input_data_buffer_offset)?,
            ))
        })??;

        Ok(Self {
            snapshots: vec![diff],
            input_data_size,
            output_data_size,
            output_data_buffer_offset,
            input_data_buffer_offset,
        })
    }

    fn build_snapshot_from_dirty_page_map<S: SharedMemory>(
        shared_mem: &mut S,
        dirty_page_map: Option<&Vec<u64>>,
    ) -> Result<PageSnapshot> {
        // If there is no dirty page map, return an empty snapshot
        if dirty_page_map.is_none() {
            return Ok(PageSnapshot::new());
        }

        #[allow(clippy::unwrap_used)]
        let dirty_page_map = dirty_page_map.unwrap(); // unwrap is safe since we checked for None above

        // Should not happen, but just in case
        if dirty_page_map.is_empty() {
            return Ok(PageSnapshot::new());
        }

        let mut dirty_pages: Vec<usize> = bit_index_iterator(dirty_page_map).collect();

        // Pre-allocate buffer for all pages
        let page_count = dirty_pages.len();
        let total_size = page_count * PAGE_SIZE_USIZE;
        let mut buffer = vec![0u8; total_size];

        // if the total size is equal to the shared memory size, we can optimize the copy
        if total_size == shared_mem.mem_size() {
            // Copy the entire memory region in one go
            shared_mem.with_exclusivity(|e| e.copy_to_slice(&mut buffer, 0))??;
        } else {
            // Sort pages for deterministic ordering and to enable consecutive page optimization
            dirty_pages.sort_unstable();

            let mut buffer_offset = 0;
            let mut i = 0;

            while i < dirty_pages.len() {
                let start_page = dirty_pages[i];
                let mut consecutive_count = 1;

                // Find consecutive pages
                while i + consecutive_count < dirty_pages.len()
                    && dirty_pages[i + consecutive_count] == start_page + consecutive_count
                {
                    consecutive_count += 1;
                }

                // Calculate memory positions
                let memory_offset = start_page * PAGE_SIZE_USIZE;
                let copy_size = consecutive_count * PAGE_SIZE_USIZE;
                let buffer_end = buffer_offset + copy_size;

                // Single copy operation for consecutive pages directly into final buffer
                shared_mem.with_exclusivity(|e| {
                    e.copy_to_slice(&mut buffer[buffer_offset..buffer_end], memory_offset)
                })??;
                // copy_operations += 1;

                buffer_offset += copy_size;
                i += consecutive_count;
            }
        }

        // Create the snapshot with the pre-allocated buffer
        let snapshot = PageSnapshot::with_pages_and_buffer(dirty_pages, buffer);

        Ok(snapshot)
    }

    pub(super) fn create_new_snapshot<S: SharedMemory>(
        &mut self,
        shared_mem: &mut S,
        dirty_page_map: Option<&Vec<u64>>,
    ) -> Result<()> {
        let snapshot = Self::build_snapshot_from_dirty_page_map(shared_mem, dirty_page_map)?;
        self.snapshots.push(snapshot);
        Ok(())
    }

    /// Copy the memory from the internally-stored memory snapshot
    /// into the internally-stored `SharedMemory`
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn restore_from_snapshot<S: SharedMemory>(
        &mut self,
        shared_mem: &mut S,
        dirty_bitmap: &[u64],
    ) -> Result<()> {
        // check the each index in the dirty bitmap and restore only the corresponding pages from the snapshots vector
        // starting at the last snapshot look for the page in each snapshot if it exists and restore it
        // if it does not exist set the page to zero
        if self.snapshots.is_empty() {
            return Err(crate::HyperlightError::NoMemorySnapshot);
        }

        // Collect dirty pages and sort them for consecutive page optimization
        let mut dirty_pages: Vec<usize> = bit_index_iterator(dirty_bitmap).collect();
        dirty_pages.sort_unstable();

        let mut i = 0;
        while i < dirty_pages.len() {
            let start_page = dirty_pages[i];
            let mut consecutive_count = 1;

            // Find consecutive pages
            while i + consecutive_count < dirty_pages.len()
                && dirty_pages[i + consecutive_count] == start_page + consecutive_count
            {
                consecutive_count += 1;
            }

            // Build buffer for consecutive pages
            let mut buffer = vec![0u8; consecutive_count * PAGE_SIZE_USIZE];
            let mut buffer_offset = 0;

            for page_idx in 0..consecutive_count {
                let page = start_page + page_idx;

                // Check for the page in every snapshot starting from the last one
                for snapshot in self.snapshots.iter().rev() {
                    if let Some(data) = snapshot.get_page(page) {
                        buffer[buffer_offset..buffer_offset + PAGE_SIZE_USIZE]
                            .copy_from_slice(data);
                        break;
                    }
                }

                buffer_offset += PAGE_SIZE_USIZE;

                // If the page was not found in any snapshot, it will be now be zero in the buffer as we skip over it above and didnt write any data
                // This is the correct state as the page was not dirty in any snapshot which means it should be zeroed (the initial state)
            }

            // Single copy operation for all consecutive pages
            let memory_offset = start_page * PAGE_SIZE_USIZE;
            shared_mem.with_exclusivity(|e| e.copy_from_slice(&buffer, memory_offset))??;

            i += consecutive_count;
        }
        // Reset input/output buffers these need to set to their initial state each time a snapshot is restored to clear any previous io/data that may be in the buffers
        shared_mem.with_exclusivity(|e| {
            e.zero_fill(self.input_data_buffer_offset, self.input_data_size)?;
            e.zero_fill(self.output_data_buffer_offset, self.output_data_size)?;
            e.write_u64(
                self.input_data_buffer_offset,
                SandboxMemoryLayout::STACK_POINTER_SIZE_BYTES,
            )?;
            e.write_u64(
                self.output_data_buffer_offset,
                SandboxMemoryLayout::STACK_POINTER_SIZE_BYTES,
            )
        })?
    }

    pub(super) fn pop_and_restore_state_from_snapshot<S: SharedMemory>(
        &mut self,
        shared_mem: &mut S,
        dirty_bitmap: &[u64],
    ) -> Result<()> {
        // Check that there is a snapshot to restore from
        if self.snapshots.is_empty() {
            return Err(crate::HyperlightError::NoMemorySnapshot);
        }
        // Get the last snapshot index
        let last_snapshot_index = self.snapshots.len() - 1;
        let last_snapshot_bitmap = self.get_bitmap_from_snapshot(last_snapshot_index);
        // merge the last snapshot bitmap with the dirty bitmap
        let merged_bitmap = bitmap_union(&last_snapshot_bitmap, dirty_bitmap);

        // drop the last snapshot then restore the state from the merged bitmap
        if self.snapshots.pop().is_none() {
            return Err(crate::HyperlightError::NoMemorySnapshot);
        }

        // restore the state from the last snapshot
        self.restore_from_snapshot(shared_mem, &merged_bitmap)?;

        Ok(())
    }

    fn get_bitmap_from_snapshot(&self, snapshot_index: usize) -> Vec<u64> {
        // Get the snapshot at the given index
        if snapshot_index < self.snapshots.len() {
            let snapshot = &self.snapshots[snapshot_index];
            // Create a bitmap from the snapshot
            let max_page = snapshot.max_page().unwrap_or_default();
            let num_blocks = max_page.div_ceil(PAGES_IN_BLOCK);
            let mut bitmap = vec![0u64; num_blocks];
            for page in snapshot.page_numbers() {
                let block = page / PAGES_IN_BLOCK;
                let offset = page % PAGES_IN_BLOCK;
                if block < bitmap.len() {
                    bitmap[block] |= 1 << offset;
                }
            }
            bitmap
        } else {
            vec![]
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperlight_common::mem::PAGE_SIZE_USIZE;

    use super::super::layout::SandboxMemoryLayout;
    use crate::mem::bitmap::new_page_bitmap;
    use crate::mem::shared_mem::{ExclusiveSharedMemory, SharedMemory};
    use crate::sandbox::SandboxConfiguration;

    fn create_test_layout() -> SandboxMemoryLayout {
        let cfg = SandboxConfiguration::default();
        // Create a layout with large init_data area for testing (64KB for plenty of test pages)
        let init_data_size = 64 * 1024; // 64KB = 16 pages of 4KB each
        SandboxMemoryLayout::new(cfg, 4096, 16384, 16384, init_data_size, None).unwrap()
    }

    fn create_test_shared_memory_with_layout(
        layout: &SandboxMemoryLayout,
    ) -> ExclusiveSharedMemory {
        let memory_size = layout.get_memory_size().unwrap();
        let mut shared_mem = ExclusiveSharedMemory::new(memory_size).unwrap();

        // Initialize the memory with the full layout to ensure it's properly set up
        layout
            .write(
                &mut shared_mem,
                SandboxMemoryLayout::BASE_ADDRESS,
                memory_size,
            )
            .unwrap();

        shared_mem
    }

    /// Get safe memory area for testing - uses init_data area which is safe to modify
    fn get_safe_test_area(
        layout: &SandboxMemoryLayout,
        shared_mem: &mut ExclusiveSharedMemory,
    ) -> (usize, usize) {
        // The init_data area is positioned after the guest stack in the memory layout
        // We can safely use this area for testing as it's designed for initialization data
        // Read the actual init_data buffer offset and size from memory
        let init_data_size_offset = layout.get_init_data_size_offset();
        let init_data_pointer_offset = layout.get_init_data_pointer_offset();

        let (init_data_size, init_data_buffer_offset) = shared_mem
            .with_exclusivity(|e| -> crate::Result<(usize, usize)> {
                Ok((
                    e.read_usize(init_data_size_offset)?,
                    e.read_usize(init_data_pointer_offset)?,
                ))
            })
            .unwrap()
            .unwrap();

        (init_data_buffer_offset, init_data_size)
    }

    #[test]
    fn test_single_snapshot_restore() {
        let layout = create_test_layout();
        let mut shared_mem = create_test_shared_memory_with_layout(&layout);

        // Get safe init_data area for testing
        let (init_data_offset, init_data_size) = get_safe_test_area(&layout, &mut shared_mem);

        // Use a safe page well within the init_data area
        let safe_offset = init_data_offset + PAGE_SIZE_USIZE; // Skip first page for extra safety

        // Ensure we have enough space for testing
        assert!(
            init_data_size >= 2 * PAGE_SIZE_USIZE,
            "Init data area too small for testing: {} bytes",
            init_data_size
        );
        assert!(
            safe_offset + PAGE_SIZE_USIZE <= init_data_offset + init_data_size,
            "Safe offset exceeds init_data bounds"
        );

        // Start tracking dirty pages
        let tracker = shared_mem.start_tracking_dirty_pages().unwrap();

        // Initial data - only initialize safe page, leave other pages as zero
        let initial_data = vec![0xAA; PAGE_SIZE_USIZE];
        shared_mem
            .copy_from_slice(&initial_data, safe_offset)
            .unwrap();

        // Stop tracking and get dirty pages bitmap
        shared_mem.stop_tracking_dirty_pages(tracker).unwrap();
        let dirty_pages_vec = shared_mem
            .get_and_clear_host_dirty_page_map()
            .unwrap()
            .unwrap_or_default();

        // Convert to bitmap format
        let mut dirty_pages = new_page_bitmap(shared_mem.mem_size(), false).unwrap();
        for page_idx in dirty_pages_vec {
            let block = page_idx / 64;
            let bit = page_idx % 64;
            if block < dirty_pages.len() {
                dirty_pages[block] |= 1 << bit;
            }
        }

        // Create snapshot
        let mut snapshot_manager =
            super::SharedMemorySnapshotManager::new(&mut shared_mem, Some(&dirty_pages), &layout)
                .unwrap();

        // Modify memory
        let modified_data = vec![0xBB; PAGE_SIZE_USIZE];
        shared_mem
            .copy_from_slice(&modified_data, safe_offset)
            .unwrap();

        // Verify modification
        let mut current_data = vec![0u8; PAGE_SIZE_USIZE];
        shared_mem
            .copy_to_slice(&mut current_data, safe_offset)
            .unwrap();
        assert_eq!(current_data, modified_data);

        // Restore from snapshot
        snapshot_manager
            .restore_from_snapshot(&mut shared_mem, &dirty_pages)
            .unwrap();

        // Verify restoration
        let mut restored_data = vec![0u8; PAGE_SIZE_USIZE];
        shared_mem
            .copy_to_slice(&mut restored_data, safe_offset)
            .unwrap();
        assert_eq!(restored_data, initial_data);
    }

    #[test]
    fn test_multiple_snapshots_and_restores() {
        let layout = create_test_layout();
        let mut shared_mem = create_test_shared_memory_with_layout(&layout);

        // Get safe init_data area for testing
        let (init_data_offset, init_data_size) = get_safe_test_area(&layout, &mut shared_mem);

        // Use a safe page well within the init_data area
        let safe_offset = init_data_offset + PAGE_SIZE_USIZE; // Skip first page for extra safety

        // Ensure we have enough space for testing
        assert!(
            init_data_size >= 2 * PAGE_SIZE_USIZE,
            "Init data area too small for testing"
        );
        assert!(
            safe_offset + PAGE_SIZE_USIZE <= init_data_offset + init_data_size,
            "Safe offset exceeds init_data bounds"
        );

        // Start tracking dirty pages
        let tracker = shared_mem.start_tracking_dirty_pages().unwrap();

        // State 1: Initial state
        let state1_data = vec![0x11; PAGE_SIZE_USIZE];
        shared_mem
            .copy_from_slice(&state1_data, safe_offset)
            .unwrap();

        // Stop tracking and get dirty pages bitmap
        shared_mem.stop_tracking_dirty_pages(tracker).unwrap();
        let dirty_pages_vec = shared_mem
            .get_and_clear_host_dirty_page_map()
            .unwrap()
            .unwrap_or_default();

        // Convert to bitmap format
        let mut dirty_pages = new_page_bitmap(shared_mem.mem_size(), false).unwrap();
        for page_idx in dirty_pages_vec {
            let block = page_idx / 64;
            let bit = page_idx % 64;
            if block < dirty_pages.len() {
                dirty_pages[block] |= 1 << bit;
            }
        }

        // Create initial snapshot (State 1)
        let mut snapshot_manager =
            super::SharedMemorySnapshotManager::new(&mut shared_mem, Some(&dirty_pages), &layout)
                .unwrap();

        // State 2: Modify and create second snapshot
        let tracker2 = shared_mem.start_tracking_dirty_pages().unwrap();
        let state2_data = vec![0x22; PAGE_SIZE_USIZE];
        shared_mem
            .copy_from_slice(&state2_data, safe_offset)
            .unwrap();
        shared_mem.stop_tracking_dirty_pages(tracker2).unwrap();
        let dirty_pages_vec2 = shared_mem
            .get_and_clear_host_dirty_page_map()
            .unwrap()
            .unwrap_or_default();

        let mut dirty_pages2 = new_page_bitmap(shared_mem.mem_size(), false).unwrap();
        for page_idx in dirty_pages_vec2 {
            let block = page_idx / 64;
            let bit = page_idx % 64;
            if block < dirty_pages2.len() {
                dirty_pages2[block] |= 1 << bit;
            }
        }

        snapshot_manager
            .create_new_snapshot(&mut shared_mem, Some(&dirty_pages2))
            .unwrap();

        // State 3: Modify again
        let state3_data = vec![0x33; PAGE_SIZE_USIZE];
        shared_mem
            .copy_from_slice(&state3_data, safe_offset)
            .unwrap();

        // Verify we're in state 3
        let mut current_data = vec![0u8; PAGE_SIZE_USIZE];
        shared_mem
            .copy_to_slice(&mut current_data, safe_offset)
            .unwrap();
        assert_eq!(current_data, state3_data);

        // Restore to state 2 (most recent snapshot)
        snapshot_manager
            .restore_from_snapshot(&mut shared_mem, &dirty_pages2)
            .unwrap();
        let mut restored_data_state2 = vec![0u8; PAGE_SIZE_USIZE];
        shared_mem
            .copy_to_slice(&mut restored_data_state2, safe_offset)
            .unwrap();
        assert_eq!(restored_data_state2, state2_data);

        // Pop state 2 and restore to state 1
        snapshot_manager
            .pop_and_restore_state_from_snapshot(&mut shared_mem, &dirty_pages)
            .unwrap();
        let mut restored_data_state1 = vec![0u8; PAGE_SIZE_USIZE];
        shared_mem
            .copy_to_slice(&mut restored_data_state1, safe_offset)
            .unwrap();
        assert_eq!(restored_data_state1, state1_data);
    }

    #[test]
    fn test_multiple_pages_snapshot_restore() {
        let layout = create_test_layout();
        let mut shared_mem = create_test_shared_memory_with_layout(&layout);

        // Get safe init_data area for testing
        let (init_data_offset, init_data_size) = get_safe_test_area(&layout, &mut shared_mem);

        // Ensure we have enough space for 4 test pages
        assert!(
            init_data_size >= 6 * PAGE_SIZE_USIZE,
            "Init data area too small for testing multiple pages"
        );

        // Use page offsets within the init_data area, skipping first page for safety
        let base_page = (init_data_offset + PAGE_SIZE_USIZE) / PAGE_SIZE_USIZE;
        let page_offsets = [base_page, base_page + 1, base_page + 2, base_page + 3];

        let page_data = [
            vec![0xAA; PAGE_SIZE_USIZE],
            vec![0xBB; PAGE_SIZE_USIZE],
            vec![0xCC; PAGE_SIZE_USIZE],
            vec![0xDD; PAGE_SIZE_USIZE],
        ];

        // Start tracking dirty pages
        let tracker = shared_mem.start_tracking_dirty_pages().unwrap();

        // Initialize data in init_data pages
        for (i, &page_offset) in page_offsets.iter().enumerate() {
            let offset = page_offset * PAGE_SIZE_USIZE;
            assert!(
                offset + PAGE_SIZE_USIZE <= shared_mem.mem_size(),
                "Page offset {} exceeds memory bounds",
                page_offset
            );
            assert!(
                offset >= init_data_offset
                    && offset + PAGE_SIZE_USIZE <= init_data_offset + init_data_size,
                "Page offset {} is outside init_data bounds",
                page_offset
            );
            shared_mem.copy_from_slice(&page_data[i], offset).unwrap();
        }

        // Stop tracking and get dirty pages bitmap
        shared_mem.stop_tracking_dirty_pages(tracker).unwrap();
        let dirty_pages_vec = shared_mem
            .get_and_clear_host_dirty_page_map()
            .unwrap()
            .unwrap_or_default();

        // Convert to bitmap format
        let mut dirty_pages = new_page_bitmap(shared_mem.mem_size(), false).unwrap();
        for page_idx in dirty_pages_vec {
            let block = page_idx / 64;
            let bit = page_idx % 64;
            if block < dirty_pages.len() {
                dirty_pages[block] |= 1 << bit;
            }
        }

        // Create snapshot
        let mut snapshot_manager =
            super::SharedMemorySnapshotManager::new(&mut shared_mem, Some(&dirty_pages), &layout)
                .unwrap();

        // Modify first and third pages
        let modified_data = [vec![0x11; PAGE_SIZE_USIZE], vec![0x22; PAGE_SIZE_USIZE]];
        shared_mem
            .copy_from_slice(&modified_data[0], page_offsets[0] * PAGE_SIZE_USIZE)
            .unwrap();
        shared_mem
            .copy_from_slice(&modified_data[1], page_offsets[2] * PAGE_SIZE_USIZE)
            .unwrap();

        // Restore from snapshot
        snapshot_manager
            .restore_from_snapshot(&mut shared_mem, &dirty_pages)
            .unwrap();

        // Verify restoration
        for (i, &page_offset) in page_offsets.iter().enumerate() {
            let mut restored_data = vec![0u8; PAGE_SIZE_USIZE];
            shared_mem
                .copy_to_slice(&mut restored_data, page_offset * PAGE_SIZE_USIZE)
                .unwrap();
            assert_eq!(
                restored_data, page_data[i],
                "Page {} should be restored to original data",
                i
            );
        }
    }

    #[test]
    fn test_sequential_modifications_with_snapshots() {
        let layout = create_test_layout();
        let mut shared_mem = create_test_shared_memory_with_layout(&layout);

        // Get safe init_data area for testing
        let (init_data_offset, init_data_size) = get_safe_test_area(&layout, &mut shared_mem);

        // Use safe page offsets within init_data area
        let safe_offset1 = init_data_offset + PAGE_SIZE_USIZE; // Skip first page for safety
        let safe_offset2 = init_data_offset + 2 * PAGE_SIZE_USIZE;

        // Ensure we have enough space for testing
        assert!(
            init_data_size >= 3 * PAGE_SIZE_USIZE,
            "Init data area too small for testing"
        );
        assert!(
            safe_offset2 + PAGE_SIZE_USIZE <= init_data_offset + init_data_size,
            "Safe offsets exceed init_data bounds"
        );

        // Start tracking dirty pages
        let tracker1 = shared_mem.start_tracking_dirty_pages().unwrap();

        // Cycle 1: Set initial data
        let cycle1_page0 = (0..PAGE_SIZE_USIZE)
            .map(|i| (i % 256) as u8)
            .collect::<Vec<u8>>();
        let cycle1_page1 = vec![0x01; PAGE_SIZE_USIZE];
        shared_mem
            .copy_from_slice(&cycle1_page0, safe_offset1)
            .unwrap();
        shared_mem
            .copy_from_slice(&cycle1_page1, safe_offset2)
            .unwrap();

        // Stop tracking and get dirty pages bitmap
        shared_mem.stop_tracking_dirty_pages(tracker1).unwrap();
        let dirty_pages_vec1 = shared_mem
            .get_and_clear_host_dirty_page_map()
            .unwrap()
            .unwrap_or_default();

        // Convert to bitmap format
        let mut dirty_pages = new_page_bitmap(shared_mem.mem_size(), false).unwrap();
        for page_idx in dirty_pages_vec1 {
            let block = page_idx / 64;
            let bit = page_idx % 64;
            if block < dirty_pages.len() {
                dirty_pages[block] |= 1 << bit;
            }
        }

        let mut snapshot_manager =
            super::SharedMemorySnapshotManager::new(&mut shared_mem, Some(&dirty_pages), &layout)
                .unwrap();

        // Cycle 2: Modify and snapshot
        let tracker2 = shared_mem.start_tracking_dirty_pages().unwrap();
        let cycle2_page0 = vec![0x02; PAGE_SIZE_USIZE];
        let cycle2_page1 = (0..PAGE_SIZE_USIZE)
            .map(|i| ((i + 100) % 256) as u8)
            .collect::<Vec<u8>>();
        shared_mem
            .copy_from_slice(&cycle2_page0, safe_offset1)
            .unwrap();
        shared_mem
            .copy_from_slice(&cycle2_page1, safe_offset2)
            .unwrap();

        shared_mem.stop_tracking_dirty_pages(tracker2).unwrap();
        let dirty_pages_vec2 = shared_mem
            .get_and_clear_host_dirty_page_map()
            .unwrap()
            .unwrap_or_default();

        let mut dirty_pages2 = new_page_bitmap(shared_mem.mem_size(), false).unwrap();
        for page_idx in dirty_pages_vec2 {
            let block = page_idx / 64;
            let bit = page_idx % 64;
            if block < dirty_pages2.len() {
                dirty_pages2[block] |= 1 << bit;
            }
        }

        snapshot_manager
            .create_new_snapshot(&mut shared_mem, Some(&dirty_pages2))
            .unwrap();

        // Cycle 3: Modify again
        let cycle3_page0 = vec![0x03; PAGE_SIZE_USIZE];
        let cycle3_page1 = vec![0x33; PAGE_SIZE_USIZE];
        shared_mem
            .copy_from_slice(&cycle3_page0, safe_offset1)
            .unwrap();
        shared_mem
            .copy_from_slice(&cycle3_page1, safe_offset2)
            .unwrap();

        // Verify current state (cycle 3)
        let mut current_page0 = vec![0u8; PAGE_SIZE_USIZE];
        shared_mem
            .copy_to_slice(&mut current_page0, safe_offset1)
            .unwrap();
        let mut current_page1 = vec![0u8; PAGE_SIZE_USIZE];
        shared_mem
            .copy_to_slice(&mut current_page1, safe_offset2)
            .unwrap();
        assert_eq!(current_page0, cycle3_page0);
        assert_eq!(current_page1, cycle3_page1);

        // Restore to cycle 2
        snapshot_manager
            .restore_from_snapshot(&mut shared_mem, &dirty_pages2)
            .unwrap();
        let mut restored_page0 = vec![0u8; PAGE_SIZE_USIZE];
        shared_mem
            .copy_to_slice(&mut restored_page0, safe_offset1)
            .unwrap();
        let mut restored_page1 = vec![0u8; PAGE_SIZE_USIZE];
        shared_mem
            .copy_to_slice(&mut restored_page1, safe_offset2)
            .unwrap();
        assert_eq!(restored_page0, cycle2_page0);
        assert_eq!(restored_page1, cycle2_page1);

        // Pop cycle 2 and restore to cycle 1
        snapshot_manager
            .pop_and_restore_state_from_snapshot(&mut shared_mem, &dirty_pages)
            .unwrap();
        let mut restored_page0 = vec![0u8; PAGE_SIZE_USIZE];
        shared_mem
            .copy_to_slice(&mut restored_page0, safe_offset1)
            .unwrap();
        let mut restored_page1 = vec![0u8; PAGE_SIZE_USIZE];
        shared_mem
            .copy_to_slice(&mut restored_page1, safe_offset2)
            .unwrap();
        assert_eq!(restored_page0, cycle1_page0);
        assert_eq!(restored_page1, cycle1_page1);
    }

    #[test]
    fn test_restore_with_zero_pages() {
        let layout = create_test_layout();
        let mut shared_mem = create_test_shared_memory_with_layout(&layout);

        // Get safe init_data area for testing
        let (init_data_offset, init_data_size) = get_safe_test_area(&layout, &mut shared_mem);

        // Ensure we have enough space for testing
        assert!(
            init_data_size >= 3 * PAGE_SIZE_USIZE,
            "Init data area too small for testing"
        );

        // Start tracking dirty pages
        let tracker = shared_mem.start_tracking_dirty_pages().unwrap();

        // Only initialize one page in the init_data area
        let page1_offset = init_data_offset + PAGE_SIZE_USIZE; // Skip first page for safety
        let page1_data = vec![0xFF; PAGE_SIZE_USIZE];
        shared_mem
            .copy_from_slice(&page1_data, page1_offset)
            .unwrap();

        // Stop tracking and get dirty pages bitmap
        shared_mem.stop_tracking_dirty_pages(tracker).unwrap();
        let dirty_pages_vec = shared_mem
            .get_and_clear_host_dirty_page_map()
            .unwrap()
            .unwrap_or_default();

        // Convert to bitmap format
        let mut dirty_pages_snapshot = new_page_bitmap(shared_mem.mem_size(), false).unwrap();
        for page_idx in dirty_pages_vec {
            let block = page_idx / 64;
            let bit = page_idx % 64;
            if block < dirty_pages_snapshot.len() {
                dirty_pages_snapshot[block] |= 1 << bit;
            }
        }

        let mut snapshot_manager = super::SharedMemorySnapshotManager::new(
            &mut shared_mem,
            Some(&dirty_pages_snapshot),
            &layout,
        )
        .unwrap();

        // Modify pages in init_data area
        let page0_offset = init_data_offset;
        let page2_offset = init_data_offset + 2 * PAGE_SIZE_USIZE;

        let modified_page0 = vec![0xAA; PAGE_SIZE_USIZE];
        let modified_page1 = vec![0xBB; PAGE_SIZE_USIZE];
        let modified_page2 = vec![0xCC; PAGE_SIZE_USIZE];
        shared_mem
            .copy_from_slice(&modified_page0, page0_offset)
            .unwrap();
        shared_mem
            .copy_from_slice(&modified_page1, page1_offset)
            .unwrap();
        shared_mem
            .copy_from_slice(&modified_page2, page2_offset)
            .unwrap();

        // Create dirty page map for all test pages
        let mut dirty_pages_restore = new_page_bitmap(shared_mem.mem_size(), false).unwrap();
        let page0_idx = page0_offset / PAGE_SIZE_USIZE;
        let page1_idx = page1_offset / PAGE_SIZE_USIZE;
        let page2_idx = page2_offset / PAGE_SIZE_USIZE;

        // Mark all test pages as dirty for restore
        for &page_idx in &[page0_idx, page1_idx, page2_idx] {
            let block = page_idx / 64;
            let bit = page_idx % 64;
            if block < dirty_pages_restore.len() {
                dirty_pages_restore[block] |= 1 << bit;
            }
        }

        // Restore from snapshot
        snapshot_manager
            .restore_from_snapshot(&mut shared_mem, &dirty_pages_restore)
            .unwrap();

        // Verify restoration
        let mut restored_page0 = vec![0u8; PAGE_SIZE_USIZE];
        shared_mem
            .copy_to_slice(&mut restored_page0, page0_offset)
            .unwrap();
        let mut restored_page1 = vec![0u8; PAGE_SIZE_USIZE];
        shared_mem
            .copy_to_slice(&mut restored_page1, page1_offset)
            .unwrap();
        let mut restored_page2 = vec![0u8; PAGE_SIZE_USIZE];
        shared_mem
            .copy_to_slice(&mut restored_page2, page2_offset)
            .unwrap();

        // Page 0 and 2 should be zeroed (not in snapshot), page 1 should be restored
        assert_eq!(restored_page0, vec![0u8; PAGE_SIZE_USIZE]);
        assert_eq!(restored_page1, page1_data);
        assert_eq!(restored_page2, vec![0u8; PAGE_SIZE_USIZE]);
    }

    #[test]
    fn test_empty_snapshot_error() {
        let layout = create_test_layout();
        let mut shared_mem = create_test_shared_memory_with_layout(&layout);
        let memory_size = shared_mem.mem_size();

        // Create snapshot manager with no snapshots
        let mut snapshot_manager = super::SharedMemorySnapshotManager {
            snapshots: vec![],
            input_data_size: 0,
            output_data_size: 0,
            output_data_buffer_offset: 0,
            input_data_buffer_offset: 0,
        };

        let dirty_pages = new_page_bitmap(memory_size, true).unwrap();

        // Should return error when trying to restore from empty snapshots
        let result = snapshot_manager.restore_from_snapshot(&mut shared_mem, &dirty_pages);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::HyperlightError::NoMemorySnapshot
        ));

        // Should return error when trying to pop from empty snapshots
        let result =
            snapshot_manager.pop_and_restore_state_from_snapshot(&mut shared_mem, &dirty_pages);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::HyperlightError::NoMemorySnapshot
        ));
    }

    #[test]
    fn test_complex_workflow_simulation() {
        let layout = create_test_layout();
        let mut shared_mem = create_test_shared_memory_with_layout(&layout);

        // Get safe init_data area for testing
        let (init_data_offset, init_data_size) = get_safe_test_area(&layout, &mut shared_mem);

        // Ensure we have enough space for 4 test pages
        assert!(
            init_data_size >= 6 * PAGE_SIZE_USIZE,
            "Init data area too small for testing"
        );

        // Start tracking dirty pages
        let tracker = shared_mem.start_tracking_dirty_pages().unwrap();

        // Use the init_data area - this is safe and won't interfere with other layout structures
        let base_page = (init_data_offset + PAGE_SIZE_USIZE) / PAGE_SIZE_USIZE; // Skip first page for safety
        let page_offsets = [base_page, base_page + 1, base_page + 2, base_page + 3];

        // Initialize memory with pattern in init_data area
        for (i, &page_offset) in page_offsets.iter().enumerate() {
            let data = vec![i as u8; PAGE_SIZE_USIZE];
            let offset = page_offset * PAGE_SIZE_USIZE;
            assert!(
                offset + PAGE_SIZE_USIZE <= shared_mem.mem_size(),
                "Page offset {} exceeds memory bounds",
                page_offset
            );
            assert!(
                offset >= init_data_offset
                    && offset + PAGE_SIZE_USIZE <= init_data_offset + init_data_size,
                "Page offset {} is outside init_data bounds",
                page_offset
            );
            shared_mem.copy_from_slice(&data, offset).unwrap();
        }

        // Stop tracking and get dirty pages bitmap
        shared_mem.stop_tracking_dirty_pages(tracker).unwrap();
        let dirty_pages_vec = shared_mem
            .get_and_clear_host_dirty_page_map()
            .unwrap()
            .unwrap_or_default();

        // Convert to bitmap format
        let mut dirty_pages = new_page_bitmap(shared_mem.mem_size(), false).unwrap();
        for page_idx in dirty_pages_vec {
            let block = page_idx / 64;
            let bit = page_idx % 64;
            if block < dirty_pages.len() {
                dirty_pages[block] |= 1 << bit;
            }
        }

        // Create initial checkpoint
        let mut snapshot_manager =
            super::SharedMemorySnapshotManager::new(&mut shared_mem, Some(&dirty_pages), &layout)
                .unwrap();

        // Simulate function call 1: modify pages 0 and 2
        let tracker1 = shared_mem.start_tracking_dirty_pages().unwrap();
        let func1_page0 = vec![0x10; PAGE_SIZE_USIZE];
        let func1_page2 = vec![0x12; PAGE_SIZE_USIZE];
        shared_mem
            .copy_from_slice(&func1_page0, page_offsets[0] * PAGE_SIZE_USIZE)
            .unwrap();
        shared_mem
            .copy_from_slice(&func1_page2, page_offsets[2] * PAGE_SIZE_USIZE)
            .unwrap();

        shared_mem.stop_tracking_dirty_pages(tracker1).unwrap();
        let dirty_pages_vec1 = shared_mem
            .get_and_clear_host_dirty_page_map()
            .unwrap()
            .unwrap_or_default();

        let mut dirty_pages1 = new_page_bitmap(shared_mem.mem_size(), false).unwrap();
        for page_idx in dirty_pages_vec1 {
            let block = page_idx / 64;
            let bit = page_idx % 64;
            if block < dirty_pages1.len() {
                dirty_pages1[block] |= 1 << bit;
            }
        }

        // Checkpoint after function 1
        snapshot_manager
            .create_new_snapshot(&mut shared_mem, Some(&dirty_pages1))
            .unwrap();

        // Simulate function call 2: modify pages 1 and 3
        let tracker2 = shared_mem.start_tracking_dirty_pages().unwrap();
        let func2_page1 = vec![0x21; PAGE_SIZE_USIZE];
        let func2_page3 = vec![0x23; PAGE_SIZE_USIZE];
        shared_mem
            .copy_from_slice(&func2_page1, page_offsets[1] * PAGE_SIZE_USIZE)
            .unwrap();
        shared_mem
            .copy_from_slice(&func2_page3, page_offsets[3] * PAGE_SIZE_USIZE)
            .unwrap();

        shared_mem.stop_tracking_dirty_pages(tracker2).unwrap();
        let dirty_pages_vec2 = shared_mem
            .get_and_clear_host_dirty_page_map()
            .unwrap()
            .unwrap_or_default();

        let mut dirty_pages2 = new_page_bitmap(shared_mem.mem_size(), false).unwrap();
        for page_idx in dirty_pages_vec2 {
            let block = page_idx / 64;
            let bit = page_idx % 64;
            if block < dirty_pages2.len() {
                dirty_pages2[block] |= 1 << bit;
            }
        }

        // Checkpoint after function 2
        snapshot_manager
            .create_new_snapshot(&mut shared_mem, Some(&dirty_pages2))
            .unwrap();

        // Simulate function call 3: modify all pages
        for (i, &page_offset) in page_offsets.iter().enumerate() {
            let data = vec![0x30 + i as u8; PAGE_SIZE_USIZE];
            shared_mem
                .copy_from_slice(&data, page_offset * PAGE_SIZE_USIZE)
                .unwrap();
        }

        // Verify current state (after function 3)
        for (i, &page_offset) in page_offsets.iter().enumerate() {
            let mut current = vec![0u8; PAGE_SIZE_USIZE];
            shared_mem
                .copy_to_slice(&mut current, page_offset * PAGE_SIZE_USIZE)
                .unwrap();
            let expected = vec![0x30 + i as u8; PAGE_SIZE_USIZE];
            assert_eq!(current, expected);
        }

        // Create a bitmap that includes all pages that were modified in function 3
        let mut dirty_pages_all_func3 = new_page_bitmap(shared_mem.mem_size(), false).unwrap();
        for &page_offset in &page_offsets {
            let block = page_offset / 64;
            let bit = page_offset % 64;
            if block < dirty_pages_all_func3.len() {
                dirty_pages_all_func3[block] |= 1 << bit;
            }
        }

        // Rollback to after function 2
        snapshot_manager
            .restore_from_snapshot(&mut shared_mem, &dirty_pages_all_func3)
            .unwrap();

        // Verify state after function 2
        let mut page0_after_func2 = vec![0u8; PAGE_SIZE_USIZE];
        shared_mem
            .copy_to_slice(&mut page0_after_func2, page_offsets[0] * PAGE_SIZE_USIZE)
            .unwrap();
        assert_eq!(page0_after_func2, func1_page0);

        let mut page1_after_func2 = vec![0u8; PAGE_SIZE_USIZE];
        shared_mem
            .copy_to_slice(&mut page1_after_func2, page_offsets[1] * PAGE_SIZE_USIZE)
            .unwrap();
        assert_eq!(page1_after_func2, func2_page1);

        let mut page2_after_func2 = vec![0u8; PAGE_SIZE_USIZE];
        shared_mem
            .copy_to_slice(&mut page2_after_func2, page_offsets[2] * PAGE_SIZE_USIZE)
            .unwrap();
        assert_eq!(page2_after_func2, func1_page2);

        let mut page3_after_func2 = vec![0u8; PAGE_SIZE_USIZE];
        shared_mem
            .copy_to_slice(&mut page3_after_func2, page_offsets[3] * PAGE_SIZE_USIZE)
            .unwrap();
        assert_eq!(page3_after_func2, func2_page3);

        // Rollback to after function 1
        // Need to create a bitmap that includes all pages that could have been modified
        let mut combined_dirty_pages1 = dirty_pages.clone();
        for i in 0..combined_dirty_pages1.len().min(dirty_pages1.len()) {
            combined_dirty_pages1[i] |= dirty_pages1[i];
        }
        for i in 0..combined_dirty_pages1.len().min(dirty_pages2.len()) {
            combined_dirty_pages1[i] |= dirty_pages2[i];
        }

        snapshot_manager
            .pop_and_restore_state_from_snapshot(&mut shared_mem, &combined_dirty_pages1)
            .unwrap();

        // Verify state after function 1
        let mut page0_after_func1 = vec![0u8; PAGE_SIZE_USIZE];
        shared_mem
            .copy_to_slice(&mut page0_after_func1, page_offsets[0] * PAGE_SIZE_USIZE)
            .unwrap();
        assert_eq!(page0_after_func1, func1_page0);

        let mut page1_after_func1 = vec![0u8; PAGE_SIZE_USIZE];
        shared_mem
            .copy_to_slice(&mut page1_after_func1, page_offsets[1] * PAGE_SIZE_USIZE)
            .unwrap();
        assert_eq!(page1_after_func1, vec![1u8; PAGE_SIZE_USIZE]); // Original

        let mut page2_after_func1 = vec![0u8; PAGE_SIZE_USIZE];
        shared_mem
            .copy_to_slice(&mut page2_after_func1, page_offsets[2] * PAGE_SIZE_USIZE)
            .unwrap();
        assert_eq!(page2_after_func1, func1_page2);

        let mut page3_after_func1 = vec![0u8; PAGE_SIZE_USIZE];
        shared_mem
            .copy_to_slice(&mut page3_after_func1, page_offsets[3] * PAGE_SIZE_USIZE)
            .unwrap();
        assert_eq!(page3_after_func1, vec![3u8; PAGE_SIZE_USIZE]); // Original

        // Rollback to initial state
        // Need to create a bitmap that includes all pages that could have been modified
        let mut combined_dirty_pages_all = dirty_pages.clone();
        for i in 0..combined_dirty_pages_all.len().min(dirty_pages1.len()) {
            combined_dirty_pages_all[i] |= dirty_pages1[i];
        }
        for i in 0..combined_dirty_pages_all.len().min(dirty_pages2.len()) {
            combined_dirty_pages_all[i] |= dirty_pages2[i];
        }

        snapshot_manager
            .pop_and_restore_state_from_snapshot(&mut shared_mem, &combined_dirty_pages_all)
            .unwrap();

        // Verify initial state
        for (i, &page_offset) in page_offsets.iter().enumerate() {
            let mut current = vec![0u8; PAGE_SIZE_USIZE];
            shared_mem
                .copy_to_slice(&mut current, page_offset * PAGE_SIZE_USIZE)
                .unwrap();
            let expected = vec![i as u8; PAGE_SIZE_USIZE];
            assert_eq!(current, expected);
        }
    }

    #[test]
    fn test_unchanged_data_verification() {
        let layout = create_test_layout();
        let mut shared_mem = create_test_shared_memory_with_layout(&layout);

        // Get safe init_data area for testing
        let (init_data_offset, init_data_size) = get_safe_test_area(&layout, &mut shared_mem);

        // Ensure we have enough space for 6 test pages
        assert!(
            init_data_size >= 8 * PAGE_SIZE_USIZE,
            "Init data area too small for testing"
        );

        // Start tracking dirty pages
        let tracker = shared_mem.start_tracking_dirty_pages().unwrap();

        // Initialize all pages with different patterns - use safe offsets within init_data area
        let base_page = (init_data_offset + PAGE_SIZE_USIZE) / PAGE_SIZE_USIZE; // Skip first page for safety
        let page_offsets = [
            base_page,
            base_page + 1,
            base_page + 2,
            base_page + 3,
            base_page + 4,
            base_page + 5,
        ];
        let initial_patterns = [
            vec![0xAA; PAGE_SIZE_USIZE], // Page 0
            vec![0xBB; PAGE_SIZE_USIZE], // Page 1
            vec![0xCC; PAGE_SIZE_USIZE], // Page 2
            vec![0xDD; PAGE_SIZE_USIZE], // Page 3
            vec![0xEE; PAGE_SIZE_USIZE], // Page 4
            vec![0xFF; PAGE_SIZE_USIZE], // Page 5
        ];

        for (i, pattern) in initial_patterns.iter().enumerate() {
            let offset = page_offsets[i] * PAGE_SIZE_USIZE;
            assert!(
                offset + PAGE_SIZE_USIZE <= shared_mem.mem_size(),
                "Page offset {} exceeds memory bounds",
                page_offsets[i]
            );
            assert!(
                offset >= init_data_offset
                    && offset + PAGE_SIZE_USIZE <= init_data_offset + init_data_size,
                "Page offset {} is outside init_data bounds",
                page_offsets[i]
            );
            shared_mem.copy_from_slice(pattern, offset).unwrap();
        }

        // Stop tracking and get dirty pages bitmap
        shared_mem.stop_tracking_dirty_pages(tracker).unwrap();
        let dirty_pages_vec = shared_mem
            .get_and_clear_host_dirty_page_map()
            .unwrap()
            .unwrap_or_default();

        // Convert to bitmap format - only track specific pages (1, 3, 5)
        let mut dirty_pages = new_page_bitmap(shared_mem.mem_size(), false).unwrap();
        let tracked_pages = [1, 3, 5]; // Only track these pages for snapshot
        for &tracked_page_idx in &tracked_pages {
            let actual_page = page_offsets[tracked_page_idx];
            if dirty_pages_vec.contains(&actual_page) {
                let block = actual_page / 64;
                let bit = actual_page % 64;
                if block < dirty_pages.len() {
                    dirty_pages[block] |= 1 << bit;
                }
            }
        }

        // Create snapshot
        let mut snapshot_manager =
            super::SharedMemorySnapshotManager::new(&mut shared_mem, Some(&dirty_pages), &layout)
                .unwrap();

        // Modify only the dirty pages
        let modified_patterns = [
            vec![0x11; PAGE_SIZE_USIZE], // Page 1 modified
            vec![0x33; PAGE_SIZE_USIZE], // Page 3 modified
            vec![0x55; PAGE_SIZE_USIZE], // Page 5 modified
        ];

        shared_mem
            .copy_from_slice(&modified_patterns[0], page_offsets[1] * PAGE_SIZE_USIZE)
            .unwrap();
        shared_mem
            .copy_from_slice(&modified_patterns[1], page_offsets[3] * PAGE_SIZE_USIZE)
            .unwrap();
        shared_mem
            .copy_from_slice(&modified_patterns[2], page_offsets[5] * PAGE_SIZE_USIZE)
            .unwrap();

        // Verify that untracked pages (0, 2, 4) remain unchanged
        let unchanged_pages = [0, 2, 4];
        for &page_idx in &unchanged_pages {
            let mut current_data = vec![0u8; PAGE_SIZE_USIZE];
            shared_mem
                .copy_to_slice(&mut current_data, page_offsets[page_idx] * PAGE_SIZE_USIZE)
                .unwrap();
            assert_eq!(
                current_data, initial_patterns[page_idx],
                "Page {} should remain unchanged after modification",
                page_idx
            );
        }

        // Verify that tracked pages were modified
        let changed_pages = [
            (1, &modified_patterns[0]),
            (3, &modified_patterns[1]),
            (5, &modified_patterns[2]),
        ];
        for &(page_idx, expected) in &changed_pages {
            let mut current_data = vec![0u8; PAGE_SIZE_USIZE];
            shared_mem
                .copy_to_slice(&mut current_data, page_offsets[page_idx] * PAGE_SIZE_USIZE)
                .unwrap();
            assert_eq!(
                current_data, *expected,
                "Page {} should be modified",
                page_idx
            );
        }

        // Restore from snapshot
        snapshot_manager
            .restore_from_snapshot(&mut shared_mem, &dirty_pages)
            .unwrap();

        // Verify tracked pages are restored to their original state
        for &page_idx in &tracked_pages {
            let mut restored_data = vec![0u8; PAGE_SIZE_USIZE];
            shared_mem
                .copy_to_slice(&mut restored_data, page_offsets[page_idx] * PAGE_SIZE_USIZE)
                .unwrap();
            assert_eq!(
                restored_data, initial_patterns[page_idx],
                "Page {} should be restored to initial pattern after snapshot restore",
                page_idx
            );
        }

        // Test partial dirty bitmap restoration
        let mut partial_dirty = new_page_bitmap(shared_mem.mem_size(), false).unwrap();
        // Only mark page 1 as dirty for restoration
        let page1_actual = page_offsets[1];
        let block = page1_actual / 64;
        let bit = page1_actual % 64;
        if block < partial_dirty.len() {
            partial_dirty[block] |= 1 << bit;
        }

        // Modify multiple pages again
        shared_mem
            .copy_from_slice(&modified_patterns[0], page_offsets[1] * PAGE_SIZE_USIZE)
            .unwrap();
        shared_mem
            .copy_from_slice(&modified_patterns[1], page_offsets[3] * PAGE_SIZE_USIZE)
            .unwrap();

        // Restore with partial dirty bitmap (only page 1)
        snapshot_manager
            .restore_from_snapshot(&mut shared_mem, &partial_dirty)
            .unwrap();

        // Verify page 1 is restored but page 3 remains modified
        let mut page1_data = vec![0u8; PAGE_SIZE_USIZE];
        shared_mem
            .copy_to_slice(&mut page1_data, page_offsets[1] * PAGE_SIZE_USIZE)
            .unwrap();
        assert_eq!(page1_data, initial_patterns[1], "Page 1 should be restored");

        let mut page3_data = vec![0u8; PAGE_SIZE_USIZE];
        shared_mem
            .copy_to_slice(&mut page3_data, page_offsets[3] * PAGE_SIZE_USIZE)
            .unwrap();
        assert_eq!(
            page3_data, modified_patterns[1],
            "Page 3 should remain modified since it wasn't in restoration dirty bitmap"
        );

        // Verify all other pages remain in their expected state
        for page_idx in [0, 2, 4, 5] {
            let mut current_data = vec![0u8; PAGE_SIZE_USIZE];
            shared_mem
                .copy_to_slice(&mut current_data, page_offsets[page_idx] * PAGE_SIZE_USIZE)
                .unwrap();
            assert_eq!(
                current_data, initial_patterns[page_idx],
                "Page {} should remain in initial state",
                page_idx
            );
        }
    }
}
