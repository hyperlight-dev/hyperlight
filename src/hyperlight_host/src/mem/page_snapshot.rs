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

use std::collections::HashMap;

use hyperlight_common::mem::PAGE_SIZE_USIZE;

/// A compact snapshot representation that stores pages in a contiguous buffer
/// with an index for efficient lookup.
///
/// This struct is designed to efficiently store and retrieve memory snapshots
/// by using a contiguous buffer for all page data combined with a HashMap index
/// for page lookups. This approach reduces memory overhead
/// compared to storing pages individually.
///
/// # Clone Derivation
///
/// This struct derives `Clone` because it's stored in `Vec<PageSnapshot>` within
/// `SharedMemorySnapshotManager`, which itself derives `Clone`.
#[derive(Clone)]
pub(super) struct PageSnapshot {
    /// Maps page numbers to their offset within the buffer (in page units)
    page_index: HashMap<usize, usize>, // page_number -> buffer_offset_in_pages
    /// Contiguous buffer containing all the page data
    buffer: Vec<u8>,
}

impl PageSnapshot {
    /// Create a new empty snapshot
    pub(super) fn new() -> Self {
        Self {
            page_index: HashMap::new(),
            buffer: Vec::new(),
        }
    }

    /// Create a snapshot from a list of page numbers with pre-allocated buffer
    pub(super) fn with_pages_and_buffer(page_numbers: Vec<usize>, buffer: Vec<u8>) -> Self {
        let page_count = page_numbers.len();
        let mut page_index = HashMap::with_capacity(page_count);

        // Map each page number to its offset in the buffer
        for (buffer_offset, page_num) in page_numbers.into_iter().enumerate() {
            page_index.insert(page_num, buffer_offset);
        }

        Self { page_index, buffer }
    }

    /// Get page data by page number, returns None if page is not in snapshot
    pub(super) fn get_page(&self, page_num: usize) -> Option<&[u8]> {
        self.page_index.get(&page_num).map(|&buffer_offset| {
            let start = buffer_offset * PAGE_SIZE_USIZE;
            let end = start + PAGE_SIZE_USIZE;
            &self.buffer[start..end]
        })
    }

    /// Get an iterator over all page numbers in this snapshot
    pub(super) fn page_numbers(&self) -> impl Iterator<Item = usize> + '_ {
        self.page_index.keys().copied()
    }

    /// Get the maximum page number in this snapshot, or None if empty
    pub(super) fn max_page(&self) -> Option<usize> {
        self.page_index.keys().max().copied()
    }
}
