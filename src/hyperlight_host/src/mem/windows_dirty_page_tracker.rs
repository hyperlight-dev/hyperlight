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

use std::sync::Arc;

use hyperlight_common::mem::PAGE_SIZE_USIZE;
use tracing::{Span, instrument};

use super::dirty_page_tracking::DirtyPageTracking;
use super::shared_mem::{HostMapping, SharedMemory};
use crate::Result;

/// Windows implementation of dirty page tracking
pub struct WindowsDirtyPageTracker {
    _base_addr: usize,
    _size: usize,
    num_pages: usize,
    /// Keep a reference to the HostMapping to ensure memory lifetime
    _mapping: Arc<HostMapping>,
}

// DirtyPageTracker should be Send because:
// 1. The Arc<HostMapping> ensures the memory stays valid
// 2. The tracker handles synchronization properly
// 3. This is needed for threaded sandbox initialization
unsafe impl Send for WindowsDirtyPageTracker {}

impl WindowsDirtyPageTracker {
    /// Create a new Windows dirty page tracker
    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    pub fn new<T: SharedMemory>(shared_memory: &T) -> Result<Self> {
        let mapping = shared_memory.region_arc();
        let base_addr = shared_memory.base_addr();
        let size = shared_memory.mem_size();
        let num_pages = size.div_ceil(PAGE_SIZE_USIZE);

        Ok(Self {
            _base_addr: base_addr,
            _size: size,
            num_pages,
            _mapping: mapping,
        })
    }
}

impl DirtyPageTracking for WindowsDirtyPageTracker {
    /// Returns a dirty page bitmap with all bits set for the memory size
    /// This is a simplified implementation that marks all pages as dirty
    /// until we implement actual dirty page tracking
    fn get_dirty_pages(self) -> Vec<usize> {
        // Return all page indices from 0 to num_pages-1
        (0..self.num_pages - 2).collect() // exclude the guard pages
    }
}
