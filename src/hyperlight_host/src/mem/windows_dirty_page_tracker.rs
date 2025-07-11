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

use super::bitmap::{bit_index_iterator, new_page_bitmap};
use super::dirty_page_tracking::DirtyPageTracking;
use super::shared_mem::HostMapping;
use crate::Result;

/// Windows implementation of dirty page tracking
#[derive(Debug)]
pub struct WindowsDirtyPageTracker {
    size: usize,
}

// DirtyPageTracker should be Send because:
// 1. The Arc<HostMapping> ensures the memory stays valid
// 2. The tracker handles synchronization properly
// 3. This is needed for threaded sandbox initialization
unsafe impl Send for WindowsDirtyPageTracker {}

impl WindowsDirtyPageTracker {
    /// Create a new Windows dirty page tracker
    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    pub fn new(mapping: Arc<HostMapping>) -> Result<Self> {
        let size = mapping.size - 2 * PAGE_SIZE_USIZE; // Exclude guard pages at start and end

        Ok(Self { size })
    }
}

impl DirtyPageTracking for WindowsDirtyPageTracker {
    #[cfg(test)]
    fn get_dirty_pages(&self) -> Result<Vec<usize>> {
        let bitmap = new_page_bitmap(self.size, true)?;
        Ok(bit_index_iterator(&bitmap).collect())
    }

    fn uninstall(self) -> Result<Vec<usize>> {
        let bitmap = new_page_bitmap(self.size, true)?;
        Ok(bit_index_iterator(&bitmap).collect())
    }
}

impl WindowsDirtyPageTracker {
    /// Stop tracking dirty pages and return the list of dirty pages
    pub fn stop_tracking_and_get_dirty_pages(self) -> Result<Vec<usize>> {
        let bitmap = new_page_bitmap(self.size, true)?;
        Ok(bit_index_iterator(&bitmap).collect())
    }
}
