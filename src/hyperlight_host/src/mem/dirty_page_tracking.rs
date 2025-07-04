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

#[cfg(target_os = "linux")]
pub use super::linux_dirty_page_tracker::LinuxDirtyPageTracker as PlatformDirtyPageTracker;
use super::shared_mem::SharedMemory;
#[cfg(target_os = "windows")]
pub use super::windows_dirty_page_tracker::WindowsDirtyPageTracker as PlatformDirtyPageTracker;
use crate::Result;

/// Trait defining the interface for dirty page tracking implementations
pub trait DirtyPageTracking {
    fn get_dirty_pages(self) -> Vec<usize>;
}

/// Cross-platform dirty page tracker that delegates to platform-specific implementations
pub struct DirtyPageTracker {
    inner: PlatformDirtyPageTracker,
}

impl DirtyPageTracker {
    /// Create a new dirty page tracker for the given shared memory
    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    pub fn new<T: SharedMemory>(shared_memory: &T) -> Result<Self> {
        let inner = PlatformDirtyPageTracker::new(shared_memory)?;
        Ok(Self { inner })
    }
}

impl DirtyPageTracking for DirtyPageTracker {
    fn get_dirty_pages(self) -> Vec<usize> {
        self.inner.get_dirty_pages()
    }
}
