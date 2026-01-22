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

// The constraint on the feature is temporary and will be removed when other arch i686 is added
#[cfg_attr(target_arch = "x86_64", path = "arch/amd64/layout.rs")]
#[cfg(feature = "init-paging")]
mod arch;

// The constraint on the feature is temporary and will be removed when other arch i686 is added
#[cfg(feature = "init-paging")]
pub use arch::MAX_GPA;
#[cfg(feature = "init-paging")]
pub use arch::{MAX_GVA, SNAPSHOT_PT_GVA};

// offsets down from the top of scratch memory for various things
pub const SCRATCH_TOP_SIZE_OFFSET: u64 = 0x08;
pub const SCRATCH_TOP_USED_OFFSET: u64 = 0x10;
pub const SCRATCH_TOP_ALLOCATOR_OFFSET: u64 = 0x18;
pub const SCRATCH_TOP_EXN_STACK_OFFSET: u64 = 0x20;

#[cfg(feature = "init-paging")]
pub fn scratch_base_gpa(size: usize) -> u64 {
    (MAX_GPA - size + 1) as u64
}
#[cfg(feature = "init-paging")]
pub fn scratch_base_gva(size: usize) -> u64 {
    (MAX_GVA - size + 1) as u64
}
