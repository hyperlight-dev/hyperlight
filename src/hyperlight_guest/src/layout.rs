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

#[cfg_attr(target_arch = "x86_64", path = "arch/amd64/layout.rs")]
#[cfg_attr(target_arch = "x86", path = "arch/i686/layout.rs")]
mod arch;

pub use arch::MAIN_STACK_TOP_GVA;
pub fn scratch_size_gva() -> *mut u64 {
    use hyperlight_common::layout::{MAX_GVA, SCRATCH_TOP_SIZE_OFFSET};
    (MAX_GVA as u64 - SCRATCH_TOP_SIZE_OFFSET + 1) as *mut u64
}
pub fn allocator_gva() -> *mut u64 {
    use hyperlight_common::layout::{MAX_GVA, SCRATCH_TOP_ALLOCATOR_OFFSET};
    (MAX_GVA as u64 - SCRATCH_TOP_ALLOCATOR_OFFSET + 1) as *mut u64
}
pub fn snapshot_pt_gpa_base_gva() -> *mut u64 {
    use hyperlight_common::layout::{MAX_GVA, SCRATCH_TOP_SNAPSHOT_PT_GPA_BASE_OFFSET};
    (MAX_GVA as u64 - SCRATCH_TOP_SNAPSHOT_PT_GPA_BASE_OFFSET + 1) as *mut u64
}
pub use arch::{scratch_base_gpa, scratch_base_gva};
