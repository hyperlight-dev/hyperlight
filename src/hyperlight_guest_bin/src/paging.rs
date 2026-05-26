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

#[cfg_attr(target_arch = "x86_64", path = "arch/amd64/paging.rs")]
#[cfg_attr(target_arch = "aarch64", path = "arch/aarch64/paging.rs")]
mod arch;

pub use arch::{map_region, phys_to_virt, virt_to_phys};
/// Barriers that other code may need to use when updating page tables
pub mod barrier {
    /// Call this function when a virtual address has just been made
    /// valid for the first time after the last tlb invalidate that
    /// affected it, and it will be used for the first time in the
    /// same execution context as has made the modification.
    ///
    /// On most architectures, TLBs will not cache invalid entries, so
    /// this does not need to issue a TLB. However, it does need to
    /// ensure coherency between the previous writes and any future
    /// uses by a page table walker.
    pub use arch::first_valid_same_ctx;

    use super::arch::barrier as arch;
}
