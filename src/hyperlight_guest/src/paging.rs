// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

//! Guest page-table operations.

#[cfg_attr(target_arch = "x86_64", path = "arch/amd64/paging.rs")]
#[cfg_attr(target_arch = "aarch64", path = "arch/aarch64/paging.rs")]
mod arch;

pub use arch::{map_region, modify_mapping, phys_to_virt, virt_to_phys, virt_to_phys_range};
/// Barriers that other code may need to use when updating page tables
pub mod barrier {
    /// Call this function when a virtual address has had its
    /// permissions changed in a way that makes previously-valid
    /// accesses invalid.
    ///
    /// Range must be page-aligned.
    pub use arch::downgrade_in_place;
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
