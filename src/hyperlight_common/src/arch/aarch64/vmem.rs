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

//! AArch64 page table manipulation code (stub implementation).
//!
//! This module provides placeholder types and functions for AArch64 page table support.
//! A full implementation would support ARMv8-A 4-level page tables with 4KB granule:
//! - Level 0: bits 47:39 - 512 entries, each covering 512GB
//! - Level 1: bits 38:30 - 512 entries, each covering 1GB
//! - Level 2: bits 29:21 - 512 entries, each covering 2MB
//! - Level 3: bits 20:12 - 512 entries, each covering 4KB pages

use crate::vmem::{Mapping, TableOps};

// AArch64 Page Table Entry flags (for 4KB granule)
// Reference: ARM Architecture Reference Manual for A-profile architecture

/// Page/block is valid (present)
pub const PAGE_PRESENT: u64 = 1;
/// Access Permission: Read/Write at EL1 (AP[2:1] = 00)
pub const PAGE_RW: u64 = 0; // In ARM, write permission is default, AP bits restrict it
/// Execute-never for EL1 (PXN bit)
pub const PAGE_NX: u64 = 1 << 53;
/// Mask to extract the output address from a PTE (bits 47:12 for 4KB granule)
pub const PTE_ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_TABLE_SIZE: usize = 4096;
pub type PageTableEntry = u64;
pub type VirtAddr = u64;
pub type PhysAddr = u64;

/// Map a memory region into the page tables.
///
/// # Safety
/// This function modifies page table structures. See the architecture-independent
/// documentation in vmem.rs for safety requirements.
///
/// # Panics
/// This stub implementation will panic as AArch64 page table support is not yet implemented.
#[allow(clippy::missing_safety_doc)]
pub unsafe fn map<Op: TableOps>(_op: &Op, _mapping: Mapping) {
    unimplemented!("AArch64 page table mapping is not yet implemented")
}

/// Translate a virtual address to its physical address by walking the page tables.
///
/// # Safety
/// This function reads page table structures. See the architecture-independent
/// documentation in vmem.rs for safety requirements.
///
/// # Panics
/// This stub implementation will panic as AArch64 page table support is not yet implemented.
#[allow(clippy::missing_safety_doc)]
pub unsafe fn virt_to_phys<Op: TableOps>(_op: &Op, _address: u64) -> Option<u64> {
    unimplemented!("AArch64 virtual to physical translation is not yet implemented")
}
