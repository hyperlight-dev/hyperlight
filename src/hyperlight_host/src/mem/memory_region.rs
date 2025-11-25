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

use std::ops::Range;

use bitflags::bitflags;
#[cfg(mshv3)]
use hyperlight_common::mem::PAGE_SHIFT;
use hyperlight_common::mem::PAGE_SIZE_USIZE;
#[cfg(kvm)]
use kvm_bindings::{KVM_MEM_READONLY, kvm_userspace_memory_region};
#[cfg(mshv3)]
use mshv_bindings::{
    MSHV_SET_MEM_BIT_EXECUTABLE, MSHV_SET_MEM_BIT_UNMAP, MSHV_SET_MEM_BIT_WRITABLE,
};
#[cfg(mshv3)]
use mshv_bindings::{hv_x64_memory_intercept_message, mshv_user_mem_region};
#[cfg(target_os = "windows")]
use windows::Win32::System::Hypervisor::{self, WHV_MEMORY_ACCESS_TYPE};

#[cfg(feature = "init-paging")]
use super::mgr::{PAGE_NX, PAGE_PRESENT, PAGE_RW, PAGE_USER};

pub(crate) const DEFAULT_GUEST_BLOB_MEM_FLAGS: MemoryRegionFlags = MemoryRegionFlags::READ;

bitflags! {
    /// flags representing memory permission for a memory region
    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    pub struct MemoryRegionFlags: u32 {
        /// no permissions
        const NONE = 0;
        /// allow guest to read
        const READ = 1;
        /// allow guest to write
        const WRITE = 2;
        /// allow guest to execute
        const EXECUTE = 4;
        /// identifier that this is a stack guard page
        const STACK_GUARD = 8;
    }
}

impl MemoryRegionFlags {
    #[cfg(feature = "init-paging")]
    pub(crate) fn translate_flags(&self) -> u64 {
        let mut page_flags = 0;

        page_flags |= PAGE_PRESENT; // Mark page as present

        if self.contains(MemoryRegionFlags::WRITE) {
            page_flags |= PAGE_RW; // Allow read/write
        }

        if self.contains(MemoryRegionFlags::STACK_GUARD) {
            page_flags |= PAGE_RW; // The guard page is marked RW so that if it gets written to we can detect it in the host
        }

        if self.contains(MemoryRegionFlags::EXECUTE) {
            page_flags |= PAGE_USER; // Allow user access
        } else {
            page_flags |= PAGE_NX; // Mark as non-executable if EXECUTE is not set
        }

        page_flags
    }
}

impl std::fmt::Display for MemoryRegionFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_empty() {
            write!(f, "NONE")
        } else {
            let mut first = true;
            if self.contains(MemoryRegionFlags::READ) {
                write!(f, "READ")?;
                first = false;
            }
            if self.contains(MemoryRegionFlags::WRITE) {
                if !first {
                    write!(f, " | ")?;
                }
                write!(f, "WRITE")?;
                first = false;
            }
            if self.contains(MemoryRegionFlags::EXECUTE) {
                if !first {
                    write!(f, " | ")?;
                }
                write!(f, "EXECUTE")?;
            }
            Ok(())
        }
    }
}

#[cfg(target_os = "windows")]
impl TryFrom<WHV_MEMORY_ACCESS_TYPE> for MemoryRegionFlags {
    type Error = crate::HyperlightError;

    fn try_from(flags: WHV_MEMORY_ACCESS_TYPE) -> crate::Result<Self> {
        match flags {
            Hypervisor::WHvMemoryAccessRead => Ok(MemoryRegionFlags::READ),
            Hypervisor::WHvMemoryAccessWrite => Ok(MemoryRegionFlags::WRITE),
            Hypervisor::WHvMemoryAccessExecute => Ok(MemoryRegionFlags::EXECUTE),
            _ => Err(crate::HyperlightError::Error(
                "unknown memory access type".to_string(),
            )),
        }
    }
}

#[cfg(mshv3)]
impl TryFrom<hv_x64_memory_intercept_message> for MemoryRegionFlags {
    type Error = crate::HyperlightError;

    fn try_from(msg: hv_x64_memory_intercept_message) -> crate::Result<Self> {
        let access_type = msg.header.intercept_access_type;
        match access_type {
            0 => Ok(MemoryRegionFlags::READ),
            1 => Ok(MemoryRegionFlags::WRITE),
            2 => Ok(MemoryRegionFlags::EXECUTE),
            _ => Err(crate::HyperlightError::Error(
                "unknown memory access type".to_string(),
            )),
        }
    }
}

// only used for debugging
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
/// The type of memory region
pub enum MemoryRegionType {
    /// The region contains the guest's page tables
    PageTables,
    /// The region contains the guest's code
    Code,
    /// The region contains the guest's init data
    InitData,
    /// The region contains the PEB
    Peb,
    /// The region contains the Host Function Definitions
    HostFunctionDefinitions,
    /// The region contains the Input Data
    InputData,
    /// The region contains the Output Data
    OutputData,
    /// The region contains the Heap
    Heap,
    /// The region contains the Guard Page
    GuardPage,
    /// The region contains the Stack
    Stack,
}

/// represents a single memory region inside the guest. All memory within a region has
/// the same memory permissions
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemoryRegion {
    /// the range of guest memory addresses
    pub guest_region: Range<usize>,
    /// the range of host memory addresses
    pub host_region: Range<usize>,
    /// memory access flags for the given region
    pub flags: MemoryRegionFlags,
    /// the type of memory region
    pub region_type: MemoryRegionType,
}

pub(crate) struct MemoryRegionVecBuilder {
    guest_base_phys_addr: usize,
    host_base_virt_addr: usize,
    regions: Vec<MemoryRegion>,
}

impl MemoryRegionVecBuilder {
    pub(crate) fn new(guest_base_phys_addr: usize, host_base_virt_addr: usize) -> Self {
        Self {
            guest_base_phys_addr,
            host_base_virt_addr,
            regions: Vec::new(),
        }
    }

    fn push(
        &mut self,
        size: usize,
        flags: MemoryRegionFlags,
        region_type: MemoryRegionType,
    ) -> usize {
        if self.regions.is_empty() {
            let guest_end = self.guest_base_phys_addr + size;
            let host_end = self.host_base_virt_addr + size;
            self.regions.push(MemoryRegion {
                guest_region: self.guest_base_phys_addr..guest_end,
                host_region: self.host_base_virt_addr..host_end,
                flags,
                region_type,
            });
            return guest_end - self.guest_base_phys_addr;
        }

        #[allow(clippy::unwrap_used)]
        // we know this is safe because we check if the regions are empty above
        let last_region = self.regions.last().unwrap();
        let new_region = MemoryRegion {
            guest_region: last_region.guest_region.end..last_region.guest_region.end + size,
            host_region: last_region.host_region.end..last_region.host_region.end + size,
            flags,
            region_type,
        };
        let ret = new_region.guest_region.end;
        self.regions.push(new_region);
        ret - self.guest_base_phys_addr
    }

    /// Pushes a memory region with the given size. Will round up the size to the nearest page.
    /// Returns the current size of the all memory regions in the builder after adding the given region.
    /// # Note:
    /// Memory regions pushed MUST match the guest's memory layout, in SandboxMemoryLayout::new(..)
    pub(crate) fn push_page_aligned(
        &mut self,
        size: usize,
        flags: MemoryRegionFlags,
        region_type: MemoryRegionType,
    ) -> usize {
        let aligned_size = (size + PAGE_SIZE_USIZE - 1) & !(PAGE_SIZE_USIZE - 1);
        self.push(aligned_size, flags, region_type)
    }

    /// Consumes the builder and returns a vec of memory regions. The regions are guaranteed to be a contiguous chunk
    /// of memory, in other words, there will be any memory gaps between them.
    pub(crate) fn build(self) -> Vec<MemoryRegion> {
        self.regions
    }
}

#[cfg(mshv3)]
impl From<MemoryRegion> for mshv_user_mem_region {
    fn from(region: MemoryRegion) -> Self {
        let size = (region.guest_region.end - region.guest_region.start) as u64;
        let guest_pfn = region.guest_region.start as u64 >> PAGE_SHIFT;
        let userspace_addr = region.host_region.start as u64;

        let flags: u8 = region.flags.iter().fold(0, |acc, flag| {
            let flag_value = match flag {
                MemoryRegionFlags::NONE => 1 << MSHV_SET_MEM_BIT_UNMAP,
                MemoryRegionFlags::READ => 0,
                MemoryRegionFlags::WRITE => 1 << MSHV_SET_MEM_BIT_WRITABLE,
                MemoryRegionFlags::EXECUTE => 1 << MSHV_SET_MEM_BIT_EXECUTABLE,
                _ => 0, // ignore any unknown flags
            };
            acc | flag_value
        });

        mshv_user_mem_region {
            guest_pfn,
            size,
            userspace_addr,
            flags,
            ..Default::default()
        }
    }
}

#[cfg(kvm)]
impl From<MemoryRegion> for kvm_bindings::kvm_userspace_memory_region {
    fn from(region: MemoryRegion) -> Self {
        let perm_flags =
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE | MemoryRegionFlags::EXECUTE;

        let perm_flags = perm_flags.intersection(region.flags);

        kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: region.guest_region.start as u64,
            memory_size: (region.guest_region.end - region.guest_region.start) as u64,
            userspace_addr: region.host_region.start as u64,
            flags: if perm_flags.contains(MemoryRegionFlags::WRITE) {
                0 // RWX
            } else {
                // Note: KVM_MEM_READONLY is executable
                KVM_MEM_READONLY // RX 
            },
        }
    }
}
