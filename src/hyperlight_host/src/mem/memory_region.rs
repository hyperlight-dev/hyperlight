/*
Copyright 2024 The Hyperlight Authors.

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

#[cfg(mshv2)]
extern crate mshv_bindings2 as mshv_bindings;
#[cfg(mshv2)]
extern crate mshv_ioctls2 as mshv_ioctls;

#[cfg(mshv3)]
extern crate mshv_bindings3 as mshv_bindings;
#[cfg(mshv3)]
extern crate mshv_ioctls3 as mshv_ioctls;

use std::ops::Range;

use bitflags::bitflags;
#[cfg(mshv)]
use hyperlight_common::mem::PAGE_SHIFT;
use hyperlight_common::mem::PAGE_SIZE_USIZE;
#[cfg(mshv)]
use mshv_bindings::{hv_x64_memory_intercept_message, mshv_user_mem_region};
#[cfg(mshv2)]
use mshv_bindings::{
    HV_MAP_GPA_EXECUTABLE, HV_MAP_GPA_PERMISSIONS_NONE, HV_MAP_GPA_READABLE, HV_MAP_GPA_WRITABLE,
};
#[cfg(mshv3)]
use mshv_bindings::{
    MSHV_SET_MEM_BIT_EXECUTABLE, MSHV_SET_MEM_BIT_UNMAP, MSHV_SET_MEM_BIT_WRITABLE,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::Hypervisor::{self, WHV_MEMORY_ACCESS_TYPE};

bitflags! {
    /// flags representing memory permission for a memory region
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
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

#[cfg(mshv)]
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
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
/// The type of memory region
pub enum MemoryRegionType {
    /// The region contains the guest's page tables
    PageTables,
    /// The region contains the guest's code
    Code,
    /// The region contains the PEB
    Peb,
    /// The region contains the Host Function Definitions
    HostFunctionDefinitions,
    /// The region contains the Host Exception Data
    HostExceptionData,
    /// The region contains the Guest Error Data
    GuestErrorData,
    /// The region contains the Input Data
    InputData,
    /// The region contains the Output Data
    OutputData,
    /// The region contains the Panic Context
    PanicContext,
    /// The region contains the Heap
    Heap,
    /// The region contains the Guard Page
    GuardPage,
    /// The region contains the Stack
    Stack,
    /// The region contains the Kernel Stack
    KernelStack,
    /// The region contains the Boot Stack
    BootStack,
}

/// represents a single memory region inside the guest. All memory within a region has
/// the same memory permissions
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRegion {
    /// the range of guest memory addresses
    pub(crate) guest_region: Range<usize>,
    /// the range of host memory addresses
    pub(crate) host_region: Range<usize>,
    /// memory access flags for the given region
    pub(crate) flags: MemoryRegionFlags,
    /// the type of memory region
    pub(crate) region_type: MemoryRegionType,
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

#[cfg(mshv)]
impl From<MemoryRegion> for mshv_user_mem_region {
    fn from(region: MemoryRegion) -> Self {
        let size = (region.guest_region.end - region.guest_region.start) as u64;
        let guest_pfn = region.guest_region.start as u64 >> PAGE_SHIFT;
        let userspace_addr = region.host_region.start as u64;

        #[cfg(mshv2)]
        {
            let flags = region.flags.iter().fold(0, |acc, flag| {
                let flag_value = match flag {
                    MemoryRegionFlags::NONE => HV_MAP_GPA_PERMISSIONS_NONE,
                    MemoryRegionFlags::READ => HV_MAP_GPA_READABLE,
                    MemoryRegionFlags::WRITE => HV_MAP_GPA_WRITABLE,
                    MemoryRegionFlags::EXECUTE => HV_MAP_GPA_EXECUTABLE,
                    _ => 0, // ignore any unknown flags
                };
                acc | flag_value
            });
            mshv_user_mem_region {
                guest_pfn,
                size,
                userspace_addr,
                flags,
            }
        }
        #[cfg(mshv3)]
        {
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
}
