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

pub const PAGE_SHIFT: u64 = 12;
pub const PAGE_SIZE: u64 = 1 << 12;
pub const PAGE_SIZE_USIZE: usize = 1 << 12;

/// A memory region in the guest address space
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct GuestMemoryRegion {
    /// The size of the memory region
    pub size: u64,
    /// The address of the memory region
    pub ptr: u64,
}

/// Maximum length of a file mapping label (excluding null terminator).
pub const FILE_MAPPING_LABEL_MAX_LEN: usize = 63;

/// Maximum number of file mappings that can be registered in the PEB.
///
/// Space for this many [`FileMappingInfo`] entries is statically
/// reserved immediately after the [`HyperlightPEB`] struct within the
/// same memory region. The reservation happens at layout time
/// (see `SandboxMemoryLayout::new`) so the guest heap never overlaps
/// the array, regardless of how many entries are actually used.
pub const MAX_FILE_MAPPINGS: usize = 32;

/// Describes a single file mapping in the guest address space.
///
/// Stored in the PEB's file mappings array so the guest can discover
/// which files have been mapped, at what address, and with what label.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FileMappingInfo {
    /// The guest address where the file is mapped.
    pub guest_addr: u64,
    /// The page-aligned size of the mapping in bytes.
    pub size: u64,
    /// Null-terminated C-style label (max 63 chars + null).
    pub label: [u8; FILE_MAPPING_LABEL_MAX_LEN + 1],
}

impl Default for FileMappingInfo {
    fn default() -> Self {
        Self {
            guest_addr: 0,
            size: 0,
            label: [0u8; FILE_MAPPING_LABEL_MAX_LEN + 1],
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct HyperlightPEB {
    pub init_data: GuestMemoryRegion,
    pub guest_heap: GuestMemoryRegion,
    /// File mappings array descriptor.
    /// **Note:** `size` holds the **entry count** (number of valid
    /// [`FileMappingInfo`] entries), NOT a byte size. `ptr` holds the
    /// guest address of the preallocated array (immediately after the
    /// PEB struct).
    #[cfg(feature = "nanvix-unstable")]
    pub file_mappings: GuestMemoryRegion,
}
