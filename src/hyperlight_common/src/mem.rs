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

impl GuestMemoryRegion {
    /// Size of a serialized `GuestMemoryRegion` in bytes.
    pub const SERIALIZED_SIZE: usize = core::mem::size_of::<Self>();

    /// Write this region's fields in native-endian byte order to `buf`.
    /// Returns `Ok(())` on success, or `Err` if `buf` is too small.
    pub fn write_to(&self, buf: &mut [u8]) -> Result<(), &'static str> {
        if buf.len() < Self::SERIALIZED_SIZE {
            return Err("buffer too small for GuestMemoryRegion");
        }
        let s = core::mem::size_of::<u64>();
        buf[..s].copy_from_slice(&self.size.to_ne_bytes());
        buf[s..s * 2].copy_from_slice(&self.ptr.to_ne_bytes());
        Ok(())
    }
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
    pub input_stack: GuestMemoryRegion,
    pub output_stack: GuestMemoryRegion,
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

impl HyperlightPEB {
    /// Write the PEB fields in native-endian byte order to `buf`.
    /// The buffer must be at least `size_of::<HyperlightPEB>()` bytes.
    /// Returns `Err` if the buffer is too small.
    pub fn write_to(&self, buf: &mut [u8]) -> Result<(), &'static str> {
        if buf.len() < core::mem::size_of::<Self>() {
            return Err("buffer too small for HyperlightPEB");
        }
        let regions = [
            &self.input_stack,
            &self.output_stack,
            &self.init_data,
            &self.guest_heap,
            #[cfg(feature = "nanvix-unstable")]
            &self.file_mappings,
        ];
        let mut offset = 0;
        for region in regions {
            region.write_to(&mut buf[offset..])?;
            offset += GuestMemoryRegion::SERIALIZED_SIZE;
        }
        Ok(())
    }
}
