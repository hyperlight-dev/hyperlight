// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

/// A memory region in the guest address space
#[derive(Debug, Clone, Copy, PartialEq, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub struct GuestMemoryRegion {
    /// The size of the memory region
    pub size: u64,
    /// The address of the memory region
    pub ptr: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub struct HyperlightPEB {
    pub init_data: GuestMemoryRegion,
    pub guest_heap: GuestMemoryRegion,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peb_round_trip() {
        let peb = HyperlightPEB {
            init_data: GuestMemoryRegion {
                size: 0x1111,
                ptr: 0x2222,
            },
            guest_heap: GuestMemoryRegion {
                size: 0x3333,
                ptr: 0x4444,
            },
        };
        let bytes = bytemuck::bytes_of(&peb);
        let peb2 = *bytemuck::from_bytes::<HyperlightPEB>(bytes);
        let peb2_bytes = bytemuck::bytes_of(&peb2);
        assert_eq!(peb, peb2);
        assert_eq!(bytes, peb2_bytes);
    }
}
