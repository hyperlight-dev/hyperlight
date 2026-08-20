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
    pub input_stack: GuestMemoryRegion,
    pub output_stack: GuestMemoryRegion,
    pub init_data: GuestMemoryRegion,
    pub guest_heap: GuestMemoryRegion,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peb_round_trip() {
        let peb = HyperlightPEB {
            input_stack: GuestMemoryRegion {
                size: 0x1111,
                ptr: 0x2222,
            },
            output_stack: GuestMemoryRegion {
                size: 0x3333,
                ptr: 0x4444,
            },
            init_data: GuestMemoryRegion {
                size: 0x5555,
                ptr: 0x6666,
            },
            guest_heap: GuestMemoryRegion {
                size: 0x7777,
                ptr: 0x8888,
            },
        };
        let bytes = bytemuck::bytes_of(&peb);
        let peb2 = *bytemuck::from_bytes::<HyperlightPEB>(bytes);
        let peb2_bytes = bytemuck::bytes_of(&peb2);
        assert_eq!(peb, peb2);
        assert_eq!(bytes, peb2_bytes);
    }
}
