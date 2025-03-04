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
use std::fmt::Debug;

use hyperlight_common::mem::PAGE_SIZE_USIZE;
use paste::paste;
use tracing::{instrument, Span};

use super::memory_region::MemoryRegionType::{GuestCode, PageTables, CustomGuestMemory};
use super::memory_region::{MemoryRegion, MemoryRegionFlags, MemoryRegionVecBuilder};
use super::mgr::AMOUNT_OF_MEMORY_PER_PT;
use super::shared_mem::{ExclusiveSharedMemory, GuestSharedMemory, SharedMemory};
use crate::error::HyperlightError::{GuestOffsetIsInvalid, MemoryRequestTooBig};
use crate::sandbox::SandboxConfiguration;
use crate::{new_error, Result};

/// The Sandbox Memory Layout allocated by the Hyperlight host.
///
/// +-------------------------------------------+
/// |            Custom Guest Memory            |
/// +-------------------------------------------+
/// |                    PT                     |
/// +-------------------------------------------+ guest_code_offset + 0x3_000
/// |                    PD                     |
/// +-------------------------------------------+ guest_code_offset + 0x2_000
/// |                   PDPT                    |
/// +-------------------------------------------+ guest_code_offset + 0x1_000
/// |                   PML4                    |
/// +-------------------------------------------+ guest_code_offset
/// |               Guest Code                  |
/// +-------------------------------------------+ 0x0
///
/// - Custom Guest Memory = an undifferentiated memory region that can be addressed by a guest
/// in any way it wants.
/// - PML4/PDPT/PD/PT = the paging sections used to map guest memory into the host's address space.
/// - Guest Code = where we load the guest binary to be executed in a sandbox.
#[derive(Copy, Clone)]
pub(crate) struct SandboxMemoryLayout {
    /// The total memory size of the sandbox
    /// (i.e., guest code size + paging sections size + configurable undifferentiated memory size)
    pub(crate) total_memory_size: usize,

    /// The offset to the start of the guest code region in the sandbox's memory
    pub(crate) guest_code_offset: usize,

    /// The size of the guest code
    pub(crate) guest_code_size: usize,

    /// The offset to the start of the paging section region in the sandbox's memory
    pub(crate) paging_sections_offset: usize,

    /// The total size of the paging sections
    pub(crate) total_page_table_size: usize,

    /// The offset to the start of the undifferentiated memory region in the sandbox's memory
    pub(crate) custom_guest_memory_offset: usize,

    /// The size of the undifferentiated memory region
    pub(crate) custom_guest_memory_size: usize,
}

impl Debug for SandboxMemoryLayout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxMemoryLayout")
            .field(
                "Total Memory Size",
                &format_args!("{:#x}", self.get_total_page_aligned_memory_size().unwrap_or(0)),
            )
            .field(
                "Guest Code Size",
                &format_args!("{:#x}", self.guest_code_size),
            )
            .field(
                "Paging Sections Size",
                &format_args!("{:#x}", self.total_page_table_size),
            )
            .field(
                "Custom Guest Memory Size",
                &format_args!("{:#x}", self.custom_guest_memory_size),
            )
            .field(
                "Guest Code",
                &format_args!(
                    "{:#x}..{:#x}",
                    Self::BASE_ADDRESS,
                    self.paging_sections_offset - 1
                ),
            )
            .field(
                "Paging Sections",
                &format_args!(
                    "{:#x}..{:#x}",
                    self.paging_sections_offset,
                    self.custom_guest_memory_offset - 1
                ),
            )
            .field(
                "Custom Guest Memory",
                &format_args!(
                    "{:#x}..{:#x}",
                    self.custom_guest_memory_offset,
                    self.custom_guest_memory_size
                ),
            )
            .finish()
    }
}

impl SandboxMemoryLayout {
    /// The offset from the start of the paging section region into the sandbox's memory where the
    /// Page Directory Pointer Table starts.
    const PDPT_OFFSET: usize = 0x1000;

    /// The offset into the sandbox's memory where the Page Directory starts.
    const PD_OFFSET: usize = 0x2000;

    /// The offset into the sandbox's memory where the Page Tables start.
    const PT_OFFSET: usize = 0x3000;

    /// The maximum amount of memory a single sandbox will be allowed.
    /// The addressable virtual memory with current paging setup is virtual address
    /// BASE_ADDRESS - 0x40000000 (i.e., excluding the memory up to BASE_ADDRESS
    /// (which is 0 by default)).
    const MAX_MEMORY_SIZE: usize = 0x40000000 - Self::BASE_ADDRESS;

    /// The base address of the sandbox's memory.
    pub(crate) const BASE_ADDRESS: usize = 0x0;

    /// Create a new `SandboxMemoryLayout` with the given `SandboxConfiguration` and guest code size.
    pub(super) fn new(sandbox_memory_config: SandboxConfiguration, guest_code_size: usize) -> Result<Self> {
        // Guest code starts at Self::BASE_ADDRESS (0x0)
        let guest_code_offset = Self::BASE_ADDRESS;

        // Paging sections start after guest_code_size
        let paging_sections_offset = guest_code_offset + round_up_to(guest_code_size, PAGE_SIZE_USIZE);
        let total_page_table_size = Self::get_total_page_table_size(sandbox_memory_config, guest_code_size);

        // Custom guest memory starts after paging sections
        let custom_guest_memory_offset = paging_sections_offset + total_page_table_size;
        let custom_guest_memory_size = sandbox_memory_config.get_custom_guest_memory_size() as usize;

        // The total size of the sandbox memory layout
        let total_memory_size = custom_guest_memory_offset + custom_guest_memory_size;

        Ok(Self {
            total_memory_size,
            guest_code_offset,
            guest_code_size,
            paging_sections_offset,
            total_page_table_size,
            custom_guest_memory_offset,
            custom_guest_memory_size,
        })
    }

    /// Get the total size of memory layout aligned to page size boundaries.
    pub(super) fn get_total_page_aligned_memory_size(&self) -> Result<usize> {
        let total_memory = self.total_memory_size;

        // Size should be a multiple of page size.
        let remainder = total_memory % PAGE_SIZE_USIZE;
        let multiples = total_memory / PAGE_SIZE_USIZE;
        let size = match remainder {
            0 => total_memory,
            _ => (multiples + 1) * PAGE_SIZE_USIZE,
        };

        if size > Self::MAX_MEMORY_SIZE {
            Err(MemoryRequestTooBig(size, Self::MAX_MEMORY_SIZE))
        } else {
            Ok(size)
        }
    }

    /// Gets the guest code offset
    /// (i.e., same as Self::BASE_ADDRESS)
    pub(crate) fn get_guest_code_offset(&self) -> usize {
        self.guest_code_offset
    }

    /// Get the PML4 offset
    /// (i.e., after the guest code)
    pub(crate) fn get_pml4_offset(&self) -> usize {
        self.paging_sections_offset
    }

    /// Get the PDPT offset
    /// (i.e., the PML4 offset + 0x1000)
    pub(crate) fn get_pdpt_offset(&self) -> usize {
        self.paging_sections_offset + Self::PDPT_OFFSET
    }

    /// Get the PD offset
    /// (i.e., the PML4 offset + 0x2000)
    pub(crate) fn get_pd_offset(&self) -> usize {
        self.paging_sections_offset + Self::PD_OFFSET
    }

    /// Get the PT offset
    /// (i.e., the PML4 offset + 0x3000)
    pub(crate) fn get_pt_offset(&self) -> usize {
        self.paging_sections_offset + Self::PT_OFFSET
    }

    /// Calculates the total size of memory required for page tables.
    ///
    /// This function determines the total memory needed to store the PML4, PDPT, PD,
    /// and Page Tables (PTs) required for address translation within the sandbox.
    ///
    /// The memory requirements are computed as follows:
    ///
    /// 1. **Guest Code Memory**: The size of the guest code is rounded up to the nearest 4KB page.
    /// 2. **Paging Structures**: The PML4, PDPT, and PD each require 4KB, contributing a total of 3 * 4KB.
    /// 3. **Page Tables (PTs)**:
    ///    - Each PT maps 2MB of memory.
    ///    - A full 1GB mapping requires 512 PTs (each 4KB), totaling 2MB.
    ///    - The number of PTs required is based on the actual memory mapped.
    /// 4. **Custom Guest Memory**: Additional custom guest memory is rounded up to the nearest 4KB page.
    ///
    /// The function then calculates the total number of 4KB pages required and returns
    /// the total memory size in bytes.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_total_page_table_size(cfg: SandboxConfiguration, guest_code_size: usize) -> usize {
        // Get the configured memory size (assume each section is 4K aligned)
        let mut total_mapped_memory_size: usize = 0;

        // Add the size of the guest code
        total_mapped_memory_size += round_up_to(guest_code_size, PAGE_SIZE_USIZE);

        // Add the size of  the PML4, PDPT and PD
        total_mapped_memory_size += 3 * PAGE_SIZE_USIZE;

        // Add the maximum possible size of the PTs
        total_mapped_memory_size += 512 * PAGE_SIZE_USIZE;

        // Add the size of the custom guest memory
        total_mapped_memory_size += round_up_to(cfg.get_custom_guest_memory_size() as usize, PAGE_SIZE_USIZE);

        // Get the number of pages needed for the PTs
        let num_pages: usize = ((total_mapped_memory_size + AMOUNT_OF_MEMORY_PER_PT - 1)
            / AMOUNT_OF_MEMORY_PER_PT)
            + 1 // Round up
            + 3; // PML4, PDPT, PD

        num_pages * PAGE_SIZE_USIZE
    }

    /// Get the custom guest memory offset
    pub(crate) fn get_custom_guest_memory_offset(&self) -> usize {
        self.custom_guest_memory_offset
    }

    /// Get the custom guest memory size
    pub(crate) fn get_custom_guest_memory_size(&self) -> usize {
        self.custom_guest_memory_size
    }

    /// Get the memory regions associated with this memory layout,
    /// suitable for passing to a hypervisor for mapping into memory.
    pub fn get_memory_regions(&self, shared_mem: &GuestSharedMemory) -> Result<Vec<MemoryRegion>> {
        let mut builder = MemoryRegionVecBuilder::new(Self::BASE_ADDRESS, shared_mem.base_addr());

        // Guest code offset should be at the base address
        assert_eq!(self.guest_code_offset, Self::BASE_ADDRESS);

        // At base, we have the guest code
        builder.push_page_aligned(
            self.guest_code_size,
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE | MemoryRegionFlags::EXECUTE,
            GuestCode,
        );

        // Following the guest code, we have the PML4, PDPT, PD, and PT sections
        builder.push_page_aligned(
            self.total_page_table_size,
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
            PageTables,
        );

        // Following the paging sections, we have the custom guest memory
        let final_offset = builder.push_page_aligned(
            self.custom_guest_memory_size,
            // TODO(danbugs:297): custom_guest_memory_size set as executable by default
            // because we might want to execute code on the heap. This should be configurable.
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE | MemoryRegionFlags::EXECUTE,
            CustomGuestMemory,
        );

        let expected_final_offset: usize = usize::try_into(self.get_total_page_aligned_memory_size()?)?;

        if final_offset != expected_final_offset {
            return Err(new_error!(
                "Final offset does not match expected final offset! Expected:  {}, actual:  {}",
                expected_final_offset,
                final_offset
            ));
        }

        Ok(builder.build())
    }

    /// Write the finished memory layout to shared memory
    pub(crate) fn write(
        &self,
        shared_mem: &mut ExclusiveSharedMemory,
        guest_base_offset: usize,
    ) -> Result<()> {
        macro_rules! get_address {
            ($something:ident) => {
                paste! {
                    {
                        u64::try_from(guest_base_offset +  self.[<$something _offset>])?
                    }
                }
            };
        }

        // Sanity check the guest offset
        if guest_base_offset != SandboxMemoryLayout::BASE_ADDRESS
            && guest_base_offset != shared_mem.base_addr()
        {
            return Err(GuestOffsetIsInvalid(guest_base_offset));
        }

        // Note: we don't need to write the guest code, because that's done when loading the binary

        // Start of custom guest memory
        let start_of_custom_guest_memory = get_address!(custom_guest_memory);

        shared_mem.write_u64(
            self.get_custom_guest_memory_offset(),
            start_of_custom_guest_memory,
        )?;

        Ok(())
    }
}

fn round_up_to(value: usize, multiple: usize) -> usize {
    (value + multiple - 1) & !(multiple - 1)
}

#[cfg(test)]
mod tests {
    use hyperlight_common::mem::PAGE_SIZE_USIZE;

    use super::*;

    // Helper function to get the expected memory size
    fn get_expected_memory_size(layout: &SandboxMemoryLayout) -> usize {
        let mut expected_size = 0;

        expected_size += layout.guest_code_size;
        expected_size += layout.total_page_table_size;
        expected_size += layout.custom_guest_memory_size;

        expected_size
    }

    #[test]
    fn test_round_up() {
        assert_eq!(0, round_up_to(0, 4));
        assert_eq!(4, round_up_to(1, 4));
        assert_eq!(4, round_up_to(2, 4));
        assert_eq!(4, round_up_to(3, 4));
        assert_eq!(4, round_up_to(4, 4));
        assert_eq!(8, round_up_to(5, 4));
        assert_eq!(8, round_up_to(6, 4));
        assert_eq!(8, round_up_to(7, 4));
        assert_eq!(8, round_up_to(8, 4));
        assert_eq!(PAGE_SIZE_USIZE, round_up_to(44, PAGE_SIZE_USIZE));
        assert_eq!(PAGE_SIZE_USIZE, round_up_to(4095, PAGE_SIZE_USIZE));
        assert_eq!(PAGE_SIZE_USIZE, round_up_to(4096, PAGE_SIZE_USIZE));
        assert_eq!(PAGE_SIZE_USIZE * 2, round_up_to(4097, PAGE_SIZE_USIZE));
        assert_eq!(PAGE_SIZE_USIZE * 2, round_up_to(8191, PAGE_SIZE_USIZE));
    }

    #[test]
    fn test_get_memory_size() -> Result<()> {
        let mut sbox_cfg = SandboxConfiguration::default();
        sbox_cfg.set_custom_guest_memory_size(4096);
        let fake_guest_binary_size = 4096;
        let sbox_mem_layout = SandboxMemoryLayout::new(sbox_cfg, fake_guest_binary_size)?;
        assert_eq!(
            sbox_mem_layout.get_total_page_aligned_memory_size().unwrap(),
            get_expected_memory_size(&sbox_mem_layout)
        );

        Ok(())
    }
}
