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

use goblin::error;
use goblin::pe::section_table::SectionTable;
use tracing::{Span, instrument};

use crate::Result;

// Below here is a base relocation implementation that we could submit to upstream goblin
const BASE_RELOCATION_SIZE: usize = 2;

/// A base relocation.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub(super) struct BaseRelocation {
    /// A value that indicates the kind of relocation that should be performed.
    /// The value is stored in the most significant 4bits.
    ///
    /// Valid relocation types depend on machine type.
    pub(super) typ: u8, // really u4 when it's unpacked from the base relocation table

    /// The offset to add to the page base RVA.
    pub(super) page_offset: u16, // really u12 when it's unpacked from the base relocation table

    /// The base RVA (relative virtual address) for all relocations specified in a page of the base relocation table
    pub(super) page_base_rva: u32,
}

/// An iterator for base relocations.
#[derive(Default)]
struct BaseRelocations<'a> {
    offset: usize,
    relocations: &'a [u8],
}

impl<'a> BaseRelocations<'a> {
    /// Parse a base relocation table at the given offset.
    ///
    /// The offset and number of relocations should be from the base relocation table header.
    pub(super) fn parse(
        bytes: &'a [u8],
        offset: usize,
        number: usize,
    ) -> Result<BaseRelocations<'a>> {
        let relocations = &bytes
            .get(offset..offset + number * BASE_RELOCATION_SIZE)
            .ok_or_else(|| {
                error::Error::Malformed(format!(
                    "Failed to read base relocations at offset {}",
                    offset
                ))
            })?;
        Ok(BaseRelocations {
            offset: 0,
            relocations,
        })
    }
}

impl Iterator for BaseRelocations<'_> {
    type Item = BaseRelocation;
    fn next(&mut self) -> Option<Self::Item> {
        // Check if we can read 2 bytes from the array
        if self.offset + 1 >= self.relocations.len() {
            return None;
        }

        // Each block is 2 bytes (WORD)
        // 0-3 is the type
        // 4-15 is the virtual address
        let block: [u8; 2] = [
            self.relocations[self.offset],
            self.relocations[self.offset + 1],
        ];

        // Read the two bytes as a number
        let word = u16::from_le_bytes(block);

        // Shift the word over so that we are only reading a number from the first (most significant) 4 bits
        let typ = u8::try_from(word >> 12).unwrap();

        // Set the first 4 bits to 0 so that we only use the lower 12 bits for the location of the RVA in the PE file
        // This is an offset to a virtual address that should be relocated later
        let addr_offset = word & 0b0000111111111111;

        // Move our iterator to the next block in the relocation data table
        self.offset += 2;

        Some(BaseRelocation {
            typ,
            page_offset: addr_offset,
            page_base_rva: 0, // This is set later using information from the relocation table
        })
    }
}

/// Reads the base relocation table directory in a PE file
#[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
pub(super) fn get_base_relocations(
    payload: &[u8],
    reloc_section: &Option<SectionTable>,
) -> Result<Vec<BaseRelocation>> {
    // Goblin doesn't implement retrieving base relocations (section relocations have a different format), so let's implement it here!
    // It would be nice to contribute this upstream later.
    // Go through each block in the relocations base table and parse the relocation entries
    // Here's a great picture of how the table and the relocation blocks are stored https://stackoverflow.com/a/22513813

    // An exe built with dynamicbase or fixed:no might have no reloc section if these have been optimised away or were not necessary.

    let mut base_relocations: Vec<BaseRelocation> = Vec::new();

    if let Some(reloc_section) = reloc_section {
        let mut next_block_offset = reloc_section.pointer_to_raw_data as usize; // The offset to the first block of relocations in the table
        let table_size = reloc_section.virtual_size as usize; // Total size of the relocation table that we need to process

        let mut size_processed: usize = 0;

        // Process each block of relocations until we have processed the expected amount of relocation data
        while size_processed < table_size {
            // Read the header for the block, which is the same format as a DataDirectory so I'm reusing its parse function
            let block_header =
                goblin::pe::data_directories::DataDirectory::parse(payload, &mut next_block_offset)
                    .expect("oops");
            // All relocation blocks in a page contain offsets against this address
            let page_virtual_address = block_header.virtual_address;

            // Subtract 8 bytes for the block header, and then each relocation is 2 bytes
            let reloc_num = (block_header.size as usize - 8) / BASE_RELOCATION_SIZE;

            // Keep track of how much of the relocation table has been processed
            size_processed += block_header.size as usize;

            // Parse all of the relocation entries in the block after the header that we read above
            let relocations = BaseRelocations::parse(payload, next_block_offset, reloc_num)?;
            for mut r in relocations {
                r.page_base_rva = page_virtual_address;
                base_relocations.push(r);
            }
            // goblin::pe::data_directories::DataDirectory::parse above will update next_block_offset
            // by the size of a DtataDirectory, which is 8 bytes so we need to advance the offset by the size of the
            // block header less the 8 bytes that DataDirectory::parse already advanced the offset by
            next_block_offset += (block_header.size - 8) as usize;
        }
    }
    Ok(base_relocations)
}
