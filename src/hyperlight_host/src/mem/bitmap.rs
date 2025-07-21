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

use hyperlight_common::mem::{PAGE_SIZE_USIZE, PAGES_IN_BLOCK};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

use super::layout::SandboxMemoryLayout;
use crate::{Result, log_then_return};

// Contains various helper functions for dealing with bitmaps.

/// Returns a new bitmap of pages. If `init_dirty` is true, all pages are marked as dirty, otherwise all pages are clean.
/// Will return an error if given size is 0.
pub fn new_page_bitmap(size_in_bytes: usize, init_dirty: bool) -> Result<Vec<u64>> {
    if size_in_bytes == 0 {
        log_then_return!("Tried to create a bitmap with size 0.");
    }
    let num_pages = size_in_bytes.div_ceil(PAGE_SIZE_USIZE);
    let num_blocks = num_pages.div_ceil(PAGES_IN_BLOCK);
    match init_dirty {
        false => Ok(vec![0; num_blocks]),
        true => {
            let mut bitmap = vec![!0u64; num_blocks]; // all pages are dirty
            let num_unused_bits = num_blocks * PAGES_IN_BLOCK - num_pages;
            // set the unused bits to 0, could cause problems otherwise
            #[allow(clippy::unwrap_used)]
            let last_block = bitmap.last_mut().unwrap(); // unwrap is safe since size_in_bytes>0
            *last_block >>= num_unused_bits;
            Ok(bitmap)
        }
    }
}

/// Returns the union (bitwise OR) of two bitmaps. The resulting bitmap will have the same length
/// as the longer of the two input bitmaps.
pub(crate) fn bitmap_union(bitmap: &[u64], other_bitmap: &[u64]) -> Result<Vec<u64>> {
    if bitmap.len() != other_bitmap.len() {
        log_then_return!("Bitmaps must be of the same length to union them.");
    }

    let mut result = vec![0; bitmap.len()];

    for i in 0..bitmap.len() {
        result[i] = bitmap[i] | other_bitmap[i];
    }

    Ok(result)
}

// Used as a helper struct to implement an iterator on.
struct SetBitIndices<'a> {
    bitmap: &'a [u64],
    block_index: usize, // one block is 1 u64, which is 64 pages
    current: u64,       // the current block we are iterating over, or 0 if first iteration
}

/// Iterates over the zero-based indices of the set bits in the given bitmap.
pub(crate) fn bit_index_iterator(bitmap: &[u64]) -> impl Iterator<Item = usize> + '_ {
    SetBitIndices {
        bitmap,
        block_index: 0,
        current: 0,
    }
}

impl Iterator for SetBitIndices<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        while self.current == 0 {
            // will always enter this on first iteration because current is initialized to 0
            if self.block_index >= self.bitmap.len() {
                // no more blocks to iterate over
                return None;
            }
            self.current = self.bitmap[self.block_index];
            self.block_index += 1;
        }
        let trailing_zeros = self.current.trailing_zeros();
        self.current &= self.current - 1; // Clear the least significant set bit
        Some((self.block_index - 1) * 64 + trailing_zeros as usize) // block_index guaranteed to be > 0 at this point
    }
}

// Unused but useful for debugging
// Prints the dirty bitmap in a human-readable format, coloring each page according to its region
// NOTE: Might need to be updated if the memory layout changes
#[allow(dead_code)]
pub(crate) fn print_dirty_bitmap(bitmap: &[u64], layout: &SandboxMemoryLayout) {
    let mut stdout = StandardStream::stdout(ColorChoice::Auto);

    // Helper function to determine which memory region a page belongs to
    fn get_region_info(page_index: usize, layout: &SandboxMemoryLayout) -> (&'static str, Color) {
        let page_offset = page_index * PAGE_SIZE_USIZE;

        // Check each memory region in order, using available methods and approximations
        if page_offset >= layout.init_data_offset {
            ("INIT_DATA", Color::Ansi256(129)) // Purple
        } else if page_offset >= layout.get_top_of_user_stack_offset() {
            ("STACK", Color::Ansi256(208)) // Orange
        } else if page_offset >= layout.get_guard_page_offset() {
            ("GUARD_PAGE", Color::White)
        } else if page_offset >= layout.guest_heap_buffer_offset {
            ("HEAP", Color::Red)
        } else if page_offset >= layout.output_data_buffer_offset {
            ("OUTPUT_DATA", Color::Green)
        } else if page_offset >= layout.input_data_buffer_offset {
            ("INPUT_DATA", Color::Blue)
        } else if page_offset >= layout.host_function_definitions_buffer_offset {
            ("HOST_FUNC_DEF", Color::Cyan)
        } else if page_offset >= layout.peb_address {
            ("PEB", Color::Magenta)
        } else if page_offset >= layout.get_guest_code_offset() {
            ("CODE", Color::Yellow)
        } else {
            // Everything up to and including guest code should be PAGE_TABLES
            ("PAGE_TABLES", Color::Ansi256(14)) // Bright cyan
        }
    }

    let mut num_dirty_pages = 0;
    for &block in bitmap.iter() {
        num_dirty_pages += block.count_ones() as usize;
    }

    for (i, &block) in bitmap.iter().enumerate() {
        if block != 0 {
            print!("Block {:3}: ", i);

            // Print each bit in the block with appropriate color
            for bit_pos in 0..64 {
                let bit_mask = 1u64 << bit_pos;
                let page_index = i * 64 + bit_pos;
                let (_region_name, color) = get_region_info(page_index, layout);

                let mut color_spec = ColorSpec::new();
                color_spec.set_fg(Some(color));

                if block & bit_mask != 0 {
                    // Make 1s bold with dark background to stand out from 0s
                    color_spec.set_bold(true).set_bg(Some(Color::Black));
                    let _ = stdout.set_color(&color_spec);
                    print!("1");
                } else {
                    // 0s are colored but not bold, no background
                    let _ = stdout.set_color(&color_spec);
                    print!("0");
                }
                let _ = stdout.reset();
            }

            // Print a legend for this block showing which regions are represented
            let mut regions_in_block = std::collections::HashMap::new();
            for bit_pos in 0..64 {
                let bit_mask = 1u64 << bit_pos;
                if block & bit_mask != 0 {
                    let page_index = i * 64 + bit_pos;
                    let (region_name, color) = get_region_info(page_index, layout);
                    regions_in_block.insert(region_name, color);
                }
            }

            if !regions_in_block.is_empty() {
                print!(" [");
                let mut sorted_regions: Vec<_> = regions_in_block.iter().collect();
                sorted_regions.sort_by_key(|(name, _)| *name);
                for (i, (region_name, color)) in sorted_regions.iter().enumerate() {
                    if i > 0 {
                        print!(", ");
                    }
                    let mut color_spec = ColorSpec::new();
                    color_spec.set_fg(Some(**color)).set_bold(true);
                    let _ = stdout.set_color(&color_spec);
                    print!("{}", region_name);
                    let _ = stdout.reset();
                }
                print!("]");
            }
            println!();
        }
    }
    // Print the total number of dirty pages
    println!("Total dirty pages: {}", num_dirty_pages);
}

#[cfg(test)]
mod tests {
    use hyperlight_common::mem::PAGE_SIZE_USIZE;

    use crate::Result;
    use crate::mem::bitmap::{bit_index_iterator, bitmap_union, new_page_bitmap};

    #[test]
    fn new_page_bitmap_test() -> Result<()> {
        let bitmap = new_page_bitmap(1, false)?;
        assert_eq!(bitmap.len(), 1);
        assert_eq!(bitmap[0], 0);

        let bitmap = new_page_bitmap(1, true)?;
        assert_eq!(bitmap.len(), 1);
        assert_eq!(bitmap[0], 1);

        let bitmap = new_page_bitmap(32 * PAGE_SIZE_USIZE, false)?;
        assert_eq!(bitmap.len(), 1);
        assert_eq!(bitmap[0], 0);

        let bitmap = new_page_bitmap(32 * PAGE_SIZE_USIZE, true)?;
        assert_eq!(bitmap.len(), 1);
        assert_eq!(bitmap[0], 0x0000_0000_FFFF_FFFF);
        Ok(())
    }

    #[test]
    fn page_iterator() {
        let data = vec![0b1000010100, 0b01, 0b100000000000000011];
        let mut iter = bit_index_iterator(&data);
        assert_eq!(iter.next(), Some(2));
        assert_eq!(iter.next(), Some(4));
        assert_eq!(iter.next(), Some(9));
        assert_eq!(iter.next(), Some(64));
        assert_eq!(iter.next(), Some(128));
        assert_eq!(iter.next(), Some(129));
        assert_eq!(iter.next(), Some(145));
        assert_eq!(iter.next(), None);

        let data_2 = vec![0, 0, 0];
        let mut iter_2 = bit_index_iterator(&data_2);
        assert_eq!(iter_2.next(), None);

        let data_3 = vec![0, 0, 0b1, 1 << 63];
        let mut iter_3 = bit_index_iterator(&data_3);
        assert_eq!(iter_3.next(), Some(128));
        assert_eq!(iter_3.next(), Some(255));
        assert_eq!(iter_3.next(), None);

        let data_4 = vec![];
        let mut iter_4 = bit_index_iterator(&data_4);
        assert_eq!(iter_4.next(), None);
    }

    #[test]
    fn union() -> Result<()> {
        let a = 0b1000010100;
        let b = 0b01;
        let c = 0b100000000000000011;
        let d = 0b101010100000011000000011;
        let e = 0b000000000000001000000000000000000000;
        let f = 0b100000000000000001010000000001010100000000000;
        let bitmap = vec![a, b, c];
        let other_bitmap = vec![d, e, f];
        let union = bitmap_union(&bitmap, &other_bitmap).unwrap();
        assert_eq!(union, vec![a | d, b | e, c | f]);

        // different length
        bitmap_union(&[a], &[d, e, f]).unwrap_err();

        // empty bitmaps
        let union = bitmap_union(&[], &[]).unwrap();
        let empty: Vec<u64> = vec![];
        assert_eq!(union, empty);

        Ok(())
    }
}
