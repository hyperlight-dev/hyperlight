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

//! ELF note types for embedding hyperlight version metadata in guest binaries.
//!
//! Guest binaries built with `hyperlight-guest-bin` include a `.note.hyperlight-version`
//! ELF note section containing the crate version they were compiled against.
//! The host reads this section at load time to verify ABI compatibility.

/// The ELF note section name used to embed the hyperlight-guest-bin version in guest binaries.
pub const HYPERLIGHT_VERSION_SECTION: &str = ".note.hyperlight-version";

/// The owner name used in the ELF note header for hyperlight version metadata.
pub const HYPERLIGHT_NOTE_NAME: &str = "Hyperlight";

/// The note type value used in the ELF note header for hyperlight version metadata.
pub const HYPERLIGHT_NOTE_TYPE: u32 = 1;

/// Size of the ELF note header (namesz + descsz + type, each u32).
const NOTE_HEADER_SIZE: usize = 3 * size_of::<u32>();

/// Compute the padded size of the name field for a 64-bit ELF note.
///
/// The name must be padded so that the descriptor starts at an 8-byte
/// aligned offset from the start of the note entry:
/// `(NOTE_HEADER_SIZE + padded_name) % 8 == 0`.
pub const fn padded_name_size(name_len_with_nul: usize) -> usize {
    let desc_offset = NOTE_HEADER_SIZE + name_len_with_nul;
    let padding = (8 - (desc_offset % 8)) % 8;
    name_len_with_nul + padding
}

/// Compute the padded size of the descriptor field for a 64-bit ELF note.
///
/// The descriptor must be padded so that the next note entry starts at
/// an 8-byte aligned offset: `padded_desc % 8 == 0`.
pub const fn padded_desc_size(desc_len_with_nul: usize) -> usize {
    let padding = (8 - (desc_len_with_nul % 8)) % 8;
    desc_len_with_nul + padding
}

/// An ELF note structure suitable for embedding in a `#[link_section]` static.
///
/// Follows the System V gABI note format as specified in
/// <https://www.sco.com/developers/gabi/latest/ch5.pheader.html#note_section>.
///
/// `NAME_SZ` and `DESC_SZ` are the **padded** sizes of the name and descriptor
/// arrays (including null terminator and alignment padding). Use
/// [`padded_name_size`] and [`padded_desc_size`] to compute them from
/// `str.len() + 1` (the null-terminated length).
///
/// The constructor enforces these constraints with compile-time assertions.
#[repr(C, align(8))]
pub struct ElfNote<const NAME_SZ: usize, const DESC_SZ: usize> {
    namesz: u32,
    descsz: u32,
    n_type: u32,
    // NAME_SZ includes the null terminator and padding to align `desc`
    // to an 8-byte boundary. Must equal `padded_name_size(namesz)`.
    // Enforced at compile time by `new()`.
    name: [u8; NAME_SZ],
    // DESC_SZ includes the null terminator and padding so the total
    // note size is a multiple of 8. Must equal `padded_desc_size(descsz)`.
    // Enforced at compile time by `new()`.
    desc: [u8; DESC_SZ],
}

// SAFETY: ElfNote contains only plain data (`u32` and `[u8; N]`).
// Required because ElfNote is used in a `static` (for `#[link_section]`),
// and `static` values must be `Sync`.
unsafe impl<const N: usize, const D: usize> Sync for ElfNote<N, D> {}

impl<const NAME_SZ: usize, const DESC_SZ: usize> ElfNote<NAME_SZ, DESC_SZ> {
    /// Create a new ELF note from a name string, descriptor string, and type.
    ///
    /// # Panics
    ///
    /// Panics at compile time if `NAME_SZ` or `DESC_SZ` don't match
    /// `padded_name_size(name.len() + 1)` or `padded_desc_size(desc.len() + 1)`.
    pub const fn new(name: &str, desc: &str, n_type: u32) -> Self {
        // NAME_SZ and DESC_SZ must match the padded sizes.
        assert!(
            NAME_SZ == padded_name_size(name.len() + 1),
            "NAME_SZ must equal padded_name_size(name.len() + 1)"
        );
        assert!(
            DESC_SZ == padded_desc_size(desc.len() + 1),
            "DESC_SZ must equal padded_desc_size(desc.len() + 1)"
        );

        // desc must start at an 8-byte aligned offset from the note start.
        assert!(
            core::mem::offset_of!(Self, desc) % 8 == 0,
            "desc is not 8-byte aligned"
        );

        // Total note size must be a multiple of 8 for next-entry alignment.
        assert!(
            size_of::<Self>() % 8 == 0,
            "total note size is not 8-byte aligned"
        );

        Self {
            namesz: (name.len() + 1) as u32,
            descsz: (desc.len() + 1) as u32,
            n_type,
            name: pad_str_to_array(name),
            desc: pad_str_to_array(desc),
        }
    }
}

/// Copy a string into a zero-initialised byte array at compile time.
const fn pad_str_to_array<const N: usize>(s: &str) -> [u8; N] {
    let bytes = s.as_bytes();
    let mut result = [0u8; N];
    let mut i = 0;
    while i < bytes.len() {
        result[i] = bytes[i];
        i += 1;
    }
    result
}
