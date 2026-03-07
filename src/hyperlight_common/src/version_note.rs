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
//! Guest binaries built with `hyperlight-guest-bin` include a `.note.hyperlight.version`
//! ELF note section containing the crate version they were compiled against.
//! The host reads this section at load time to verify ABI compatibility.

/// The ELF note section name used to embed the hyperlight-guest-bin version in guest binaries.
pub const HYPERLIGHT_VERSION_SECTION: &str = ".note.hyperlight.version";

/// The owner name used in the ELF note header for hyperlight version metadata.
pub const HYPERLIGHT_NOTE_NAME: &str = "Hyperlight";

/// The note type value used in the ELF note header for hyperlight version metadata.
pub const HYPERLIGHT_NOTE_TYPE: u32 = 1;

/// A byte array with 4-byte alignment, used for ELF note name/descriptor
/// fields. The compiler inserts trailing padding automatically so that the
/// next field starts at a 4-byte boundary.
#[repr(C, align(4))]
struct Aligned4<const N: usize>(pub(self) [u8; N]);

/// An ELF note structure suitable for embedding in a `#[link_section]` static.
///
/// `NAME_SZ` and `DESC_SZ` must include the null terminator.
/// The `+ 1` can't be hidden inside the struct because stable Rust doesn't
/// allow `[u8; N + 1]` in struct fields. [`Aligned4`] handles the 4-byte
/// alignment padding required by the note format.
#[repr(C)]
pub struct ElfNote<const NAME_SZ: usize, const DESC_SZ: usize> {
    namesz: u32,
    descsz: u32,
    n_type: u32,
    name: Aligned4<NAME_SZ>,
    desc: Aligned4<DESC_SZ>,
}

// SAFETY: ElfNote contains only plain data (`u32` and `[u8; N]`).
// Required because ElfNote is used in a `static` (for `#[link_section]`),
// and `static` values must be `Sync`.
unsafe impl<const N: usize, const D: usize> Sync for ElfNote<N, D> {}

impl<const NAME_SZ: usize, const DESC_SZ: usize> ElfNote<NAME_SZ, DESC_SZ> {
    /// Create a new ELF note from a name string, descriptor string, and type.
    ///
    /// `NAME_SZ` and `DESC_SZ` must equal `name.len() + 1` and `desc.len() + 1`
    /// respectively (the `+ 1` accounts for the null terminator).
    pub const fn new(name: &str, desc: &str, n_type: u32) -> Self {
        Self {
            namesz: NAME_SZ as u32,
            descsz: DESC_SZ as u32,
            n_type,
            name: Aligned4(pad_str_to_array(name)),
            desc: Aligned4(pad_str_to_array(desc)),
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
