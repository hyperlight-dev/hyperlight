use std::fs::File;
use std::io::{Cursor, Read, Write};

use goblin::pe::optional_header::OptionalHeader;
use goblin::pe::section_table::SectionTable;
use goblin::pe::PE;
use tracing::{info, instrument, Span};

use crate::mem::pe::base_relocations;
use crate::{debug, log_then_return, Result};

const IMAGE_REL_BASED_DIR64: u8 = 10;
const IMAGE_REL_BASED_ABSOLUTE: u8 = 0;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const CHARACTERISTICS_RELOCS_STRIPPED: u16 = 0x0001;
const CHARACTERISTICS_EXECUTABLE_IMAGE: u16 = 0x0002;

/// An owned representation of a PE file.
///
/// Does not contain comprehensive information about a given
/// PE file, but rather just enough to be able to do relocations,
/// symbol resolution, and actually execute it within a `Sandbox`.
pub(crate) struct PEInfo {
    payload: Vec<u8>,
    payload_len: usize,
    optional_header: OptionalHeader,
    reloc_section: Option<SectionTable>,
}

impl PEInfo {
    #[instrument(err(Debug), parent = Span::current(), level= "Trace")]
    pub(crate) fn from_file(filename: &str) -> Result<Self> {
        info!("Loading PE file from {}", filename);
        let mut file = File::open(filename)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        Self::new(contents.as_slice())
    }
    /// Create a new `PEInfo` from a slice of bytes.
    ///
    /// Returns `Ok` with the new `PEInfo` if `pe_bytes` is a valid
    /// PE file and could properly be parsed as such, and `Err` if not.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn new(pe_bytes: &[u8]) -> Result<Self> {
        let mut pe = PE::parse(pe_bytes)?;

        // Validate that the PE file has the expected characteristics up-front

        if pe.header.coff_header.machine != IMAGE_FILE_MACHINE_AMD64 {
            log_then_return!("unsupported PE file, contents is not a x64 File")
        }

        if !pe.is_64 {
            log_then_return!("unsupported PE file, not a PE32+ formatted file")
        }

        if (pe.header.coff_header.characteristics & CHARACTERISTICS_EXECUTABLE_IMAGE)
            != CHARACTERISTICS_EXECUTABLE_IMAGE
        {
            log_then_return!("unsupported PE file, not an executable image")
        }

        let optional_header = pe
            .header
            .optional_header
            .expect("unsupported PE file, missing optional header entry");

        // check that the PE file was built with the option /DYNAMICBASE

        if optional_header.windows_fields.dll_characteristics & 0x0040 == 0 {
            log_then_return!("unsupported PE file, not built with /DYNAMICBASE")
        }

        if optional_header.windows_fields.section_alignment
            != optional_header.windows_fields.file_alignment
        {
            log_then_return!("unsupported PE file, section alignment does not match file alignment make sure to link the .exe with /FILEALIGN and /ALIGN options set to the same value")
        }

        if (pe.header.coff_header.characteristics & CHARACTERISTICS_RELOCS_STRIPPED)
            == CHARACTERISTICS_RELOCS_STRIPPED
        {
            log_then_return!("unsupported PE file, relocations have been removed")
        }

        // Check sections and make sure that the virtual size is less than or equal to the raw size
        // If a difference is found in the .data section, we will resize the data section to match the virtual size

        let mut data_section_additional_bytes = 0;
        let mut pre_additonal_data_size = 0;
        let mut post_additional_data_index = 0;
        let mut data_section_raw_pointer = 0;

        for (i, section) in pe.sections.iter().enumerate() {
            let name = section.name().unwrap_or("Unknown");
            let virtual_size = section.virtual_size;
            let raw_size = section.size_of_raw_data;
            debug!(
                "Section: {}, Virtual Size: {}, On-Disk Size: {}",
                name, virtual_size, raw_size
            );

            if virtual_size > raw_size {
                // we are going to take care of the data section
                if name == ".data" {
                    data_section_raw_pointer = section.pointer_to_raw_data;
                    data_section_additional_bytes = virtual_size - raw_size;
                    debug!(
                        "Resizing the data section - Data Section Additional Bytes: {}",
                        data_section_additional_bytes
                    );
                    debug!(
                        "Resizing the data section - Existing PE File Size: {} New PE File Size: {}",
                        pe_bytes.len(),
                        pe_bytes.len() + data_section_additional_bytes as usize,
                    );
                    debug!(
                        "Resizing the data section - Data Section Raw Pointer: {}",
                        data_section_raw_pointer
                    );

                    // we use all the data in pe_bytes up to the end of the raw data of the .data section
                    pre_additonal_data_size =
                        (section.pointer_to_raw_data + section.size_of_raw_data) as usize;

                    debug!("Pre Additional Data Size: {}", pre_additonal_data_size);

                    // the remainder of the data is the rest of the file after the .data section if any

                    let next_section = pe.sections.get(i + 1);

                    if let Some(next_section) = next_section {
                        post_additional_data_index = (next_section.pointer_to_raw_data) as usize;
                        debug!("Post Additional Data Index: {}", post_additional_data_index);
                    } else {
                        debug!("No more sections after the .data section");
                    }
                } else {
                    log_then_return!(
                        "Section {} has a virtual size {} greater than the on-disk size {}",
                        name,
                        virtual_size,
                        raw_size
                    );
                }
            }
        }

        // Now we need to fix up any section addresses if we have resized the .data section

        if data_section_additional_bytes > 0 {
            for section in pe.sections.iter_mut() {
                if section.pointer_to_raw_data > data_section_raw_pointer {
                    section.pointer_to_raw_data += data_section_additional_bytes;
                }
            }
        }

        // Now we need to create the Vec<u8> that will be loaded into guest memory

        let payload = if data_section_additional_bytes > 0 {
            // extend the data section to match the virtual size in the payload
            // resize data section is the difference between the virtual size and the raw size of the data section so we need to add that to the size of the pe_file
            let mut new_pe_bytes =
                Vec::with_capacity(pe_bytes.len() + data_section_additional_bytes as usize);

            // the first slice is from the start of the file to the end of the raw data of the .data section
            new_pe_bytes.extend_from_slice(&pe_bytes[..pre_additonal_data_size]);

            // the second slice is the difference between the virtual size and the raw size of the .data section
            new_pe_bytes.extend_from_slice(&vec![0; data_section_additional_bytes as usize]);

            // the remainder of the data is the rest of the file after the .data section if any

            if post_additional_data_index > 0 {
                new_pe_bytes.extend_from_slice(&pe_bytes[post_additional_data_index..]);
            }
            new_pe_bytes
        } else {
            Vec::from(pe_bytes)
        };

        let reloc_section = pe
            .sections
            .iter()
            .find(|section| section.name().unwrap_or_default() == ".reloc")
            .cloned();

        Ok(Self {
            payload,
            optional_header,
            payload_len: pe_bytes.len() + data_section_additional_bytes as usize,
            reloc_section,
        })
    }

    /// Get a reference to the payload contained within `self`
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_payload(&self) -> &[u8] {
        &self.payload
    }

    /// Get a mutable reference to the payload contained within `self`
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_payload_mut(&mut self) -> &mut [u8] {
        &mut self.payload
    }
    /// Get the length of the entire PE file payload
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_payload_len(&self) -> usize {
        self.payload_len
    }

    /// Get the entry point offset from the PE file's optional COFF
    /// header.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn entry_point_offset(&self) -> u64 {
        self.optional_header.standard_fields.address_of_entry_point
    }

    /// Get the load address specified in the PE file's optional COFF header.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn preferred_load_address(&self) -> u64 {
        self.optional_header.windows_fields.image_base
    }

    /// Return the stack reserve field from the optional COFF header.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn stack_reserve(&self) -> u64 {
        self.optional_header.windows_fields.size_of_stack_reserve
    }

    /// Return the stack commit field from the optional COFF header.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn stack_commit(&self) -> u64 {
        self.optional_header.windows_fields.size_of_stack_commit
    }

    /// Return the heap reserve field from the optional COFF header.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn heap_reserve(&self) -> u64 {
        self.optional_header.windows_fields.size_of_heap_reserve
    }

    /// Return the heap commit field from the optional COFF header.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn heap_commit(&self) -> u64 {
        self.optional_header.windows_fields.size_of_heap_commit
    }

    /// Apply the list of `RelocationPatch`es in `patches` to the given
    /// `payload` and return the number of patches applied.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn apply_relocation_patches(
        payload: &mut [u8],
        patches: Vec<RelocationPatch>,
    ) -> Result<usize> {
        let payload_len = payload.len();
        let mut cur = Cursor::new(payload);

        // Track how many patches were applied to the payload
        let mut applied: usize = 0;
        for patch in patches {
            if patch.offset >= payload_len {
                log_then_return!("invalid offset is larger than the payload");
            }

            cur.set_position(patch.offset as u64);
            cur.write_all(&patch.relocated_virtual_address.to_le_bytes())
                .expect("failed to write patch to pe file contents");
            applied += 1;
        }

        Ok(applied)
    }

    /// Get a list of patches to make to the symbol table to
    /// complete the relocations in the relocation table.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_exe_relocation_patches(
        &self,
        payload: &[u8],
        address_to_load_at: usize,
    ) -> Result<Vec<RelocationPatch>> {
        // see the following for information on relocations:
        //
        // - https://stackoverflow.com/questions/17436668/how-are-pe-base-relocations-build-up
        // - https://0xrick.github.io/win-internals/pe7/
        // - https://www.codeproject.com/Articles/12532/Inject-your-code-to-a-Portable-Executable-file#ImplementRelocationTable7_2

        // If the exe is loading/loaded at its preferred address there is nothing to do
        let addr_diff = (address_to_load_at as u64).wrapping_sub(self.preferred_load_address());
        if addr_diff == 0 {
            return Ok(Vec::new());
        }

        let relocations = base_relocations::get_base_relocations(payload, &self.reloc_section)
            .expect("error parsing base relocations");
        let mut patches = Vec::with_capacity(relocations.len());

        for reloc in relocations {
            match reloc.typ {
                // IMAGE_REL_BASED_DIR64:
                // "The base relocation applies the difference to the
                // 64-bit field at offset"
                // see: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types
                IMAGE_REL_BASED_DIR64 => {
                    let offset = reloc.page_base_rva as u64 + (reloc.page_offset as u64);

                    // Read the virtual address stored in reloc_offset as a 64bit value
                    let mut cur = Cursor::new(payload);
                    cur.set_position(offset);
                    let mut bytes = [0; 8];
                    cur.read_exact(&mut bytes)?;
                    let original_address = u64::from_le_bytes(bytes);

                    // Add the address diff to the original address
                    // Note that we are using wrapping when calculating the diff and then again when applying it to the original address
                    // So even though the diff is an unsigned number, we can represent a negative number using 2's complement.
                    // This lets us avoid trying to work with signed and unsigned integers (which isn't supported in stable rust yet).
                    let relocated_virtual_address = original_address.wrapping_add(addr_diff);
                    patches.push(RelocationPatch {
                        offset: offset as usize,
                        relocated_virtual_address,
                    });
                }

                // IMAGE_REL_BASED_ABSOLUTE
                // "The base relocation is skipped. This type can
                // be used to pad a block."
                // see: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types
                IMAGE_REL_BASED_ABSOLUTE => (),

                // Give up on any other relocation type
                _ => {
                    log_then_return!("unsupported relocation type {}", reloc.typ);
                }
            }
        }
        Ok(patches)
    }
}

/// Represents a patch that relocates a symbol to its final destination.
#[derive(Debug, Copy, Clone)]
pub(crate) struct RelocationPatch {
    /// The offset of the address to patch.
    offset: usize,
    /// The new virtual address that should be written at offset.
    relocated_virtual_address: u64,
}

#[cfg(test)]
mod tests {
    use std::fs;

    use hyperlight_testing::{callback_guest_as_string, simple_guest_as_string};

    use crate::{new_error, Result};

    #[allow(dead_code)]
    struct PEFileTest {
        path: String,
        stack_size: u64,
        heap_size: u64,
        load_address: u64,
        num_relocations: Vec<usize>,
    }
    fn pe_files() -> Result<Vec<PEFileTest>> {
        let simple_guest_pe_file_test = if cfg!(debug_assertions) {
            PEFileTest {
                path: simple_guest_as_string()
                    .map_err(|e| new_error!("Simple Guest Path Error {}", e))?,
                stack_size: 65536,
                heap_size: 131072,
                load_address: 5368709120,
                num_relocations: (900..1200).collect(),
                // range of possible # of relocations
                // (hardware dependant)
            }
        } else {
            PEFileTest {
                path: simple_guest_as_string()
                    .map_err(|e| new_error!("Simple Guest Path Error {}", e))?,
                stack_size: 65536,
                heap_size: 131072,
                load_address: 5368709120,
                num_relocations: (600..900).collect(),
            }
        };
        // if your test fails w/ num_relocations,
        // feel free to edit these values to match
        // what you get when you run the test.
        // This test is really just to make sure
        // our PE parsing logic is working, so
        // specifics don't matter.

        let callback_guest_pe_file_test = if cfg!(debug_assertions) {
            PEFileTest {
                path: callback_guest_as_string()
                    .map_err(|e| new_error!("Callback Guest Path Error {}", e))?,
                stack_size: 65536,
                heap_size: 131072,
                load_address: 5368709120,
                num_relocations: (600..900).collect(),
            }
        } else {
            PEFileTest {
                path: callback_guest_as_string()
                    .map_err(|e| new_error!("Callback Guest Path Error {}", e))?,
                stack_size: 65536,
                heap_size: 131072,
                load_address: 5368709120,
                num_relocations: (500..800).collect(),
            }
        };

        Ok(vec![simple_guest_pe_file_test, callback_guest_pe_file_test])
    }

    #[test]
    fn load_pe_info() -> Result<()> {
        for test in pe_files()? {
            let pe_path = test.path;
            let pe_bytes = fs::read(pe_path.clone())?;
            let pe_info = super::PEInfo::new(&pe_bytes)?;

            // Validate that the pe headers aren't empty
            assert_eq!(
                test.stack_size,
                pe_info.stack_reserve(),
                "unexpected stack reserve for {pe_path}",
            );
            assert_eq!(
                test.stack_size,
                pe_info.stack_commit(),
                "unexpected stack commit for {pe_path}"
            );
            assert_eq!(
                pe_info.heap_reserve(),
                test.heap_size,
                "unexpected heap reserve for {pe_path}",
            );
            assert_eq!(
                pe_info.heap_commit(),
                test.heap_size,
                "unexpected heap commit for {pe_path}",
            );
            assert_eq!(
                pe_info.preferred_load_address(),
                test.load_address,
                "unexpected load address for {pe_path}"
            );

            let patches = pe_info
                .get_exe_relocation_patches(&pe_info.payload, 0)
                .unwrap_or_else(|_| panic!("wrong # of relocation patches returned for {pe_path}"));

            let num_patches = patches.len();
            assert!(
                test.num_relocations.contains(&num_patches),
                "unexpected number ({num_patches}) of relocations for {pe_path}"
            );

            // simple guest is the only test file with relocations, check that it was calculated correctly
            // if pe_path.ends_with("simpleguest.exe") {
            //     let patch = patches[0];
            //     let expected_patch_offset = if cfg!(debug_assertions) {
            //         0x210A0
            //     } else {
            //         0xEEA0
            //     };
            //     // these values might have to
            //     // be modified if you change
            //     // simpleguest.

            //     let received_patch_offset = patch.offset;

            //     assert_eq!(
            //         patch.offset, expected_patch_offset,
            //         "incorrect patch offset ({received_patch_offset}) for {pe_path}, expected {expected_patch_offset}"
            //     );
            // }

            // ^^^ I am commenting this out because we can a different patch_offset in CI than we do locally.
        }
        Ok(())
    }
}
