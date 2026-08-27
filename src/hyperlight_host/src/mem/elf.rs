// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

#[cfg(feature = "mem_profile")]
use std::sync::Arc;

#[cfg(target_arch = "aarch64")]
use goblin::elf::reloc::{R_AARCH64_NONE, R_AARCH64_RELATIVE};
#[cfg(target_arch = "x86_64")]
use goblin::elf::reloc::{R_X86_64_NONE, R_X86_64_RELATIVE};
use goblin::elf::{Elf, ProgramHeaders, Reloc};
use goblin::elf64::program_header::PT_LOAD;

use super::exe::LoadInfo;
use crate::{Result, log_then_return, new_error};

#[cfg(feature = "mem_profile")]
struct ResolvedSectionHeader {
    name: String,
    addr: u64,
    offset: u64,
    size: u64,
}

pub(crate) struct ElfInfo {
    payload: Vec<u8>,
    phdrs: ProgramHeaders,
    #[cfg(feature = "mem_profile")]
    shdrs: Vec<ResolvedSectionHeader>,
    entry: u64,
    relocs: Vec<Reloc>,
    /// Lowest `p_vaddr` across all PT_LOAD segments.
    base_va: u64,
    /// Total loaded span: `max(p_vaddr + p_memsz) - min(p_vaddr)`.
    va_size: u64,
    /// The hyperlight version string embedded by `hyperlight-guest-bin`, if
    /// present. Used to detect version/ABI mismatches between guest and host.
    guest_bin_version: Option<String>,
}

#[cfg(feature = "mem_profile")]
struct UnwindInfo {
    payload: Vec<u8>,
    load_addr: u64,
    va_size: u64,
    base_svma: u64,
    shdrs: Vec<ResolvedSectionHeader>,
}

#[cfg(feature = "mem_profile")]
impl super::exe::UnwindInfo for UnwindInfo {
    fn as_module(&self) -> framehop::Module<Vec<u8>> {
        framehop::Module::new(
            // TODO: plumb through a name from from_file if this
            // came from a file
            "guest".to_string(),
            self.load_addr..self.load_addr + self.va_size,
            self.load_addr,
            self,
        )
    }
    fn hash(&self) -> blake3::Hash {
        blake3::hash(&self.payload)
    }
}

#[cfg(feature = "mem_profile")]
impl UnwindInfo {
    fn resolved_section_header(&self, name: &[u8]) -> Option<&ResolvedSectionHeader> {
        self.shdrs
            .iter()
            .find(|&sh| sh.name.as_bytes()[0..core::cmp::min(name.len(), sh.name.len())] == *name)
    }
}

#[cfg(feature = "mem_profile")]
impl framehop::ModuleSectionInfo<Vec<u8>> for &UnwindInfo {
    fn base_svma(&self) -> u64 {
        self.base_svma
    }
    fn section_svma_range(&mut self, name: &[u8]) -> Option<std::ops::Range<u64>> {
        let shdr = self.resolved_section_header(name)?;
        Some(shdr.addr..shdr.addr + shdr.size)
    }
    fn section_data(&mut self, name: &[u8]) -> Option<Vec<u8>> {
        if name == b".eh_frame" && self.resolved_section_header(b".debug_frame").is_some() {
            /* Rustc does not always emit enough information for stack
             * unwinding in .eh_frame, presumably because we use panic =
             * abort in the guest. Framehop defaults to ignoring
             * .debug_frame if .eh_frame exists, but we want the opposite
             * behaviour here, since .debug_frame will actually contain
             * frame information whereas .eh_frame often doesn't because
             * of the aforementioned behaviour.  Consequently, we hack
             * around this by pretending that .eh_frame doesn't exist if
             * .debug_frame does. */
            return None;
        }
        let shdr = self.resolved_section_header(name)?;
        Some(self.payload[shdr.offset as usize..(shdr.offset + shdr.size) as usize].to_vec())
    }
}

impl ElfInfo {
    pub(crate) fn new(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let bytes = bytes.into();
        let mut elf = Elf::parse(&bytes)?;
        let relocs: Vec<Reloc> = elf.dynrels.iter().chain(elf.dynrelas.iter()).collect();
        for phdr in elf.program_headers.iter().filter(|p| p.p_type == PT_LOAD) {
            if phdr.p_filesz > phdr.p_memsz {
                log_then_return!(
                    "PT_LOAD segment has p_filesz ({:#x}) > p_memsz ({:#x})",
                    phdr.p_filesz,
                    phdr.p_memsz
                );
            }
            let file_end = phdr.p_offset.checked_add(phdr.p_filesz).ok_or_else(|| {
                new_error!(
                    "PT_LOAD segment file range overflows: p_offset={:#x} p_filesz={:#x}",
                    phdr.p_offset,
                    phdr.p_filesz
                )
            })?;
            if file_end as usize > bytes.len() {
                log_then_return!(
                    "PT_LOAD segment file range [{:#x}..{:#x}) exceeds file size ({:#x})",
                    phdr.p_offset,
                    file_end,
                    bytes.len()
                );
            }
        }

        let base_va = elf
            .program_headers
            .iter()
            .filter(|p| p.p_type == PT_LOAD)
            .map(|p| p.p_vaddr)
            .min()
            .ok_or_else(|| new_error!("ELF must have at least one PT_LOAD header"))?;
        let max_va_end = elf
            .program_headers
            .iter()
            .filter(|p| p.p_type == PT_LOAD)
            .map(|p| {
                p.p_vaddr.checked_add(p.p_memsz).ok_or_else(|| {
                    new_error!(
                        "PT_LOAD segment virtual address range overflows: p_vaddr={:#x} p_memsz={:#x}",
                        p.p_vaddr,
                        p.p_memsz
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .max()
            .ok_or_else(|| new_error!("ELF must have at least one PT_LOAD header"))?;
        let va_size = max_va_end - base_va;
        if va_size > super::layout::SandboxMemoryLayout::MAX_MEMORY_SIZE as u64 {
            log_then_return!(
                "ELF loaded size ({:#x}) exceeds the maximum sandbox memory size ({:#x})",
                va_size,
                super::layout::SandboxMemoryLayout::MAX_MEMORY_SIZE
            );
        }

        const RELOC_WRITE_SIZE: u64 = 8;
        for r in relocs.iter() {
            let end = r.r_offset.checked_add(RELOC_WRITE_SIZE).ok_or_else(|| {
                new_error!("relocation offset overflows: r_offset={:#x}", r.r_offset)
            })?;
            if end > va_size {
                log_then_return!(
                    "relocation target [{:#x}..{:#x}) is outside the loaded image ({:#x} bytes)",
                    r.r_offset,
                    end,
                    va_size
                );
            }
        }

        // Look for the hyperlight version note embedded by
        // hyperlight-guest-bin.
        let guest_bin_version = Self::read_version_note(&elf, &bytes);

        let phdrs = std::mem::take(&mut elf.program_headers);
        let entry = elf.entry;
        #[cfg(feature = "mem_profile")]
        let shdrs = elf
            .section_headers
            .iter()
            .filter_map(|sh| {
                Some(ResolvedSectionHeader {
                    name: elf.shdr_strtab.get_at(sh.sh_name)?.to_string(),
                    addr: sh.sh_addr,
                    offset: sh.sh_offset,
                    size: sh.sh_size,
                })
            })
            .collect();

        drop(elf);

        Ok(ElfInfo {
            payload: bytes,
            phdrs,
            base_va,
            va_size,
            #[cfg(feature = "mem_profile")]
            shdrs,
            entry,
            relocs,
            guest_bin_version,
        })
    }

    /// Read the hyperlight version note from the ELF binary
    fn read_version_note<'a>(elf: &Elf<'a>, bytes: &'a [u8]) -> Option<String> {
        use hyperlight_common::version_note::{
            HYPERLIGHT_NOTE_NAME, HYPERLIGHT_NOTE_TYPE, HYPERLIGHT_VERSION_SECTION,
        };

        let notes = elf.iter_note_sections(bytes, Some(HYPERLIGHT_VERSION_SECTION))?;
        for note in notes {
            let Ok(note) = note else { continue };
            if note.name == HYPERLIGHT_NOTE_NAME && note.n_type == HYPERLIGHT_NOTE_TYPE {
                let desc = core::str::from_utf8(note.desc).ok()?;
                return Some(desc.trim_end_matches('\0').to_string());
            }
        }
        None
    }

    pub(crate) fn entrypoint_va(&self) -> u64 {
        self.entry
    }

    /// Returns the hyperlight version string embedded in the guest binary, if
    /// present. Used to detect version/ABI mismatches between guest and host.
    pub(crate) fn guest_bin_version(&self) -> Option<&str> {
        self.guest_bin_version.as_deref()
    }

    pub(crate) fn get_base_va(&self) -> u64 {
        self.base_va
    }
    pub(crate) fn get_va_size(&self) -> usize {
        // new() bounds this by MAX_MEMORY_SIZE, which fits in a usize.
        self.va_size as usize
    }
    pub(crate) fn load_at(self, load_addr: usize, target: &mut [u8]) -> Result<LoadInfo> {
        let base_va = self.get_base_va();
        let va_size = self.get_va_size();
        if target.len() < va_size {
            log_then_return!(
                "load target ({:#x} bytes) is smaller than the loaded ELF size ({:#x} bytes)",
                target.len(),
                va_size
            );
        }
        for phdr in self.phdrs.iter().filter(|phdr| phdr.p_type == PT_LOAD) {
            let start_va = usize::try_from(phdr.p_vaddr.checked_sub(base_va).ok_or_else(|| {
                new_error!(
                    "PT_LOAD p_vaddr ({:#x}) is below base_va ({:#x})",
                    phdr.p_vaddr,
                    base_va
                )
            })?)
            .map_err(|_| new_error!("segment offset exceeds addressable range"))?;
            let payload_offset =
                usize::try_from(phdr.p_offset).map_err(|_| new_error!("p_offset too large"))?;
            let payload_len =
                usize::try_from(phdr.p_filesz).map_err(|_| new_error!("p_filesz too large"))?;
            let memsz =
                usize::try_from(phdr.p_memsz).map_err(|_| new_error!("p_memsz too large"))?;
            let file_end = start_va
                .checked_add(payload_len)
                .ok_or_else(|| new_error!("segment file region overflows"))?;
            let payload_src_end = payload_offset
                .checked_add(payload_len)
                .ok_or_else(|| new_error!("payload source range overflows"))?;
            let seg_end = start_va
                .checked_add(memsz)
                .ok_or_else(|| new_error!("segment memory region overflows"))?;
            target
                .get_mut(start_va..file_end)
                .ok_or_else(|| new_error!("segment file region out of bounds"))?
                .copy_from_slice(
                    self.payload
                        .get(payload_offset..payload_src_end)
                        .ok_or_else(|| new_error!("payload slice out of bounds"))?,
                );
            target
                .get_mut(file_end..seg_end)
                .ok_or_else(|| new_error!("segment zero-fill region out of bounds"))?
                .fill(0);
        }
        let get_addend = |name, r: &Reloc| {
            r.r_addend
                .ok_or_else(|| new_error!("{} missing addend", name))
        };
        for r in self.relocs.iter() {
            let r_off = usize::try_from(r.r_offset)
                .map_err(|_| new_error!("relocation offset too large"))?;
            let r_end = r_off
                .checked_add(8)
                .ok_or_else(|| new_error!("relocation range overflows"))?;
            let dest = target
                .get_mut(r_off..r_end)
                .ok_or_else(|| new_error!("relocation target out of bounds"))?;
            #[cfg(target_arch = "aarch64")]
            match r.r_type {
                R_AARCH64_RELATIVE => {
                    let addend = get_addend("R_AARCH64_RELATIVE", r)?;
                    let value = (load_addr as i64)
                        .checked_add(addend)
                        .ok_or_else(|| new_error!("relocation addend overflows"))?;
                    dest.copy_from_slice(&value.to_le_bytes());
                }
                R_AARCH64_NONE => {}
                _ => {
                    log_then_return!("unsupported aarch64 relocation {}", r.r_type);
                }
            }
            #[cfg(target_arch = "x86_64")]
            match r.r_type {
                R_X86_64_RELATIVE => {
                    let addend = get_addend("R_X86_64_RELATIVE", r)?;
                    let value = (load_addr as i64)
                        .checked_add(addend)
                        .ok_or_else(|| new_error!("relocation addend overflows"))?;
                    dest.copy_from_slice(&value.to_le_bytes());
                }
                R_X86_64_NONE => {}
                _ => {
                    log_then_return!("unsupported x86_64 relocation {}", r.r_type);
                }
            }
        }
        cfg_if::cfg_if! {
            if #[cfg(feature = "mem_profile")] {
                let va_size = self.get_va_size() as u64;
                let base_svma = self.get_base_va();
                Ok(LoadInfo {
                    info: Arc::new(UnwindInfo {
                        payload: self.payload,
                        load_addr: load_addr as u64,
                        va_size,
                        base_svma,
                        shdrs: self.shdrs,
                    })
                })
            } else {
                Ok(LoadInfo {})
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EHDR_SIZE: usize = 64;
    const PHDR_SIZE: usize = 56;

    struct TestPh {
        p_offset: u64,
        p_vaddr: u64,
        p_filesz: u64,
        p_memsz: u64,
    }

    fn build_test_elf(phs: &[TestPh], file_len: usize) -> Vec<u8> {
        let mut v = Vec::new();
        // ELF header
        v.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        v.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
        v.extend_from_slice(&0x3eu16.to_le_bytes()); // e_machine = x86-64
        v.extend_from_slice(&1u32.to_le_bytes()); // e_version
        v.extend_from_slice(&0x1000u64.to_le_bytes()); // e_entry
        v.extend_from_slice(&(EHDR_SIZE as u64).to_le_bytes()); // e_phoff
        v.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
        v.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        v.extend_from_slice(&(EHDR_SIZE as u16).to_le_bytes()); // e_ehsize
        v.extend_from_slice(&(PHDR_SIZE as u16).to_le_bytes()); // e_phentsize
        v.extend_from_slice(&(phs.len() as u16).to_le_bytes()); // e_phnum
        v.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize
        v.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
        v.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
        // Program headers
        for p in phs {
            v.extend_from_slice(&PT_LOAD.to_le_bytes()); // p_type
            v.extend_from_slice(&5u32.to_le_bytes()); // p_flags = R+X
            v.extend_from_slice(&p.p_offset.to_le_bytes());
            v.extend_from_slice(&p.p_vaddr.to_le_bytes());
            v.extend_from_slice(&p.p_vaddr.to_le_bytes()); // p_paddr
            v.extend_from_slice(&p.p_filesz.to_le_bytes());
            v.extend_from_slice(&p.p_memsz.to_le_bytes());
            v.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
        }
        if v.len() < file_len {
            v.resize(file_len, 0);
        }
        v
    }

    #[test]
    fn valid_single_segment() {
        let elf = build_test_elf(
            &[TestPh {
                p_offset: 0,
                p_vaddr: 0x1000,
                p_filesz: 0x40,
                p_memsz: 0x1000,
            }],
            0x1000,
        );
        let info = ElfInfo::new(elf).expect("valid ELF should parse");
        assert_eq!(info.get_base_va(), 0x1000);
        assert_eq!(info.get_va_size(), 0x1000);
    }

    #[test]
    fn unsorted_pt_load_segments_handled_correctly() {
        let elf = build_test_elf(
            &[
                TestPh {
                    p_offset: 0,
                    p_vaddr: 0x10000,
                    p_filesz: 0x40,
                    p_memsz: 0x1000,
                },
                TestPh {
                    p_offset: 0,
                    p_vaddr: 0x1000,
                    p_filesz: 0x40,
                    p_memsz: 0x1000,
                },
            ],
            0x1000,
        );
        let info = ElfInfo::new(elf).expect("unsorted segments should parse");
        assert_eq!(info.get_base_va(), 0x1000);
        // va_size = max(0x10000+0x1000, 0x1000+0x1000) - 0x1000 = 0x11000 - 0x1000 = 0x10000
        assert_eq!(info.get_va_size(), 0x10000);
    }

    #[test]
    fn reject_p_offset_past_eof() {
        let elf = build_test_elf(
            &[TestPh {
                p_offset: 0x100000,
                p_vaddr: 0x1000,
                p_filesz: 0x10,
                p_memsz: 0x2000,
            }],
            0x1000,
        );
        assert!(
            ElfInfo::new(elf).is_err(),
            "should reject segment with p_offset past end of file"
        );
    }

    #[test]
    fn reject_p_filesz_greater_than_p_memsz() {
        let elf = build_test_elf(
            &[TestPh {
                p_offset: 0,
                p_vaddr: 0x1000,
                p_filesz: 0x100,
                p_memsz: 0x10,
            }],
            0x1000,
        );
        assert!(
            ElfInfo::new(elf).is_err(),
            "should reject segment with p_filesz > p_memsz"
        );
    }

    #[test]
    fn reject_vaddr_memsz_overflow() {
        let elf = build_test_elf(
            &[TestPh {
                p_offset: 0,
                p_vaddr: u64::MAX - 0x100,
                p_filesz: 0x40,
                p_memsz: 0x200,
            }],
            0x1000,
        );
        assert!(
            ElfInfo::new(elf).is_err(),
            "should reject segment where p_vaddr + p_memsz overflows u64"
        );
    }

    #[test]
    fn reject_p_offset_p_filesz_overflow() {
        let elf = build_test_elf(
            &[TestPh {
                p_offset: u64::MAX - 0x10,
                p_vaddr: 0x1000,
                p_filesz: 0x20,
                p_memsz: 0x1000,
            }],
            0x1000,
        );
        assert!(
            ElfInfo::new(elf).is_err(),
            "should reject segment where p_offset + p_filesz overflows u64"
        );
    }

    #[test]
    fn reject_huge_memsz_exceeding_max_memory() {
        let elf = build_test_elf(
            &[TestPh {
                p_offset: 0,
                p_vaddr: 0x1000,
                p_filesz: 0x40,
                p_memsz: 0x7fff_ffff_0000,
            }],
            0x1000,
        );
        assert!(
            ElfInfo::new(elf).is_err(),
            "should reject ELF whose loaded size exceeds MAX_MEMORY_SIZE"
        );
    }

    #[test]
    fn load_at_rejects_undersized_target() {
        let elf_bytes = build_test_elf(
            &[TestPh {
                p_offset: 0,
                p_vaddr: 0x1000,
                p_filesz: 0x40,
                p_memsz: 0x1000,
            }],
            0x1000,
        );
        let info = ElfInfo::new(elf_bytes.clone()).expect("should parse");
        let mut target = vec![0u8; 0x100];
        assert!(
            info.load_at(0x1000, &mut target).is_err(),
            "should reject target smaller than va_size"
        );
    }

    #[test]
    fn load_at_with_unsorted_segments() {
        let elf_bytes = build_test_elf(
            &[
                TestPh {
                    p_offset: 0,
                    p_vaddr: 0x2000,
                    p_filesz: 0x40,
                    p_memsz: 0x40,
                },
                TestPh {
                    p_offset: 0,
                    p_vaddr: 0x1000,
                    p_filesz: 0x40,
                    p_memsz: 0x40,
                },
            ],
            0x1000,
        );
        let info = ElfInfo::new(elf_bytes.clone()).expect("should parse");
        let va_size = info.get_va_size();
        // va_size = max(0x2000+0x40, 0x1000+0x40) - 0x1000 = 0x2040 - 0x1000 = 0x1040
        assert_eq!(va_size, 0x1040);
        let mut target = vec![0u8; va_size];
        info.load_at(0x1000, &mut target)
            .expect("load_at should succeed with unsorted segments");
    }
}
