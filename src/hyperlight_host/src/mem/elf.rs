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

#[cfg(feature = "unwind_guest")]
use std::sync::Arc;

#[cfg(target_arch = "aarch64")]
use goblin::elf::reloc::{R_AARCH64_NONE, R_AARCH64_RELATIVE};
#[cfg(target_arch = "x86_64")]
use goblin::elf::reloc::{R_X86_64_NONE, R_X86_64_RELATIVE};
use goblin::elf::{Elf, ProgramHeaders, Reloc};
use goblin::elf64::program_header::PT_LOAD;

use crate::{log_then_return, new_error, Result};

#[cfg(feature = "unwind_guest")]
struct ResolvedSectionHeader {
    name: String,
    addr: u64,
    offset: u64,
    size: u64,
}

pub(crate) struct ElfInfo {
    payload: Vec<u8>,
    phdrs: ProgramHeaders,
    #[cfg(feature = "unwind_guest")]
    shdrs: Vec<ResolvedSectionHeader>,
    entry: u64,
    relocs: Vec<Reloc>,
}

#[cfg(feature = "unwind_guest")]
struct UnwindInfo {
    payload: Vec<u8>,
    load_addr: u64,
    va_size: u64,
    base_svma: u64,
    shdrs: Vec<ResolvedSectionHeader>,
}

#[cfg(feature = "unwind_guest")]
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

#[cfg(feature = "unwind_guest")]
impl UnwindInfo {
    fn resolved_section_header(&self, name: &[u8]) -> Option<&ResolvedSectionHeader> {
        self.shdrs
            .iter()
            .find(|&sh| sh.name.as_bytes()[0..core::cmp::min(name.len(), sh.name.len())] == *name)
    }
}

#[cfg(feature = "unwind_guest")]
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
    pub(crate) fn new(bytes: &[u8]) -> Result<Self> {
        let elf = Elf::parse(bytes)?;
        let relocs = elf.dynrels.iter().chain(elf.dynrelas.iter()).collect();
        if !elf
            .program_headers
            .iter()
            .any(|phdr| phdr.p_type == PT_LOAD)
        {
            log_then_return!("ELF must have at least one PT_LOAD header");
        }
        Ok(ElfInfo {
            payload: bytes.to_vec(),
            phdrs: elf.program_headers,
            #[cfg(feature = "unwind_guest")]
            shdrs: elf
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
                .collect(),
            entry: elf.entry,
            relocs,
        })
    }
    pub(crate) fn entrypoint_va(&self) -> u64 {
        self.entry
    }
    pub(crate) fn get_base_va(&self) -> u64 {
        let min_phdr = self
            .phdrs
            .iter()
            .find(|phdr| phdr.p_type == PT_LOAD)
            .unwrap(); // guaranteed not to panic because of the check in new()
        min_phdr.p_vaddr
    }
    pub(crate) fn get_va_size(&self) -> usize {
        let max_phdr = self
            .phdrs
            .iter()
            .rev()
            .find(|phdr| phdr.p_type == PT_LOAD)
            .unwrap(); // guaranteed not to panic because of the check in new()
        (max_phdr.p_vaddr + max_phdr.p_memsz - self.get_base_va()) as usize
    }
    pub(crate) fn load_at(
        self,
        load_addr: usize,
        target: &mut [u8],
    ) -> Result<super::exe::LoadInfo> {
        let base_va = self.get_base_va();
        for phdr in self.phdrs.iter().filter(|phdr| phdr.p_type == PT_LOAD) {
            let start_va = (phdr.p_vaddr - base_va) as usize;
            let payload_offset = phdr.p_offset as usize;
            let payload_len = phdr.p_filesz as usize;
            target[start_va..start_va + payload_len]
                .copy_from_slice(&self.payload[payload_offset..payload_offset + payload_len]);
            target[start_va + payload_len..start_va + phdr.p_memsz as usize].fill(0);
        }
        let get_addend = |name, r: &Reloc| {
            r.r_addend
                .ok_or_else(|| new_error!("{} missing addend", name))
        };
        for r in self.relocs.iter() {
            #[cfg(target_arch = "aarch64")]
            match r.r_type {
                R_AARCH64_RELATIVE => {
                    let addend = get_addend("R_AARCH64_RELATIVE", r)?;
                    target[r.r_offset as usize..r.r_offset as usize + 8]
                        .copy_from_slice(&(load_addr as i64 + addend).to_le_bytes());
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
                    target[r.r_offset as usize..r.r_offset as usize + 8]
                        .copy_from_slice(&(load_addr as i64 + addend).to_le_bytes());
                }
                R_X86_64_NONE => {}
                _ => {
                    log_then_return!("unsupported x86_64 relocation {}", r.r_type);
                }
            }
        }
        cfg_if::cfg_if! {
            if #[cfg(feature = "unwind_guest")] {
                let va_size = self.get_va_size() as u64;
                let base_svma = self.get_base_va();
                Ok(Arc::new(UnwindInfo {
                    payload: self.payload,
                    load_addr: load_addr as u64,
                    va_size,
                    base_svma,
                    shdrs: self.shdrs,
                }))
            } else {
                Ok(())
            }
        }
    }
}
