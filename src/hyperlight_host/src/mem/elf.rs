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

#[cfg(target_arch = "aarch64")]
use goblin::elf::reloc::{R_AARCH64_NONE, R_AARCH64_RELATIVE};
#[cfg(target_arch = "x86_64")]
use goblin::elf::reloc::{R_X86_64_NONE, R_X86_64_RELATIVE};
use goblin::elf::{Elf, ProgramHeaders, Reloc};
use goblin::elf64::program_header::PT_LOAD;

use crate::{log_then_return, new_error, Result};

pub(crate) struct ElfInfo {
    payload: Vec<u8>,
    phdrs: ProgramHeaders,
    entry: u64,
    relocs: Vec<Reloc>,
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
            entry: elf.entry,
            relocs,
        })
    }
    pub(crate) fn entrypoint_va(&self) -> u64 {
        self.entry
    }
    pub(crate) fn get_base_va(&self) -> u64 {
        #[allow(clippy::unwrap_used)] // guaranteed not to panic because of the check in new()
        let min_phdr = self
            .phdrs
            .iter()
            .find(|phdr| phdr.p_type == PT_LOAD)
            .unwrap();
        min_phdr.p_vaddr
    }
    pub(crate) fn get_va_size(&self) -> usize {
        #[allow(clippy::unwrap_used)] // guaranteed not to panic because of the check in new()
        let max_phdr = self
            .phdrs
            .iter()
            .rev()
            .find(|phdr| phdr.p_type == PT_LOAD)
            .unwrap();
        (max_phdr.p_vaddr + max_phdr.p_memsz - self.get_base_va()) as usize
    }
    pub(crate) fn load_at(&self, load_addr: usize, target: &mut [u8]) -> Result<()> {
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
        Ok(())
    }
}
