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

use std::fs::File;
use std::io::Read;
use std::vec::Vec;

use super::elf::ElfInfo;
use super::ptr_offset::Offset;
use crate::Result;

// This is used extremely infrequently, so being unusually large for PE
// files _really_ doesn't matter, and probably isn't really worth the
// cost of an indirection.
#[allow(clippy::large_enum_variant)]
pub enum ExeInfo {
    Elf(ElfInfo),
}

// There isn't a commonly-used standard convention for heap and stack
// limits to be included in ELF files as they are in
// PEs. Consequently, we use these static defaults as the default
// limits, unless overwritten when setting up the sandbox.
const DEFAULT_ELF_STACK_RESERVE: u64 = 65536;
const DEFAULT_ELF_HEAP_RESERVE: u64 = 131072;

impl ExeInfo {
    pub fn from_file(path: &str) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        Self::from_buf(&contents)
    }
    pub fn from_buf(buf: &[u8]) -> Result<Self> {
        ElfInfo::new(buf).map(ExeInfo::Elf)
    }
    pub fn stack_reserve(&self) -> u64 {
        match self {
            ExeInfo::Elf(_) => DEFAULT_ELF_STACK_RESERVE,
        }
    }
    pub fn heap_reserve(&self) -> u64 {
        match self {
            ExeInfo::Elf(_) => DEFAULT_ELF_HEAP_RESERVE,
        }
    }
    pub fn entrypoint(&self) -> Offset {
        match self {
            ExeInfo::Elf(elf) => Offset::from(elf.entrypoint_va()),
        }
    }
    pub fn loaded_size(&self) -> usize {
        match self {
            ExeInfo::Elf(elf) => elf.get_va_size(),
        }
    }
    // todo: this doesn't morally need to be &mut self, since we're
    // copying into target, but the PE loader chooses to apply
    // relocations in its owned representation of the PE contents,
    // which requires it to be &mut.
    pub fn load(&mut self, load_addr: usize, target: &mut [u8]) -> Result<()> {
        match self {
            ExeInfo::Elf(elf) => {
                elf.load_at(load_addr, target)?;
            }
        }
        Ok(())
    }
}
