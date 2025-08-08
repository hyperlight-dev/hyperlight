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
#[cfg(feature = "unwind_guest")]
use std::sync::Arc;
use std::vec::Vec;

use super::elf::ElfInfo;
use super::ptr_offset::Offset;
use super::shared_mem::ExclusiveSharedMemory;
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

#[cfg(feature = "unwind_guest")]
pub(crate) trait UnwindInfo: Send + Sync {
    fn as_module(&self) -> framehop::Module<Vec<u8>>;
    fn hash(&self) -> blake3::Hash;
}

#[cfg(feature = "unwind_guest")]
pub(crate) struct DummyUnwindInfo {}
#[cfg(feature = "unwind_guest")]
impl UnwindInfo for DummyUnwindInfo {
    fn as_module(&self) -> framehop::Module<Vec<u8>> {
        framehop::Module::new("unsupported".to_string(), 0..0, 0, self)
    }
    fn hash(&self) -> blake3::Hash {
        blake3::Hash::from_bytes([0; 32])
    }
}
#[cfg(feature = "unwind_guest")]
impl<A> framehop::ModuleSectionInfo<A> for &DummyUnwindInfo {
    fn base_svma(&self) -> u64 {
        0
    }
    fn section_svma_range(&mut self, _name: &[u8]) -> Option<std::ops::Range<u64>> {
        None
    }
    fn section_data(&mut self, _name: &[u8]) -> Option<A> {
        None
    }
}

#[cfg(feature = "unwind_guest")]
pub(crate) type LoadInfo = Arc<dyn UnwindInfo>;
#[cfg(not(feature = "unwind_guest"))]
pub(crate) type LoadInfo = ();

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
    pub fn load(
        self,
        load_addr: usize,
        guest_code_offset: usize,
        target: &mut ExclusiveSharedMemory,
    ) -> Result<LoadInfo> {
        match self {
            ExeInfo::Elf(elf) => elf.load_at(load_addr, guest_code_offset, target),
        }
    }
}
