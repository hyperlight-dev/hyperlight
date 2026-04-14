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
#[cfg(feature = "mem_profile")]
use std::sync::Arc;
use std::vec::Vec;

use super::elf::ElfInfo;
use super::ptr_offset::Offset;
use crate::Result;

pub enum ExeInfo {
    Elf(ElfInfo),
}

#[cfg(feature = "mem_profile")]
pub(crate) trait UnwindInfo: Send + Sync {
    fn as_module(&self) -> framehop::Module<Vec<u8>>;
    fn hash(&self) -> blake3::Hash;
}

#[cfg(feature = "mem_profile")]
pub(crate) struct DummyUnwindInfo {}
#[cfg(feature = "mem_profile")]
impl UnwindInfo for DummyUnwindInfo {
    fn as_module(&self) -> framehop::Module<Vec<u8>> {
        framehop::Module::new("unsupported".to_string(), 0..0, 0, self)
    }
    fn hash(&self) -> blake3::Hash {
        blake3::Hash::from_bytes([0; 32])
    }
}
#[cfg(feature = "mem_profile")]
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

#[derive(Clone)]
pub(crate) struct LoadInfo {
    #[cfg(feature = "mem_profile")]
    pub(crate) info: Arc<dyn UnwindInfo>,
}

impl LoadInfo {
    pub(crate) fn dummy() -> Self {
        LoadInfo {
            #[cfg(feature = "mem_profile")]
            info: Arc::new(DummyUnwindInfo {}),
        }
    }
}

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
    pub fn entrypoint(&self) -> Offset {
        match self {
            ExeInfo::Elf(elf) => Offset::from(elf.entrypoint_va()),
        }
    }
    /// Returns the base virtual address of the loaded binary (lowest PT_LOAD p_vaddr).
    pub fn base_va(&self) -> u64 {
        match self {
            ExeInfo::Elf(elf) => elf.get_base_va(),
        }
    }
    pub fn loaded_size(&self) -> usize {
        match self {
            ExeInfo::Elf(elf) => elf.get_va_size(),
        }
    }

    /// Returns the hyperlight version string embedded in the guest binary, if
    /// the binary was built with a version of `hyperlight-guest-bin` that
    /// supports version tagging.
    pub fn guest_bin_version(&self) -> Option<&str> {
        match self {
            ExeInfo::Elf(elf) => elf.guest_bin_version(),
        }
    }
    // todo: this doesn't morally need to be &mut self, since we're
    // copying into target, but the PE loader chooses to apply
    // relocations in its owned representation of the PE contents,
    // which requires it to be &mut.
    pub fn load(self, load_addr: usize, target: &mut [u8]) -> Result<LoadInfo> {
        match self {
            ExeInfo::Elf(elf) => elf.load_at(load_addr, target),
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperlight_testing::{dummy_guest_as_string, simple_guest_as_string};

    use super::ExeInfo;

    /// Read the simpleguest binary and patch the version note descriptor to `"0.0.0"`.
    fn simpleguest_with_patched_version() -> Vec<u8> {
        let path = simple_guest_as_string().expect("failed to locate simpleguest");
        let mut bytes = std::fs::read(path).expect("failed to read simpleguest");

        let elf = goblin::elf::Elf::parse(&bytes).expect("failed to parse ELF");

        // Use goblin's note iterator to locate the version note.
        let note = elf
            .iter_note_sections(
                &bytes,
                Some(hyperlight_common::version_note::HYPERLIGHT_VERSION_SECTION),
            )
            .expect("note section should exist")
            .find_map(|n| n.ok())
            .expect("should contain a valid note");

        // Compute byte offsets from the slice pointers goblin gives us.
        let desc_offset = note.desc.as_ptr() as usize - bytes.as_ptr() as usize;
        // Walk backwards from desc to find descsz: skip padded name and
        // the descsz + n_type fields (4 bytes each).
        let name_padded = hyperlight_common::version_note::padded_name_size(note.name.len() + 1);
        let descsz_offset = desc_offset - name_padded - 8;

        let fake_version = b"0.0.0\0";
        assert!(fake_version.len() <= note.desc.len());

        bytes[desc_offset..desc_offset + fake_version.len()].copy_from_slice(fake_version);
        bytes[descsz_offset..descsz_offset + 4]
            .copy_from_slice(&(fake_version.len() as u32).to_le_bytes());
        bytes
    }

    #[test]
    fn exe_info_exposes_guest_bin_version() {
        let path = simple_guest_as_string().expect("failed to locate simpleguest");
        let info = ExeInfo::from_file(&path).expect("failed to load ELF");

        let version = info
            .guest_bin_version()
            .expect("simpleguest should have a version note");
        assert_eq!(version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn dummyguest_has_no_version_section() {
        let path = dummy_guest_as_string().expect("failed to locate dummyguest");
        let info = ExeInfo::from_file(&path).expect("failed to load ELF");

        assert!(
            info.guest_bin_version().is_none(),
            "dummyguest should not have a version note"
        );
    }

    /// A guest not built with hyperlight-guest-bin has no version note and
    /// should be accepted (no version check is performed).
    #[test]
    fn from_env_accepts_guest_without_version_note() {
        let path = dummy_guest_as_string().expect("failed to locate dummyguest");

        let result = crate::sandbox::snapshot::Snapshot::from_env(
            crate::GuestBinary::FilePath(path),
            crate::sandbox::SandboxConfiguration::default(),
        );

        assert!(result.is_ok(), "should accept guest without version note");
    }

    /// Patch the version section in-memory to simulate a version mismatch.
    #[test]
    fn patched_version_reports_mismatch() {
        let bytes = simpleguest_with_patched_version();

        let info = ExeInfo::from_buf(&bytes).expect("failed to load patched ELF");
        assert_eq!(info.guest_bin_version(), Some("0.0.0"));
        assert_ne!(
            info.guest_bin_version().unwrap(),
            env!("CARGO_PKG_VERSION"),
            "patched version should differ from host version"
        );
    }

    /// Load an unpatched simpleguest through `Snapshot::from_env` and verify
    /// that it succeeds when the embedded version matches the host version.
    #[test]
    fn from_env_accepts_matching_version() {
        let path = simple_guest_as_string().expect("failed to locate simpleguest");

        let result = crate::sandbox::snapshot::Snapshot::from_env(
            crate::GuestBinary::FilePath(path),
            crate::sandbox::SandboxConfiguration::default(),
        );

        assert!(result.is_ok(), "should accept matching version");
    }

    /// Load a patched guest binary through `Snapshot::from_env` and verify
    /// that a version mismatch produces `GuestBinVersionMismatch`.
    #[test]
    fn from_env_rejects_version_mismatch() {
        let bytes = simpleguest_with_patched_version();

        let result = crate::sandbox::snapshot::Snapshot::from_env(
            crate::GuestBinary::Buffer(&bytes),
            crate::sandbox::SandboxConfiguration::default(),
        );

        assert!(result.is_err(), "should reject mismatched version");
        let err = result.err().expect("already checked is_err");
        assert!(
            matches!(
                err,
                crate::HyperlightError::GuestBinVersionMismatch {
                    ref guest_bin_version,
                    ref host_version,
                } if guest_bin_version == "0.0.0" && host_version == env!("CARGO_PKG_VERSION")
            ),
            "expected GuestBinVersionMismatch, got: {err}"
        );
    }
}
