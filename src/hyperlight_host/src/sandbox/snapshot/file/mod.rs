/*
Copyright 2025 The Hyperlight Authors.

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

//! OCI Image Layout serde for [`Snapshot`]. See
//! `docs/snapshot-oci-format.md` for the on-disk format.

mod config;
mod digest;
mod fsutil;
mod media_types;

use std::path::Path;

use hyperlight_common::flatbuffer_wrappers::host_function_details::HostFunctionDetails;
use hyperlight_common::vmem::PAGE_SIZE;
use oci_spec::image::{
    Descriptor, DescriptorBuilder, ImageIndex, ImageIndexBuilder, ImageManifest,
    ImageManifestBuilder, MediaType, SCHEMA_VERSION,
};

use self::config::{
    Arch, Entrypoint, HostFunction, Hypervisor, MemoryLayout, OciSnapshotConfig, Sregs,
};
use self::digest::{Digest256, oci_digest, parse_oci_digest, verify_blob_bytes, verify_blob_file};
use self::fsutil::{read_bounded, write_blob_if_absent, write_file_atomic};
use self::media_types::{
    MT_CONFIG_CURRENT, MT_CONFIG_V1, MT_SNAPSHOT_CURRENT, MT_SNAPSHOT_V1, SNAPSHOT_ABI_VERSION,
};
use super::{NextAction, Snapshot};
use crate::hypervisor::regs::CommonSpecialRegisters;
use crate::mem::layout::SandboxMemoryLayout;
use crate::mem::memory_region::MemoryRegionFlags;
use crate::mem::shared_mem::{ReadonlySharedMemory, SharedMemory};

const OCI_LAYOUT_VERSION: &str = "1.0.0";

/// Maximum size of the config JSON blob. Bounds the allocation done
/// before we parse the JSON.
const MAX_CONFIG_BLOB_SIZE: u64 = 1024 * 1024;

/// OCI standard annotation key for a manifest's tag inside an image
/// index. Set on the manifest descriptor in `index.json`, not on the
/// manifest blob itself. See the OCI Image Spec, "Annotations" and
/// the Image Layout spec.
const ANNOTATION_REF_NAME: &str = "org.opencontainers.image.ref.name";

/// Validate a tag against the OCI Distribution spec rules:
/// `[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}`. Required so that the same
/// strings work both in our local layout and when pushed to a
/// registry via `oras` / `crane` / `skopeo`.
fn validate_tag(tag: &str) -> crate::Result<()> {
    let bytes = tag.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 {
        return Err(crate::new_error!(
            "tag {:?} is invalid: must be 1..=128 bytes",
            tag
        ));
    }
    let first = bytes[0];
    if !(first.is_ascii_alphanumeric() || first == b'_') {
        return Err(crate::new_error!(
            "tag {:?} is invalid: first character must be alphanumeric or '_'",
            tag
        ));
    }
    for &b in &bytes[1..] {
        if !(b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-') {
            return Err(crate::new_error!(
                "tag {:?} is invalid: characters after the first must be \
                 alphanumeric or one of '_', '.', '-'",
                tag
            ));
        }
    }
    Ok(())
}

impl Snapshot {
    /// Save this snapshot into the OCI Image Layout directory at
    /// `path` under `tag`.
    ///
    /// `tag` is written to `index.json` as
    /// `org.opencontainers.image.ref.name` and must satisfy the OCI
    /// tag grammar (`[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}`).
    ///
    /// The parent directory of `path` must already exist. `path`
    /// itself is created if absent. If a layout already exists at
    /// `path`, this call appends to it: other tags in `index.json`
    /// are kept untouched, and a manifest descriptor whose
    /// `org.opencontainers.image.ref.name` annotation equals `tag`
    /// is replaced. Blobs are content-addressed and shared across
    /// tags. See `docs/snapshot-oci-format.md` for the full on-disk
    /// format and atomicity guarantees.
    ///
    /// A pre-existing `oci-layout` file must declare a supported
    /// `imageLayoutVersion`. Otherwise the call errors without
    /// touching the directory.
    ///
    /// # Portability
    ///
    /// Snapshot images are bound to a specific CPU architecture and
    /// hypervisor. Both are recorded in the config blob and checked
    /// at load time, with mismatches rejected with a clear error.
    /// The hypervisor tag (kvm/mshv/whp) constrains the host OS.
    pub fn to_oci(&self, path: impl AsRef<Path>, tag: &str) -> crate::Result<()> {
        let path = path.as_ref();
        validate_tag(tag)?;

        // The parent directory must already exist. `path` itself is
        // created if absent. An existing regular file at `path` is
        // rejected by the underlying `create_dir`.
        match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => {
                let parent_meta = std::fs::metadata(p).map_err(|e| {
                    crate::new_error!("to_oci: parent directory {:?} not accessible: {}", p, e)
                })?;
                if !parent_meta.is_dir() {
                    return Err(crate::new_error!(
                        "to_oci: parent of {:?} is not a directory",
                        path
                    ));
                }
            }
            _ => {}
        }
        match std::fs::create_dir(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let meta = std::fs::metadata(path)
                    .map_err(|e| crate::new_error!("to_oci: failed to stat {:?}: {}", path, e))?;
                if !meta.is_dir() {
                    return Err(crate::new_error!(
                        "to_oci: {:?} exists and is not a directory",
                        path
                    ));
                }
            }
            Err(e) => {
                return Err(crate::new_error!(
                    "to_oci: failed to create layout dir {:?}: {}",
                    path,
                    e
                ));
            }
        }

        // Validate any pre-existing `oci-layout` marker before
        // touching anything else, so a foreign layout (future
        // version, hand-edited file) is reported without altering
        // the directory.
        let layout_marker = path.join("oci-layout");
        let marker_existed = layout_marker
            .try_exists()
            .map_err(|e| crate::new_error!("to_oci: failed to stat {:?}: {}", layout_marker, e))?;
        if marker_existed {
            let bytes = read_bounded(&layout_marker, MAX_CONFIG_BLOB_SIZE).map_err(|e| {
                crate::new_error!("to_oci: failed to read existing oci-layout: {}", e)
            })?;
            let v: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
                crate::new_error!("to_oci: existing oci-layout is not valid JSON: {}", e)
            })?;
            match v.get("imageLayoutVersion").and_then(|s| s.as_str()) {
                Some(s) if s == OCI_LAYOUT_VERSION => {}
                Some(other) => {
                    return Err(crate::new_error!(
                        "to_oci: existing imageLayoutVersion {:?} is unsupported (expected {:?})",
                        other,
                        OCI_LAYOUT_VERSION
                    ));
                }
                None => {
                    return Err(crate::new_error!(
                        "to_oci: existing oci-layout is missing imageLayoutVersion"
                    ));
                }
            }
        }

        let index_path = path.join("index.json");
        let index_existed = index_path
            .try_exists()
            .map_err(|e| crate::new_error!("to_oci: failed to stat {:?}: {}", index_path, e))?;
        let mut manifests: Vec<Descriptor> = if index_existed {
            let bytes = read_bounded(&index_path, MAX_CONFIG_BLOB_SIZE).map_err(|e| {
                crate::new_error!("to_oci: failed to read existing index.json: {}", e)
            })?;
            let existing: ImageIndex = serde_json::from_slice(&bytes).map_err(|e| {
                crate::new_error!(
                    "to_oci: existing index.json is not a valid OCI image index: {}",
                    e
                )
            })?;
            existing.manifests().to_vec()
        } else {
            Vec::new()
        };

        let new_desc = self.write_blobs_and_build_descriptor(path, tag)?;

        // Replacement is by tag, not by digest: a new snapshot may
        // hash to a different value but still claim the same logical
        // ref. Blobs from the replaced manifest become orphans.
        manifests.retain(|d| {
            d.annotations()
                .as_ref()
                .and_then(|a| a.get(ANNOTATION_REF_NAME))
                .map(|s| s.as_str() != tag)
                .unwrap_or(true)
        });
        manifests.push(new_desc);

        let index = ImageIndexBuilder::default()
            .schema_version(SCHEMA_VERSION)
            .media_type(MediaType::ImageIndex)
            .manifests(manifests)
            .build()
            .map_err(|e| crate::new_error!("failed to build OCI index: {}", e))?;
        let index_bytes = serde_json::to_vec_pretty(&index)
            .map_err(|e| crate::new_error!("failed to serialise OCI index: {}", e))?;

        // Write the marker before the index swap. A loader that sees
        // the new index requires the marker; ordering them this way
        // keeps the layout valid at every step.
        if !marker_existed {
            let layout_bytes = serde_json::to_vec(&serde_json::json!({
                "imageLayoutVersion": OCI_LAYOUT_VERSION,
            }))
            .map_err(|e| crate::new_error!("failed to serialise oci-layout: {}", e))?;
            write_file_atomic(&layout_marker, &layout_bytes)?;
        }

        // Index swap is the commit point.
        write_file_atomic(&index_path, &index_bytes)?;

        Ok(())
    }

    fn write_blobs_and_build_descriptor(&self, dir: &Path, tag: &str) -> crate::Result<Descriptor> {
        let blobs_dir = dir.join("blobs").join("sha256");
        std::fs::create_dir_all(&blobs_dir).map_err(|e| {
            crate::new_error!("failed to create OCI blobs dir {:?}: {}", blobs_dir, e)
        })?;

        // Snapshot blob: the raw memory bytes.
        let memory_bytes = self.memory.as_slice();
        let memory_size = memory_bytes.len();
        if memory_size == 0 || memory_size % PAGE_SIZE != 0 {
            return Err(crate::new_error!(
                "snapshot memory size {} must be a non-zero multiple of PAGE_SIZE",
                memory_size
            ));
        }
        let snapshot_digest = Digest256::from_bytes(memory_bytes);
        write_blob_if_absent(&blobs_dir, &snapshot_digest, memory_bytes)?;

        // Config blob.
        let cfg = self.build_config()?;
        let cfg_bytes = serde_json::to_vec_pretty(&cfg)
            .map_err(|e| crate::new_error!("failed to serialise config JSON: {}", e))?;
        let cfg_digest = Digest256::from_bytes(&cfg_bytes);
        write_blob_if_absent(&blobs_dir, &cfg_digest, &cfg_bytes)?;

        // Manifest blob.
        let config_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::Other(MT_CONFIG_CURRENT.to_string()))
            .digest(oci_digest(&cfg_digest)?)
            .size(cfg_bytes.len() as u64)
            .build()
            .map_err(|e| crate::new_error!("failed to build config descriptor: {}", e))?;
        let snapshot_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::Other(MT_SNAPSHOT_CURRENT.to_string()))
            .digest(oci_digest(&snapshot_digest)?)
            .size(memory_size as u64)
            .build()
            .map_err(|e| crate::new_error!("failed to build snapshot descriptor: {}", e))?;
        // `artifactType` is set equal to `config.mediaType` per OCI
        // image-spec "Guidelines for Artifact Usage". Registries
        // surface this on the distribution-spec referrers API. Tools
        // that read only `config.mediaType` see the same value.
        let manifest = ImageManifestBuilder::default()
            .schema_version(SCHEMA_VERSION)
            .media_type(MediaType::ImageManifest)
            .artifact_type(MediaType::Other(MT_CONFIG_CURRENT.to_string()))
            .config(config_descriptor)
            .layers(vec![snapshot_descriptor])
            .build()
            .map_err(|e| crate::new_error!("failed to build OCI manifest: {}", e))?;
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|e| crate::new_error!("failed to serialise OCI manifest: {}", e))?;
        let manifest_digest = Digest256::from_bytes(&manifest_bytes);
        write_blob_if_absent(&blobs_dir, &manifest_digest, &manifest_bytes)?;

        let mut anns = std::collections::HashMap::new();
        anns.insert(ANNOTATION_REF_NAME.to_string(), tag.to_string());
        DescriptorBuilder::default()
            .media_type(MediaType::ImageManifest)
            .digest(oci_digest(&manifest_digest)?)
            .size(manifest_bytes.len() as u64)
            .annotations(anns)
            .build()
            .map_err(|e| crate::new_error!("failed to build manifest descriptor: {}", e))
    }

    fn build_config(&self) -> crate::Result<OciSnapshotConfig> {
        let entrypoint = match (self.entrypoint, self.sregs.as_ref()) {
            (NextAction::Initialise(addr), None) => Entrypoint::Initialise { addr },
            (NextAction::Call(addr), Some(sregs)) => Entrypoint::Call {
                addr,
                sregs: Box::new(Sregs::from(sregs)),
            },
            (NextAction::Initialise(_), Some(_)) => {
                return Err(crate::new_error!(
                    "snapshot inconsistent: Initialise entrypoint must not have sregs"
                ));
            }
            (NextAction::Call(_), None) => {
                return Err(crate::new_error!(
                    "snapshot inconsistent: Call entrypoint must have sregs"
                ));
            }
            #[cfg(test)]
            (NextAction::None, _) => {
                return Err(crate::new_error!(
                    "snapshot with NextAction::None cannot be persisted"
                ));
            }
        };

        let host_functions = match &self.host_functions.host_functions {
            Some(v) => v.iter().map(HostFunction::from).collect(),
            None => Vec::new(),
        };

        let l = &self.layout;
        Ok(OciSnapshotConfig {
            hyperlight_version: env!("CARGO_PKG_VERSION").to_string(),
            arch: Arch::current(),
            abi_version: SNAPSHOT_ABI_VERSION,
            hypervisor: Hypervisor::current()
                .ok_or_else(|| crate::new_error!("no hypervisor available to tag snapshot"))?,
            stack_top_gva: self.stack_top_gva,
            entrypoint,
            layout: MemoryLayout {
                input_data_size: l.input_data_size,
                output_data_size: l.output_data_size,
                heap_size: l.heap_size,
                code_size: l.code_size,
                init_data_size: l.init_data_size,
                init_data_permissions: l.init_data_permissions.map(|f| f.bits()),
                scratch_size: l.get_scratch_size(),
                snapshot_size: l.snapshot_size,
                pt_size: l.pt_size,
            },
            memory_size: self.memory.mem_size() as u64,
            host_functions,
            snapshot_generation: self.snapshot_generation,
        })
    }

    /// Load the snapshot tagged `tag` from an OCI Image Layout
    /// directory at `path`.
    ///
    /// `tag` selects one manifest from `index.json` using
    /// `org.opencontainers.image.ref.name`. Missing tags and duplicate
    /// tags are rejected.
    ///
    /// This verifies sha256 for manifest, config, and snapshot blobs.
    /// Use [`Snapshot::from_oci_unchecked`] to skip digest verification
    /// in trusted paths.
    ///
    /// Returns an error for arch, hypervisor, and ABI mismatches.
    ///
    /// # File-mutation hazard
    ///
    /// Do not modify or replace files in `path` while the returned
    /// `Snapshot` (or sandboxes built from it) is still alive.
    pub fn from_oci(path: impl AsRef<Path>, tag: &str) -> crate::Result<Self> {
        Self::from_oci_inner(path.as_ref(), tag, true)
    }

    /// Like [`Snapshot::from_oci`] but **skips sha256 verification of
    /// the manifest, config, and snapshot blob bytes**, trading
    /// integrity checking for performance. All other validation
    /// (OCI structure, descriptor sizes, schema versions, arch /
    /// hypervisor / ABI tags, layout bounds, entrypoint bounds) is
    /// unchanged.
    pub fn from_oci_unchecked(path: impl AsRef<Path>, tag: &str) -> crate::Result<Self> {
        Self::from_oci_inner(path.as_ref(), tag, false)
    }

    fn from_oci_inner(path: &Path, tag: &str, verify_blobs: bool) -> crate::Result<Self> {
        validate_tag(tag)?;
        let meta = std::fs::metadata(path)
            .map_err(|e| crate::new_error!("from_oci failed to stat {:?}: {}", path, e))?;
        if !meta.is_dir() {
            return Err(crate::new_error!(
                "from_oci path {:?} is not a directory",
                path
            ));
        }

        // 1. oci-layout
        let layout_bytes = read_bounded(&path.join("oci-layout"), MAX_CONFIG_BLOB_SIZE)
            .map_err(|e| crate::new_error!("failed to read oci-layout: {}", e))?;
        let layout_json: serde_json::Value = serde_json::from_slice(&layout_bytes)
            .map_err(|e| crate::new_error!("oci-layout is not valid JSON: {}", e))?;
        let v = layout_json
            .get("imageLayoutVersion")
            .and_then(|v| v.as_str())
            .ok_or_else(|| crate::new_error!("oci-layout missing imageLayoutVersion field"))?;
        if v != OCI_LAYOUT_VERSION {
            return Err(crate::new_error!(
                "unsupported OCI image layout version {:?} (expected {:?})",
                v,
                OCI_LAYOUT_VERSION
            ));
        }

        // 2. index.json -> manifest descriptor for `tag`. Multiple
        //    manifests are fine in OCI Image Layout; we select the
        //    one whose `org.opencontainers.image.ref.name` annotation
        //    matches the requested tag. Two manifests with the same
        //    tag is a malformed layout.
        let index_bytes = read_bounded(&path.join("index.json"), MAX_CONFIG_BLOB_SIZE)
            .map_err(|e| crate::new_error!("failed to read index.json: {}", e))?;
        let index: ImageIndex = serde_json::from_slice(&index_bytes)
            .map_err(|e| crate::new_error!("failed to parse index.json: {}", e))?;
        let mut matching = index.manifests().iter().filter(|d| {
            d.annotations()
                .as_ref()
                .and_then(|a| a.get(ANNOTATION_REF_NAME))
                .map(|s| s.as_str() == tag)
                .unwrap_or(false)
        });
        let manifest_desc = match (matching.next(), matching.next()) {
            (None, _) => {
                let known: Vec<&str> = index
                    .manifests()
                    .iter()
                    .filter_map(|d| {
                        d.annotations()
                            .as_ref()
                            .and_then(|a| a.get(ANNOTATION_REF_NAME))
                            .map(|s| s.as_str())
                    })
                    .collect();
                return Err(crate::new_error!(
                    "no manifest tagged {:?} in OCI layout {:?}. Available tags: {:?}",
                    tag,
                    path,
                    known
                ));
            }
            (Some(_), Some(_)) => {
                return Err(crate::new_error!(
                    "OCI layout {:?} has multiple manifests tagged {:?}; tags must be unique",
                    path,
                    tag
                ));
            }
            (Some(d), None) => d,
        };
        // The manifest descriptor must advertise an OCI image
        // manifest. Refuse anything else up front so we never try to
        // parse, say, an image index or an arbitrary artifact blob
        // as an `ImageManifest`.
        if !matches!(manifest_desc.media_type(), MediaType::ImageManifest) {
            return Err(crate::new_error!(
                "manifest descriptor for tag {:?} has unexpected media type {:?} (expected {:?})",
                tag,
                manifest_desc.media_type().to_string(),
                MediaType::ImageManifest.to_string()
            ));
        }
        let manifest_hex = parse_oci_digest(manifest_desc.digest().as_ref())?;

        // 3. manifest blob
        let manifest_path = path.join("blobs").join("sha256").join(&manifest_hex);
        let manifest_bytes = read_bounded(&manifest_path, MAX_CONFIG_BLOB_SIZE)?;
        if manifest_bytes.len() as u64 != manifest_desc.size() {
            return Err(crate::new_error!(
                "OCI manifest size mismatch: descriptor says {}, file is {}",
                manifest_desc.size(),
                manifest_bytes.len()
            ));
        }
        if verify_blobs {
            verify_blob_bytes("manifest", &manifest_bytes, &manifest_hex)?;
        }
        let manifest: ImageManifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|e| crate::new_error!("failed to parse OCI manifest JSON: {}", e))?;
        if manifest.schema_version() != SCHEMA_VERSION {
            return Err(crate::new_error!(
                "unsupported OCI manifest schemaVersion {} (expected {})",
                manifest.schema_version(),
                SCHEMA_VERSION
            ));
        }
        let cfg_desc = manifest.config();
        // Loader dispatch on config media type. A future v2 lands
        // as a new arm that converts to the in-memory current shape.
        let cfg_media = cfg_desc.media_type().to_string();
        match cfg_media.as_str() {
            MT_CONFIG_V1 => {}
            other => {
                return Err(crate::new_error!(
                    "unexpected config media type {:?} (supported: {:?})",
                    other,
                    MT_CONFIG_V1
                ));
            }
        }
        // `artifactType` mirrors `config.mediaType` (manifest.md
        // "Guidelines for Artifact Usage"). The OCI spec leaves this
        // field OPTIONAL. A Hyperlight snapshot requires it to be
        // present and equal to `config.mediaType` so loaders can
        // distinguish a Hyperlight artifact from an arbitrary
        // manifest that happens to share blob layout.
        match manifest.artifact_type() {
            Some(at) if at.to_string() == cfg_media => {}
            Some(at) => {
                return Err(crate::new_error!(
                    "OCI manifest artifactType {:?} does not match config media type {:?}",
                    at.to_string(),
                    cfg_media
                ));
            }
            None => {
                return Err(crate::new_error!(
                    "OCI manifest is missing required artifactType (expected {:?})",
                    cfg_media
                ));
            }
        }
        let layers = manifest.layers();
        if layers.len() != 1 {
            return Err(crate::new_error!(
                "expected exactly one OCI layer (the snapshot), found {}",
                layers.len()
            ));
        }
        let snap_desc = &layers[0];
        let snap_media = snap_desc.media_type().to_string();
        match snap_media.as_str() {
            MT_SNAPSHOT_V1 => {}
            other => {
                return Err(crate::new_error!(
                    "unexpected snapshot layer media type {:?} (supported: {:?})",
                    other,
                    MT_SNAPSHOT_V1
                ));
            }
        }

        // 4. config blob
        let cfg_hex = parse_oci_digest(cfg_desc.digest().as_ref())?;
        let cfg_path = path.join("blobs").join("sha256").join(&cfg_hex);
        let cfg_bytes = read_bounded(&cfg_path, MAX_CONFIG_BLOB_SIZE)?;
        if cfg_bytes.len() as u64 != cfg_desc.size() {
            return Err(crate::new_error!(
                "config blob size mismatch: descriptor says {}, file is {}",
                cfg_desc.size(),
                cfg_bytes.len()
            ));
        }
        if verify_blobs {
            verify_blob_bytes("config", &cfg_bytes, &cfg_hex)?;
        }
        let cfg: OciSnapshotConfig = serde_json::from_slice(&cfg_bytes)
            .map_err(|e| crate::new_error!("failed to parse Hyperlight config JSON: {}", e))?;
        cfg.validate_for_load()?;

        // 5. snapshot blob: open once, hash and mmap the same
        //    handle so an attacker cannot swap the file between
        //    verification and mapping.
        let snap_hex = parse_oci_digest(snap_desc.digest().as_ref())?;
        let snap_path = path.join("blobs").join("sha256").join(&snap_hex);
        let mut snap_file = std::fs::File::open(&snap_path).map_err(|e| {
            crate::new_error!("failed to open snapshot blob {:?}: {}", snap_path, e)
        })?;
        let snap_file_len = snap_file
            .metadata()
            .map_err(|e| crate::new_error!("failed to stat snapshot blob: {}", e))?
            .len();
        let expected_blob_len = cfg.memory_size;
        if snap_file_len != expected_blob_len {
            return Err(crate::new_error!(
                "snapshot blob size mismatch: file is {} bytes, expected {} \
                 (memory_size)",
                snap_file_len,
                expected_blob_len,
            ));
        }
        if snap_file_len != snap_desc.size() {
            return Err(crate::new_error!(
                "snapshot blob size {} disagrees with OCI descriptor size {}",
                snap_file_len,
                snap_desc.size()
            ));
        }
        if verify_blobs {
            verify_blob_file("snapshot", &mut snap_file, &snap_hex)?;
        }

        // 6. Reconstruct layout.
        let mut sbox_cfg = crate::sandbox::SandboxConfiguration::default();
        sbox_cfg.set_input_data_size(cfg.layout.input_data_size);
        sbox_cfg.set_output_data_size(cfg.layout.output_data_size);
        sbox_cfg.set_heap_size(cfg.layout.heap_size as u64);
        sbox_cfg.set_scratch_size(cfg.layout.scratch_size);
        let init_data_perms = match cfg.layout.init_data_permissions {
            None => None,
            Some(bits) => Some(MemoryRegionFlags::from_bits(bits).ok_or_else(|| {
                crate::new_error!(
                    "snapshot init_data_permissions {:#x} contains unknown flag bits",
                    bits
                )
            })?),
        };
        let mut layout = SandboxMemoryLayout::new(
            sbox_cfg,
            cfg.layout.code_size,
            cfg.layout.init_data_size,
            init_data_perms,
        )?;
        // `snapshot_size` and `pt_size` are independent fields.
        if let Some(pt) = cfg.layout.pt_size {
            layout.set_pt_size(pt)?;
        }
        layout.set_snapshot_size(cfg.layout.snapshot_size);

        // 7. mmap the snapshot blob (file-backed CoW). The blob is
        //    the raw memory image. `ReadonlySharedMemory::from_file`
        //    surrounds it with host guard pages. The guest mapping
        //    of the snapshot region covers only the data prefix
        //    (`snapshot_size`). The PT tail sits past that prefix
        //    in the host mapping and is copied into the scratch
        //    region on restore. Keeping it out of the guest mapping
        //    of the snapshot region avoids overlap with
        //    `map_file_cow` regions installed immediately after the
        //    snapshot in guest PA space.
        let memory = ReadonlySharedMemory::from_file(&snap_file, layout.snapshot_size)?;

        // 8. Build entrypoint + sregs back from the tagged enum.
        let (entrypoint, sregs) = match cfg.entrypoint {
            Entrypoint::Initialise { addr } => (NextAction::Initialise(addr), None),
            Entrypoint::Call { addr, sregs } => (
                NextAction::Call(addr),
                Some(CommonSpecialRegisters::from(*sregs)),
            ),
        };

        // 9. Reconstitute host_functions metadata.
        let snapshot_generation = cfg.snapshot_generation;
        let host_funcs_vec: Vec<
            hyperlight_common::flatbuffer_wrappers::host_function_definition::HostFunctionDefinition,
        > = cfg.host_functions.into_iter().map(Into::into).collect();
        let host_functions = if host_funcs_vec.is_empty() {
            HostFunctionDetails {
                host_functions: None,
            }
        } else {
            HostFunctionDetails {
                host_functions: Some(host_funcs_vec),
            }
        };

        Ok(Snapshot {
            layout,
            memory,
            regions: Vec::new(),
            load_info: crate::mem::exe::LoadInfo::dummy(),
            stack_top_gva: cfg.stack_top_gva,
            sregs,
            entrypoint,
            snapshot_generation,
            host_functions,
        })
    }
}
