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
pub(crate) mod reference;

use std::path::{Path, PathBuf};

use hyperlight_common::flatbuffer_wrappers::host_function_details::HostFunctionDetails;
use hyperlight_common::vmem::PAGE_SIZE;
use oci_spec::image::{
    Descriptor, DescriptorBuilder, ImageIndex, ImageIndexBuilder, ImageManifest,
    ImageManifestBuilder, MediaType, SCHEMA_VERSION,
};

use self::config::{Arch, HostFunction, Hypervisor, MemoryLayout, OciSnapshotConfig};
use self::digest::{Digest256, oci_digest, parse_oci_digest, verify_blob_bytes, verify_blob_file};
use self::fsutil::{put_blob, put_blob_if_absent, read_bounded, replace_file_atomic};
use self::media_types::{
    ANNOTATION_ARCH, ANNOTATION_HYPERVISOR, ANNOTATION_REF_NAME, MT_CONFIG_CURRENT, MT_CONFIG_V1,
    MT_SNAPSHOT_CURRENT, MT_SNAPSHOT_V1, SNAPSHOT_ABI_VERSION,
};
use self::reference::{OciDigest, OciReference, OciTag};
use super::{NextAction, Snapshot};
use crate::mem::layout::SandboxMemoryLayout;
use crate::mem::memory_region::MemoryRegionFlags;
use crate::mem::shared_mem::{ReadonlySharedMemory, SharedMemory};

const OCI_LAYOUT_VERSION: &str = "1.0.0";

/// Maximum size of any JSON blob read from disk during load:
/// `oci-layout`, `index.json`, the OCI image manifest, and the
/// Hyperlight config blob. Bounds the allocation done before parsing.
const MAX_JSON_BLOB_SIZE: u64 = 1024 * 1024;

/// Reject a JSON artifact larger than the cap the loader reads with
/// [`read_bounded`]. The writer holds to the same cap so every layout
/// it writes can be read back. `what` names the artifact in the error.
fn check_json_blob_size(what: &str, len: usize) -> crate::Result<()> {
    if len as u64 > MAX_JSON_BLOB_SIZE {
        return Err(crate::new_error!(
            "{} of {} bytes exceeds the {} byte maximum for a snapshot artifact",
            what,
            len,
            MAX_JSON_BLOB_SIZE
        ));
    }
    Ok(())
}

/// Select one manifest descriptor from `index` by `reference`.
///
/// A tag matches the `org.opencontainers.image.ref.name` annotation
/// and must be unique. A digest matches the manifest content digest.
/// Identical manifests shared across tags select the first, since
/// they are byte-for-byte equal.
fn select_manifest<'a>(
    index: &'a ImageIndex,
    reference: &OciReference,
    path: &Path,
) -> crate::Result<&'a Descriptor> {
    match reference {
        OciReference::Tag(tag) => {
            let mut matching = index.manifests().iter().filter(|d| {
                d.annotations()
                    .as_ref()
                    .and_then(|a| a.get(ANNOTATION_REF_NAME))
                    .map(|s| s.as_str() == tag.as_str())
                    .unwrap_or(false)
            });
            match (matching.next(), matching.next()) {
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
                    Err(crate::new_error!(
                        "no manifest tagged {:?} in OCI layout {:?}. Available tags: {:?}",
                        tag.as_str(),
                        path,
                        known
                    ))
                }
                (Some(_), Some(_)) => Err(crate::new_error!(
                    "OCI layout {:?} has multiple manifests tagged {:?}; tags must be unique",
                    path,
                    tag.as_str()
                )),
                (Some(d), None) => Ok(d),
            }
        }
        OciReference::Digest(digest) => index
            .manifests()
            .iter()
            .find(|d| d.digest().to_string() == digest.as_str())
            .ok_or_else(|| {
                crate::new_error!(
                    "no manifest with digest {} in OCI layout {:?}",
                    digest.as_str(),
                    path
                )
            }),
    }
}

fn read_layout_marker(path: &Path) -> crate::Result<()> {
    let layout_bytes = read_bounded(&path.join("oci-layout"), MAX_JSON_BLOB_SIZE)
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
    Ok(())
}

fn load_manifest(
    path: &Path,
    blobs_dir: &Path,
    reference: &OciReference,
    verify_blobs: bool,
) -> crate::Result<ImageManifest> {
    let index_bytes = read_bounded(&path.join("index.json"), MAX_JSON_BLOB_SIZE)
        .map_err(|e| crate::new_error!("failed to read index.json: {}", e))?;
    let index: ImageIndex = serde_json::from_slice(&index_bytes)
        .map_err(|e| crate::new_error!("failed to parse index.json: {}", e))?;
    let manifest_desc = select_manifest(&index, reference, path)?;
    if !matches!(manifest_desc.media_type(), MediaType::ImageManifest) {
        return Err(crate::new_error!(
            "manifest descriptor for {} has unexpected media type {:?} (expected {:?})",
            reference,
            manifest_desc.media_type().to_string(),
            MediaType::ImageManifest.to_string()
        ));
    }
    let manifest_hex = parse_oci_digest(manifest_desc.digest())?;
    let manifest_path = blobs_dir.join(&manifest_hex);
    let manifest_bytes = read_bounded(&manifest_path, MAX_JSON_BLOB_SIZE)?;
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
    Ok(manifest)
}

fn load_config(
    blobs_dir: &Path,
    cfg_desc: &Descriptor,
    verify_blobs: bool,
) -> crate::Result<OciSnapshotConfig> {
    let cfg_hex = parse_oci_digest(cfg_desc.digest())?;
    let cfg_path = blobs_dir.join(&cfg_hex);
    let cfg_bytes = read_bounded(&cfg_path, MAX_JSON_BLOB_SIZE)?;
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
    Ok(cfg)
}

fn open_snapshot_blob(
    blobs_dir: &Path,
    snap_desc: &Descriptor,
    expected_blob_len: u64,
    verify_blobs: bool,
) -> crate::Result<std::fs::File> {
    let snap_hex = parse_oci_digest(snap_desc.digest())?;
    let snap_path = blobs_dir.join(&snap_hex);

    let mut snap_file = self::fsutil::open_no_follow(&snap_path)?;

    let snap_file_len = snap_file
        .metadata()
        .map_err(|e| crate::new_error!("failed to stat snapshot blob: {}", e))?
        .len();
    if snap_file_len != expected_blob_len {
        return Err(crate::new_error!(
            "snapshot blob size mismatch: file is {} bytes, expected {} (memory_size)",
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
    Ok(snap_file)
}

impl Snapshot {
    /// Save this snapshot into an OCI Image Layout directory on disk.
    /// The saved snapshot can be loaded later with
    /// [`Snapshot::load`].
    ///
    /// Returns the [`OciDigest`] of the manifest that was written,
    /// which [`Snapshot::load`] accepts as a stable handle to
    /// this exact snapshot.
    ///
    /// # `path`
    ///
    /// The OCI Image Layout directory to write to. The directory at
    /// `path` is created if absent. Its parent directory must exist.
    ///
    /// If `path` holds no OCI layout, a new one is created. If it
    /// holds one, this snapshot is added alongside the others. If
    /// `path` holds something that is not a readable OCI layout, the
    /// call fails and the directory is left unchanged.
    ///
    /// # `tag`
    ///
    /// A standard OCI tag that names this snapshot within the layout.
    /// [`Snapshot::load`] can load the snapshot back by this tag.
    ///
    /// A tag points to one snapshot at a time. If the layout has a
    /// snapshot under this tag, the tag is moved to the new snapshot.
    /// The old snapshot's data stays on disk, reachable by its
    /// digest but not by this tag. Snapshots under other tags are
    /// untouched.
    ///
    /// # Portability
    ///
    /// Snapshot images are bound to the specific CPU architecture and
    /// hypervisor that the snapshot was created on. For example, a
    /// snapshot taken on x86_64 with KVM can only be loaded on an
    /// x86_64 host running KVM. Loading on any other host is rejected.
    ///
    /// # Compatibility
    ///
    /// While Hyperlight is at version 0.x.y the on-disk format is not
    /// stable. A snapshot written by one Hyperlight version is not
    /// guaranteed to load on a different Hyperlight version. An
    /// incompatible snapshot is always rejected at load time with a
    /// clear error. It can never load and then misbehave once the
    /// guest is running. Any release that breaks the format is called
    /// out in the Hyperlight changelog.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use hyperlight_host::{MultiUseSandbox, UninitializedSandbox, GuestBinary};
    /// # use hyperlight_host::sandbox::snapshot::OciTag;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut sandbox: MultiUseSandbox = UninitializedSandbox::new(
    ///     GuestBinary::FilePath("guest.bin".into()),
    ///     None,
    /// )?.evolve()?;
    ///
    /// // Capture the initialized state and write it to an OCI layout on disk.
    /// let snapshot = sandbox.snapshot()?;
    /// let tag = OciTag::new("latest")?;
    /// let digest = snapshot.save("./guest_snapshot", &tag)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn save(&self, path: impl AsRef<Path>, tag: &OciTag) -> crate::Result<OciDigest> {
        let path = path.as_ref();

        // Building the config can reject the snapshot. Do it before
        // writing any file.
        let cfg = self.build_config()?;
        let cfg_bytes = serde_json::to_vec_pretty(&cfg)
            .map_err(|e| crate::new_error!("failed to serialise config JSON: {}", e))?;
        check_json_blob_size("config blob", cfg_bytes.len())?;

        // The parent directory must already exist. `path` itself is
        // created if absent. An existing regular file at `path` is
        // rejected by the underlying `create_dir`.
        match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => {
                let parent_meta = std::fs::metadata(p).map_err(|e| {
                    crate::new_error!("save: parent directory {:?} not accessible: {}", p, e)
                })?;
                if !parent_meta.is_dir() {
                    return Err(crate::new_error!(
                        "save: parent of {:?} is not a directory",
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
                    .map_err(|e| crate::new_error!("save: failed to stat {:?}: {}", path, e))?;
                if !meta.is_dir() {
                    return Err(crate::new_error!(
                        "save: {:?} exists and is not a directory",
                        path
                    ));
                }
            }
            Err(e) => {
                return Err(crate::new_error!(
                    "save: failed to create layout dir {:?}: {}",
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
            .map_err(|e| crate::new_error!("save: failed to stat {:?}: {}", layout_marker, e))?;
        if marker_existed {
            let bytes = read_bounded(&layout_marker, MAX_JSON_BLOB_SIZE).map_err(|e| {
                crate::new_error!("save: failed to read existing oci-layout: {}", e)
            })?;
            let v: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
                crate::new_error!("save: existing oci-layout is not valid JSON: {}", e)
            })?;
            match v.get("imageLayoutVersion").and_then(|s| s.as_str()) {
                Some(s) if s == OCI_LAYOUT_VERSION => {}
                Some(other) => {
                    return Err(crate::new_error!(
                        "save: existing imageLayoutVersion {:?} is unsupported (expected {:?})",
                        other,
                        OCI_LAYOUT_VERSION
                    ));
                }
                None => {
                    return Err(crate::new_error!(
                        "save: existing oci-layout is missing imageLayoutVersion"
                    ));
                }
            }
        }

        let index_path = path.join("index.json");
        let index_existed = index_path
            .try_exists()
            .map_err(|e| crate::new_error!("save: failed to stat {:?}: {}", index_path, e))?;
        let mut manifests: Vec<Descriptor> = if index_existed {
            let bytes = read_bounded(&index_path, MAX_JSON_BLOB_SIZE).map_err(|e| {
                crate::new_error!("save: failed to read existing index.json: {}", e)
            })?;
            let existing: ImageIndex = serde_json::from_slice(&bytes).map_err(|e| {
                crate::new_error!(
                    "save: existing index.json is not a valid OCI image index: {}",
                    e
                )
            })?;
            existing.manifests().to_vec()
        } else {
            Vec::new()
        };

        let new_desc = self.write_blobs_and_build_descriptor(path, tag, &cfg, &cfg_bytes)?;
        let written_digest = OciDigest::from_oci_spec_digest(new_desc.digest());

        // Replacement is by tag, not by digest: a new snapshot may
        // hash to a different value but still claim the same logical
        // ref. Blobs from the replaced manifest become orphans.
        manifests.retain(|d| {
            d.annotations()
                .as_ref()
                .and_then(|a| a.get(ANNOTATION_REF_NAME))
                .map(|s| s.as_str() != tag.as_str())
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
        check_json_blob_size("index.json", index_bytes.len())?;

        // Write the marker before the index swap. A loader that sees
        // the new index requires the marker; ordering them this way
        // keeps the layout valid at every step.
        if !marker_existed {
            let layout_bytes = serde_json::to_vec(&serde_json::json!({
                "imageLayoutVersion": OCI_LAYOUT_VERSION,
            }))
            .map_err(|e| crate::new_error!("failed to serialise oci-layout: {}", e))?;
            replace_file_atomic(&layout_marker, &layout_bytes)?;
        }

        // Index swap is the commit point.
        replace_file_atomic(&index_path, &index_bytes)?;

        Ok(written_digest)
    }

    fn write_blobs_and_build_descriptor(
        &self,
        dir: &Path,
        tag: &OciTag,
        cfg: &OciSnapshotConfig,
        cfg_bytes: &[u8],
    ) -> crate::Result<Descriptor> {
        let memory_bytes = self.memory.as_slice();
        let memory_size = memory_bytes.len();
        if memory_size == 0 || !memory_size.is_multiple_of(PAGE_SIZE) {
            return Err(crate::new_error!(
                "snapshot memory size {} must be a non-zero multiple of PAGE_SIZE",
                memory_size
            ));
        }

        let blobs_dir = dir.join("blobs").join("sha256");
        std::fs::create_dir_all(&blobs_dir).map_err(|e| {
            crate::new_error!("failed to create OCI blobs dir {:?}: {}", blobs_dir, e)
        })?;

        // Snapshot blob: the raw memory bytes.
        let snapshot_digest = Digest256::from_bytes(memory_bytes);
        put_blob_if_absent(&blobs_dir, &snapshot_digest, memory_bytes)?;

        // Config blob.
        let cfg_digest = Digest256::from_bytes(cfg_bytes);
        put_blob(&blobs_dir, &cfg_digest, cfg_bytes)?;

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
        check_json_blob_size("manifest blob", manifest_bytes.len())?;
        let manifest_digest = Digest256::from_bytes(&manifest_bytes);
        put_blob(&blobs_dir, &manifest_digest, &manifest_bytes)?;

        let mut anns = std::collections::HashMap::new();
        anns.insert(ANNOTATION_REF_NAME.to_string(), tag.as_str().to_string());
        anns.insert(ANNOTATION_ARCH.to_string(), cfg.arch.as_str().to_string());
        anns.insert(
            ANNOTATION_HYPERVISOR.to_string(),
            cfg.hypervisor.as_str().to_string(),
        );
        DescriptorBuilder::default()
            .media_type(MediaType::ImageManifest)
            .digest(oci_digest(&manifest_digest)?)
            .size(manifest_bytes.len() as u64)
            .annotations(anns)
            .build()
            .map_err(|e| crate::new_error!("failed to build manifest descriptor: {}", e))
    }

    fn build_config(&self) -> crate::Result<OciSnapshotConfig> {
        let (entrypoint_addr, sregs) = match (self.entrypoint, self.sregs.as_ref()) {
            (NextAction::Call(addr), Some(sregs)) => (addr, sregs),
            (NextAction::Call(_), None) => {
                return Err(crate::new_error!(
                    "snapshot inconsistent: Call entrypoint must have sregs"
                ));
            }
            (NextAction::Initialise(_), _) => {
                return Err(crate::new_error!(
                    "pre-init snapshots cannot be persisted. Only a snapshot taken after the guest has run can be saved to disk"
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
            entrypoint_addr,
            sregs: *sregs,
            regs: self.regs,
            fpu: self.fpu,
            msrs: self.msrs.clone(),
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
            io_buffers: self.io_buffers.as_ref().map(Into::into),
        })
    }

    /// Load a snapshot from an OCI Image Layout directory produced by
    /// [`Snapshot::save`].
    ///
    /// # `path`
    ///
    /// The OCI Image Layout directory to read from. It must hold a
    /// readable OCI layout containing at least one Hyperlight
    /// snapshot.
    ///
    /// # `reference`
    ///
    /// Determines which snapshot in the layout to load, given as
    /// either an [`OciTag`] or an [`OciDigest`]. Loading fails if no
    /// snapshot in the layout has the given tag or digest.
    ///
    /// # Portability
    ///
    /// Snapshot images are bound to the specific CPU architecture and
    /// hypervisor that the snapshot was created on. For example, a
    /// snapshot taken on x86_64 with KVM can only be loaded on an
    /// x86_64 host running KVM. Loading on any other host is rejected.
    ///
    /// # Compatibility
    ///
    /// While Hyperlight is at version 0.x.y the on-disk format is not
    /// stable. A snapshot written by one Hyperlight version is not
    /// guaranteed to load on a different Hyperlight version. An
    /// incompatible snapshot is always rejected at load time with a
    /// clear error. It can never load and then misbehave once the
    /// guest is running. Any release that breaks the format is called
    /// out in the Hyperlight changelog.
    ///
    /// # Verification
    ///
    /// This method does not check the manifest, config, or snapshot
    /// blobs against their recorded sha256 digests. Load only from a
    /// layout you trust.
    ///
    /// To check the digests on load at the expense of some
    /// performance, use [`Snapshot::checked_load`].
    ///
    /// # File-mutation hazard
    ///
    /// The snapshot blob stays memory-mapped while the returned
    /// `Snapshot` or any sandbox built from it is alive. The existing
    /// blob files in the layout at `path` must not be overwritten,
    /// truncated, or deleted while the mapping is live. Doing so can
    /// corrupt guest memory and can lead to undefined behavior.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use hyperlight_host::{HostFunctions, MultiUseSandbox};
    /// # use hyperlight_host::sandbox::snapshot::{OciTag, Snapshot};
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let tag = OciTag::new("latest")?;
    /// let snapshot = Arc::new(Snapshot::load("./guest_snapshot", tag)?);
    /// let mut sandbox = MultiUseSandbox::from_snapshot(snapshot, HostFunctions::default(), None)?;
    /// let result: String = sandbox.call("Echo", "hello".to_string())?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn load(path: impl AsRef<Path>, reference: impl Into<OciReference>) -> crate::Result<Self> {
        Self::load_inner(path.as_ref(), &reference.into(), false)
    }

    /// Loads a snapshot like [`Snapshot::load`]. See its rustdoc for
    /// `path`, `reference`, portability, and the file-mutation
    /// hazard. This method additionally checks the manifest, config,
    /// and snapshot blobs against their recorded sha256 digests
    /// before use, at the expense of some performance.
    ///
    /// # Trust
    ///
    /// A digest check does not prove the bytes are authentic. Anyone
    /// who edits a blob can recompute its digest to match, so a
    /// hostile layout passes the check. Load only from a source you
    /// trust.
    pub fn checked_load(
        path: impl AsRef<Path>,
        reference: impl Into<OciReference>,
    ) -> crate::Result<Self> {
        Self::load_inner(path.as_ref(), &reference.into(), true)
    }

    fn load_inner(
        path: &Path,
        reference: &OciReference,
        verify_blobs: bool,
    ) -> crate::Result<Self> {
        let meta = std::fs::metadata(path)
            .map_err(|e| crate::new_error!("load failed to stat {:?}: {}", path, e))?;
        if !meta.is_dir() {
            return Err(crate::new_error!("load path {:?} is not a directory", path));
        }

        let blobs_dir: PathBuf = path.join("blobs").join("sha256");

        // 1. oci-layout
        read_layout_marker(path)?;

        // 2. index.json -> manifest descriptor for `reference`.
        //    Multiple manifests are valid in an OCI Image Layout. A
        //    tag selects the one whose
        //    `org.opencontainers.image.ref.name` annotation matches it
        //    (two manifests sharing a tag is a malformed layout). A
        //    digest selects the descriptor carrying that manifest
        //    digest.
        let manifest = load_manifest(path, &blobs_dir, reference, verify_blobs)?;
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
        let cfg = load_config(&blobs_dir, cfg_desc, verify_blobs)?;

        // 5. snapshot blob: open once, hash and mmap the same
        //    handle so an attacker cannot swap the file between
        //    verification and mapping.
        let snap_file = open_snapshot_blob(&blobs_dir, snap_desc, cfg.memory_size, verify_blobs)?;

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

        // `snapshot_size` is the guest-visible prefix mapped into the
        // snapshot region. It must cover at least the regions the
        // layout fields describe (code, PEB, heap, init data),
        // otherwise the guest mapping is too short to back them. The
        // `snapshot_size + pt_size == memory_size` invariant alone
        // does not bound `snapshot_size` from below, since a smaller
        // `snapshot_size` can be offset by a larger `pt_size`.
        let required_memory_size = layout.get_memory_size()? as u64;
        if (layout.snapshot_size as u64) < required_memory_size {
            return Err(crate::new_error!(
                "snapshot snapshot_size ({}) is smaller than the layout size ({})",
                layout.snapshot_size,
                required_memory_size
            ));
        }

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

        // The size validation in `open_snapshot_blob` stats the file
        // before mapping. Nothing prevents the file from being
        // truncated between that stat and the mmap, which would leave
        // the mapping shorter than the config claims and make restore
        // read past the end. Compare the mapped length against
        // `memory_size` to reject a file mutated under us.
        if memory.mem_size() as u64 != cfg.memory_size {
            return Err(crate::new_error!(
                "mapped snapshot size ({}) does not match config memory_size ({}); the blob may have changed during loading",
                memory.mem_size(),
                cfg.memory_size
            ));
        }

        // 8. Build entrypoint + sregs back from the config.
        let entrypoint = NextAction::Call(cfg.entrypoint_addr);

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

        // 10. Reconstitute the paused-snapshot IO buffers, if present.
        let io_buffers = cfg.io_buffers.map(TryInto::try_into).transpose()?;

        Ok(Snapshot {
            layout,
            memory,
            load_info: crate::mem::exe::LoadInfo::dummy(),
            stack_top_gva: cfg.stack_top_gva,
            sregs: Some(cfg.sregs),
            regs: cfg.regs,
            fpu: cfg.fpu,
            msrs: cfg.msrs,
            entrypoint,
            snapshot_generation,
            host_functions,
            io_buffers,
        })
    }
}
