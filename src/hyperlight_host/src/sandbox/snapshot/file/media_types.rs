// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

// Media types are versioned by suffix. The writer emits `_CURRENT`.
// The loader matches each version explicitly. See
// docs/snapshot-versioning.md for how to add a version.
pub(in crate::sandbox::snapshot) const MT_CONFIG_V1: &str =
    "application/vnd.hyperlight.snapshot.config.v1+json";
pub(in crate::sandbox::snapshot) const MT_CONFIG_CURRENT: &str = MT_CONFIG_V1;
pub(in crate::sandbox::snapshot) const MT_SNAPSHOT_V1: &str =
    "application/vnd.hyperlight.snapshot.memory.v1";
pub(in crate::sandbox::snapshot) const MT_SNAPSHOT_CURRENT: &str = MT_SNAPSHOT_V1;

/// ABI version for the snapshot memory blob. Bumped when the
/// host-guest contract for the snapshot bytes changes. See
/// docs/snapshot-versioning.md.
pub(in crate::sandbox::snapshot) const SNAPSHOT_ABI_VERSION: u32 = 2;

/// OCI standard annotation key for a manifest's tag inside an image
/// index. Set on the manifest descriptor in `index.json`, not on the
/// manifest blob itself. See the OCI Image Spec, "Annotations" and
/// the Image Layout spec.
pub(super) const ANNOTATION_REF_NAME: &str = "org.opencontainers.image.ref.name";

/// Advisory annotation keys recording the guest arch, hypervisor
/// backend, and CPU vendor on the manifest descriptor in
/// `index.json`. These mirror the authoritative `arch`, `hypervisor`,
/// and `cpu_vendor` fields in the config blob so registry UIs and
/// tools like `oras` and `skopeo` can show them. The loader validates
/// against the config blob.
pub(super) const ANNOTATION_ARCH: &str = "dev.hyperlight.snapshot.arch";
pub(super) const ANNOTATION_HYPERVISOR: &str = "dev.hyperlight.snapshot.hypervisor";
pub(super) const ANNOTATION_CPU: &str = "dev.hyperlight.snapshot.cpu.vendor";
