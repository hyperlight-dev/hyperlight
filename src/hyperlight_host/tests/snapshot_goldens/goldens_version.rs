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

//! The goldens version string, kept in its own file.
//!
//! The `.github/workflows/RegenSnapshotGoldens.yml` path filter watches
//! this file, so a version bump is the only edit that triggers a
//! publish. See `docs/snapshot-versioning.md`.

/// Goldens version, a `vMAJOR.MINOR` string.
pub(crate) const GOLDENS_VERSION: &str = "v1.0";

/// Old majors kept loadable through a compatibility path, verified
/// alongside `GOLDENS_VERSION`. A backwards-compatible break (Option 2)
/// adds the outgoing version here. See `docs/snapshot-versioning.md`.
pub(crate) const COMPAT_VERSIONS: &[&str] = &[];

/// Every version the verify test checks: the current one and each kept
/// old major.
pub(crate) fn verify_versions() -> impl Iterator<Item = &'static str> {
    std::iter::once(GOLDENS_VERSION).chain(COMPAT_VERSIONS.iter().copied())
}

/// The ABI major in a `vMAJOR.MINOR` string. MAJOR tracks
/// `SNAPSHOT_ABI_VERSION`, so the verify run uses it to skip checks
/// newer than a golden. See `docs/snapshot-versioning.md`.
pub(crate) fn abi_major(version: &str) -> u32 {
    version
        .strip_prefix('v')
        .and_then(|s| s.split('.').next())
        .and_then(|s| s.parse().ok())
        .expect("version must be a vMAJOR.MINOR string")
}
