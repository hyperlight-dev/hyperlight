// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use std::io::{Read, Seek, SeekFrom};

use oci_spec::image::Digest;
use sha2::{Digest as _, Sha256};

/// A `sha256:<hex>` digest as recorded in OCI manifests. The bare hex
/// (without prefix) is also the blob's filename inside `blobs/sha256/`.
#[derive(Clone)]
pub(super) struct Digest256 {
    /// Lowercase hex of the 32-byte sha256 output.
    pub(super) hex: String,
}

impl Digest256 {
    pub(super) fn from_bytes(bytes: &[u8]) -> Self {
        let arr: [u8; 32] = Sha256::digest(bytes).into();
        Self::from_digest_array(arr)
    }

    pub(super) fn from_digest_array(arr: [u8; 32]) -> Self {
        Self {
            hex: hex::encode(arr),
        }
    }
}

/// Build an `oci_spec::image::Digest` from a [`Digest256`].
pub(super) fn oci_digest(d: &Digest256) -> crate::Result<Digest> {
    Digest::try_from(format!("sha256:{}", d.hex))
        .map_err(|e| crate::new_error!("failed to construct OCI digest: {}", e))
}

pub(super) fn parse_oci_digest(digest: &Digest) -> crate::Result<String> {
    let s = digest.as_ref();
    let rest = s.strip_prefix("sha256:").ok_or_else(|| {
        crate::new_error!(
            "OCI descriptor digest {:?} is not a sha256 digest (only sha256 is supported)",
            s
        )
    })?;
    Ok(rest.to_string())
}

/// Compute sha256 of `bytes` and verify it equals `expected_hex`.
/// Used to validate manifest and config blobs (small, in memory).
pub(super) fn verify_blob_bytes(
    label: &str,
    bytes: &[u8],
    expected_hex: &str,
) -> crate::Result<()> {
    let actual = Digest256::from_bytes(bytes);
    if actual.hex != expected_hex {
        return Err(crate::new_error!(
            "{} blob digest mismatch: descriptor declares sha256:{}, file hashes to sha256:{}",
            label,
            expected_hex,
            actual.hex
        ));
    }
    Ok(())
}

/// Stream-hash an open file and verify its sha256 equals
/// `expected_hex`.
///
/// Takes the same `File` handle the caller will subsequently `mmap`,
/// not a path. Hashing one open and mapping another is open-then-
/// replace TOCTOU bait. Seeks to start before and after so the
/// caller's file position is unchanged.
pub(super) fn verify_blob_file(
    label: &str,
    file: &mut std::fs::File,
    expected_hex: &str,
) -> crate::Result<()> {
    file.seek(SeekFrom::Start(0))
        .map_err(|e| crate::new_error!("failed to seek {} blob: {}", label, e))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| crate::new_error!("failed to read {} blob: {}", label, e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|e| crate::new_error!("failed to rewind {} blob: {}", label, e))?;
    let arr: [u8; 32] = hasher.finalize().into();
    let actual = Digest256::from_digest_array(arr);
    if actual.hex != expected_hex {
        return Err(crate::new_error!(
            "{} blob digest mismatch: descriptor declares sha256:{}, file hashes to sha256:{}",
            label,
            expected_hex,
            actual.hex
        ));
    }
    Ok(())
}
