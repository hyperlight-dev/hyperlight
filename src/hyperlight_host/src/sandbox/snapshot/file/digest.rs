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
        Self {
            hex: hex::encode(arr),
        }
    }

    fn from_hasher(h: Sha256) -> Self {
        let arr: [u8; 32] = h.finalize().into();
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

pub(super) fn parse_oci_digest(s: &str) -> crate::Result<String> {
    let rest = s.strip_prefix("sha256:").ok_or_else(|| {
        crate::new_error!(
            "OCI descriptor digest {:?} is not a sha256 digest (only sha256 is supported)",
            s
        )
    })?;
    // OCI image-spec pins sha256 encoding to `[a-f0-9]{64}`. Reject
    // uppercase hex up front so we stay byte-compatible with
    // containerd, oras, crane, and the Docker registry.
    if rest.len() != 64
        || !rest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(crate::new_error!(
            "OCI descriptor digest {:?} is not a 64-character lowercase hex string",
            s
        ));
    }
    Ok(rest.to_string())
}

/// Compute sha256 of `bytes` and verify it equals `expected_hex`.
/// Used to validate manifest and config blobs (small, already in
/// memory).
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

/// Stream-hash an already-open file and verify its sha256 equals
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
    let actual = Digest256::from_hasher(hasher);
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
