// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use std::io::{Read, Seek, SeekFrom};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

use oci_spec::image::Digest;
use sha2::{Digest as _, Sha256};

#[cfg(test)]
thread_local! {
    // Counts hashed bytes to test save's cache reuse versus checked_save's full hashing.
    // Thread-local storage isolates parallel tests; this is absent from production builds.
    pub(super) static HASHED_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// A `sha256:<hex>` digest as recorded in OCI manifests. The bare hex
/// (without prefix) is also the blob's filename inside `blobs/sha256/`.
#[derive(Clone)]
pub(super) struct Digest256 {
    /// Lowercase hex of the 32-byte sha256 output.
    pub(super) hex: String,
}

impl Digest256 {
    pub(super) fn from_bytes(bytes: &[u8]) -> Self {
        #[cfg(test)]
        HASHED_BYTES.update(|count| count + bytes.len());
        let arr: [u8; 32] = Sha256::digest(bytes).into();
        Self::from_digest_array(arr)
    }

    fn from_digest_array(arr: [u8; 32]) -> Self {
        Self {
            hex: hex::encode(arr),
        }
    }
}

/// A blob's declared and computed digests must agree whenever both are known.
///
/// The digest is written once; only its trust state changes. A mismatch is
/// terminal for all owners sharing this hash: neither the stored digest nor
/// the current bytes are assumed authoritative.
#[derive(Debug)]
pub(crate) struct BlobHash {
    hash: OnceLock<String>,
    state: AtomicU32,
}

// States only advance; the failure sentinel must exceed every valid state.
const INVALID_HASH_STATE: u32 = u32::MAX;
const UNKNOWN_HASH_STATE: u32 = 0;
const DECLARED_HASH_STATE: u32 = 1;
const VERIFIED_HASH_STATE: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HashState<'a> {
    Unknown,
    Declared(&'a str),
    Verified(&'a str),
}

impl HashState<'_> {
    pub(crate) fn as_digest(&self) -> Option<String> {
        match *self {
            Self::Unknown => None,
            Self::Declared(digest) | Self::Verified(digest) => Some(digest.to_owned()),
        }
    }
}

impl Default for BlobHash {
    fn default() -> Self {
        Self::unknown()
    }
}

impl BlobHash {
    fn decode(&self, state: u32) -> crate::Result<HashState<'_>> {
        match state {
            UNKNOWN_HASH_STATE => Ok(HashState::Unknown),
            DECLARED_HASH_STATE => Ok(HashState::Declared(
                self.hash.get().expect("declared hash must be initialized"),
            )),
            VERIFIED_HASH_STATE => Ok(HashState::Verified(
                self.hash.get().expect("verified hash must be initialized"),
            )),
            INVALID_HASH_STATE => Err(crate::new_error!(
                "snapshot blob digest mismatch: hash is invalid"
            )),
            _ => unreachable!("invalid internal blob hash state"),
        }
    }

    pub(crate) fn unknown() -> Self {
        Self {
            hash: OnceLock::new(),
            state: AtomicU32::new(UNKNOWN_HASH_STATE),
        }
    }

    pub(crate) fn declared(digest: String) -> Self {
        Self {
            state: AtomicU32::new(DECLARED_HASH_STATE),
            ..Self::verified(digest)
        }
    }

    /// The caller must have computed or verified this digest against the blob's bytes.
    pub(crate) fn verified(digest: String) -> Self {
        Self {
            hash: OnceLock::from(digest),
            state: AtomicU32::new(VERIFIED_HASH_STATE),
        }
    }

    pub(crate) fn get(&self) -> crate::Result<HashState<'_>> {
        // This is a point-in-time state, not a lease against later invalidation
        // or a fresh check of the blob's bytes.
        self.decode(self.state.load(Ordering::Acquire))
    }

    /// Always hash the bytes and validate consistency with any previously known digest.
    pub(crate) fn verify_bytes(&self, bytes: &[u8]) -> crate::Result<HashState<'_>> {
        self.record_computed(Digest256::from_bytes(bytes).hex)
    }

    /// Verify the same open file that backs the blob, restoring its position to the start.
    pub(crate) fn verify_file(&self, file: &mut std::fs::File) -> crate::Result<HashState<'_>> {
        self.record_computed(hash_blob_file("snapshot", file)?.hex)
    }

    /// Record a computed or verified digest, rejecting inconsistent immutable bytes.
    fn record_computed(&self, digest: String) -> crate::Result<HashState<'_>> {
        self.get()?;
        // For an unknown hash, concurrent verifiers agree on the first stored
        // digest or invalidate it; they never replace one another's digest.
        let expected = self.hash.get_or_init(|| digest.clone());
        if expected != &digest {
            self.state.fetch_max(INVALID_HASH_STATE, Ordering::AcqRel);
            return Err(crate::new_error!(
                "snapshot blob digest mismatch: expected sha256:{}, computed sha256:{}",
                expected,
                digest
            ));
        }
        // Publish the initialized digest without reviving an invalid hash.
        // Inspect the previous state to catch invalidation racing with get().
        let previous = self.state.fetch_max(VERIFIED_HASH_STATE, Ordering::AcqRel);
        self.decode(previous)?;
        Ok(HashState::Verified(expected))
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
    let actual = hash_blob_file(label, file)?;
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

fn hash_blob_file(label: &str, file: &mut std::fs::File) -> crate::Result<Digest256> {
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
        #[cfg(test)]
        HASHED_BYTES.update(|count| count + n);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|e| crate::new_error!("failed to rewind {} blob: {}", label, e))?;
    let arr: [u8; 32] = hasher.finalize().into();
    Ok(Digest256::from_digest_array(arr))
}
