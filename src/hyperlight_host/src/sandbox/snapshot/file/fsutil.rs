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

use std::io::{Read, Write};
use std::path::Path;

use tempfile::NamedTempFile;

use super::digest::{Digest256, verify_blob_file};

/// Replace `target` atomically: a reader either sees the old
/// contents or the full new contents, never a partial write. A
/// failure before commit leaves `target` untouched and removes the
/// staging file.
pub(super) fn replace_file_atomic(target: &Path, bytes: &[u8]) -> crate::Result<()> {
    let parent = target.parent().ok_or_else(|| {
        crate::new_error!("atomic write: target {:?} has no parent directory", target)
    })?;
    let mut tmp = NamedTempFile::new_in(parent).map_err(|e| {
        crate::new_error!("atomic write: failed to create tmp in {:?}: {}", parent, e)
    })?;
    tmp.write_all(bytes).map_err(|e| {
        crate::new_error!("atomic write: failed to write tmp {:?}: {}", tmp.path(), e)
    })?;
    tmp.persist(target).map_err(|e| {
        crate::new_error!("atomic write: failed to persist tmp to {:?}: {}", target, e)
    })?;
    Ok(())
}

/// Write a content-addressed blob into `blobs_dir` unconditionally,
/// via [`replace_file_atomic`]. Intended for small blobs (manifest,
/// config) where the cost of an extra atomic write is negligible
/// compared to the cost of reading and re-hashing the existing file.
pub(super) fn put_blob(blobs_dir: &Path, digest: &Digest256, bytes: &[u8]) -> crate::Result<()> {
    replace_file_atomic(&blobs_dir.join(&digest.hex), bytes)
}

/// Write a content-addressed blob into `blobs_dir`, reusing the
/// existing file at `blobs_dir/<hex>` only if it is present, has the
/// expected length, AND hashes to `digest`. A wrong-content file of
/// the right length (corruption, partial copy, foreign tool) is
/// overwritten rather than silently trusted.
///
/// Intended for the large snapshot blob, where the cost of one full
/// re-hash of the existing file is far less than the cost of an
/// unconditional rewrite.
pub(super) fn put_blob_if_absent(
    blobs_dir: &Path,
    digest: &Digest256,
    bytes: &[u8],
) -> crate::Result<()> {
    let target = blobs_dir.join(&digest.hex);
    if let Ok(meta) = std::fs::metadata(&target)
        && meta.is_file()
        && meta.len() == bytes.len() as u64
        && let Ok(mut file) = std::fs::File::open(&target)
        && verify_blob_file("existing snapshot", &mut file, &digest.hex).is_ok()
    {
        return Ok(());
    }
    replace_file_atomic(&target, bytes)
}

/// Read a file in full, refusing if the file is bigger than `max_size`.
///
/// The cap is enforced on the actual byte stream via [`Read::take`], so files
/// whose `metadata().len()` is misleading cannot exceed the limit.
pub(super) fn read_bounded(path: &Path, max_size: u64) -> crate::Result<Vec<u8>> {
    let f = std::fs::File::open(path)
        .map_err(|e| crate::new_error!("failed to open {:?}: {}", path, e))?;
    let hint = f.metadata().map(|m| m.len().min(max_size)).unwrap_or(0);
    let mut buf = Vec::with_capacity(hint as usize);
    // Read one extra byte so we can distinguish "exactly at the limit" from
    // "over the limit" instead of silently truncating an oversize file.
    f.take(max_size.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| crate::new_error!("failed to read {:?}: {}", path, e))?;
    if buf.len() as u64 > max_size {
        return Err(crate::new_error!(
            "file {:?} exceeds maximum allowed {} bytes",
            path,
            max_size
        ));
    }
    Ok(buf)
}
