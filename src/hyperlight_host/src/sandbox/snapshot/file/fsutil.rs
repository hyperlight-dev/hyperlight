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

use std::io::Read;
use std::path::Path;

use super::digest::Digest256;

/// Write `bytes` to `target` atomically: write to a sibling tmp
/// file in the same directory, fsync nothing extra, then `rename`.
/// On rename failure the tmp file is removed.
///
/// The tmp name embeds pid and a monotonic-ish nanos suffix to keep
/// concurrent writers in the same directory from colliding on the
/// tmp path. Concurrent writers to the same `target` still race on
/// the final rename, which is the caller's contract to avoid.
pub(super) fn write_file_atomic(target: &Path, bytes: &[u8]) -> crate::Result<()> {
    let parent = target.parent().unwrap_or(Path::new("."));
    let file_name = target.file_name().and_then(|s| s.to_str()).ok_or_else(|| {
        crate::new_error!("atomic write: target {:?} has no UTF-8 file name", target)
    })?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = parent.join(format!(
        ".{}.tmp-{}-{}",
        file_name,
        std::process::id(),
        nanos
    ));
    std::fs::write(&tmp, bytes)
        .map_err(|e| crate::new_error!("atomic write: failed to write tmp {:?}: {}", tmp, e))?;
    std::fs::rename(&tmp, target).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        crate::new_error!(
            "atomic write: failed to rename {:?} -> {:?}: {}",
            tmp,
            target,
            e
        )
    })
}

/// Write a content-addressed blob into `blobs_dir`, skipping the
/// write if a file at `blobs_dir/<hex>` is already present and has
/// the expected length. Skipping is safe because the filename is the
/// sha256 of the bytes: a name match implies a content match outside
/// of a hash collision. The size check defends against half-written
/// stragglers left over from a previous crash.
pub(super) fn write_blob_if_absent(
    blobs_dir: &Path,
    digest: &Digest256,
    bytes: &[u8],
) -> crate::Result<()> {
    let target = blobs_dir.join(&digest.hex);
    if let Ok(meta) = std::fs::metadata(&target)
        && meta.is_file()
        && meta.len() == bytes.len() as u64
    {
        return Ok(());
    }
    write_file_atomic(&target, bytes)
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
