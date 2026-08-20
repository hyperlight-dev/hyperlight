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
    tmp.as_file_mut().sync_all().map_err(|e| {
        crate::new_error!("atomic write: failed to sync tmp {:?}: {}", tmp.path(), e)
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
/// overwritten.
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
    if let Ok(meta) = std::fs::symlink_metadata(&target)
        && meta.is_file()
        && meta.len() == bytes.len() as u64
        && let Ok(mut file) = std::fs::File::open(&target)
        && verify_blob_file("existing snapshot", &mut file, &digest.hex).is_ok()
    {
        return Ok(());
    }
    replace_file_atomic(&target, bytes)
}

/// Reject a path that is a symbolic link.
///
/// Blobs in an OCI layout are content-addressed regular files. A
/// symlink in their place could redirect a read outside the layout
/// directory, so refuse it before opening. A missing path passes
/// this check so the caller's open reports the absence with one
/// consistent error.
#[cfg(not(unix))]
pub(super) fn reject_symlink(path: &Path) -> crate::Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(crate::new_error!("failed to stat {:?}: {}", path, e)),
    };
    if meta.file_type().is_symlink() {
        return Err(crate::new_error!(
            "{:?} is a symbolic link; refusing to follow it",
            path
        ));
    }
    Ok(())
}

/// Open a blob file for reading without following a final-component
/// symlink. A missing file maps to a fixed "not found" error whose
/// text is the same on every platform, so callers and tests do not
/// depend on the OS wording for a missing file.
pub(super) fn open_no_follow(path: &Path) -> crate::Result<std::fs::File> {
    // On unix, `O_NOFOLLOW` rejects a final-component symlink in the
    // same syscall that opens the file, so there is no window between
    // a stat and the open for the path to be swapped. On other
    // platforms, a stat-then-open pre-check is the available option.
    #[cfg(unix)]
    let opened = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
    };
    #[cfg(not(unix))]
    let opened = {
        reject_symlink(path)?;
        std::fs::File::open(path)
    };
    let file = opened.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            crate::new_error!("blob file {:?} not found", path)
        } else {
            crate::new_error!("failed to open {:?}: {}", path, e)
        }
    })?;
    let file_type = file
        .metadata()
        .map_err(|e| crate::new_error!("failed to stat {:?}: {}", path, e))?
        .file_type();
    if !file_type.is_file() {
        return Err(crate::new_error!("{:?} is not a regular file", path));
    }
    Ok(file)
}

/// Read a file in full, refusing if the file is bigger than `max_size`.
///
/// The cap is enforced on the actual byte stream via [`Read::take`], so files
/// whose `metadata().len()` is misleading cannot exceed the limit. Symbolic
/// links are rejected.
pub(super) fn read_bounded(path: &Path, max_size: u64) -> crate::Result<Vec<u8>> {
    let f = open_no_follow(path)?;
    let hint = f.metadata().map(|m| m.len().min(max_size)).unwrap_or(0);
    let mut buf = Vec::with_capacity(hint as usize);
    // Read one extra byte so an oversize file is detected as "over the
    // limit" and rejected, never silently truncated to the cap.
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

#[cfg(all(test, unix))]
mod tests {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;

    use super::*;

    #[test]
    fn open_no_follow_rejects_fifo() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fifo");
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c_path` is a valid NUL-terminated path and mode has valid permission bits.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        let _guard = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)
            .unwrap();

        let err = open_no_follow(&path).unwrap_err();
        assert!(format!("{err}").contains("regular file"));
    }
}
