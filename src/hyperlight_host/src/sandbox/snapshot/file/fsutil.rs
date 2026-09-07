// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use tempfile::NamedTempFile;

use super::digest::{Digest256, verify_blob_file};

/// Granularity at which [`write_sparse`] looks for all-zero regions.
/// A hole can only exist on a filesystem-block boundary, and 4 KiB is
/// the block size of every filesystem we target, so scanning finer
/// would cost comparisons that can never turn into a hole.
const SPARSE_BLOCK: usize = 4096;

/// Ask the filesystem to treat `file` as sparse, so that ranges left
/// unwritten by [`write_sparse`] become holes.
///
/// Unix filesystems make a file sparse implicitly, so there is
/// nothing to request. NTFS does not: unless a file is explicitly
/// marked sparse, it zero-fills any range skipped by a seek, and the
/// file ends up fully allocated. Marking it costs one ioctl on an
/// empty file.
///
/// Best-effort by design. A filesystem that does not support sparse
/// files (FAT32, exFAT) rejects the request, which is not an error:
/// the write that follows is still correct, just dense.
#[cfg(not(windows))]
fn try_set_sparse(_file: &std::fs::File) {}

#[cfg(windows)]
fn try_set_sparse(file: &std::fs::File) {
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_SPARSE;

    let mut returned: u32 = 0;
    // SAFETY: the handle is valid and owned by `file` for the
    // duration of the call. FSCTL_SET_SPARSE takes no input or output
    // buffer, so all buffer pointers are null with zero lengths, and
    // `returned` is a valid writable u32. The return value is
    // deliberately ignored: see the doc comment.
    unsafe {
        DeviceIoControl(
            file.as_raw_handle() as _,
            FSCTL_SET_SPARSE,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        );
    }
}

/// Write `bytes` to `file`, seeking over all-zero blocks instead of
/// writing them.
///
/// `write_all` allocates blocks for zeros like any other data: the
/// kernel cannot know the caller would accept a hole. Seeking past a
/// range and extending the file with `set_len` leaves that range
/// unwritten, and a filesystem that supports sparse files reports it
/// as a hole.
///
/// The result is byte-for-byte identical to a dense write — reads of
/// a hole return zeros — so this is invisible to anything that reads
/// the file, including digest verification. Only the blocks the file
/// occupies on disk differ. On a filesystem without sparse support
/// the range is zero-filled instead, which is still correct.
///
/// Runs of adjacent non-zero blocks are written in a single call, so
/// a blob with no zeros costs exactly one `write_all` plus one seek.
fn write_sparse(file: &mut std::fs::File, bytes: &[u8]) -> std::io::Result<()> {
    // Must happen while the file is still empty, and before any seek
    // past a gap, or NTFS zero-fills the skipped ranges instead of
    // leaving holes.
    try_set_sparse(file);
    let zero = [0u8; SPARSE_BLOCK];
    let len = bytes.len();
    let mut pos = 0;
    while pos < len {
        let end = (pos + SPARSE_BLOCK).min(len);
        // Skipped: leave a hole and move on.
        if bytes[pos..end] == zero[..end - pos] {
            pos = end;
            continue;
        }
        // Extend over adjacent non-zero blocks so the whole run goes
        // out in one write rather than one write per block.
        let start = pos;
        pos = end;
        while pos < len {
            let block_end = (pos + SPARSE_BLOCK).min(len);
            if bytes[pos..block_end] == zero[..block_end - pos] {
                break;
            }
            pos = block_end;
        }
        file.seek(SeekFrom::Start(start as u64))?;
        file.write_all(&bytes[start..pos])?;
    }
    // The file must reach its full length even when it ends in zeros,
    // which are skipped above and so never extend it.
    file.set_len(len as u64)?;
    Ok(())
}

/// Replace `target` atomically: a reader either sees the old
/// contents or the full new contents, never a partial write. A
/// failure before commit leaves `target` untouched and removes the
/// staging file.
pub(super) fn replace_file_atomic(target: &Path, bytes: &[u8]) -> crate::Result<()> {
    replace_file_atomic_inner(target, bytes, false)
}

/// [`replace_file_atomic`], but skipping all-zero blocks so the file
/// lands sparse. See [`write_sparse`] for why the contents are
/// unchanged.
pub(super) fn replace_file_atomic_sparse(target: &Path, bytes: &[u8]) -> crate::Result<()> {
    replace_file_atomic_inner(target, bytes, true)
}

fn replace_file_atomic_inner(target: &Path, bytes: &[u8], sparse: bool) -> crate::Result<()> {
    let parent = target.parent().ok_or_else(|| {
        crate::new_error!("atomic write: target {:?} has no parent directory", target)
    })?;
    let mut tmp = NamedTempFile::new_in(parent).map_err(|e| {
        crate::new_error!("atomic write: failed to create tmp in {:?}: {}", parent, e)
    })?;
    if sparse {
        write_sparse(tmp.as_file_mut(), bytes)
    } else {
        tmp.write_all(bytes)
    }
    .map_err(|e| crate::new_error!("atomic write: failed to write tmp {:?}: {}", tmp.path(), e))?;
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
///
/// Written sparsely: a guest memory image is mostly untouched pages,
/// so writing its zeros would dominate the cost of saving a snapshot
/// while adding nothing a reader can observe.
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
    replace_file_atomic_sparse(&target, bytes)
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

#[cfg(test)]
mod sparse_tests {
    use super::*;

    /// Every pattern must round-trip byte-for-byte. The interesting
    /// cases are the ones where a hole meets data: leading and
    /// trailing zeros, a gap in the middle, and a final block shorter
    /// than `SPARSE_BLOCK` (so the tail is compared against a partial
    /// zero block, not a whole one).
    fn patterns() -> Vec<(&'static str, Vec<u8>)> {
        let b = SPARSE_BLOCK;
        vec![
            ("empty", vec![]),
            ("all zero, one block", vec![0u8; b]),
            ("all zero, many blocks", vec![0u8; b * 4]),
            ("all data", vec![0xABu8; b * 4]),
            ("leading zeros", [vec![0u8; b * 2], vec![7u8; b]].concat()),
            ("trailing zeros", [vec![7u8; b], vec![0u8; b * 2]].concat()),
            (
                "hole in the middle",
                [vec![7u8; b], vec![0u8; b * 2], vec![9u8; b]].concat(),
            ),
            ("unaligned tail of data", vec![3u8; b * 2 + 17]),
            ("unaligned tail of zeros", {
                let mut v = vec![3u8; b];
                v.extend(std::iter::repeat_n(0u8, 17));
                v
            }),
            ("single non-zero byte in a block", {
                let mut v = vec![0u8; b * 3];
                v[b + 5] = 1;
                v
            }),
            ("shorter than one block", vec![1u8, 0, 2]),
        ]
    }

    #[test]
    fn sparse_write_round_trips_every_pattern() {
        let dir = tempfile::tempdir().unwrap();
        for (name, bytes) in patterns() {
            let path = dir.path().join("blob");
            replace_file_atomic_sparse(&path, &bytes).unwrap();
            let read_back = std::fs::read(&path).unwrap();
            assert_eq!(read_back, bytes, "content mismatch for {name}");
            assert_eq!(
                std::fs::metadata(&path).unwrap().len(),
                bytes.len() as u64,
                "length mismatch for {name}"
            );
            std::fs::remove_file(&path).unwrap();
        }
    }

    /// A sparse write must be indistinguishable from a dense one to
    /// anything that reads the file. This is what lets the snapshot
    /// blob go out sparse without touching the digest it is addressed
    /// by, or the format version.
    #[test]
    fn sparse_and_dense_writes_produce_identical_files() {
        let dir = tempfile::tempdir().unwrap();
        for (name, bytes) in patterns() {
            let dense = dir.path().join("dense");
            let sparse = dir.path().join("sparse");
            replace_file_atomic(&dense, &bytes).unwrap();
            replace_file_atomic_sparse(&sparse, &bytes).unwrap();
            assert_eq!(
                std::fs::read(&dense).unwrap(),
                std::fs::read(&sparse).unwrap(),
                "dense and sparse differ for {name}"
            );
        }
    }

    /// The blob must still hash to the digest it is stored under, and
    /// the reuse path must accept a sparse file it wrote itself —
    /// otherwise every save would rewrite the blob.
    #[test]
    fn put_blob_if_absent_writes_a_verifiable_blob_and_reuses_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = vec![0u8; SPARSE_BLOCK * 8];
        bytes[SPARSE_BLOCK * 3..SPARSE_BLOCK * 4].fill(0x5A);
        let digest = Digest256::from_bytes(&bytes);

        put_blob_if_absent(dir.path(), &digest, &bytes).unwrap();
        let target = dir.path().join(&digest.hex);
        assert_eq!(std::fs::read(&target).unwrap(), bytes);

        let mut file = std::fs::File::open(&target).unwrap();
        verify_blob_file("test", &mut file, &digest.hex).unwrap();

        // Second call must take the reuse path and leave the file be.
        let before = std::fs::metadata(&target).unwrap().modified().unwrap();
        put_blob_if_absent(dir.path(), &digest, &bytes).unwrap();
        let after = std::fs::metadata(&target).unwrap().modified().unwrap();
        assert_eq!(before, after, "blob was rewritten instead of reused");
    }
}

#[cfg(all(test, unix))]
mod sparse_unix_tests {
    use std::os::unix::fs::MetadataExt;

    use super::*;

    /// The point of the change: a mostly-zero blob, like a guest
    /// memory image, must occupy far fewer blocks on disk than its
    /// length.
    ///
    /// Sparseness is a filesystem capability, so the test first
    /// probes whether the temp filesystem supports holes at all and
    /// skips if not (HFS+, FAT). The probe keeps the assertion sharp
    /// where holes *are* supported, rather than weakening it
    /// everywhere to accommodate filesystems where they are not.
    #[test]
    fn sparse_write_allocates_fewer_blocks_than_dense() {
        let dir = tempfile::tempdir().unwrap();

        // Probe: a file with a large unwritten gap should occupy far
        // fewer blocks than its length if this filesystem has holes.
        let probe_path = dir.path().join("probe");
        {
            let mut probe = std::fs::File::create(&probe_path).unwrap();
            probe.seek(SeekFrom::Start(8 * 1024 * 1024)).unwrap();
            probe.write_all(b"x").unwrap();
            probe.sync_all().unwrap();
        }
        let probe_meta = std::fs::metadata(&probe_path).unwrap();
        let supports_holes =
            probe_meta.blocks() > 0 && probe_meta.blocks() * 512 < probe_meta.len() / 2;
        if !supports_holes {
            eprintln!("filesystem does not support sparse files; skipping");
            return;
        }

        // 8 MiB, of which one 64 KiB run is non-zero.
        let mut bytes = vec![0u8; 8 * 1024 * 1024];
        bytes[1024 * 1024..1024 * 1024 + 64 * 1024].fill(0xC3);

        let dense = dir.path().join("dense");
        let sparse = dir.path().join("sparse");
        replace_file_atomic(&dense, &bytes).unwrap();
        replace_file_atomic_sparse(&sparse, &bytes).unwrap();

        let dense_blocks = std::fs::metadata(&dense).unwrap().blocks();
        let sparse_blocks = std::fs::metadata(&sparse).unwrap().blocks();

        assert!(
            sparse_blocks * 4 < dense_blocks,
            "expected a large saving, got sparse={sparse_blocks} dense={dense_blocks} blocks"
        );
    }
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
