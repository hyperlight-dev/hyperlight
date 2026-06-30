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

//! Stream a snapshot's OCI Image Layout into a single `.tar` or
//! `.tar.gz` archive, and read one back.
//!
//! The archive is just the OCI layout (`oci-layout`, `index.json`,
//! `blobs/sha256/...`) stored at the archive root. The writer
//! ([`ArchiveWriter`]) appends entries directly to the tar stream, so a
//! snapshot is packed without first materialising the layout in a
//! temporary directory: the (large) memory image is streamed straight
//! from its in-memory mapping into the archive. The reader extracts the
//! layout into a directory so the regular directory loader can run
//! against it unchanged.

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use tar::{Archive, Builder, EntryType, Header};

/// The container format used to store a snapshot's OCI Image Layout as a
/// single file.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ArchiveFormat {
    /// An uncompressed POSIX tar archive (`.tar`).
    Tar,
    /// A gzip-compressed tar archive (`.tar.gz` / `.tgz`).
    TarGz,
}

impl ArchiveFormat {
    /// Infer the archive format from a path's extension. Recognises
    /// `.tar`, `.tar.gz`, and `.tgz` (case-insensitively). Returns
    /// `None` for any other path so the caller can demand an explicit
    /// format.
    pub fn from_path(path: impl AsRef<Path>) -> Option<Self> {
        let name = path.as_ref().file_name()?.to_str()?.to_ascii_lowercase();
        if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
            Some(ArchiveFormat::TarGz)
        } else if name.ends_with(".tar") {
            Some(ArchiveFormat::Tar)
        } else {
            None
        }
    }
}

/// Normalise a tar entry path to a layout-relative path with forward
/// slashes and no leading `./`. Archives written by older code packed
/// the layout under `./`, so both forms read back the same.
fn normalise_entry_path(raw: &str) -> String {
    raw.replace('\\', "/").trim_start_matches("./").to_string()
}

/// Writes an OCI Image Layout into a tar (optionally gzip-compressed)
/// stream. The compression choice is fixed at construction; the enum
/// keeps callers free of the writer's generic type.
pub(crate) enum ArchiveWriter {
    Plain(Builder<BufWriter<File>>),
    Gz(Builder<GzEncoder<BufWriter<File>>>),
}

impl ArchiveWriter {
    /// Create an archive file at `path` and prepare to write entries in
    /// `format`.
    pub(crate) fn create(path: &Path, format: ArchiveFormat) -> crate::Result<Self> {
        let file = File::create(path)
            .map_err(|e| crate::new_error!("save_archive: failed to create {:?}: {}", path, e))?;
        let writer = BufWriter::new(file);
        Ok(match format {
            ArchiveFormat::Tar => ArchiveWriter::Plain(Builder::new(writer)),
            ArchiveFormat::TarGz => {
                ArchiveWriter::Gz(Builder::new(GzEncoder::new(writer, Compression::default())))
            }
        })
    }

    /// Append a single regular-file entry at layout-relative `rel_path`,
    /// reading exactly `size` bytes from `data`. The bulk memory image
    /// is written this way straight from its mapping, so it never lands
    /// in a temporary file.
    pub(crate) fn append(
        &mut self,
        rel_path: &str,
        size: u64,
        data: &mut dyn Read,
    ) -> crate::Result<()> {
        let mut header = Header::new_gnu();
        header.set_size(size);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_entry_type(EntryType::Regular);
        let res = match self {
            ArchiveWriter::Plain(b) => b.append_data(&mut header, rel_path, data),
            ArchiveWriter::Gz(b) => b.append_data(&mut header, rel_path, data),
        };
        res.map_err(|e| crate::new_error!("save_archive: failed to add {}: {}", rel_path, e))
    }

    /// Append an in-memory blob (small JSON: manifest, config, index,
    /// marker).
    pub(crate) fn append_bytes(&mut self, rel_path: &str, bytes: &[u8]) -> crate::Result<()> {
        self.append(rel_path, bytes.len() as u64, &mut &bytes[..])
    }

    /// Finish the archive: flush the tar trailer and, for gzip, the
    /// compression trailer, then flush the buffered file.
    pub(crate) fn finish(self) -> crate::Result<()> {
        match self {
            ArchiveWriter::Plain(b) => {
                let mut w = b
                    .into_inner()
                    .map_err(|e| crate::new_error!("save_archive: failed to finish tar: {}", e))?;
                w.flush().map_err(|e| {
                    crate::new_error!("save_archive: failed to flush archive: {}", e)
                })?;
            }
            ArchiveWriter::Gz(b) => {
                let enc = b
                    .into_inner()
                    .map_err(|e| crate::new_error!("save_archive: failed to finish tar: {}", e))?;
                let mut w = enc
                    .finish()
                    .map_err(|e| crate::new_error!("save_archive: failed to finish gzip: {}", e))?;
                w.flush().map_err(|e| {
                    crate::new_error!("save_archive: failed to flush archive: {}", e)
                })?;
            }
        }
        Ok(())
    }
}

/// Stream every blob entry from the existing snapshot archive at `src`
/// into `out`, and return the archive's `index.json` bytes if present.
///
/// Used to merge a new snapshot into an existing archive without a
/// temporary directory: blobs (including other tags' memory images) are
/// copied through the tar streams, while `oci-layout` and `index.json`
/// are dropped here because the caller rewrites them. A blob whose
/// layout-relative path is already in `written` is skipped; copied
/// paths are inserted into `written` so the caller's own blobs dedup
/// against them.
pub(crate) fn copy_existing_blobs(
    src: &Path,
    format: ArchiveFormat,
    out: &mut ArchiveWriter,
    written: &mut HashSet<String>,
) -> crate::Result<Option<Vec<u8>>> {
    let file = File::open(src)
        .map_err(|e| crate::new_error!("save_archive: failed to open {:?}: {}", src, e))?;
    let reader = BufReader::new(file);
    let mut index_bytes = None;
    match format {
        ArchiveFormat::Tar => {
            copy_entries(Archive::new(reader), out, written, &mut index_bytes)?;
        }
        ArchiveFormat::TarGz => {
            copy_entries(
                Archive::new(GzDecoder::new(reader)),
                out,
                written,
                &mut index_bytes,
            )?;
        }
    }
    Ok(index_bytes)
}

fn copy_entries<R: Read>(
    mut archive: Archive<R>,
    out: &mut ArchiveWriter,
    written: &mut HashSet<String>,
    index_bytes: &mut Option<Vec<u8>>,
) -> crate::Result<()> {
    let entries = archive
        .entries()
        .map_err(|e| crate::new_error!("save_archive: failed to read existing archive: {}", e))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| {
            crate::new_error!("save_archive: corrupt entry in existing archive: {}", e)
        })?;
        let raw = entry
            .path()
            .map_err(|e| crate::new_error!("save_archive: bad path in existing archive: {}", e))?
            .to_string_lossy()
            .into_owned();
        let rel = normalise_entry_path(&raw);

        if rel == "index.json" {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).map_err(|e| {
                crate::new_error!("save_archive: failed to read existing index.json: {}", e)
            })?;
            *index_bytes = Some(buf);
            continue;
        }
        // The marker is rewritten by the caller; directory entries are
        // recreated on extraction; non-blob entries are ignored.
        if rel == "oci-layout" || entry.header().entry_type().is_dir() || !rel.starts_with("blobs/")
        {
            continue;
        }
        if !written.insert(rel.clone()) {
            continue;
        }
        let size = entry
            .header()
            .size()
            .map_err(|e| crate::new_error!("save_archive: bad size in existing archive: {}", e))?;
        out.append(&rel, size, &mut entry)?;
    }
    Ok(())
}

/// Unpack the tar (or tar.gz) archive at `archive` into the directory
/// `dir`, which must already exist. `format` selects the decoder; pass
/// the format inferred from the path, or detected by [`detect_format`].
pub(crate) fn unpack_archive_to_dir(
    archive: &Path,
    dir: &Path,
    format: ArchiveFormat,
) -> crate::Result<()> {
    let file = File::open(archive)
        .map_err(|e| crate::new_error!("load_archive: failed to open {:?}: {}", archive, e))?;
    let reader = BufReader::new(file);

    // `Archive::unpack` rejects entries whose paths escape `dir`
    // (absolute paths or `..` traversal), so a hostile archive cannot
    // write outside the extraction directory.
    match format {
        ArchiveFormat::Tar => {
            let mut tar = Archive::new(reader);
            tar.unpack(dir)
                .map_err(|e| crate::new_error!("load_archive: failed to extract tar: {}", e))?;
        }
        ArchiveFormat::TarGz => {
            let mut tar = Archive::new(GzDecoder::new(reader));
            tar.unpack(dir)
                .map_err(|e| crate::new_error!("load_archive: failed to extract tar.gz: {}", e))?;
        }
    }

    Ok(())
}

/// Detect the archive format for `path`. Prefers the path extension;
/// when the extension is unknown, sniffs the first two bytes for the
/// gzip magic (`0x1f 0x8b`) and otherwise assumes an uncompressed tar.
pub(crate) fn detect_format(path: &Path) -> crate::Result<ArchiveFormat> {
    if let Some(fmt) = ArchiveFormat::from_path(path) {
        return Ok(fmt);
    }

    let mut magic = [0u8; 2];
    let n = {
        let mut f = File::open(path)
            .map_err(|e| crate::new_error!("load_archive: failed to open {:?}: {}", path, e))?;
        f.read(&mut magic)
            .map_err(|e| crate::new_error!("load_archive: failed to read {:?}: {}", path, e))?
    };

    if n == 2 && magic == [0x1f, 0x8b] {
        Ok(ArchiveFormat::TarGz)
    } else {
        Ok(ArchiveFormat::Tar)
    }
}
