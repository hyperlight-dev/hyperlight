// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use std::path::PathBuf;

pub(crate) fn goldens_root() -> PathBuf {
    // Workspace target dir is two levels up from this crate.
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let raw = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("..")
                .join("target");
            std::fs::canonicalize(&raw).unwrap_or(raw)
        });
    target.join("snapshot-goldens")
}

fn goldens_dir_for(tag: &str) -> PathBuf {
    goldens_root().join(tag)
}

/// Locate the golden OCI Image Layout for `tag` in the local
/// directory. A missing layout is an error with guidance to populate
/// it.
pub(crate) fn golden_dir(tag: &str) -> Result<PathBuf, String> {
    let dir = goldens_dir_for(tag);
    if dir.join("oci-layout").is_file() {
        return Ok(dir);
    }
    Err(format!(
        "no golden OCI layout found at {dir:?} for tag `{tag}`. \
         Run `just snapshot-goldens-pull` to fetch the published goldens, \
         or `just snapshot-goldens-generate` to regenerate them locally.",
    ))
}
