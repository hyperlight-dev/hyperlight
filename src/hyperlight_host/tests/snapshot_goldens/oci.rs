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
