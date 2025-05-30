/*
Copyright 2024 The Hyperlight Authors.

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

use std::fs;
use std::path::PathBuf;

use hyperlight_testing::rust_guest_as_pathbuf;

use crate::mem::exe::ExeInfo;
use crate::{new_error, Result};
pub(crate) mod log_values;

/// Get an `ExeInfo` representing `simpleguest.exe`
pub(crate) fn simple_guest_exe_info() -> Result<ExeInfo> {
    let bytes = bytes_for_path(rust_guest_as_pathbuf("simpleguest"))?;
    ExeInfo::from_buf(bytes.as_slice())
}

/// Read the file at `path_buf` into a `Vec<u8>` and return it,
/// or return `Err` if that went wrong
pub(crate) fn bytes_for_path(path_buf: PathBuf) -> Result<Vec<u8>> {
    let guest_path = path_buf
        .as_path()
        .to_str()
        .ok_or_else(|| new_error!("couldn't convert guest {:?} to a path", path_buf))?;
    let guest_bytes = fs::read(guest_path)
        .map_err(|e| new_error!("failed to open guest at path {} ({})", guest_path, e))?;
    Ok(guest_bytes)
}
