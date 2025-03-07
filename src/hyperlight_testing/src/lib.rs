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

// This crate contains testing utilities which need to be shared across multiple
// crates in this project.
use std::env;
use std::path::PathBuf;

use anyhow::{anyhow, Result};

pub const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");
pub mod logger;
pub mod simplelogger;
pub mod tracing_subscriber;

/// Join all the `&str`s in the `v` parameter as a path with appropriate
/// path separators, then prefix it with `start`, again with the appropriate
/// path separator
fn join_to_path(start: &str, v: Vec<&str>) -> PathBuf {
    let fold_start: PathBuf = {
        let mut pb = PathBuf::new();
        pb.push(start);
        pb
    };
    let fold_closure = |mut agg: PathBuf, cur: &&str| {
        agg.push(cur);
        agg
    };
    v.iter().fold(fold_start, fold_closure)
}

/// Get a new `PathBuf` to a specified Rust guest
/// $REPO_ROOT/src/tests/rust_guests/bin/${profile}/net6.0
pub fn rust_guest_as_pathbuf(guest: &str) -> PathBuf {
    let build_dir_selector = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };

    join_to_path(
        MANIFEST_DIR,
        vec![
            "..",
            "tests",
            "rust_guests",
            "bin",
            build_dir_selector,
            guest,
        ],
    )
}

/// Get a fully qualified OS-specific path to the simpleguest elf binary
pub fn simple_guest_as_string() -> Result<String> {
    let buf = rust_guest_as_pathbuf("simpleguest");
    buf.to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("couldn't convert simple guest PathBuf to string"))
}

/// Get a fully qualified OS-specific path to the simpleguest.exe PE binary
pub fn simple_guest_exe_as_string() -> Result<String> {
    let buf = rust_guest_as_pathbuf("simpleguest.exe");
    buf.to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("couldn't convert simple guest PathBuf to string"))
}

/// Get a fully qualified OS-specific path to the callbackguest elf binary
pub fn callback_guest_as_string() -> Result<String> {
    let buf = rust_guest_as_pathbuf("callbackguest");
    buf.to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("couldn't convert callback guest PathBuf to string"))
}

/// Get a fully qualified OS-specific path to the callbackguest.exe PE binary
pub fn callback_guest_exe_as_string() -> Result<String> {
    let buf = rust_guest_as_pathbuf("callbackguest.exe");
    buf.to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("couldn't convert callback guest PathBuf to string"))
}

/// Get a fully qualified OS-specific path to the dummyguest elf binary
pub fn dummy_guest_as_string() -> Result<String> {
    let buf = rust_guest_as_pathbuf("dummyguest");
    buf.to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("couldn't convert dummy guest PathBuf to string"))
}

pub fn c_guest_as_pathbuf(guest: &str) -> PathBuf {
    let build_dir_selector = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };

    join_to_path(
        MANIFEST_DIR,
        vec!["..", "tests", "c_guests", "bin", build_dir_selector, guest],
    )
}

pub fn c_simple_guest_as_string() -> Result<String> {
    let buf = c_guest_as_pathbuf("simpleguest");
    buf.to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("couldn't convert simple guest PathBuf to string"))
}

pub fn c_callback_guest_as_string() -> Result<String> {
    let buf = c_guest_as_pathbuf("callbackguest");
    buf.to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("couldn't convert callback guest PathBuf to string"))
}

/// Get a fully qualified path to a simple guest binary preferring a binary
/// in the same directory as the parent executable. This will be used in
/// fuzzing scenarios where pre-built binaries will be built and submitted to
/// a fuzzing framework.
pub fn simple_guest_for_fuzzing_as_string() -> Result<String> {
    let exe_dir = env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|p| p.to_path_buf()));

    if let Some(exe_dir) = exe_dir {
        let guest_path = exe_dir.join("simpleguest");

        if guest_path.exists() {
            return Ok(guest_path
                .to_str()
                .ok_or(anyhow!("Invalid path string"))?
                .to_string());
        }
    }

    simple_guest_as_string()
}
