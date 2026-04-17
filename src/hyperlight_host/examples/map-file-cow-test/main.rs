/*
Copyright 2025  The Hyperlight Authors.

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
// Test that map_file_cow works end-to-end: UninitializedSandbox::new →
// map_file_cow → evolve → guest function call. Exercises the cross-process
// section mapping via MapViewOfFileNuma2 on Windows (the surrogate process
// must be able to map the file-backed section).
//
// Covers both a page-aligned file and an intentionally unaligned file.
// Before fix: the unaligned case fails on Windows with
//   HyperlightVmError(MapRegion(MapMemory(SurrogateProcess(
//     "MapViewOfFileNuma2 failed: ... Access is denied."))))
// because the file-backed section has max_size == file_size (< the
// page-aligned host_size the surrogate requests).
//
// Run:
//   cargo run --release --example map-file-cow-test

#![allow(clippy::disallowed_macros)]
use std::path::Path;

use hyperlight_host::sandbox::SandboxConfiguration;
use hyperlight_host::{MultiUseSandbox, UninitializedSandbox};

fn run_once(test_file: &Path, label: &str) -> hyperlight_host::Result<()> {
    let mut config = SandboxConfiguration::default();
    config.set_heap_size(4 * 1024 * 1024);
    config.set_scratch_size(64 * 1024 * 1024);

    let mut usbox = UninitializedSandbox::new(
        hyperlight_host::GuestBinary::FilePath(
            hyperlight_testing::simple_guest_as_string().unwrap(),
        ),
        Some(config),
    )?;
    eprintln!("[{label}] UninitializedSandbox::new OK");

    usbox.map_file_cow(test_file, 0xC000_0000, Some(label))?;
    eprintln!(
        "[{label}] map_file_cow OK ({} bytes)",
        std::fs::metadata(test_file)?.len()
    );

    let mut mu: MultiUseSandbox = usbox.evolve()?;
    eprintln!("[{label}] evolve OK");

    let result: String = mu.call("Echo", format!("{label}: map_file_cow works!"))?;
    eprintln!("[{label}] guest returned: {result}");
    Ok(())
}

fn main() -> hyperlight_host::Result<()> {
    let aligned = std::env::temp_dir().join("hl_map_file_cow_aligned.bin");
    let unaligned = std::env::temp_dir().join("hl_map_file_cow_unaligned.bin");

    // 2 full pages.
    std::fs::write(&aligned, vec![0xABu8; 8192]).unwrap();
    // Deliberately unaligned: not a multiple of 4 KiB. Must succeed
    // (Windows: requires the surrogate to map "to end of section" rather
    // than the caller's page-aligned host_size).
    std::fs::write(&unaligned, vec![0xCDu8; 8193]).unwrap();

    run_once(&aligned, "aligned")?;
    run_once(&unaligned, "unaligned")?;

    let _ = std::fs::remove_file(&aligned);
    let _ = std::fs::remove_file(&unaligned);
    Ok(())
}
