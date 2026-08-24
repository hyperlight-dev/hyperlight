// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.
// Test that mapping a file copy-on-write works end-to-end: build a sandbox with
// a mapped file, then call a guest function. Exercises the cross-process
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

use std::path::Path;

use hyperlight_host::SandboxBuilder;

fn run_once(test_file: &Path, label: &str) -> hyperlight_host::Result<()> {
    let mut sandbox = SandboxBuilder::from_file(hyperlight_testing::simple_guest_as_pathbuf())
        .heap_size(4 * 1024 * 1024)
        .scratch_size(64 * 1024 * 1024)
        .mapped_file_cow(test_file, 0xC000_0000)
        .build()?;
    eprintln!(
        "[{label}] sandbox built with a {} byte file mapped",
        std::fs::metadata(test_file)?.len()
    );

    let result: String = sandbox.call("Echo", format!("{label}: mapped_file_cow works!"))?;
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
