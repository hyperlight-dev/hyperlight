<<<<<<< Updated upstream
=======
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
>>>>>>> Stashed changes
// Test that map_file_cow works end-to-end: UninitializedSandbox::new →
// map_file_cow → evolve → guest function call. Exercises the cross-process
// section mapping via MapViewOfFileNuma2 on Windows (the surrogate process
// must be able to map the file-backed section).
//
// Before the NULL DACL fix, this fails on Windows with:
//   HyperlightVmError(MapRegion(MapMemory(SurrogateProcess(
//     "MapViewOfFileNuma2 failed: ... Access is denied."))))
//
// Run:
//   cargo run --release --example map-file-cow-test

#![allow(clippy::disallowed_macros)]
use hyperlight_host::sandbox::SandboxConfiguration;
use hyperlight_host::{MultiUseSandbox, UninitializedSandbox};
use std::path::Path;

fn main() -> hyperlight_host::Result<()> {
    let mut config = SandboxConfiguration::default();
    config.set_heap_size(4 * 1024 * 1024);
    config.set_scratch_size(64 * 1024 * 1024);

    // Create a test file to map (simulating an initrd).
    let test_file = std::env::temp_dir().join("hl_map_file_cow_test.bin");
    std::fs::write(&test_file, vec![0xABu8; 8192]).unwrap();

    let mut usbox = UninitializedSandbox::new(
        hyperlight_host::GuestBinary::FilePath(
            hyperlight_testing::simple_guest_as_string().unwrap(),
        ),
        Some(config),
    )?;
    eprintln!("[test] UninitializedSandbox::new OK");

    usbox.map_file_cow(Path::new(&test_file), 0xC000_0000, Some("test"))?;
    eprintln!("[test] map_file_cow OK");

    let mut mu: MultiUseSandbox = usbox.evolve()?;
    eprintln!("[test] evolve OK");

    let result: String = mu.call("Echo", "map_file_cow works!".to_string())?;
    eprintln!("[test] guest returned: {result}");

    let _ = std::fs::remove_file(&test_file);
    Ok(())
}
