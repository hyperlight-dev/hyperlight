// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.
use std::thread;

use hyperlight_host::SandboxBuilder;

fn main() -> hyperlight_host::Result<()> {
    // Build a sandbox running a guest binary, with a host function registered.
    // Note: the host function is unused, it's just here for demonstration purposes
    let mut sandbox = SandboxBuilder::from_file(hyperlight_testing::simple_guest_as_pathbuf())
        .host_function("Sleep5Secs", || {
            thread::sleep(std::time::Duration::from_secs(5));
            Ok(())
        })
        .build()?;

    // Call guest function
    let message = "Hello, World! I am executing inside of a VM :)\n".to_string();
    sandbox
        .call::<i32>(
            "PrintOutput", // function must be defined in the guest binary
            message,
        )
        .unwrap();

    Ok(())
}
