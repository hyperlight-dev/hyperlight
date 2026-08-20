// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.
use std::thread;

use hyperlight_host::{MultiUseSandbox, UninitializedSandbox};

fn main() -> hyperlight_host::Result<()> {
    // Create an uninitialized sandbox with a guest binary
    let mut uninitialized_sandbox = UninitializedSandbox::new(
        hyperlight_host::GuestBinary::FilePath(hyperlight_testing::simple_guest_as_pathbuf()),
        None, // default configuration
    )?;

    // Register a host functions
    uninitialized_sandbox.register("Sleep5Secs", || {
        thread::sleep(std::time::Duration::from_secs(5));
        Ok(())
    })?;
    // Note: This function is unused, it's just here for demonstration purposes

    // Initialize sandbox to be able to call host functions
    let mut multi_use_sandbox: MultiUseSandbox = uninitialized_sandbox.evolve()?;

    // Call guest function
    let message = "Hello, World! I am executing inside of a VM :)\n".to_string();
    multi_use_sandbox
        .call::<i32>(
            "PrintOutput", // function must be defined in the guest binary
            message,
        )
        .unwrap();

    Ok(())
}
