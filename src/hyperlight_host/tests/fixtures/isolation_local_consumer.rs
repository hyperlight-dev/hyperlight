// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Local-only consumer for matched baseline, feature-disabled and enabled-unused builds.

use hyperlight_host::{Result, SandboxBuilder, new_error};

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let guest = args
        .next()
        .ok_or_else(|| new_error!("Usage: isolation_local_consumer GUEST"))?;
    if args.next().is_some() {
        return Err(new_error!("Unexpected trailing arguments"));
    }
    let mut sandbox = SandboxBuilder::from_file(guest)
        .host_function("HostAdd", |left: i32, right: i32| left + right)
        .build()?;
    let value = sandbox.call::<i32>("Add", (17, 25))?;
    if value != 42 {
        return Err(new_error!("HostAdd returned {value}, expected 42"));
    }
    println!("{value}");
    Ok(())
}
