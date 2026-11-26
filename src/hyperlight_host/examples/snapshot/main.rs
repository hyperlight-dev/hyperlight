// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Run from the repository root after building the test guests:
//!
//! ```sh
//! just guests
//! cargo run -p hyperlight-host --example snapshot
//! ```

use std::sync::Arc;

use anyhow::ensure;
use hyperlight_host::SandboxBuilder;
use hyperlight_host::sandbox::snapshot::{OciTag, Snapshot};

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let layout = tempfile::tempdir()?;
    let tag = OciTag::new("v1")?;
    let mut sandbox = SandboxBuilder::from_file(hyperlight_testing::simple_guest_as_pathbuf())
        .host_function("HostEchoI32", |value: i32| Ok(value))
        .build()?;
    let value: i32 = sandbox.call("AddToStatic", 42i32)?;
    ensure!(value == 42, "expected counter 42, got {value}");

    let snapshot = sandbox.snapshot()?;
    let value: i32 = sandbox.call("AddToStatic", 1i32)?;
    ensure!(value == 43, "expected counter 43, got {value}");

    let digest = snapshot.save(layout.path(), &tag)?;
    println!("Saved counter 42 as {tag} ({digest}). Live counter is {value}.");
    drop(sandbox);
    drop(snapshot);

    let snapshot = Arc::new(Snapshot::checked_load(layout.path(), tag)?);
    let mut sandbox = SandboxBuilder::from_snapshot(snapshot)
        .host_function("HostEchoI32", |value: i32| Ok(value))
        .build()?;
    let value: i32 = sandbox.call("GetStatic", ())?;
    ensure!(value == 42, "expected restored counter 42, got {value}");

    let echoed: i32 = sandbox.call("RoundTripHostI32", value)?;
    ensure!(echoed == value, "expected host echo {value}, got {echoed}");
    println!("Restored counter {value}. Host echo returned {echoed}.");

    Ok(())
}
