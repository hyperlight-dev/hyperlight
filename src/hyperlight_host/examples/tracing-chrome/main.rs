// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.
use hyperlight_host::{Result, SandboxBuilder};
use hyperlight_testing::simple_guest_as_pathbuf;
use tracing_chrome::ChromeLayerBuilder;
use tracing_subscriber::prelude::*;

// This example can be run with `cargo run --package hyperlight_host --example tracing-chrome --release`
fn main() -> Result<()> {
    // set up tracer
    let (chrome_layer, _guard) = ChromeLayerBuilder::new().build();
    tracing_subscriber::registry().with(chrome_layer).init();

    let simple_guest_path = simple_guest_as_pathbuf();

    // Create a new sandbox.
    let mut sbox = SandboxBuilder::from_file(simple_guest_path).build()?;

    // do the function call
    let current_time = std::time::Instant::now();
    let res: String = sbox.call("Echo", "Hello, World!".to_string())?;
    let elapsed = current_time.elapsed();
    println!("Function call finished in {:?}.", elapsed);
    assert_eq!(res, "Hello, World!");
    Ok(())
}
