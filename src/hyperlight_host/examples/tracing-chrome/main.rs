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
#![allow(clippy::disallowed_macros)]
use hyperlight_host::sandbox::uninitialized::UninitializedSandbox;
use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
use hyperlight_host::sandbox_state::transition::Noop;
use hyperlight_host::{GuestBinary, MultiUseSandbox, Result};
use hyperlight_testing::simple_guest_as_string;
use tracing_chrome::ChromeLayerBuilder;
use tracing_subscriber::prelude::*;

// This example can be run with `cargo run --package hyperlight_host --example tracing-chrome --release`
fn main() -> Result<()> {
    // set up tracer
    let (chrome_layer, _guard) = ChromeLayerBuilder::new().build();
    tracing_subscriber::registry().with(chrome_layer).init();

    let simple_guest_path =
        simple_guest_as_string().expect("Cannot find the guest binary at the expected location.");

    // Create a new sandbox.
    let usandbox = UninitializedSandbox::new(GuestBinary::FilePath(simple_guest_path), None)?;

    let mut sbox = usandbox
        .evolve(Noop::<UninitializedSandbox, MultiUseSandbox>::default())
        .unwrap();

    // do the function call
    let current_time = std::time::Instant::now();
    let res: String = sbox.call_guest_function_by_name("Echo", "Hello, World!".to_string())?;
    let elapsed = current_time.elapsed();
    println!("Function call finished in {:?}.", elapsed);
    assert_eq!(res, "Hello, World!");
    Ok(())
}
