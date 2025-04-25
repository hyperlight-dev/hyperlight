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

use hyperlight_host::func::{ParameterValue, ReturnType, ReturnValue};
use hyperlight_host::sandbox::uninitialized::UninitializedSandbox;
use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
use hyperlight_host::sandbox_state::transition::Noop;
use hyperlight_host::{GuestBinary, MultiUseSandbox, Result};
use hyperlight_testing::simple_guest_as_string;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::EnvFilter;

// An example of how to get tracy tracing working with hyperlight.
// Run with:
// TRACY_NO_EXIT=1 RUST_LOG=trace cargo run --package hyperlight-host --example tracing-tracy --profile release-with-debug,
// and then open the `tracy-profiler` GUI, and there should be an option to load the client created by this example.
fn main() -> Result<()> {
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry()
            .with(EnvFilter::from_default_env())
            .with(tracing_tracy::TracyLayer::default()),
    )
    .expect("setup tracy layer");

    let simple_guest_path =
        simple_guest_as_string().expect("Cannot find the guest binary at the expected location.");

    // Create a new sandbox.
    let usandbox =
        UninitializedSandbox::new(GuestBinary::FilePath(simple_guest_path), None, None, None)?;

    let mut sbox = usandbox
        .evolve(Noop::<UninitializedSandbox, MultiUseSandbox>::default())
        .unwrap();

    // do the function call
    let current_time = std::time::Instant::now();
    let res = sbox.call_guest_function_by_name(
        "Echo",
        ReturnType::String,
        Some(vec![ParameterValue::String("Hello, World!".to_string())]),
    )?;
    let elapsed = current_time.elapsed();
    println!("Function call finished in {:?}.", elapsed);
    assert!(matches!(res, ReturnValue::String(s) if s == "Hello, World!"));
    Ok(())
}
