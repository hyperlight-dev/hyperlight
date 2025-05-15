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
use tracing::{span, Level};
extern crate hyperlight_host;
use std::thread::{spawn, JoinHandle};

use hyperlight_host::sandbox::uninitialized::UninitializedSandbox;
use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
use hyperlight_host::sandbox_state::transition::Noop;
use hyperlight_host::{GuestBinary, MultiUseSandbox, Result};
use hyperlight_testing::simple_guest_as_string;
use tracing_forest::ForestLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, Registry};
use uuid::Uuid;

fn fn_writer(_msg: String) -> Result<i32> {
    Ok(0)
}

// Shows how to consume trace events from Hyperlight using the tracing-subscriber crate.
// and also how to consume logs as trace events.

fn main() -> Result<()> {
    // Set up the tracing subscriber.
    // tracing_forest uses the tracing subscriber, which, by default, will consume logs as trace events
    // unless the tracing-log feature is disabled.
    let layer = ForestLayer::default()
        .with_filter(EnvFilter::builder().parse("none,hyperlight=info").unwrap());
    Registry::default().with(layer).init();
    run_example()
}
fn run_example() -> Result<()> {
    // Get the path to a simple guest binary.
    let hyperlight_guest_path =
        simple_guest_as_string().expect("Cannot find the guest binary at the expected location.");

    let mut join_handles: Vec<JoinHandle<Result<()>>> = vec![];

    // Construct a new span named "hyperlight tracing example" with INFO  level.
    let span = span!(Level::INFO, "hyperlight tracing example");
    let _entered = span.enter();

    for i in 0..10 {
        let path = hyperlight_guest_path.clone();
        let handle = spawn(move || -> Result<()> {
            // Construct a new span named "hyperlight tracing example thread" with INFO  level.
            let id = Uuid::new_v4();
            let span = span!(
                Level::INFO,
                "hyperlight tracing example thread",
                context = format!("Thread number {}", i),
                uuid = %id,
            );
            let _entered = span.enter();

            // Create a new sandbox.
            let mut usandbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None)?;
            usandbox.register_print(fn_writer)?;

            // Initialize the sandbox.

            let no_op = Noop::<UninitializedSandbox, MultiUseSandbox>::default();

            let mut multiuse_sandbox = usandbox.evolve(no_op)?;

            // Call a guest function 5 times to generate some log entries.
            for _ in 0..5 {
                multiuse_sandbox
                    .call_guest_function_by_name::<String>("Echo", "a".to_string())
                    .unwrap();
            }

            // Define a message to send to the guest.

            let msg = "Hello, World!!\n".to_string();

            // Call a guest function that calls the HostPrint host function 5 times to generate some log entries.
            for _ in 0..5 {
                multiuse_sandbox
                    .call_guest_function_by_name::<i32>("PrintOutput", msg.clone())
                    .unwrap();
            }
            Ok(())
        });
        join_handles.push(handle);
    }

    // Create a new sandbox.
    let usandbox =
        UninitializedSandbox::new(GuestBinary::FilePath(hyperlight_guest_path.clone()), None)?;

    // Initialize the sandbox.

    let no_op = Noop::<UninitializedSandbox, MultiUseSandbox>::default();

    let mut multiuse_sandbox = usandbox.evolve(no_op)?;

    // Call a function that gets cancelled by the host function 5 times to generate some log entries.

    for i in 0..5 {
        let id = Uuid::new_v4();
        // Construct a new span named "hyperlight tracing call cancellation example thread" with INFO  level.
        let span = span!(
            Level::INFO,
            "hyperlight tracing call cancellation example thread",
            context = format!("Thread number {}", i),
            uuid = %id,
        );
        let _entered = span.enter();
        let mut ctx = multiuse_sandbox.new_call_context();

        ctx.call::<()>("Spin", ()).unwrap_err();
        multiuse_sandbox = ctx.finish().unwrap();
    }

    for join_handle in join_handles {
        let result = join_handle.join();
        assert!(result.is_ok());
    }

    Ok(())
}
