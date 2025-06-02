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
extern crate hyperlight_host;
use std::thread::{spawn, JoinHandle};

use hyperlight_host::sandbox::uninitialized::UninitializedSandbox;
use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
use hyperlight_host::sandbox_state::transition::Noop;
use hyperlight_host::{GuestBinary, MultiUseSandbox, Result};
use hyperlight_testing::simple_guest_as_string;

// Run this rust example with the flag --features "function_call_metrics" to enable more metrics to be emitted

fn main() {
    // Install prometheus metrics exporter.
    // We only install the metrics recorder here, but you can also use the
    // `metrics_exporter_prometheus::PrometheusBuilder::new().install()` method
    // to install a HTTP listener that serves the metrics.
    let prometheus_handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .expect("Failed to install Prometheus exporter");

    // Do some hyperlight stuff to generate metrics.
    do_hyperlight_stuff();

    // Get the metrics and print them in prometheus exposition format.
    let payload = prometheus_handle.render();
    println!("Prometheus metrics:\n{}", payload);
}

fn do_hyperlight_stuff() {
    // Get the path to a simple guest binary.
    let hyperlight_guest_path =
        simple_guest_as_string().expect("Cannot find the guest binary at the expected location.");

    let mut join_handles: Vec<JoinHandle<Result<()>>> = vec![];

    for _ in 0..20 {
        let path = hyperlight_guest_path.clone();
        let handle = spawn(move || -> Result<()> {
            // Create a new sandbox.
            let mut usandbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None)?;
            usandbox.register_print(fn_writer)?;

            // Initialize the sandbox.

            let no_op = Noop::<UninitializedSandbox, MultiUseSandbox>::default();

            let mut multiuse_sandbox = usandbox.evolve(no_op).expect("Failed to evolve sandbox");

            // Call a guest function 5 times to generate some metrics.
            for _ in 0..5 {
                multiuse_sandbox
                    .call_guest_function_by_name::<String>("Echo", "a".to_string())
                    .unwrap();
            }

            // Define a message to send to the guest.

            let msg = "Hello, World!!\n".to_string();

            // Call a guest function that calls the HostPrint host function 5 times to generate some metrics.
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
        UninitializedSandbox::new(GuestBinary::FilePath(hyperlight_guest_path.clone()), None)
            .expect("Failed to create UninitializedSandbox");

    // Initialize the sandbox.

    let no_op = Noop::<UninitializedSandbox, MultiUseSandbox>::default();

    let mut multiuse_sandbox = usandbox.evolve(no_op).expect("Failed to evolve sandbox");

    // Call a function that gets cancelled by the host function 5 times to generate some metrics.

    for _ in 0..5 {
        let mut ctx = multiuse_sandbox.new_call_context();

        ctx.call::<()>("Spin", ()).unwrap_err();
        multiuse_sandbox = ctx.finish().unwrap();
    }

    for join_handle in join_handles {
        let result = join_handle.join();
        assert!(result.is_ok());
    }
}

fn fn_writer(_msg: String) -> Result<i32> {
    Ok(0)
}
