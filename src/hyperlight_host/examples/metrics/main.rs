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

extern crate hyperlight_host;
use std::sync::{Arc, Mutex};
use std::thread::{spawn, JoinHandle};

use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};
use hyperlight_host::sandbox::uninitialized::UninitializedSandbox;
use hyperlight_host::sandbox::Callable;
use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
use hyperlight_host::sandbox_state::transition::Noop;
use hyperlight_host::{set_metrics_registry, GuestBinary, MultiUseSandbox, Result};
use hyperlight_testing::simple_guest_as_string;
use lazy_static::lazy_static;
use prometheus::Registry;

lazy_static! {
    static ref HOST_REGISTRY: Registry = Registry::new();
}
fn fn_writer(_msg: String) -> Result<i32> {
    Ok(0)
}

fn main() -> Result<()> {
    // If this is not called then the default registry `prometheus::default_registry` will be used.
    set_metrics_registry(&HOST_REGISTRY)?;

    // Get the path to a simple guest binary.
    let hyperlight_guest_path =
        simple_guest_as_string().expect("Cannot find the guest binary at the expected location.");

    let mut join_handles: Vec<JoinHandle<Result<()>>> = vec![];

    for _ in 0..20 {
        let path = hyperlight_guest_path.clone();
        let writer_func = Arc::new(Mutex::new(fn_writer));
        let handle = spawn(move || -> Result<()> {
            // Create a new sandbox.
            let usandbox = UninitializedSandbox::new(
                GuestBinary::FilePath(path),
                None,
                None,
                Some(&writer_func),
            )?;

            // Initialize the sandbox.

            let no_op = Noop::<UninitializedSandbox, MultiUseSandbox>::default();

            let mut multiuse_sandbox = usandbox.evolve(no_op)?;

            // Call a guest function 5 times to generate some metrics.
            for _ in 0..5 {
                let result = multiuse_sandbox.call_guest_function_by_name(
                    "Echo",
                    ReturnType::String,
                    Some(vec![ParameterValue::String("a".to_string())]),
                );
                assert!(result.is_ok());
            }

            // Define a message to send to the guest.

            let msg = "Hello, World!!\n".to_string();

            // Call a guest function that calls the HostPrint host function 5 times to generate some metrics.
            for _ in 0..5 {
                let result = multiuse_sandbox.call_guest_function_by_name(
                    "PrintOutput",
                    ReturnType::Int,
                    Some(vec![ParameterValue::String(msg.clone())]),
                );
                assert!(result.is_ok());
            }
            Ok(())
        });

        join_handles.push(handle);
    }

    // Create a new sandbox.
    let usandbox = UninitializedSandbox::new(
        GuestBinary::FilePath(hyperlight_guest_path.clone()),
        None,
        None,
        None,
    )?;

    // Initialize the sandbox.

    let no_op = Noop::<UninitializedSandbox, MultiUseSandbox>::default();

    let mut multiuse_sandbox = usandbox.evolve(no_op)?;

    // Call a function that gets cancelled by the host function 5 times to generate some metrics.

    for _ in 0..5 {
        let mut ctx = multiuse_sandbox.new_call_context();

        let result = ctx.call("Spin", ReturnType::Void, None);
        assert!(result.is_err());
        let result = ctx.finish();
        assert!(result.is_ok());
        multiuse_sandbox = result.unwrap();
    }

    for join_handle in join_handles {
        let result = join_handle.join();
        assert!(result.is_ok());
    }

    get_metrics();

    Ok(())
}

fn get_metrics() {
    // Get the metrics from the registry.

    let metrics = HOST_REGISTRY.gather();

    // Print the metrics.

    print!("\nMETRICS:\n");

    for metric in metrics.iter() {
        match metric.get_field_type() {
            prometheus::proto::MetricType::COUNTER => {
                println!("Counter: {:?}", metric.get_help());
                metric.get_metric().iter().for_each(|metric| {
                    let pair = metric.get_label();
                    for pair in pair.iter() {
                        println!("Label: {:?} Name: {:?}", pair.get_name(), pair.get_value());
                    }
                    println!("Value: {:?}", metric.get_counter().get_value());
                });
            }
            prometheus::proto::MetricType::GAUGE => {
                println!("Gauge: {:?}", metric.get_help());
                metric.get_metric().iter().for_each(|metric| {
                    let pair = metric.get_label();
                    for pair in pair.iter() {
                        println!("Label: {:?} Name: {:?}", pair.get_name(), pair.get_value());
                    }
                    println!("Value: {:?}", metric.get_gauge().get_value());
                });
            }
            prometheus::proto::MetricType::UNTYPED => {
                println!("Metric: {:?}", metric.get_help());
            }
            prometheus::proto::MetricType::HISTOGRAM => {
                println!("Histogram: {:?}", metric.get_help());
                for metric in metric.get_metric() {
                    let pair = metric.get_label();
                    for pair in pair.iter() {
                        println!("Label: {:?} Name: {:?}", pair.get_name(), pair.get_value());
                    }
                    let count = metric.get_histogram().get_sample_count();
                    println!("Number of observations: {:?}", count);
                    let sm = metric.get_histogram().get_sample_sum();
                    println!("Sum of observations: {:?}", sm);
                    metric
                        .get_histogram()
                        .get_bucket()
                        .iter()
                        .for_each(|bucket| {
                            println!(
                                "Bucket: {:?} Count: {:?}",
                                bucket.get_upper_bound(),
                                bucket.get_cumulative_count()
                            )
                        });
                }
            }
            prometheus::proto::MetricType::SUMMARY => {
                println!("Summary: {:?}", metric.get_help());
            }
        }
    }
}
