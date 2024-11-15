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

use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};
use rand::Rng;
use tracing::{span, Level};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
extern crate hyperlight_host;
use hyperlight_host::sandbox::uninitialized::UninitializedSandbox;
use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
use hyperlight_host::sandbox_state::transition::Noop;
use hyperlight_host::{GuestBinary, MultiUseSandbox, Result as HyperlightResult};
use hyperlight_testing::simple_guest_as_string;
use opentelemetry::{
    global::{self, shutdown_tracer_provider},
    trace::TracerProvider,
    KeyValue,
};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::{runtime::Tokio, trace, Resource};
use opentelemetry_semantic_conventions::{
    attribute::{SERVICE_NAME, SERVICE_VERSION},
    SCHEMA_URL,
};
use std::error::Error;
use std::io::stdin;
use std::sync::{Arc, Mutex};
use std::thread::{self, spawn, JoinHandle};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

const ADDR: &str = "http://localhost:4317";

fn fn_writer(_msg: String) -> HyperlightResult<i32> {
    Ok(0)
}

// Shows how to send tracing events to an OTLP collector using the opentelemetry crate.

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    init_tracing_subscriber(ADDR)?;

    Ok(run_example()?)
}

fn init_tracing_subscriber(addr: &str) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(addr)
        .build()?;

    let provider = trace::TracerProvider::builder()
        .with_config(
            trace::Config::default().with_resource(Resource::from_schema_url(
                vec![
                    KeyValue::new(SERVICE_NAME, "hyperlight_otel_example"),
                    KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
                ],
                SCHEMA_URL,
            )),
        )
        .with_batch_exporter(exporter, Tokio)
        .build();

    global::set_tracer_provider(provider.clone());
    let tracer = provider.tracer("trace-demo");

    let otel_layer = OpenTelemetryLayer::new(tracer);

    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(otel_layer)
        .try_init()?;

    Ok(())
}

fn run_example() -> HyperlightResult<()> {
    // Get the path to a simple guest binary.
    let hyperlight_guest_path =
        simple_guest_as_string().expect("Cannot find the guest binary at the expected location.");

    let mut join_handles: Vec<JoinHandle<HyperlightResult<()>>> = vec![];

    // Construct a new span named "hyperlight otel tracing example" with INFO  level.
    let span = span!(Level::INFO, "hyperlight otel tracing example",);
    let _entered = span.enter();

    let should_exit = Arc::new(Mutex::new(false));

    for i in 0..10 {
        let path = hyperlight_guest_path.clone();
        let exit = Arc::clone(&should_exit);
        let writer_func = Arc::new(Mutex::new(fn_writer));
        let handle = spawn(move || -> HyperlightResult<()> {
            while !*exit.try_lock().unwrap() {
                // Construct a new span named "hyperlight tracing example thread" with INFO  level.
                let id = Uuid::new_v4();
                let span = span!(
                    Level::INFO,
                    "hyperlight tracing example thread",
                    context = format!("Thread number {} GUID {}", i, id),
                    uuid = %id,
                );
                let _entered = span.enter();

                // Create a new sandbox.
                let usandbox = UninitializedSandbox::new(
                    GuestBinary::FilePath(path.clone()),
                    None,
                    None,
                    Some(&writer_func),
                )?;

                // Initialize the sandbox.

                let no_op = Noop::<UninitializedSandbox, MultiUseSandbox>::default();

                let mut multiuse_sandbox = usandbox.evolve(no_op)?;

                // Call a guest function 5 times to generate some log entries.
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

                // Call a guest function that calls the HostPrint host function 5 times to generate some log entries.
                for _ in 0..5 {
                    let result = multiuse_sandbox.call_guest_function_by_name(
                        "PrintOutput",
                        ReturnType::Int,
                        Some(vec![ParameterValue::String(msg.clone())]),
                    );
                    assert!(result.is_ok());
                }

                // Call a function that gets cancelled by the host function 5 times to generate some log entries.

                for i in 0..5 {
                    let id = Uuid::new_v4();
                    // Construct a new span named "hyperlight tracing call cancellation example thread" with INFO  level.
                    let span = span!(
                        Level::INFO,
                        "hyperlight tracing call cancellation example thread",
                        context = format!("Thread number {} GUID {}", i, id),
                        uuid = %id,
                    );
                    let _entered = span.enter();
                    let mut ctx = multiuse_sandbox.new_call_context();

                    let result = ctx.call("Spin", ReturnType::Void, None);
                    assert!(result.is_err());
                    let result = ctx.finish();
                    assert!(result.is_ok());
                    multiuse_sandbox = result.unwrap();
                }
                let sleep_for = {
                    let mut rng = rand::thread_rng();
                    rng.gen_range(500..3000)
                };
                thread::sleep(std::time::Duration::from_millis(sleep_for));
            }
            Ok(())
        });
        join_handles.push(handle);
    }

    println!("Press enter to exit...");
    let mut input = String::new();
    stdin().read_line(&mut input)?;
    *should_exit.try_lock().unwrap() = true;
    for join_handle in join_handles {
        let result = join_handle.join();
        assert!(result.is_ok());
    }
    shutdown_tracer_provider();

    Ok(())
}
