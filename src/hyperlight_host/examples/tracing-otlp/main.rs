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
//use opentelemetry_sdk::resource::ResourceBuilder;
use opentelemetry_sdk::trace::SdkTracerProvider;
use rand::Rng;
use tracing::{span, Level};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
extern crate hyperlight_host;
use std::error::Error;
use std::io::stdin;
use std::sync::{Arc, Mutex};
use std::thread::{self, spawn, JoinHandle};

use hyperlight_host::sandbox::uninitialized::UninitializedSandbox;
use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
use hyperlight_host::sandbox_state::transition::Noop;
use hyperlight_host::{GuestBinary, MultiUseSandbox, Result as HyperlightResult};
use hyperlight_testing::simple_guest_as_string;
use opentelemetry::trace::TracerProvider;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
//use opentelemetry_sdk::runtime::Tokio;
use opentelemetry_sdk::Resource;
use opentelemetry_semantic_conventions::attribute::SERVICE_VERSION;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

const ENDPOINT_ADDR: &str = "http://localhost:4317";

fn fn_writer(_msg: String) -> HyperlightResult<i32> {
    Ok(0)
}

// Shows how to send tracing events to an OTLP collector using the opentelemetry crate.

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let provider = init_tracing_subscriber(ENDPOINT_ADDR)?;

    run_example(true)?;

    provider.shutdown()?;

    Ok(())
}

fn init_tracing_subscriber(
    addr: &str,
) -> Result<SdkTracerProvider, Box<dyn Error + Send + Sync + 'static>> {
    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(addr)
        .build()?;

    let version = KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION"));
    let resource = Resource::builder()
        .with_service_name("hyperlight_otel_example")
        .with_attribute(version)
        .build();

    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build();

    global::set_tracer_provider(provider.clone());
    let tracer = provider.tracer("trace-demo");

    let otel_layer = OpenTelemetryLayer::new(tracer);

    // Try using the environment otherwise set default filters
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::from_default_env()
            .add_directive("hyperlight_host=info".parse().unwrap())
            .add_directive("tracing=info".parse().unwrap())
    });

    tracing_subscriber::registry()
        .with(filter)
        .with(otel_layer)
        .try_init()?;

    Ok(provider)
}

fn run_example(wait_input: bool) -> HyperlightResult<()> {
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
                    let mut rng = rand::rng();
                    rng.random_range(500..3000)
                };
                thread::sleep(std::time::Duration::from_millis(sleep_for));
            }
            Ok(())
        });
        join_handles.push(handle);
    }

    if wait_input {
        println!("Press enter to exit...");
        let mut input = String::new();
        stdin().read_line(&mut input)?;
    }

    *should_exit.try_lock().unwrap() = true;
    for join_handle in join_handles {
        let result = join_handle.join();
        assert!(result.is_ok());
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use hyperlight_host::{HyperlightError, Result};
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    const TESTER_ADDR: &str = "127.0.0.1:4317";

    async fn handle(mut stream: TcpStream) -> Result<()> {
        let mut buf = Vec::with_capacity(128);
        let size = stream.read_buf(&mut buf).await?;

        if size > 0 {
            Ok(())
        } else {
            Err(HyperlightError::Error("Cannot read req body".to_string()))
        }
    }

    async fn check_otl_connection(addr: &str) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;

        let (stream, _) = listener.accept().await?;

        handle(stream).await
    }

    #[tokio::test]
    async fn test_subscriber() {
        // Create task that generates spans
        let task = tokio::spawn(async move {
            let _ = init_tracing_subscriber(ENDPOINT_ADDR);

            // No need to wait for input, just generate some spans and exit
            let _ = run_example(false);
        });

        // Create server that listens and checks to see if traces are received
        let result = check_otl_connection(TESTER_ADDR).await;

        // Abort task in case it doesn't finish
        task.abort();

        assert!(result.is_ok());
    }
}
