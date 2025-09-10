# Observability

Hyperlight provides the following observability features:

* [Metrics](#metrics) are provided using the [metrics](https://docs.rs/metrics/latest/metrics/index.html) crate, which is a lightweight metrics facade.
* [Logs](#logs) are provided using the Rust [log crate](https://docs.rs/log/0.4.6/log/), and can be consumed by any Rust logger implementation, including LogTracer which can be used to emit log records as tracing events.
* [Tracing](#tracing) is provided using the Rust [tracing crate](https://docs.rs/tracing/0.1.37/tracing/), and can be consumed by any Rust tracing implementation. In addition, the [log feature](https://docs.rs/tracing/latest/tracing/#crate-feature-flags) is enabled which means that should a hyperlight host application not want to consume tracing events, you can still consume them as logs.

## Metrics

Metrics are provided using the [metrics](https://docs.rs/metrics/latest/metrics/index.html) crate, which is a lightweight metrics facade. When an executable installs a [recorder](https://docs.rs/metrics/latest/metrics/trait.Recorder.html), Hyperlight will emit its metrics to that recorder, which allows library authors to seamless emit their own metrics without knowing or caring which exporter implementation is chosen, or even if one is installed. In case where no recorder is installed, the metrics will be emitted to the default recorder, which is a no-op implementation with minimal overhead.

There are many different implementations of recorders. One example is the [prometheus exporter](https://docs.rs/metrics-exporter-prometheus/latest/metrics_exporter_prometheus/) which can be used to export metrics to a Prometheus server. An example of how to use this is provided in the [examples/metrics](../src/hyperlight_host/examples/metrics) directory.

The following metrics are provided and are enabled by default:

* `guest_errors_total` - Counter that tracks the number of guest errors by error code.
* `guest_cancellations_total` - Counter that tracks the number of guest executions that have been cancelled because the execution time exceeded the time allowed.

The following metrics are provided but are disabled by default:

* `guest_call_duration_seconds` - Histogram that tracks the execution time of guest functions in seconds by function name. The histogram also tracks the number of calls to each function.
* `host_call_duration_seconds` - Histogram that tracks the execution time of host functions in seconds by function name. The histogram also tracks the number of calls to each function.

The rationale for disabling the function call metrics by default is that:
* A Hyperlight host may wish to provide its own metrics for function calls.
* Enabling a trace subscriber will cause the function call metrics to be emitted as trace events, which may be sufficient for some use cases.
* These 2 metrics require string clones for the function names, which may be too expensive for some use cases.
We might consider enabling these metrics by default in the future.

## Logs

Hyperlight provides logs using the Rust [log crate](https://docs.rs/log/0.4.6/log/), and can be consumed by any Rust logger implementation, including LogTracer which can be used to emit log records as tracing events(see below for more details). To consume logs, the host application must provide a logger implementation either by using the `set_logger` function directly or using a logger implementation that is compatible with the log crate.

For an example that uses the `env_logger` crate, see the [examples/logging](../src/hyperlight_host/examples/logging) directory. By default, the `env_logger` crate will only log messages at the `error` level or higher. To see all log messages, set the `RUST_LOG` environment variable to `debug`.

Hyperlight also provides tracing capabilities (see below for more details), if no trace subscriber is registered, trace records will be emitted as log records, using the `log` feature of the [tracing crate](https://docs.rs/tracing/latest/tracing/#crate-feature-flags).

## Tracing

Tracing spans are created for any call to a public API and the parent span will be set to the current span in the host if one exists, the level of the span is set to `info`. The span will be closed when the call returns. Any Result that contains an error variant will be logged as an error event. In addition to the public APIs, all internal functions are instrumented with trace spans at the `trace` level, therefore in order to see full trace information, the trace level should be enabled.

Hyperlight provides tracing using the Rust [tracing crate](https://docs.rs/tracing/0.1.37/tracing/), and can be consumed by any Rust trace subscriber implementation(see[here](https://docs.rs/tracing/latest/tracing/index.html#related-crates) for some examples). In addition to consuming trace output the log records may also be consumed by a tracing subscriber, using the `tracing-log` crate.

There are two examples that show how to consume both tracing events and log records as tracing events.

### Using tracing_forest

In the [examples/tracing](../src/hyperlight_host/examples/tracing) directory, there is an example that shows how to capture and output trace and log information using the tracing_forest crate. With this example the following commands can be used to set the verbosity of the trace output to `INFO` and run the example:

#### Linux

```bash
RUST_LOG='none,hyperlight_host=info,tracing=info' cargo run --example tracing
```

#### Windows

```powershell
$env:RUST_LOG='none,hyperlight_host=info,tracing=info'; cargo run --example tracing
```

### Using OTLP exporter and Jaeger

In the [examples/tracing-otlp](../src/hyperlight_host/examples/tracing-otlp) directory, there is an example that shows how to capture and send trace and log information to an otlp_collector using the opentelemetry_otlp crate. With this example the following commands can be used to set the verbosity of the trace output to `INFO` and run the example to generate trace data:

#### Linux

```bash
RUST_LOG='none,hyperlight_host=info,tracing=info' cargo run --example tracing-otlp
```

#### Windows

```powershell
$env:RUST_LOG='none,hyperlight_host=info,tracing=info';cargo run --example tracing-otlp
```

The sample will run and generate trace data until any key is pressed.

To view the trace data, leave the example running and use the jaegertracing/all-in-one container image with the following command:

```console
 docker run -p 16686:16686 -p 4317:4317 -p 4318:4318 -e COLLECTOR_OTLP_ENABLED=true jaegertracing/all-in-one:latest
```

NOTE: when running this on windows that this is a linux container, so you will need to ensure that docker is configured to run linux containers using WSL2. Alternatively, you can download the Jaeger binaries from [here](https://www.jaegertracing.io/download/). Extract the archive and run the `jaeger-all-in-one` executable as follows:

```powershell
.\jaeger-all-in-one.exe
```

Once the container or the exe is running, the trace output can be viewed in the jaeger UI at [http://localhost:16686/search](http://localhost:16686/search).

## Guest Tracing, Unwinding, and Memory Profiling

Hyperlight provides advanced observability features for guest code running inside micro virtual machines. You can enable guest-side tracing, stack unwinding, and memory profiling using the `trace_guest` and `mem_profile` features. This section explains how to build, run, and inspect guest traces.

The following features are available for guest tracing:
- `trace_guest`: Enables tracing for guest code, capturing function calls and execution time.
- `mem_profile`: Enables memory profiling for guest code with stack unwinding, capturing memory allocations and usage.

### Building a Guest with Tracing Support

To build a guest with tracing enabled, use the following commands:

```bash
just build-rust-guests debug trace_guest
just move-rust-guests debug
```

This builds the guest binaries with the `trace_guest` feature enabled and move them to the appropriate location for use by the host.

**NOTE**: To enable the tracing in your application you need to use the `trace_guest` feature on the `hyperlight-guest-bin` and `hyperlight-guest` crates.

### Running a Hyperlight Example with Guest Tracing

Once the guest is built, you can run a Hyperlight example with guest tracing enabled. For example:

```bash
RUST_LOG="info,hyperlight_host::sandbox=info,hyperlight_guest=trace,hyperlight_guest_bin=trace" cargo run --example tracing-otlp --features trace_guest
```

This will execute the `tracing-otlp` example, loading the guest with tracing enabled.
During execution, trace data will be collected on the host and exported as `opentelemetry` spans/events.

You can set up a collector to gather all the traces and inspect the traces from both host and guests.

Due to the nature of execution inside a Sandbox, on a call basis, the guest tracing sets up a stack of spans to keep track of the correct parents for the incoming
guest spans.
We start with `call-to-guest` which contains all the spans coming from a guest. Additionally, for each exit into the host, we add another layer marking it with
a `call-to-host` span to follow the execution in the host and correctly set it as a child of the active span in the guest.
This logic simulates the propagation of `Opentelemetry` context that is usually done between two services, but cannot be done here seamlessly because the guest side
runs `no_std` which `opentelemetry` doesn't know.

#### How it works

##### Guest

When the guest starts executing the `entrypoint` function, it receives a `max_log_level` parameter that tells the guest what kind of logging level is expected from it.

The `trace_guest` logic takes advantage of this parameter and when the `max_log_level` is `trace`, it allocates a custom made `GuestSubscriber` that implements the `Subscriber`
trait from `tracing_core` that allows defining a subscriber for the `tracing` crate to handle new spans and events.

This custom subscriber stores the spans and events in a buffer initialized only when tracing is enabled. For each new span and event, a method is called on the custom subscriber which not only stores the data, but also keeps track of the hierarchy and dependencies between the other spans/events.
**NOTE**: The spans/events attributes are truncated to fit in the allocated buffer.

When the storage space is filled, the guest triggers a VM Exit that sends the guest pointers to the host. The host can access the guest memory, get the data and parse it to create the `spans` and `events` using the `opentelemetry` crate which allows specifying the starting and ending timestamps
which are captured in the guest using the `TSC`.

To improve performance, for each VMExit, the guest adds metadata for the host to be able to report the tracing data and free space.

##### Host

When a guest exits, the host checks for metadata from the guest reporting tracing data.
If tracing data is found, the host starts parsing it and reconstructing a tree which represents the spans hierarchy.

Additionally, the host also adds new children `span`s to the guest's reported active span, emphasizing the spans created on the host as a result of a temporary VM Exit. This helps visualize a call into the guest with context propagated across the VM boundary.

The host creates `opentelemetry` spans and events for each guest span and event reported.

### Inspecting Guest memory Trace Files (for mem_profile)

To inspect the trace file generated by the guest, use the `trace_dump` crate. You will need the path to the guest symbols and the trace file. Run the following command:

```bash
cargo run -p trace_dump <path_to_guest_symbols> <trace_file_path> list_frames
```

Replace `<path_to_guest_symbols>` with the path to the guest binary or symbol file, and `<trace_file_path>` with the path to the trace file in the `trace` directory.

This command will list the stack frames and tracing information captured during guest execution, allowing you to analyze guest behavior, stack traces, and memory usage.

#### Example

```bash
cargo run -p trace_dump ./src/tests/rust_guests/bin/debug/simpleguest ./trace/<UUID>.trace list_frames
```

You can use the `mem_profile` additional feature by enabling them during the build and run steps.

> **Note:** Make sure to follow the build and run steps in order, and ensure that the guest binaries are up to date before running the host example.

## System Prerequisites for `trace_dump`

To build and use the `trace_dump` crate and related guest tracing features, you must have the following system libraries and development tools installed on your system:

- **glib-2.0** development files  
  - Fedora/RHEL/CentOS:  
    ```bash
    sudo dnf install glib2-devel pkgconf-pkg-config
    ```
- **cairo** and **cairo-gobject** development files  
  - Fedora/RHEL/CentOS:  
    ```bash
    sudo dnf install cairo-devel cairo-gobject-devel
    ```
- **pango** development files  
  - Fedora/RHEL/CentOS:  
    ```bash
    sudo dnf install pango-devel
    ```

These libraries are required by Rust crates such as `glib-sys`, `cairo-sys-rs`, and `pango-sys`, which are dependencies of the tracing and visualization tools. If you encounter errors about missing `.pc` files (e.g., `glib-2.0.pc`, `cairo.pc`, `pango.pc`), ensure the corresponding `-devel` packages are installed.
