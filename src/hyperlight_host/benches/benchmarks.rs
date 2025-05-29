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

use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};
use hyperlight_host::sandbox::{MultiUseSandbox, SandboxConfiguration, UninitializedSandbox};
use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
use hyperlight_host::sandbox_state::transition::Noop;
use hyperlight_host::GuestBinary;
use hyperlight_testing::simple_guest_as_string;

fn create_uninit_sandbox() -> UninitializedSandbox {
    let path = simple_guest_as_string().unwrap();
    UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap()
}

fn create_multiuse_sandbox() -> MultiUseSandbox {
    create_uninit_sandbox().evolve(Noop::default()).unwrap()
}

fn guest_call_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("guest_functions");

    // Benchmarks a single guest function call.
    // The benchmark does **not** include the time to reset the sandbox memory after the call.
    group.bench_function("guest_call", |b| {
        let mut call_ctx = create_multiuse_sandbox().new_call_context();

        b.iter(|| {
            call_ctx
                .call(
                    "Echo",
                    ReturnType::Int,
                    Some(vec![ParameterValue::String("hello\n".to_string())]),
                )
                .unwrap()
        });
    });

    // Benchmarks a single guest function call.
    // The benchmark does include the time to reset the sandbox memory after the call.
    group.bench_function("guest_call_with_reset", |b| {
        let mut sandbox = create_multiuse_sandbox();

        b.iter(|| {
            sandbox
                .call_guest_function_by_name(
                    "Echo",
                    ReturnType::Int,
                    Some(vec![ParameterValue::String("hello\n".to_string())]),
                )
                .unwrap()
        });
    });

    // This benchmark includes time to first clone a vector and string, so it is not a "pure' benchmark of the guest call, but it's still useful
    group.bench_function("guest_call_with_large_parameters", |b| {
        const SIZE: usize = 50 * 1024 * 1024; // 50 MB
        let large_vec = vec![0u8; SIZE];
        let large_string = unsafe { String::from_utf8_unchecked(large_vec.clone()) }; // Safety: indeed above vec is valid utf8

        let mut config = SandboxConfiguration::default();
        config.set_input_data_size(2 * SIZE + (1024 * 1024)); // 2 * SIZE + 1 MB, to allow 1MB for the rest of the serialized function call
        config.set_heap_size(SIZE as u64 * 15);
        config.set_max_execution_time(Duration::from_secs(30));

        let sandbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().unwrap()),
            Some(config),
        )
        .unwrap();
        let mut sandbox = sandbox.evolve(Noop::default()).unwrap();

        b.iter(|| {
            sandbox
                .call_guest_function_by_name(
                    "LargeParameters",
                    ReturnType::Void,
                    Some(vec![
                        ParameterValue::VecBytes(large_vec.clone()),
                        ParameterValue::String(large_string.clone()),
                    ]),
                )
                .unwrap()
        });
    });

    // Benchmarks a guest function call calling into the host.
    // The benchmark does **not** include the time to reset the sandbox memory after the call.
    group.bench_function("guest_call_with_call_to_host_function", |b| {
        let mut uninitialized_sandbox = create_uninit_sandbox();

        // Define a host function that adds two integers and register it.
        uninitialized_sandbox
            .register("HostAdd", |a: i32, b: i32| Ok(a + b))
            .unwrap();

        let multiuse_sandbox: MultiUseSandbox =
            uninitialized_sandbox.evolve(Noop::default()).unwrap();
        let mut call_ctx = multiuse_sandbox.new_call_context();

        b.iter(|| {
            call_ctx
                .call(
                    "Add",
                    ReturnType::Int,
                    Some(vec![ParameterValue::Int(1), ParameterValue::Int(41)]),
                )
                .unwrap()
        });
    });

    group.finish();
}

fn sandbox_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("sandboxes");

    // Benchmarks the time to create a new uninitialized sandbox.
    // Does **not** include the time to drop the sandbox.
    group.bench_function("create_uninitialized_sandbox", |b| {
        b.iter_with_large_drop(create_uninit_sandbox);
    });

    // Benchmarks the time to create a new uninitialized sandbox and drop it.
    group.bench_function("create_uninitialized_sandbox_and_drop", |b| {
        b.iter(create_uninit_sandbox);
    });

    // Benchmarks the time to create a new sandbox.
    // Does **not** include the time to drop the sandbox.
    group.bench_function("create_sandbox", |b| {
        b.iter_with_large_drop(create_multiuse_sandbox);
    });

    // Benchmarks the time to create a new sandbox and drop it.
    group.bench_function("create_sandbox_and_drop", |b| {
        b.iter(create_multiuse_sandbox);
    });

    // Benchmarks the time to create a new sandbox and create a new call context.
    // Does **not** include the time to drop the sandbox or the call context.
    group.bench_function("create_sandbox_and_call_context", |b| {
        b.iter_with_large_drop(|| create_multiuse_sandbox().new_call_context());
    });

    // Benchmarks the time to create a new sandbox, create a new call context, and drop the call context.
    group.bench_function("create_sandbox_and_call_context_and_drop", |b| {
        b.iter(|| create_multiuse_sandbox().new_call_context());
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = guest_call_benchmark, sandbox_benchmark
}
criterion_main!(benches);
