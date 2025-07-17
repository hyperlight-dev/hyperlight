/*
Copyright 2025  The Hyperlight Authors.

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

use criterion::{Criterion, criterion_group, criterion_main};
use hyperlight_host::GuestBinary;
use hyperlight_host::sandbox::{
    Callable, MultiUseSandbox, SandboxConfiguration, UninitializedSandbox,
};
use hyperlight_testing::simple_guest_as_string;

fn create_uninit_sandbox() -> UninitializedSandbox {
    let path = simple_guest_as_string().unwrap();
    UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap()
}

fn create_multiuse_sandbox() -> MultiUseSandbox {
    create_uninit_sandbox().evolve().unwrap()
}

fn create_sandbox_with_heap_size(heap_size_mb: Option<u64>) -> MultiUseSandbox {
    let path = simple_guest_as_string().unwrap();
    let config = if let Some(size_mb) = heap_size_mb {
        let mut config = SandboxConfiguration::default();
        config.set_heap_size(size_mb * 1024 * 1024); // Convert MB to bytes
        Some(config)
    } else {
        None
    };

    let uninit_sandbox = UninitializedSandbox::new(GuestBinary::FilePath(path), config).unwrap();
    uninit_sandbox.evolve().unwrap()
}

fn guest_call_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("guest_functions");

    // Single guest function call.
    group.bench_function("guest_call", |b| {
        let mut sbox = create_multiuse_sandbox();

        b.iter(|| sbox.call::<String>("Echo", "hello\n".to_string()).unwrap());
    });

    // Single snapshot restore after a guest function call.
    group.bench_function("guest_restore", |b| {
        let mut sbox = create_multiuse_sandbox();
        let snapshot = sbox.snapshot().unwrap();

        b.iter_custom(|iters| {
            let mut total_duration = std::time::Duration::ZERO;

            for _ in 0..iters {
                // Dirty some pages
                sbox.call::<String>("Echo", "hello\n".to_string()).unwrap();

                // Measure only the restore operation
                let start = std::time::Instant::now();
                sbox.restore(&snapshot).unwrap();
                total_duration += start.elapsed();
            }

            total_duration
        });
    });

    // Single guest function call after a restore.
    group.bench_function("guest_call_after_restore", |b| {
        let mut sbox = create_multiuse_sandbox();
        let snapshot = sbox.snapshot().unwrap();

        b.iter_custom(|iters| {
            let mut total_duration = std::time::Duration::ZERO;

            for _ in 0..iters {
                // Restore (not timed)
                sbox.restore(&snapshot).unwrap();

                // Measure only the guest function call
                let start = std::time::Instant::now();
                sbox.call::<String>("Echo", "hello\n".to_string()).unwrap();
                total_duration += start.elapsed();
            }

            total_duration
        });
    });

    // Single guest function call with a snapshot restore after
    group.bench_function("guest_call_with_restore", |b| {
        let mut sbox = create_multiuse_sandbox();
        let snapshot = sbox.snapshot().unwrap();

        b.iter(|| {
            sbox.call::<String>("Echo", "hello\n".to_string()).unwrap();
            sbox.restore(&snapshot).unwrap();
        });
    });

    // Single guest function call which includes a call to a host function.
    group.bench_function("guest_call_with_call_to_host_function", |b| {
        let mut uninitialized_sandbox = create_uninit_sandbox();

        // Define a host function that adds two integers and register it.
        uninitialized_sandbox
            .register("HostAdd", |a: i32, b: i32| Ok(a + b))
            .unwrap();

        let mut multiuse_sandbox: MultiUseSandbox = uninitialized_sandbox.evolve().unwrap();

        b.iter(|| {
            multiuse_sandbox
                .call::<i32>("Add", (1_i32, 41_i32))
                .unwrap()
        });
    });

    group.finish();
}

// Guest function call and restore, with large parameters passed as arguments.
fn guest_call_benchmark_large_params(c: &mut Criterion) {
    let mut group = c.benchmark_group("2_large_parameters");
    #[cfg(target_os = "windows")]
    group.sample_size(10); // This benchmark is very slow on Windows, so we reduce the sample size to avoid long test runs.

    // Parameter sizes to test in MB. Each guest call will use two parameters of this size (vec and str).
    const PARAM_SIZES_MB: &[u64] = &[5, 20, 60];

    for &param_size_mb in PARAM_SIZES_MB {
        let benchmark_name = format!("guest_call_restore_{}mb_params", param_size_mb);
        group.bench_function(&benchmark_name, |b| {
            let param_size_bytes = param_size_mb * 1024 * 1024;

            let large_vec = vec![0u8; param_size_bytes as usize];
            let large_string = String::from_utf8(large_vec.clone()).unwrap();

            let mut config = SandboxConfiguration::default();
            config.set_heap_size(600 * 1024 * 1024);
            config.set_input_data_size(300 * 1024 * 1024);

            let sandbox = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().unwrap()),
                Some(config),
            )
            .unwrap();
            let mut sandbox = sandbox.evolve().unwrap();
            let snapshot = sandbox.snapshot().unwrap();

            // Iter_custom to avoid measure clone time of params
            b.iter_custom(|iters| {
                let mut total_duration = std::time::Duration::ZERO;

                for _ in 0..iters {
                    let vec_clone = large_vec.clone();
                    let string_clone = large_string.clone();

                    let start = std::time::Instant::now();
                    sandbox
                        .call_guest_function_by_name::<()>(
                            "LargeParameters",
                            (vec_clone, string_clone),
                        )
                        .unwrap();
                    sandbox.restore(&snapshot).unwrap();
                    total_duration += start.elapsed();
                }

                total_duration
            });
        });
    }

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

    group.finish();
}

// Sandbox creation with different heap sizes
fn sandbox_heap_size_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("sandbox_heap_sizes");

    const HEAP_SIZES_MB: &[Option<u64>] = &[None, Some(50), Some(500), Some(995)];

    // Benchmark sandbox creation with different heap sizes (including default)
    for &heap_size_mb in HEAP_SIZES_MB {
        let benchmark_name = match heap_size_mb {
            None => "create_sandbox_default_heap".to_string(),
            Some(size) => format!("create_sandbox_{}mb_heap", size),
        };
        group.bench_function(&benchmark_name, |b| {
            b.iter_with_large_drop(|| create_sandbox_with_heap_size(heap_size_mb));
        });
    }

    group.finish();
}

// Guest function call and restore with different heap sizes
fn guest_call_heap_size_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("guest_call_restore_heap_sizes");

    const HEAP_SIZES_MB: &[Option<u64>] = &[None, Some(50), Some(500), Some(995)];

    // Benchmark guest function call with different heap sizes (including default)
    for &heap_size_mb in HEAP_SIZES_MB {
        let benchmark_name = match heap_size_mb {
            None => "guest_call_restore_default_heap".to_string(),
            Some(size) => format!("guest_call_restore_{}mb_heap", size),
        };
        group.bench_function(&benchmark_name, |b| {
            let mut sandbox = create_sandbox_with_heap_size(heap_size_mb);
            let snapshot = sandbox.snapshot().unwrap();

            b.iter(|| {
                sandbox
                    .call_guest_function_by_name::<String>("Echo", "hello\n".to_string())
                    .unwrap();
                sandbox.restore(&snapshot).unwrap();
            });
        });
    }

    group.finish();
}

// Snapshot creation with varying heap size
fn snapshot_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("snapshot");

    const HEAP_SIZES_MB: &[Option<u64>] = &[None, Some(50), Some(500), Some(995)];

    for &heap_size_mb in HEAP_SIZES_MB {
        let benchmark_name = match heap_size_mb {
            None => "default_heap".to_string(),
            Some(size) => format!("{}_mb_heap", size),
        };
        group.bench_function(&benchmark_name, |b| {
            let mut sandbox = create_sandbox_with_heap_size(heap_size_mb);
            let original_state = sandbox.snapshot().unwrap();

            b.iter_custom(|iters| {
                let mut total_duration = std::time::Duration::ZERO;

                for _ in 0..iters {
                    // Dirty some pages
                    sandbox
                        .call::<String>("Echo", "hello\n".to_string())
                        .unwrap();

                    // Measure only the snapshot operation
                    let start = std::time::Instant::now();
                    let _snapshot = sandbox.snapshot().unwrap();
                    total_duration += start.elapsed();

                    // Restore the original state to avoid accumulating snapshots
                    sandbox.restore(&original_state).unwrap();
                }

                total_duration
            });
        });
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = guest_call_benchmark, sandbox_benchmark, sandbox_heap_size_benchmark, guest_call_benchmark_large_params, guest_call_heap_size_benchmark, snapshot_benchmark
}
criterion_main!(benches);
