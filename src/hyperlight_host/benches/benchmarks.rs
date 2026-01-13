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

#![expect(
    clippy::disallowed_macros,
    reason = "This is a benchmark file, so using disallowed macros is fine here."
)]

use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use flatbuffers::FlatBufferBuilder;
use hyperlight_common::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};
use hyperlight_common::flatbuffer_wrappers::util::estimate_flatbuffer_capacity;
use hyperlight_host::GuestBinary;
use hyperlight_host::mem::shared_mem::ExclusiveSharedMemory;
use hyperlight_host::sandbox::{MultiUseSandbox, SandboxConfiguration, UninitializedSandbox};
use hyperlight_testing::sandbox_sizes::{LARGE_HEAP_SIZE, MEDIUM_HEAP_SIZE, SMALL_HEAP_SIZE};
use hyperlight_testing::{c_simple_guest_as_string, simple_guest_as_string};

/// Sandbox heap size configurations for benchmarking.
/// Only affects heap size - all other configuration remains at defaults.
#[derive(Clone, Copy)]
enum SandboxSize {
    /// Default configuration (uses hyperlight defaults)
    Default,
    /// Small heap: 8 MB
    Small,
    /// Medium heap: 64 MB
    Medium,
    /// Large heap: 256 MB
    Large,
}

impl SandboxSize {
    /// Returns the configuration for this sandbox size.
    /// Returns None for Default to use hyperlight's default configuration.
    fn config(&self) -> Option<SandboxConfiguration> {
        match self {
            Self::Default => None,
            Self::Small => {
                let mut cfg = SandboxConfiguration::default();
                cfg.set_heap_size(SMALL_HEAP_SIZE);
                Some(cfg)
            }
            Self::Medium => {
                let mut cfg = SandboxConfiguration::default();
                cfg.set_heap_size(MEDIUM_HEAP_SIZE);
                Some(cfg)
            }
            Self::Large => {
                let mut cfg = SandboxConfiguration::default();
                cfg.set_heap_size(LARGE_HEAP_SIZE);
                Some(cfg)
            }
        }
    }

    /// Returns the name of this size for use in benchmark identifiers.
    fn name(&self) -> &str {
        match self {
            Self::Default => "default",
            Self::Small => "small",
            Self::Medium => "medium",
            Self::Large => "large",
        }
    }

    /// Returns all size variants for iteration.
    const fn all() -> [SandboxSize; 4] {
        [Self::Default, Self::Small, Self::Medium, Self::Large]
    }
}

fn create_uninit_sandbox_with_size(size: SandboxSize) -> UninitializedSandbox {
    let path = simple_guest_as_string().unwrap();
    UninitializedSandbox::new(GuestBinary::FilePath(path), size.config()).unwrap()
}

fn create_multiuse_sandbox_with_size(size: SandboxSize) -> MultiUseSandbox {
    create_uninit_sandbox_with_size(size).evolve().unwrap()
}

// ============================================================================
// Benchmark Category: Sandbox Lifecycle
// ============================================================================

fn bench_create_uninitialized(b: &mut criterion::Bencher, size: SandboxSize) {
    // Ideally wanted to use b.iter_with_large_drop, but runs out of memory on windows runners: "The paging file is too small for this operation to complete."
    b.iter_batched(
        || (),
        |_| create_uninit_sandbox_with_size(size),
        criterion::BatchSize::PerIteration,
    );
}

fn bench_create_uninitialized_and_drop(b: &mut criterion::Bencher, size: SandboxSize) {
    b.iter(|| create_uninit_sandbox_with_size(size));
}

fn bench_create_initialized(b: &mut criterion::Bencher, size: SandboxSize) {
    // Ideally wanted to use b.iter_with_large_drop, but runs out of memory on windows runners: "The paging file is too small for this operation to complete."
    b.iter_batched(
        || (),
        |_| create_multiuse_sandbox_with_size(size),
        criterion::BatchSize::PerIteration,
    );
}

fn bench_create_initialized_and_drop(b: &mut criterion::Bencher, size: SandboxSize) {
    b.iter(|| create_multiuse_sandbox_with_size(size));
}

fn sandbox_lifecycle_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("sandboxes");

    for size in SandboxSize::all() {
        group.bench_function(format!("create_uninitialized/{}", size.name()), |b| {
            bench_create_uninitialized(b, size)
        });
    }

    for size in SandboxSize::all() {
        group.bench_function(
            format!("create_uninitialized_and_drop/{}", size.name()),
            |b| bench_create_uninitialized_and_drop(b, size),
        );
    }

    for size in SandboxSize::all() {
        group.bench_function(format!("create_initialized/{}", size.name()), |b| {
            bench_create_initialized(b, size)
        });
    }

    for size in SandboxSize::all() {
        group.bench_function(
            format!("create_initialized_and_drop/{}", size.name()),
            |b| bench_create_initialized_and_drop(b, size),
        );
    }

    group.finish();
}

// ============================================================================
// Benchmark Category: Guest Calls
// ============================================================================

fn bench_guest_call(b: &mut criterion::Bencher, size: SandboxSize) {
    let mut sbox = create_multiuse_sandbox_with_size(size);
    b.iter(|| sbox.call::<String>("Echo", "hello\n".to_string()).unwrap());
}

fn bench_guest_call_with_restore(b: &mut criterion::Bencher, size: SandboxSize) {
    let mut sbox = create_multiuse_sandbox_with_size(size);
    let snapshot = sbox.snapshot().unwrap();

    b.iter(|| {
        sbox.call::<String>("Echo", "hello\n".to_string()).unwrap();
        sbox.restore(snapshot.clone()).unwrap();
    });
}

fn bench_guest_call_with_host_function(b: &mut criterion::Bencher, size: SandboxSize) {
    let mut uninitialized_sandbox = create_uninit_sandbox_with_size(size);

    uninitialized_sandbox
        .register("HostAdd", |a: i32, b: i32| Ok(a + b))
        .unwrap();

    let mut multiuse_sandbox: MultiUseSandbox = uninitialized_sandbox.evolve().unwrap();

    b.iter(|| {
        multiuse_sandbox
            .call::<i32>("Add", (1_i32, 41_i32))
            .unwrap()
    });
}

fn bench_guest_call_different_thread(b: &mut criterion::Bencher, size: SandboxSize) {
    b.iter_custom(|iters| {
        let mut total_duration = Duration::ZERO;
        let sbox = Arc::new(Mutex::new(create_multiuse_sandbox_with_size(size)));

        for _ in 0..iters {
            // Ensure vcpu is "bound" on this main thread
            {
                let mut sbox = sbox.lock().unwrap();
                sbox.call::<String>("Echo", "warmup\n".to_string()).unwrap();
            }

            let barrier = Arc::new(Barrier::new(2));
            let barrier_clone = Arc::clone(&barrier);
            let sbox_clone = Arc::clone(&sbox);

            let handle = thread::spawn(move || {
                barrier_clone.wait();

                let mut sbox = sbox_clone.lock().unwrap();
                let start = Instant::now();
                // Measure the first call after thread switch
                sbox.call::<String>("Echo", "hello\n".to_string()).unwrap();
                start.elapsed()
            });

            barrier.wait();

            total_duration += handle.join().unwrap();
        }

        total_duration
    });
}

fn bench_guest_call_interrupt_latency(b: &mut criterion::Bencher, size: SandboxSize) {
    b.iter_custom(|iters| {
        let mut total_interrupt_latency = Duration::ZERO;

        for _ in 0..iters {
            let mut sbox = create_multiuse_sandbox_with_size(size);
            let interrupt_handle = sbox.interrupt_handle();

            let start_barrier = Arc::new(Barrier::new(2));
            let start_barrier_clone = Arc::clone(&start_barrier);

            let observer_thread = thread::spawn(move || {
                start_barrier_clone.wait();

                // Small delay to ensure the guest function is running in VM before interrupting
                thread::sleep(std::time::Duration::from_millis(10));
                let kill_start = Instant::now();
                assert!(interrupt_handle.kill());
                kill_start
            });

            start_barrier.wait();

            let result = sbox.call::<i32>("Spin", ());

            let call_end = Instant::now();
            let kill_start = observer_thread.join().unwrap();

            assert!(
                matches!(
                    result,
                    Err(hyperlight_host::HyperlightError::ExecutionCanceledByHost())
                ),
                "Guest function should be interrupted"
            );

            total_interrupt_latency += call_end.duration_since(kill_start);
        }

        total_interrupt_latency
    });
}

fn guest_calls_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("guest_calls");

    for size in SandboxSize::all() {
        group.bench_function(format!("call/{}", size.name()), |b| {
            bench_guest_call(b, size)
        });
    }

    for size in SandboxSize::all() {
        group.bench_function(format!("call_with_restore/{}", size.name()), |b| {
            bench_guest_call_with_restore(b, size)
        });
    }

    for size in SandboxSize::all() {
        group.bench_function(format!("call_with_host_function/{}", size.name()), |b| {
            bench_guest_call_with_host_function(b, size)
        });
    }

    group.bench_function("different_thread".to_string(), |b| {
        bench_guest_call_different_thread(b, SandboxSize::Default)
    });

    group.bench_function("interrupt_latency".to_string(), |b| {
        bench_guest_call_interrupt_latency(b, SandboxSize::Default)
    });

    group.finish();
}

// ============================================================================
// Benchmark Category: Snapshots
// ============================================================================

fn bench_snapshot_create(b: &mut criterion::Bencher, size: SandboxSize) {
    b.iter_custom(|iters| {
        let mut sbox = create_multiuse_sandbox_with_size(size);
        let mut total_duration = Duration::ZERO;

        for _ in 0..iters {
            // Make a call to modify memory
            sbox.call::<String>("Echo", "hello\n".to_string()).unwrap();

            // Measure only the snapshot creation time
            let start = Instant::now();
            let snapshot = sbox.snapshot().unwrap();
            total_duration += start.elapsed();

            std::hint::black_box(snapshot);
        }

        total_duration
    });
}

fn bench_snapshot_restore(b: &mut criterion::Bencher, size: SandboxSize) {
    b.iter_custom(|iters| {
        let mut sbox = create_multiuse_sandbox_with_size(size);
        // Create initial snapshot
        let snapshot = sbox.snapshot().unwrap();
        let mut total_duration = Duration::ZERO;

        for _ in 0..iters {
            // Make a call to modify memory
            sbox.call::<String>("Echo", "hello\n".to_string()).unwrap();

            // Measure only the restore time
            let start = Instant::now();
            sbox.restore(snapshot.clone()).unwrap();
            total_duration += start.elapsed();
        }

        total_duration
    });
}

fn snapshots_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("snapshots");

    for size in SandboxSize::all() {
        group.bench_function(format!("create/{}", size.name()), |b| {
            bench_snapshot_create(b, size)
        });
    }

    for size in SandboxSize::all() {
        group.bench_function(format!("restore/{}", size.name()), |b| {
            bench_snapshot_restore(b, size)
        });
    }

    group.finish();
}

// ============================================================================
// Benchmark Category: Guest Calls (Large Parameters)
// ============================================================================

fn guest_call_benchmark_large_param(c: &mut Criterion) {
    let mut group = c.benchmark_group("guest_functions_with_large_parameters");
    #[cfg(target_os = "windows")]
    group.sample_size(10); // This benchmark is very slow on Windows, so we reduce the sample size to avoid long test runs.

    // This benchmark includes time to first clone a vector and string, so it is not a "pure' benchmark of the guest call, but it's still useful
    group.bench_function("guest_call_with_large_parameters", |b| {
        const SIZE: usize = 50 * 1024 * 1024; // 50 MB
        let large_vec = vec![0u8; SIZE];
        let large_string = unsafe { String::from_utf8_unchecked(large_vec.clone()) }; // Safety: indeed above vec is valid utf8

        let mut config = SandboxConfiguration::default();
        config.set_input_data_size(2 * SIZE + (1024 * 1024)); // 2 * SIZE + 1 MB, to allow 1MB for the rest of the serialized function call
        config.set_heap_size(SIZE as u64 * 15);

        let sandbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().unwrap()),
            Some(config),
        )
        .unwrap();
        let mut sandbox = sandbox.evolve().unwrap();

        b.iter(|| {
            sandbox
                .call::<()>("LargeParameters", (large_vec.clone(), large_string.clone()))
                .unwrap()
        });
    });

    group.finish();
}

// ============================================================================
// Benchmark Category: Serialization
// ============================================================================

fn function_call_serialization_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("function_call_serialization");

    let function_call = FunctionCall::new(
        "TestFunction".to_string(),
        Some(vec![
            ParameterValue::VecBytes(vec![1; 10 * 1024 * 1024]),
            ParameterValue::String(String::from_utf8(vec![2; 10 * 1024 * 1024]).unwrap()),
            ParameterValue::Int(42),
            ParameterValue::UInt(100),
            ParameterValue::Long(1000),
            ParameterValue::ULong(2000),
            ParameterValue::Float(521521.53),
            ParameterValue::Double(432.53),
            ParameterValue::Bool(true),
            ParameterValue::VecBytes(vec![1; 10 * 1024 * 1024]),
            ParameterValue::String(String::from_utf8(vec![2; 10 * 1024 * 1024]).unwrap()),
        ]),
        FunctionCallType::Guest,
        ReturnType::Int,
    );

    group.bench_function("serialize_function_call", |b| {
        b.iter(|| {
            // We specifically want to include the time to estimate the capacity in this benchmark
            let estimated_capacity = estimate_flatbuffer_capacity(
                function_call.function_name.as_str(),
                function_call.parameters.as_deref().unwrap_or(&[]),
            );
            let mut builder = FlatBufferBuilder::with_capacity(estimated_capacity);
            let serialized: &[u8] = function_call.encode(&mut builder);
            std::hint::black_box(serialized);
        });
    });

    group.bench_function("deserialize_function_call", |b| {
        let mut builder = FlatBufferBuilder::new();
        let bytes = function_call.clone().encode(&mut builder);

        b.iter(|| {
            let deserialized: FunctionCall = bytes.try_into().unwrap();
            std::hint::black_box(deserialized);
        });
    });

    group.finish();
}

// ============================================================================
// Benchmark Category: Sample Workloads
// ============================================================================

fn sample_workloads_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("sample_workloads");

    fn bench_24k_in_8k_out(b: &mut criterion::Bencher, guest_path: String) {
        let mut cfg = SandboxConfiguration::default();
        cfg.set_input_data_size(25 * 1024);

        let mut sandbox = UninitializedSandbox::new(GuestBinary::FilePath(guest_path), Some(cfg))
            .unwrap()
            .evolve()
            .unwrap();

        b.iter_with_setup(
            || vec![1; 24 * 1024],
            |input| {
                let ret: Vec<u8> = sandbox.call("24K_in_8K_out", (input,)).unwrap();
                assert_eq!(ret.len(), 8 * 1024, "Expected output length to be 8K");
                std::hint::black_box(ret);
            },
        );
    }

    group.bench_function("24K_in_8K_out_c", |b| {
        bench_24k_in_8k_out(b, c_simple_guest_as_string().unwrap());
    });

    group.bench_function("24K_in_8K_out_rust", |b| {
        bench_24k_in_8k_out(b, simple_guest_as_string().unwrap());
    });

    group.finish();
}

// ============================================================================
// Benchmark Category: Shared Memory Operations
// ============================================================================

fn shared_memory_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("shared_memory");

    let sizes: &[(usize, &str)] = &[(1024 * 1024, "1MB"), (64 * 1024 * 1024, "64MB")];

    // Benchmark fill
    for &(size, name) in sizes {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("fill", name), &size, |b, &size| {
            let eshm = ExclusiveSharedMemory::new(size).unwrap();
            let (mut hshm, _) = eshm.build();
            b.iter(|| {
                hshm.fill(0xAB, 0, size).unwrap();
            });
        });
    }

    // Benchmark copy_to_slice (read from shared memory)
    for &(size, name) in sizes {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("copy_to_slice", name),
            &size,
            |b, &size| {
                let eshm = ExclusiveSharedMemory::new(size).unwrap();
                let (hshm, _) = eshm.build();
                let mut dst = vec![0u8; size];
                b.iter(|| {
                    hshm.copy_to_slice(&mut dst, 0).unwrap();
                });
            },
        );
    }

    // Benchmark copy_from_slice (write to shared memory)
    for &(size, name) in sizes {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("copy_from_slice", name),
            &size,
            |b, &size| {
                let eshm = ExclusiveSharedMemory::new(size).unwrap();
                let (hshm, _) = eshm.build();
                let src = vec![0xCDu8; size];
                b.iter(|| {
                    hshm.copy_from_slice(&src, 0).unwrap();
                });
            },
        );
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets =
        sandbox_lifecycle_benchmark,
        guest_calls_benchmark,
        snapshots_benchmark,
        guest_call_benchmark_large_param,
        function_call_serialization_benchmark,
        sample_workloads_benchmark,
        shared_memory_benchmark
}
criterion_main!(benches);
