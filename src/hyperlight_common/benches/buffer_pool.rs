/*
Copyright 2026  The Hyperlight Authors.

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

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use hyperlight_common::virtq::{BufferPool, BufferProvider, RecyclePool};

// Helper to create a pool for benchmarking
fn make_pool<const L: usize, const U: usize>(size: usize) -> BufferPool<L, U> {
    let base = 0x10000;
    BufferPool::<L, U>::new(base, size).unwrap()
}

// Single allocation performance
fn bench_alloc_single(c: &mut Criterion) {
    let mut group = c.benchmark_group("alloc_single");

    for size in [64, 128, 256, 512, 1024, 1500, 4096].iter() {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let pool = make_pool::<256, 4096>(4 * 1024 * 1024);
            b.iter(|| {
                let alloc = pool.alloc(black_box(size)).unwrap();
                pool.dealloc(alloc.addr).unwrap();
            });
        });
    }
    group.finish();
}

// LIFO recycling
fn bench_alloc_lifo(c: &mut Criterion) {
    let mut group = c.benchmark_group("alloc_lifo");

    for size in [256, 1500, 4096].iter() {
        group.throughput(Throughput::Elements(100));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let pool = make_pool::<256, 4096>(4 * 1024 * 1024);
            b.iter(|| {
                for _ in 0..100 {
                    let alloc = pool.alloc(black_box(size)).unwrap();
                    pool.dealloc(alloc.addr).unwrap();
                }
            });
        });
    }
    group.finish();
}

// Fragmented allocation worst case
fn bench_alloc_fragmented(c: &mut Criterion) {
    let mut group = c.benchmark_group("alloc_fragmented");

    group.bench_function("fragmented_256", |b| {
        let pool = make_pool::<256, 4096>(4 * 1024 * 1024);

        // Create fragmentation pattern: allocate many, free every other
        let mut allocations = Vec::new();
        for _ in 0..100 {
            allocations.push(pool.alloc(128).unwrap());
        }
        for i in (0..100).step_by(2) {
            pool.dealloc(allocations[i].addr).unwrap();
        }

        b.iter(|| {
            let alloc = pool.alloc(black_box(256)).unwrap();
            pool.dealloc(alloc.addr).unwrap();
        });
    });

    group.finish();
}

// Free performance
fn bench_free(c: &mut Criterion) {
    let mut group = c.benchmark_group("free");

    for size in [256, 1500, 4096].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let pool = make_pool::<256, 4096>(4 * 1024 * 1024);
            b.iter(|| {
                let alloc = pool.alloc(size).unwrap();
                pool.dealloc(black_box(alloc.addr)).unwrap();
            });
        });
    }

    group.finish();
}

// Free-list reuse
fn bench_free_list_reuse(c: &mut Criterion) {
    let mut group = c.benchmark_group("free_list_reuse");

    // With cursor optimization (LIFO)
    group.bench_function("lifo_pattern", |b| {
        let pool = make_pool::<256, 4096>(4 * 1024 * 1024);
        b.iter(|| {
            let alloc = pool.alloc(256).unwrap();
            pool.dealloc(alloc.addr).unwrap();
            let alloc2 = pool.alloc(black_box(256)).unwrap();
            pool.dealloc(alloc2.addr).unwrap();
        });
    });

    // Without cursor benefit (FIFO-like)
    group.bench_function("fifo_pattern", |b| {
        let pool = make_pool::<256, 4096>(4 * 1024 * 1024);
        let mut queue = Vec::new();

        // Pre-fill queue
        for _ in 0..10 {
            queue.push(pool.alloc(256).unwrap());
        }

        b.iter(|| {
            // FIFO: free oldest, allocate new
            let old = queue.remove(0);
            pool.dealloc(old.addr).unwrap();
            queue.push(pool.alloc(black_box(256)).unwrap());
        });
    });

    group.finish();
}

// Segmented logical payload allocation
fn bench_segmented_payload(c: &mut Criterion) {
    let mut group = c.benchmark_group("segmented_payload");

    for payload_size in [8 * 1024usize, 64 * 1024, 256 * 1024] {
        group.throughput(Throughput::Bytes(payload_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(payload_size),
            &payload_size,
            |b, &payload_size| {
                let pool = make_pool::<256, 4096>(4 * 1024 * 1024);
                b.iter(|| {
                    let sgs = pool.alloc_sg(black_box(payload_size)).unwrap();
                    for sg in sgs {
                        pool.dealloc(sg.addr).unwrap();
                    }
                });
            },
        );
    }

    group.finish();
}

fn bench_recycle_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("recycle_pool");

    group.bench_function("alloc_dealloc_4096", |b| {
        let pool = RecyclePool::new(0x80000, 4 * 1024 * 1024, 4096).unwrap();
        b.iter(|| {
            let alloc = pool.alloc(black_box(4096)).unwrap();
            pool.dealloc(alloc.addr).unwrap();
        });
    });

    group.bench_function("alloc_dealloc_128", |b| {
        let pool = RecyclePool::new(0x80000, 4 * 1024 * 1024, 256).unwrap();
        b.iter(|| {
            let alloc = pool.alloc(black_box(128)).unwrap();
            pool.dealloc(alloc.addr).unwrap();
        });
    });

    group.bench_function("alloc_dealloc_1500", |b| {
        let pool = RecyclePool::new(0x80000, 4 * 1024 * 1024, 4096).unwrap();
        b.iter(|| {
            let alloc = pool.alloc(black_box(1500)).unwrap();
            pool.dealloc(alloc.addr).unwrap();
        });
    });

    group.bench_function("alloc_sg_64k", |b| {
        let pool = RecyclePool::new(0x80000, 4 * 1024 * 1024, 4096).unwrap();
        b.iter(|| {
            let sgs = pool.alloc_sg(black_box(64 * 1024)).unwrap();
            for sg in sgs {
                pool.dealloc(sg.addr).unwrap();
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_alloc_single,
    bench_alloc_lifo,
    bench_alloc_fragmented,
    bench_free,
    bench_free_list_reuse,
    bench_segmented_payload,
    bench_recycle_pool,
);

criterion_main!(benches);
