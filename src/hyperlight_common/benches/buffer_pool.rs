use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use hyperlight_common::virtq::{BufferPool, BufferProvider};

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
                pool.dealloc(alloc).unwrap();
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
                    pool.dealloc(alloc).unwrap();
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
            pool.dealloc(allocations[i]).unwrap();
        }

        b.iter(|| {
            let alloc = pool.alloc(black_box(256)).unwrap();
            pool.dealloc(alloc).unwrap();
        });
    });

    group.finish();
}

// Realloc operations
fn bench_realloc(c: &mut Criterion) {
    let mut group = c.benchmark_group("realloc");

    // In-place grow (same tier)
    group.bench_function("grow_inplace", |b| {
        let pool = make_pool::<256, 4096>(4 * 1024 * 1024);
        b.iter(|| {
            let alloc = pool.alloc(256).unwrap();
            let grown = pool.resize(alloc, black_box(512)).unwrap();
            pool.dealloc(grown).unwrap();
        });
    });

    // Relocate grow (cross tier)
    group.bench_function("grow_relocate", |b| {
        let pool = make_pool::<256, 4096>(4 * 1024 * 1024);
        b.iter(|| {
            let alloc = pool.alloc(128).unwrap();
            // Block in-place growth
            let blocker = pool.alloc(256).unwrap();
            let grown = pool.resize(alloc, black_box(1500)).unwrap();
            pool.dealloc(grown).unwrap();
            pool.dealloc(blocker).unwrap();
        });
    });

    // Shrink
    group.bench_function("shrink", |b| {
        let pool = make_pool::<256, 4096>(4 * 1024 * 1024);
        b.iter(|| {
            let alloc = pool.alloc(1500).unwrap();
            let shrunk = pool.resize(alloc, black_box(256)).unwrap();
            pool.dealloc(shrunk).unwrap();
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
                pool.dealloc(black_box(alloc)).unwrap();
            });
        });
    }

    group.finish();
}

// Cursor optimization
fn bench_last_free_run(c: &mut Criterion) {
    let mut group = c.benchmark_group("last_free_run");

    // With cursor optimization (LIFO)
    group.bench_function("lifo_pattern", |b| {
        let pool = make_pool::<256, 4096>(4 * 1024 * 1024);
        b.iter(|| {
            let alloc = pool.alloc(256).unwrap();
            pool.dealloc(alloc).unwrap();
            let alloc2 = pool.alloc(black_box(256)).unwrap();
            pool.dealloc(alloc2).unwrap();
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
            pool.dealloc(old).unwrap();
            queue.push(pool.alloc(black_box(256)).unwrap());
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_alloc_single,
    bench_alloc_lifo,
    bench_alloc_fragmented,
    bench_realloc,
    bench_free,
    bench_last_free_run,
);

criterion_main!(benches);
