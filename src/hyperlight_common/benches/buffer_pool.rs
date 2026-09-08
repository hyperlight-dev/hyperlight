// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use hyperlight_common::virtq::{SlotLayout, SlotPool};

// Raw segmented allocation without producer bookkeeping.
fn bench_segmented_payload(c: &mut Criterion) {
    let mut group = c.benchmark_group("payload_allocation");

    for payload_size in [8 * 1024usize, 64 * 1024, 256 * 1024] {
        group.throughput(Throughput::Bytes(payload_size as u64));
        group.bench_with_input(
            BenchmarkId::new("slot_pool_segmented", payload_size),
            &payload_size,
            |b, &payload_size| {
                let pool = SlotPool::new(SlotLayout::new(0x80000, 4096, 1024)).unwrap();
                b.iter(|| {
                    let allocations: Vec<_> = (0..black_box(payload_size).div_ceil(4096))
                        .map(|_| pool.alloc(4096).unwrap())
                        .collect();
                    for allocation in allocations.into_iter().rev() {
                        pool.dealloc(allocation.addr).unwrap();
                    }
                });
            },
        );
    }

    group.finish();
}

fn bench_slot_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("slot_pool");

    group.bench_function("alloc_dealloc_4096", |b| {
        let layout = SlotLayout::new(0x80000, 4096, 1024);
        let pool = SlotPool::new(layout).unwrap();
        b.iter(|| {
            let alloc = pool.alloc(black_box(4096)).unwrap();
            pool.dealloc(alloc.addr).unwrap();
        });
    });

    group.bench_function("alloc_dealloc_128", |b| {
        let layout = SlotLayout::new(0x80000, 256, 16 * 1024);
        let pool = SlotPool::new(layout).unwrap();
        b.iter(|| {
            let alloc = pool.alloc(black_box(128)).unwrap();
            pool.dealloc(alloc.addr).unwrap();
        });
    });

    group.bench_function("alloc_dealloc_1500", |b| {
        let layout = SlotLayout::new(0x80000, 4096, 1024);
        let pool = SlotPool::new(layout).unwrap();
        b.iter(|| {
            let alloc = pool.alloc(black_box(1500)).unwrap();
            pool.dealloc(alloc.addr).unwrap();
        });
    });

    group.finish();
}

criterion_group!(benches, bench_segmented_payload, bench_slot_pool);

criterion_main!(benches);
