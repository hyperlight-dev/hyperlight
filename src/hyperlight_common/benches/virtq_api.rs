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
use hyperlight_common::virtq::UsedChain;

mod common;
use common::*;

fn bench_readonly_strategies(c: &mut Criterion) {
    let mut group = c.benchmark_group("virtq_readonly_allocator_strategy");

    for size in [8 * 1024usize, 64 * 1024, 256 * 1024] {
        let payload = vec![0xA5u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("buffer_pool_run", size),
            &payload,
            |b, payload| {
                let mut pair = make_pair(128, run_buffer_pool);
                b.iter(|| {
                    let used = readonly_roundtrip(&mut pair, black_box(payload));
                    debug_assert!(matches!(used, UsedChain::Ack(_)));
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("buffer_pool_run_fragmented", size),
            &payload,
            |b, payload| {
                let mut pair = make_pair(128, |base, pool_size| {
                    fragmented_run_buffer_pool(base, pool_size, payload.len())
                });
                b.iter(|| {
                    let used = readonly_roundtrip(&mut pair, black_box(payload));
                    debug_assert!(matches!(used, UsedChain::Ack(_)));
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("recycle_pool_segmented", size),
            &payload,
            |b, payload| {
                let mut pair = make_pair(128, recycle_pool);
                b.iter(|| {
                    let used = readonly_roundtrip(&mut pair, black_box(payload));
                    debug_assert!(matches!(used, UsedChain::Ack(_)));
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("recycle_pool_segmented_fragmented", size),
            &payload,
            |b, payload| {
                let mut pair = make_pair(128, |base, pool_size| {
                    fragmented_recycle_pool(base, pool_size, payload.len())
                });
                b.iter(|| {
                    let used = readonly_roundtrip(&mut pair, black_box(payload));
                    debug_assert!(matches!(used, UsedChain::Ack(_)));
                });
            },
        );
    }

    group.finish();
}

fn bench_readwrite_strategies(c: &mut Criterion) {
    let mut group = c.benchmark_group("virtq_readwrite_allocator_strategy");

    for size in [8 * 1024usize, 64 * 1024, 256 * 1024] {
        let request = vec![0x11u8; size];
        let response = vec![0x22u8; size];
        group.throughput(Throughput::Bytes((request.len() + response.len()) as u64));

        group.bench_with_input(
            BenchmarkId::new("buffer_pool_run", size),
            &(request.clone(), response.clone()),
            |b, (request, response)| {
                let mut pair = make_pair(128, run_buffer_pool);
                b.iter(|| {
                    let used = readwrite_roundtrip(
                        &mut pair,
                        black_box(request.as_slice()),
                        black_box(response.as_slice()),
                    );
                    black_box(used.segments().unwrap().segment_count());
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("buffer_pool_run_fragmented", size),
            &(request.clone(), response.clone()),
            |b, (request, response)| {
                let mut pair = make_pair(128, |base, pool_size| {
                    fragmented_run_buffer_pool(base, pool_size, request.len())
                });
                b.iter(|| {
                    let used = readwrite_roundtrip(
                        &mut pair,
                        black_box(request.as_slice()),
                        black_box(response.as_slice()),
                    );
                    black_box(used.segments().unwrap().segment_count());
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("recycle_pool_segmented", size),
            &(request.clone(), response.clone()),
            |b, (request, response)| {
                let mut pair = make_pair(128, recycle_pool);
                b.iter(|| {
                    let used = readwrite_roundtrip(
                        &mut pair,
                        black_box(request.as_slice()),
                        black_box(response.as_slice()),
                    );
                    black_box(used.segments().unwrap().segment_count());
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("recycle_pool_segmented_fragmented", size),
            &(request, response),
            |b, (request, response)| {
                let mut pair = make_pair(128, |base, pool_size| {
                    fragmented_recycle_pool(base, pool_size, request.len())
                });
                b.iter(|| {
                    let used = readwrite_roundtrip(
                        &mut pair,
                        black_box(request.as_slice()),
                        black_box(response.as_slice()),
                    );
                    black_box(used.segments().unwrap().segment_count());
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_readonly_strategies,
    bench_readwrite_strategies,
);

criterion_main!(benches);
