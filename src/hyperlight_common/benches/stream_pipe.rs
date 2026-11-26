// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::hint::black_box;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use hyperlight_common::stream::{self, DEFAULT_WINDOW};

/// Each iteration starts with an empty pipe and writes at most one window.
fn ready<F: Future>(future: F) -> F::Output {
    let Poll::Ready(output) = pin!(future).poll(&mut Context::from_waker(Waker::noop())) else {
        panic!("local pipe operation blocked");
    };

    output
}

/// Compare copying and transferring an owned buffer. Input allocation is outside the timer.
fn bench_owned_writes(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream_pipe_write");

    for size in [128, 4096, DEFAULT_WINDOW.get() as usize] {
        let payload = vec![0x5a; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(BenchmarkId::new("write_all", size), |b| {
            let (mut reader, mut writer) = stream::new::<u8>();

            b.iter_batched(
                || payload.clone(),
                |data| {
                    ready(writer.write_all(&data)).unwrap();
                    black_box(ready(reader.read_chunk()).unwrap().unwrap());
                },
                BatchSize::LargeInput,
            );
        });

        group.bench_function(BenchmarkId::new("write_chunk", size), |b| {
            let (mut reader, mut writer) = stream::new::<u8>();

            b.iter_batched(
                || payload.clone(),
                |data| {
                    ready(writer.write_chunk(data.into())).unwrap();
                    black_box(ready(reader.read_chunk()).unwrap().unwrap());
                },
                BatchSize::LargeInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_owned_writes);
criterion_main!(benches);
