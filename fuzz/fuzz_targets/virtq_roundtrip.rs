// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

#![no_main]

use std::num::NonZeroU16;

use hyperlight_common::virtq::{
    Layout, Notifier, QueueStats, ReplyChain, SlotLayout, SlotPool, UsedChain, VirtqConsumer,
    VirtqError, VirtqProducer,
};
use libfuzzer_sys::{Corpus, fuzz_target};

mod virtq_memory;
use virtq_memory::FuzzMem;

const BASE_ADDR: u64 = 0x1000;
const QUEUE_SIZE: usize = 16;
const SLOT_SIZE: usize = 64;
const POOL_SIZE: usize = QUEUE_SIZE * SLOT_SIZE;

struct NoopNotifier;

impl Notifier for NoopNotifier {
    fn notify(&self, _: QueueStats) {}
}

fuzz_target!(|data: &[u8]| -> Corpus {
    let Some((header, bytes)) = data.split_first_chunk::<4>() else {
        return Corpus::Reject;
    };
    if bytes.len() > POOL_SIZE {
        return Corpus::Reject;
    }

    let split = usize::from(u16::from_le_bytes([header[0], header[1]])) % (bytes.len() + 1);
    let (request_bytes, response_bytes) = bytes.split_at(split);

    let chunk_size = usize::from(header[2]) + 1;
    let reply_capacity = response_bytes.len() + usize::from(header[3]);

    if request_bytes.is_empty() && reply_capacity == 0 {
        return Corpus::Reject;
    }

    let ring_bytes = Layout::query_size(QUEUE_SIZE).next_multiple_of(SLOT_SIZE);
    let mem = FuzzMem::new(BASE_ADDR, ring_bytes + POOL_SIZE);

    // SAFETY: The aligned descriptor table and both events fit in the backing.
    let layout = unsafe {
        Layout::from_base(BASE_ADDR, NonZeroU16::new(QUEUE_SIZE as u16).unwrap()).unwrap()
    };

    let pool_layout =
        SlotLayout::new(BASE_ADDR + ring_bytes as u64, SLOT_SIZE, QUEUE_SIZE).unwrap();
    let pool = SlotPool::new(pool_layout).unwrap();

    let mut producer = VirtqProducer::new(layout, mem.clone(), NoopNotifier, pool.clone());
    let mut consumer = VirtqConsumer::new(layout, mem, NoopNotifier);

    let mut builder = producer.chain();
    if !request_bytes.is_empty() {
        builder = builder.readable(request_bytes.len());
    }
    if reply_capacity != 0 {
        builder = builder.writable(reply_capacity);
    }

    let writable_descriptors = reply_capacity.div_ceil(SLOT_SIZE);
    let descriptors = request_bytes.len().div_ceil(SLOT_SIZE) + writable_descriptors;
    let result = builder.build();

    if descriptors > QUEUE_SIZE {
        assert!(matches!(result, Err(VirtqError::Backpressure)));
        assert_eq!(pool.num_free(), QUEUE_SIZE);
        assert_eq!(producer.num_free(), QUEUE_SIZE);
        return Corpus::Keep;
    }

    let mut chain = result.unwrap();
    assert_eq!(chain.desc_count(), descriptors);
    assert_eq!(pool.num_live(), descriptors);

    for chunk in request_bytes.chunks(chunk_size) {
        chain.write_all(chunk).unwrap();
    }

    assert_eq!(chain.written(), request_bytes.len());

    let token = producer.submit(chain).unwrap();
    assert_eq!(producer.num_inflight(), descriptors);

    let (mut request, mut reply) = consumer.poll(request_bytes.len()).unwrap().unwrap();
    assert_eq!(request.token(), token);
    assert_eq!(reply.token(), token);
    assert_eq!(request.len(), request_bytes.len());

    let mut received = vec![0xa5; request_bytes.len()];
    for chunk in received.chunks_mut(chunk_size) {
        request.read_exact(chunk).unwrap();
    }

    assert_eq!(received, request_bytes);
    assert_eq!(request.remaining(), 0);

    assert_eq!(
        matches!(reply, ReplyChain::Writable(_)),
        reply_capacity != 0
    );

    if let ReplyChain::Writable(writable) = &mut reply {
        assert_eq!(writable.capacity(), writable_descriptors * SLOT_SIZE);
        for chunk in response_bytes.chunks(chunk_size) {
            writable.write_all(chunk).unwrap();
        }
        assert_eq!(writable.written(), response_bytes.len());
    }

    consumer.complete(request, reply).unwrap();
    let used = producer.poll().unwrap().unwrap();

    assert_eq!(used.token(), token);
    match &used {
        UsedChain::Ack(_) => assert_eq!(reply_capacity, 0),
        UsedChain::Data(_, segments) => {
            assert_ne!(reply_capacity, 0);
            assert_eq!(segments.to_bytes().as_ref(), response_bytes);
        }
    }

    assert_eq!(producer.num_free(), QUEUE_SIZE);
    assert_eq!(pool.num_live(), response_bytes.len().div_ceil(SLOT_SIZE));

    drop(used);

    assert_eq!(pool.num_free(), QUEUE_SIZE);
    assert!(producer.poll().unwrap().is_none());
    assert!(consumer.poll(POOL_SIZE).unwrap().is_none());

    Corpus::Keep
});
