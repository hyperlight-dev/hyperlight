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

//! Shared harness for the `virtq_api` benchmarks: an in-memory [`MemOps`]
//! backend, a counting [`Notifier`], producer/consumer pair construction, pool
//! factories, and request/response round-trip drivers.

use std::cell::UnsafeCell;
use std::hint::black_box;
use std::num::NonZeroU16;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};

use bytemuck::Pod;
use hyperlight_common::virtq::{
    BufferPool, BufferProvider, Descriptor, Layout, MemOps, Notifier, QueueStats, RecyclePool,
    ReplyChain, UsedChain, VirtqConsumer, VirtqProducer,
};

pub const LOWER_SLOT: usize = 256;
pub const UPPER_SLOT: usize = 4096;
pub const POOL_SIZE: usize = 8 * 1024 * 1024;

pub type RunBufferPool = BufferPool<LOWER_SLOT, UPPER_SLOT>;

#[derive(Clone)]
struct BenchMem {
    inner: Arc<BenchMemInner>,
}

struct BenchMemInner {
    storage: UnsafeCell<Vec<u8>>,
    base_addr: u64,
}

unsafe impl Send for BenchMemInner {}
unsafe impl Sync for BenchMemInner {}

impl BenchMem {
    fn new(size: usize) -> Self {
        let storage = vec![0u8; size];
        let base_addr = storage.as_ptr() as u64;
        Self {
            inner: Arc::new(BenchMemInner {
                storage: UnsafeCell::new(storage),
                base_addr,
            }),
        }
    }

    fn base_addr(&self) -> u64 {
        self.inner.base_addr
    }

    fn ptr_for_addr(&self, addr: u64) -> *mut u8 {
        let storage = unsafe { &mut *self.inner.storage.get() };
        let offset = (addr - self.inner.base_addr) as usize;
        storage.as_mut_ptr().wrapping_add(offset)
    }
}

unsafe impl MemOps for BenchMem {
    type Error = core::convert::Infallible;

    fn read(&self, addr: u64, dst: &mut [u8]) -> Result<(), Self::Error> {
        let src = self.ptr_for_addr(addr);
        unsafe {
            ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), dst.len());
        }
        Ok(())
    }

    fn write(&self, addr: u64, src: &[u8]) -> Result<(), Self::Error> {
        let dst = self.ptr_for_addr(addr);
        unsafe {
            ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
        }
        Ok(())
    }

    fn read_val<T: Pod>(&self, addr: u64) -> Result<T, Self::Error> {
        let ptr = self.ptr_for_addr(addr).cast::<T>();
        Ok(unsafe { ptr::read_volatile(ptr) })
    }

    fn write_val<T: Pod>(&self, addr: u64, val: T) -> Result<(), Self::Error> {
        let ptr = self.ptr_for_addr(addr).cast::<T>();
        unsafe { ptr::write_volatile(ptr, val) };
        Ok(())
    }

    fn load_acquire(&self, addr: u64) -> Result<u16, Self::Error> {
        let ptr = self.ptr_for_addr(addr).cast::<AtomicU16>();
        Ok(unsafe { (*ptr).load(Ordering::Acquire) })
    }

    fn store_release(&self, addr: u64, val: u16) -> Result<(), Self::Error> {
        let ptr = self.ptr_for_addr(addr).cast::<AtomicU16>();
        unsafe { (*ptr).store(val, Ordering::Release) };
        Ok(())
    }

    unsafe fn as_slice(&self, addr: u64, len: usize) -> Result<&[u8], Self::Error> {
        let ptr = self.ptr_for_addr(addr);
        Ok(unsafe { core::slice::from_raw_parts(ptr, len) })
    }

    unsafe fn as_mut_slice(&self, addr: u64, len: usize) -> Result<&mut [u8], Self::Error> {
        let ptr = self.ptr_for_addr(addr);
        Ok(unsafe { core::slice::from_raw_parts_mut(ptr, len) })
    }
}

#[derive(Clone)]
struct BenchNotifier {
    count: Arc<AtomicUsize>,
}

impl BenchNotifier {
    fn new() -> Self {
        Self {
            count: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl Notifier for BenchNotifier {
    fn notify(&self, _stats: QueueStats) {
        self.count.fetch_add(1, Ordering::Relaxed);
    }
}

/// A producer/consumer pair sharing one in-memory ring and pool.
pub struct BenchPair<P> {
    producer: VirtqProducer<BenchMem, BenchNotifier, P>,
    consumer: VirtqConsumer<BenchMem, BenchNotifier>,
}

fn align_up(value: usize, align: usize) -> usize {
    value.div_ceil(align) * align
}

/// Build a [`BenchPair`] with `descs` ring descriptors and a pool built by
/// `make_pool`.
pub fn make_pair<P>(descs: usize, make_pool: impl FnOnce(u64, usize) -> P) -> BenchPair<P>
where
    P: BufferProvider + Clone,
{
    let ring_size = Layout::query_size(descs);
    let mem = BenchMem::new(ring_size + POOL_SIZE + 0x20000);
    let ring_base = align_up(mem.base_addr() as usize, Descriptor::ALIGN) as u64;
    let descs_nz = NonZeroU16::new(descs as u16).unwrap();

    let layout = unsafe { Layout::from_base(ring_base, descs_nz).unwrap() };
    let pool_base = align_up((ring_base + ring_size as u64 + 0x1000) as usize, UPPER_SLOT) as u64;
    let pool = make_pool(pool_base, POOL_SIZE);

    let notifier = BenchNotifier::new();
    let producer = VirtqProducer::new(layout, mem.clone(), notifier.clone(), pool);
    let consumer = VirtqConsumer::new(layout, mem, notifier);

    BenchPair { producer, consumer }
}

pub fn run_buffer_pool(base: u64, size: usize) -> RunBufferPool {
    BufferPool::new(base, size).unwrap()
}

pub fn fragmented_run_buffer_pool(base: u64, size: usize, payload_size: usize) -> RunBufferPool {
    let pool = run_buffer_pool(base, size);
    let payload_slots = payload_size.div_ceil(UPPER_SLOT);
    let prefix_slots = 32;
    let suffix_slots = 32;

    let allocated: Vec<_> = (0..prefix_slots + payload_slots + suffix_slots)
        .map(|_| pool.alloc(UPPER_SLOT).unwrap())
        .collect();

    for alloc in &allocated[prefix_slots..prefix_slots + payload_slots] {
        pool.dealloc(alloc.addr).unwrap();
    }

    pool
}

pub fn recycle_pool(base: u64, size: usize) -> RecyclePool {
    RecyclePool::new(base, size, UPPER_SLOT).unwrap()
}

pub fn fragmented_recycle_pool(base: u64, size: usize, payload_size: usize) -> RecyclePool {
    let pool = recycle_pool(base, size);
    let payload_slots = payload_size.div_ceil(UPPER_SLOT);
    let allocated: Vec<_> = (0..payload_slots * 2 + 16)
        .map(|_| pool.alloc(UPPER_SLOT).unwrap())
        .collect();

    for alloc in allocated.iter().step_by(2).take(payload_slots) {
        pool.dealloc(alloc.addr).unwrap();
    }

    pool
}

/// Drive one read-only (fire-and-forget) chain through submit, consume, ack, and
/// poll, returning the producer-observed used chain.
pub fn readonly_roundtrip<P>(pair: &mut BenchPair<P>, payload: &[u8]) -> UsedChain
where
    P: BufferProvider + Clone + Send + 'static,
{
    let mut chain = pair
        .producer
        .chain()
        .readable(payload.len())
        .build()
        .unwrap();

    chain.write_all(payload).unwrap();
    let token = pair.producer.submit(chain).unwrap();

    let (recv, reply) = pair.consumer.poll(payload.len()).unwrap().unwrap();
    black_box(recv.segments().segment_count());
    pair.consumer.complete(reply).unwrap();

    let used = pair.producer.poll().unwrap().unwrap();
    debug_assert_eq!(used.token(), token);
    used
}

/// Drive one request/response chain through submit, consume, write reply,
/// complete, and poll, returning the producer-observed used chain.
pub fn readwrite_roundtrip<P>(pair: &mut BenchPair<P>, request: &[u8], response: &[u8]) -> UsedChain
where
    P: BufferProvider + Clone + Send + 'static,
{
    let mut chain = pair
        .producer
        .chain()
        .readable(request.len())
        .writable(response.len())
        .build()
        .unwrap();

    chain.write_all(request).unwrap();
    let token = pair.producer.submit(chain).unwrap();

    let (recv, reply) = pair.consumer.poll(request.len()).unwrap().unwrap();
    black_box(recv.segments().segment_count());
    let ReplyChain::Writable(mut writable) = reply else {
        panic!("expected writable reply");
    };

    writable.write_all(response).unwrap();
    pair.consumer.complete(writable).unwrap();

    let used = pair.producer.poll().unwrap().unwrap();
    debug_assert_eq!(used.token(), token);
    used
}
