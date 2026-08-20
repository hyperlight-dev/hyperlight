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

//! Loom-based concurrency testing for the virtqueue implementation.
//!
//! Loom will explores all possible thread interleavings to find data races
//! and other concurrency bugs. However, it has specific requirements that
//! make our memory model more involved:
//!
//! ## Flag-Based Synchronization
//!
//! The virtqueue protocol uses flag-based synchronization:
//! 1. Producer writes descriptor fields (addr, len, id), then writes flags with release semantics
//! 2. Consumer reads flags with acquire semantics, then reads descriptor fields
//!
//! Loom  would see this as concurrent access to the same memory and report a race, even though
//! acquire/release on flags provides proper synchronization.
//!
//! ## Shadow Atomics for Flags
//!
//! We maintain shadow atomics that loom tracks for synchronization:
//!
//! - `desc_flags`: One `AtomicU16` per descriptor for flags field
//! - `drv_flags`: `AtomicU16` for driver event suppression flags
//! - `dev_flags`: `AtomicU16` for device event suppression flags
//!
//! The `load_acquire`/`store_release` operations use these loom atomics, while
//! `read`/`write` access the underlying data. All shared regions (descriptors,
//! the event-suppression structs, and the pool) are held in
//! `loom::cell::UnsafeCell`s, so loom also tracks every data access and verifies
//! the flag-based synchronization actually orders them race-free.
//!
//! ## Memory Regions
//!
//! We use a `BTreeMap` to map addresses to memory regions:
//! - `Desc(idx)`: Individual descriptors in the ring
//! - `DrvEvt`: Driver event suppression structure
//! - `DevEvt`: Device event suppression structure
//! - `Pool`: Buffer pool for chain payload data

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use core::num::NonZeroU16;

use bytemuck::Zeroable;
use loom::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use loom::thread;

use super::*;
use crate::virtq::desc::Descriptor;
use crate::virtq::pool::BufferPoolSync;

#[derive(Debug)]
pub struct MemErr;

#[derive(Debug, Clone, Copy)]
enum RegionKind {
    Desc(usize),
    DrvEvt,
    DevEvt,
    Pool,
}

#[derive(Debug, Clone, Copy)]
struct RegionInfo {
    kind: RegionKind,
    size: usize,
}

#[derive(Debug)]
pub struct LoomMem {
    // All shared regions live in `loom::cell::UnsafeCell` so loom tracks every
    // data access and verifies it is race-free.
    descs: Vec<loom::cell::UnsafeCell<Descriptor>>,
    drv: loom::cell::UnsafeCell<EventSuppression>,
    dev: loom::cell::UnsafeCell<EventSuppression>,
    pool: loom::cell::UnsafeCell<Vec<u8>>,

    desc_flags: Vec<AtomicU16>,
    drv_flags: AtomicU16,
    dev_flags: AtomicU16,

    regions: BTreeMap<u64, RegionInfo>,
    layout: Layout,
}

unsafe impl Sync for LoomMem {}
unsafe impl Send for LoomMem {}

impl LoomMem {
    pub fn new(ring_base: u64, num_descs: usize, pool_base: u64, pool_size: usize) -> Self {
        let descs_nz = NonZeroU16::new(num_descs as u16).unwrap();
        let layout = unsafe { Layout::from_base(ring_base, descs_nz).unwrap() };

        let descs: Vec<_> = (0..num_descs)
            .map(|_| loom::cell::UnsafeCell::new(Descriptor::zeroed()))
            .collect();
        let desc_flags: Vec<_> = (0..num_descs).map(|_| AtomicU16::new(0)).collect();

        let mut regions = BTreeMap::new();

        // Register each descriptor as a separate region
        for i in 0..num_descs {
            let addr = layout.desc_table_addr() + (i * Descriptor::SIZE) as u64;
            regions.insert(
                addr,
                RegionInfo {
                    kind: RegionKind::Desc(i),
                    size: Descriptor::SIZE,
                },
            );
        }

        regions.insert(
            layout.drv_evt_addr(),
            RegionInfo {
                kind: RegionKind::DrvEvt,
                size: EventSuppression::SIZE,
            },
        );

        regions.insert(
            layout.dev_evt_addr(),
            RegionInfo {
                kind: RegionKind::DevEvt,
                size: EventSuppression::SIZE,
            },
        );

        regions.insert(
            pool_base,
            RegionInfo {
                kind: RegionKind::Pool,
                size: pool_size,
            },
        );

        Self {
            descs,
            drv: loom::cell::UnsafeCell::new(EventSuppression::zeroed()),
            dev: loom::cell::UnsafeCell::new(EventSuppression::zeroed()),
            pool: loom::cell::UnsafeCell::new(vec![0u8; pool_size]),
            desc_flags,
            drv_flags: AtomicU16::new(0),
            dev_flags: AtomicU16::new(0),
            regions,
            layout,
        }
    }

    pub fn layout(&self) -> Layout {
        self.layout
    }

    fn region(&self, addr: u64) -> Option<(RegionInfo, usize)> {
        let (&base, &info) = self.regions.range(..=addr).next_back()?;
        let offset = (addr - base) as usize;

        if offset < info.size {
            Some((info, offset))
        } else {
            None
        }
    }
}

unsafe impl MemOps for LoomMem {
    type Error = MemErr;

    fn read(&self, addr: u64, dst: &mut [u8]) -> Result<(), Self::Error> {
        let (info, offset) = self.region(addr).ok_or(MemErr)?;

        match info.kind {
            RegionKind::Desc(idx) => {
                self.descs[idx].with(|p| {
                    let bytes = bytemuck::bytes_of(unsafe { &*p });
                    dst.copy_from_slice(&bytes[offset..offset + dst.len()]);
                });
            }
            RegionKind::DrvEvt => {
                self.drv.with(|p| {
                    let bytes = bytemuck::bytes_of(unsafe { &*p });
                    dst.copy_from_slice(&bytes[offset..offset + dst.len()]);
                });
            }
            RegionKind::DevEvt => {
                self.dev.with(|p| {
                    let bytes = bytemuck::bytes_of(unsafe { &*p });
                    dst.copy_from_slice(&bytes[offset..offset + dst.len()]);
                });
            }
            RegionKind::Pool => {
                self.pool.with(|buf| {
                    dst.copy_from_slice(&(unsafe { &*buf })[offset..offset + dst.len()]);
                });
            }
        }
        Ok(())
    }

    fn write(&self, addr: u64, src: &[u8]) -> Result<(), Self::Error> {
        let (info, offset) = self.region(addr).ok_or(MemErr)?;

        match info.kind {
            RegionKind::Desc(idx) => {
                self.descs[idx].with_mut(|p| {
                    let bytes = bytemuck::bytes_of_mut(unsafe { &mut *p });
                    bytes[offset..offset + src.len()].copy_from_slice(src);
                });
            }
            RegionKind::DrvEvt => {
                self.drv.with_mut(|p| {
                    let bytes = bytemuck::bytes_of_mut(unsafe { &mut *p });
                    bytes[offset..offset + src.len()].copy_from_slice(src);
                });
            }
            RegionKind::DevEvt => {
                self.dev.with_mut(|p| {
                    let bytes = bytemuck::bytes_of_mut(unsafe { &mut *p });
                    bytes[offset..offset + src.len()].copy_from_slice(src);
                });
            }
            RegionKind::Pool => {
                self.pool.with_mut(|buf| {
                    (unsafe { &mut *buf })[offset..offset + src.len()].copy_from_slice(src);
                });
            }
        }
        Ok(())
    }

    fn load_acquire(&self, addr: u64) -> Result<u16, Self::Error> {
        let (info, _offset) = self.region(addr).ok_or(MemErr)?;

        Ok(match info.kind {
            RegionKind::Desc(idx) => self.desc_flags[idx].load(Ordering::Acquire),
            RegionKind::DrvEvt => self.drv_flags.load(Ordering::Acquire),
            RegionKind::DevEvt => self.dev_flags.load(Ordering::Acquire),
            RegionKind::Pool => return Err(MemErr),
        })
    }

    fn store_release(&self, addr: u64, val: u16) -> Result<(), Self::Error> {
        let (info, _offset) = self.region(addr).ok_or(MemErr)?;

        match info.kind {
            RegionKind::Desc(idx) => self.desc_flags[idx].store(val, Ordering::Release),
            RegionKind::DrvEvt => self.drv_flags.store(val, Ordering::Release),
            RegionKind::DevEvt => self.dev_flags.store(val, Ordering::Release),
            RegionKind::Pool => return Err(MemErr),
        }
        Ok(())
    }

    unsafe fn as_slice(&self, addr: u64, len: usize) -> Result<&[u8], Self::Error> {
        let (info, offset) = self.region(addr).ok_or(MemErr)?;

        match info.kind {
            RegionKind::Pool => {
                let end = offset.checked_add(len).ok_or(MemErr)?;
                if end > info.size {
                    return Err(MemErr);
                }
                // Safety: pool memory is a contiguous Vec<u8>; caller ensures
                // no concurrent writes for the lifetime of the returned slice.
                Ok(self.pool.get().with(|buf| unsafe { &(&*buf)[offset..end] }))
            }
            _ => Err(MemErr),
        }
    }

    unsafe fn as_mut_slice(&self, addr: u64, len: usize) -> Result<&mut [u8], Self::Error> {
        let (info, offset) = self.region(addr).ok_or(MemErr)?;

        match info.kind {
            RegionKind::Pool => {
                let end = offset.checked_add(len).ok_or(MemErr)?;
                if end > info.size {
                    return Err(MemErr);
                }
                Ok(self
                    .pool
                    .get_mut()
                    .with(|buf| unsafe { &mut (&mut *buf)[offset..end] }))
            }
            _ => Err(MemErr),
        }
    }
}

#[derive(Debug)]
pub struct Notify {
    kicks: AtomicUsize,
}

impl Notify {
    pub fn new() -> Self {
        Self {
            kicks: AtomicUsize::new(0),
        }
    }
}

impl Notifier for Arc<Notify> {
    fn notify(&self, _stats: QueueStats) {
        self.kicks.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn virtq_ping_pong() {
    loom::model(|| {
        let ring_base = 0x10000;
        let pool_base = 0x40000;
        let pool_size = 0x10000;

        let mem = Arc::new(LoomMem::new(ring_base, 8, pool_base, pool_size));
        let pool = BufferPoolSync::<256, 4096>::new(pool_base, pool_size).unwrap();
        let notify = Arc::new(Notify::new());

        let mut prod = VirtqProducer::new(mem.layout(), mem.clone(), notify.clone(), pool);
        let mut cons = VirtqConsumer::new(mem.layout(), mem.clone(), notify.clone());

        let t_prod = thread::spawn(move || {
            let mut se = prod.chain().readable(4).writable(32).build().unwrap();
            se.write_all(b"ping").unwrap();
            let tok = prod.submit(se).unwrap();
            loop {
                if let Some(r) = prod.poll().unwrap() {
                    assert_eq!(r.token(), tok);
                    assert_eq!(r.to_bytes().unwrap().as_ref(), b"pong");
                    break;
                }
                thread::yield_now();
            }
        });

        let t_cons = thread::spawn(move || {
            let (recv, reply) = loop {
                if let Some(r) = cons.poll(1024).unwrap() {
                    break r;
                }
                thread::yield_now();
            };
            assert_eq!(recv.to_bytes().as_ref(), b"ping");
            let ReplyChain::Writable(mut wc) = reply else {
                panic!("expected writable reply");
            };
            wc.write_all(b"pong").unwrap();
            cons.complete(wc).unwrap();
        });

        t_prod.join().unwrap();
        t_cons.join().unwrap();
    });
}

#[test]
fn virtq_ack_only() {
    loom::model(|| {
        let ring_base = 0x10000;
        let pool_base = 0x40000;
        let pool_size = 0x10000;

        let mem = Arc::new(LoomMem::new(ring_base, 4, pool_base, pool_size));
        let pool = BufferPoolSync::<256, 4096>::new(pool_base, pool_size).unwrap();
        let notify = Arc::new(Notify::new());

        let mut prod = VirtqProducer::new(mem.layout(), mem.clone(), notify.clone(), pool);
        let mut cons = VirtqConsumer::new(mem.layout(), mem.clone(), notify.clone());

        let t_prod = thread::spawn(move || {
            let mut se = prod.chain().readable(4).build().unwrap();
            se.write_all(b"ping").unwrap();
            let tok = prod.submit(se).unwrap();
            loop {
                if let Some(r) = prod.poll().unwrap() {
                    assert!(matches!(r, UsedChain::Ack(t) if t == tok));
                    break;
                }
                thread::yield_now();
            }
        });

        let t_cons = thread::spawn(move || {
            let (recv, reply) = loop {
                if let Some(r) = cons.poll(1024).unwrap() {
                    break r;
                }
                thread::yield_now();
            };
            assert_eq!(recv.to_bytes().as_ref(), b"ping");
            assert!(matches!(reply, ReplyChain::Ack(_)));
            cons.complete(reply).unwrap();
        });

        t_prod.join().unwrap();
        t_cons.join().unwrap();
    });
}

#[test]
fn virtq_out_of_order_completions() {
    loom::model(|| {
        let ring_base = 0x10000;
        let pool_base = 0x40000;
        let pool_size = 0x10000;

        let mem = Arc::new(LoomMem::new(ring_base, 8, pool_base, pool_size));
        let pool = BufferPoolSync::<256, 4096>::new(pool_base, pool_size).unwrap();
        let notify = Arc::new(Notify::new());

        let mut prod = VirtqProducer::new(mem.layout(), mem.clone(), notify.clone(), pool);
        let mut cons = VirtqConsumer::new(mem.layout(), mem.clone(), notify.clone());
        let submitted = Arc::new(AtomicUsize::new(0));
        let submitted_for_consumer = submitted.clone();

        let t_prod = thread::spawn(move || {
            let mut first = prod.chain().readable(5).writable(8).build().unwrap();
            first.write_all(b"first").unwrap();
            let tok1 = prod.submit(first).unwrap();

            let mut second = prod.chain().readable(6).writable(8).build().unwrap();
            second.write_all(b"second").unwrap();
            let tok2 = prod.submit(second).unwrap();
            submitted.store(1, Ordering::Release);

            let mut got_first = false;
            let mut got_second = false;
            while !(got_first && got_second) {
                if let Some(r) = prod.poll().unwrap() {
                    let token = r.token();
                    let bytes = r.to_bytes().unwrap();
                    if token == tok1 {
                        assert!(bytes.is_empty());
                        got_first = true;
                    } else if token == tok2 {
                        assert!(bytes.is_empty());
                        got_second = true;
                    } else {
                        panic!("unexpected token");
                    }
                } else {
                    thread::yield_now();
                }
            }
        });

        let t_cons = thread::spawn(move || {
            while submitted_for_consumer.load(Ordering::Acquire) == 0 {
                thread::yield_now();
            }

            let (recv1, reply1) = loop {
                if let Some(r) = cons.poll(1024).unwrap() {
                    break r;
                }
                thread::yield_now();
            };
            assert_eq!(recv1.to_bytes().as_ref(), b"first");

            let (recv2, reply2) = loop {
                if let Some(r) = cons.poll(1024).unwrap() {
                    break r;
                }
                thread::yield_now();
            };
            assert_eq!(recv2.to_bytes().as_ref(), b"second");

            let ReplyChain::Writable(second) = reply2 else {
                panic!("expected writable reply");
            };
            cons.complete(second).unwrap();

            let ReplyChain::Writable(first) = reply1 else {
                panic!("expected writable reply");
            };
            cons.complete(first).unwrap();
        });

        t_prod.join().unwrap();
        t_cons.join().unwrap();
    });
}

/// Exercise concurrent access to an event-suppression structure.
///
/// The producer publishing a chain reads the device event-suppression struct
/// (in `should_notify_device`) at the same time the consumer reconfigures that
/// same struct via `set_avail_suppression`. Descriptor mode writes the
/// `off_wrap` payload, so this stresses the flag-first event-suppression read:
/// the notify decision must acquire the flags before touching `off_wrap`, or the
/// read races the consumer's publish. Loom verifies no such race exists.
#[test]
fn virtq_event_suppression_reconfig() {
    loom::model(|| {
        let ring_base = 0x10000;
        let pool_base = 0x40000;
        let pool_size = 0x10000;

        let mem = Arc::new(LoomMem::new(ring_base, 4, pool_base, pool_size));
        let pool = BufferPoolSync::<256, 4096>::new(pool_base, pool_size).unwrap();
        let notify = Arc::new(Notify::new());

        let mut prod = VirtqProducer::new(mem.layout(), mem.clone(), notify.clone(), pool);
        let mut cons = VirtqConsumer::new(mem.layout(), mem.clone(), notify.clone());

        // Descriptor-mode suppression writes the `off_wrap` field that the
        // producer's notify decision may read concurrently.
        let cursor = cons.avail_cursor();

        let t_cons = thread::spawn(move || {
            cons.set_avail_suppression(SuppressionKind::Descriptor(cursor))
                .unwrap();
        });

        let t_prod = thread::spawn(move || {
            let mut se = prod.chain().readable(4).build().unwrap();
            se.write_all(b"ping").unwrap();
            prod.submit(se).unwrap();
        });

        t_cons.join().unwrap();
        t_prod.join().unwrap();
    });
}
