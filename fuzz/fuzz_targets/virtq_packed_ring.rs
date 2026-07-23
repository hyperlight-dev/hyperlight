// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

#![no_main]

use std::cell::UnsafeCell;
use std::num::NonZeroU16;
use std::ops::Range;
use std::rc::Rc;

use hyperlight_common::virtq::canonical::validate_canon_image;
use hyperlight_common::virtq::{Descriptor, Layout, MemOps, RingConsumer, RingError};
use libfuzzer_sys::{Corpus, fuzz_target};

const DEFAULT_QUEUE_SIZE: usize = 16;
const MAX_QUEUE_SIZE: usize = 64;
const MAX_DESCS: usize = 64;
const PAYLOAD_SIZE: usize = 4096;
const BASE_ADDR: u64 = 0x1000;
const HEADER_SIZE: usize = 16;
const DESC_SIZE: usize = 12;

#[derive(Clone, Debug)]
struct FuzzDesc {
    addr_offset: u32,
    len: u32,
    id: u16,
    flags: u16,
}

#[derive(Clone, Debug)]
struct FuzzCase {
    queue_size: usize,
    avail_descs: usize,
    driver_event_off_wrap: u16,
    driver_event_flags: u16,
    written_len: u32,
    poll_count: usize,
    descs: Vec<FuzzDesc>,
}

#[derive(Clone)]
struct FuzzMem {
    inner: Rc<FuzzMemInner>,
}

struct FuzzMemInner {
    storage: UnsafeCell<Vec<u8>>,
    base_addr: u64,
}

impl FuzzMem {
    fn new(base_addr: u64, size: usize) -> Self {
        Self {
            inner: Rc::new(FuzzMemInner {
                storage: UnsafeCell::new(vec![0; size]),
                base_addr,
            }),
        }
    }

    fn range(&self, addr: u64, len: usize) -> Result<Range<usize>, ()> {
        let offset = addr.checked_sub(self.inner.base_addr).ok_or(())? as usize;
        let end = offset.checked_add(len).ok_or(())?;
        let storage_len = unsafe { &*self.inner.storage.get() }.len();
        if end > storage_len {
            return Err(());
        }

        Ok(offset..end)
    }
}

// SAFETY: `FuzzMem` bounds-checks every translated address against its owned
// backing storage and reports failures instead of dereferencing invalid memory.
unsafe impl MemOps for FuzzMem {
    type Error = ();

    fn read(&self, addr: u64, dst: &mut [u8]) -> Result<(), Self::Error> {
        let range = self.range(addr, dst.len())?;
        let storage = unsafe { &*self.inner.storage.get() };
        dst.copy_from_slice(&storage[range]);
        Ok(())
    }

    fn write(&self, addr: u64, src: &[u8]) -> Result<(), Self::Error> {
        let range = self.range(addr, src.len())?;
        let storage = unsafe { &mut *self.inner.storage.get() };
        storage[range].copy_from_slice(src);
        Ok(())
    }

    fn load_acquire(&self, addr: u64) -> Result<u16, Self::Error> {
        let mut bytes = [0; 2];
        self.read(addr, &mut bytes)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn store_release(&self, addr: u64, val: u16) -> Result<(), Self::Error> {
        self.write(addr, &val.to_le_bytes())
    }

    unsafe fn as_slice(&self, addr: u64, len: usize) -> Result<&[u8], Self::Error> {
        let range = self.range(addr, len)?;
        let storage = unsafe { &*self.inner.storage.get() };
        Ok(&storage[range])
    }

    #[allow(clippy::mut_from_ref)]
    unsafe fn as_mut_slice(&self, addr: u64, len: usize) -> Result<&mut [u8], Self::Error> {
        let range = self.range(addr, len)?;
        let storage = unsafe { &mut *self.inner.storage.get() };
        Ok(&mut storage[range])
    }
}

fn write_event(mem: &FuzzMem, addr: u64, off_wrap: u16, flags: u16) -> Result<(), ()> {
    mem.write(
        addr,
        &[
            (off_wrap & 0xff) as u8,
            (off_wrap >> 8) as u8,
            (flags & 0xff) as u8,
            (flags >> 8) as u8,
        ],
    )
}

/// Parse a compact little-endian packed-ring blob:
///
/// ```text
/// u16 queue_size
/// u16 desc_count
/// u16 driver_event_off_wrap
/// u16 driver_event_flags
/// u32 written_len
/// u8  poll_count
/// u8  reserved[3]
/// desc[desc_count]:
///   u32 addr_offset
///   u32 len
///   u16 id
///   u16 flags
/// ```
fn parse_case(data: &[u8]) -> Option<FuzzCase> {
    if data.len() < HEADER_SIZE {
        return None;
    }

    let read_u16 = |i: usize| u16::from_le_bytes([data[i], data[i + 1]]);
    let read_u32 = |i: usize| u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

    let raw_queue_size = read_u16(0);
    let queue_size = normalize_queue_size(raw_queue_size);
    let avail_descs = usize::from(read_u16(2));
    let desc_count = avail_descs.min(MAX_DESCS).min(queue_size);

    let driver_event_off_wrap = read_u16(4);
    let driver_event_flags = read_u16(6);
    let written_len = read_u32(8);
    let poll_count = usize::from(data[12]).min(8);

    let desc_bytes = desc_count.checked_mul(DESC_SIZE)?;
    if data.len() < HEADER_SIZE.checked_add(desc_bytes)? {
        return None;
    }

    let mut descs = Vec::with_capacity(desc_count);
    let mut offset = HEADER_SIZE;

    for _ in 0..desc_count {
        descs.push(FuzzDesc {
            addr_offset: read_u32(offset),
            len: read_u32(offset + 4),
            id: read_u16(offset + 8),
            flags: read_u16(offset + 10),
        });
        offset += DESC_SIZE;
    }

    Some(FuzzCase {
        queue_size,
        avail_descs,
        driver_event_off_wrap,
        driver_event_flags,
        written_len,
        poll_count,
        descs,
    })
}

fn normalize_queue_size(raw: u16) -> usize {
    let raw = usize::from(raw);
    if raw == 0 || !raw.is_power_of_two() {
        return DEFAULT_QUEUE_SIZE;
    }

    raw.min(MAX_QUEUE_SIZE)
}

fn fuzz_canon_image(
    mem: &FuzzMem,
    layout: Layout,
    case: &FuzzCase,
    payload_base: u64,
) -> Result<(), ()> {
    write_event(
        mem,
        layout.drv_evt_addr(),
        case.driver_event_off_wrap,
        case.driver_event_flags,
    )?;
    let _ = validate_canon_image(mem, layout, case.avail_descs, |_, _| true);

    write_event(mem, layout.drv_evt_addr(), 0, 0)?;
    let canon = validate_canon_image(mem, layout, case.avail_descs, |_, _| true);

    let payload_end = payload_base + PAYLOAD_SIZE as u64;
    let _ = validate_canon_image(mem, layout, case.avail_descs, |_, elem| {
        elem.addr >= payload_base
            && elem
                .addr
                .checked_add(u64::from(elem.len))
                .is_some_and(|end| end <= payload_end)
    });

    if let Ok(chains) = canon {
        let mut consumer = RingConsumer::new(layout, mem.clone());
        for expected in chains {
            let Ok((id, actual)) = consumer.poll_available() else {
                panic!("canonical image was rejected by the ring consumer");
            };
            assert_eq!(id, expected.id());
            assert_eq!(actual.elems().len(), expected.buffers().elems().len());
            for (actual, expected) in actual.elems().iter().zip(expected.buffers().elems()) {
                assert_eq!(actual.addr, expected.addr);
                assert_eq!(actual.len, expected.len);
                assert_eq!(actual.writable, expected.writable);
            }
        }
        assert!(matches!(
            consumer.poll_available(),
            Err(RingError::WouldBlock)
        ));
    }

    write_event(
        mem,
        layout.drv_evt_addr(),
        case.driver_event_off_wrap,
        case.driver_event_flags,
    )
}

fn run_case(case: FuzzCase) -> Corpus {
    let Some(num_descs) = NonZeroU16::new(case.queue_size as u16) else {
        return Corpus::Reject;
    };

    let ring_size = Layout::query_size(case.queue_size);
    let mem = FuzzMem::new(BASE_ADDR, ring_size + PAYLOAD_SIZE);
    let layout = match unsafe { Layout::from_base(BASE_ADDR, num_descs) } {
        Ok(layout) => layout,
        Err(_) => return Corpus::Reject,
    };

    let payload_base = BASE_ADDR + ring_size as u64;
    for (idx, fuzz_desc) in case.descs.iter().enumerate() {
        let payload_offset = fuzz_desc.addr_offset as usize % PAYLOAD_SIZE;
        let desc = Descriptor {
            addr: payload_base + payload_offset as u64,
            len: fuzz_desc.len,
            id: fuzz_desc.id,
            flags: fuzz_desc.flags,
        };
        let desc_addr = layout.desc_table_addr() + idx as u64 * Descriptor::SIZE as u64;
        if mem.write_val(desc_addr, desc).is_err() {
            return Corpus::Reject;
        }
    }

    if fuzz_canon_image(&mem, layout, &case, payload_base).is_err() {
        return Corpus::Reject;
    }

    let mut consumer = RingConsumer::new(layout, mem);
    for _ in 0..case.poll_count {
        let Ok((id, _chain)) = consumer.poll_available() else {
            break;
        };

        if consumer
            .submit_used_with_notify(id, case.written_len)
            .is_err()
        {
            break;
        }
    }

    Corpus::Keep
}

fuzz_target!(|data: &[u8]| -> Corpus {
    let Some(case) = parse_case(data) else {
        return Corpus::Reject;
    };

    run_case(case)
});
