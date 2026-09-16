// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

#![cfg_attr(not(test), no_main)]

use std::num::NonZeroU16;

use hyperlight_common::virtq::canonical::validate_canon_image;
use hyperlight_common::virtq::{
    Descriptor, Layout, MemOps, Notifier, QueueStats, ReplyChain, RingConsumer, RingError,
    VirtqConsumer,
};
use libfuzzer_sys::Corpus;

mod virtq_memory;
use virtq_memory::FuzzMem;

const DEFAULT_QUEUE_SIZE: usize = 16;
const MAX_QUEUE_SIZE: usize = 64;
const MAX_DESCS: usize = 64;
const PAYLOAD_SIZE: usize = 4096;
const BASE_ADDR: u64 = 0x1000;
const HEADER_SIZE: usize = 16;
const DESC_SIZE: usize = 12;

#[derive(Clone, Debug)]
struct FuzzDesc {
    addr_offset: i32,
    len: u32,
    id: u16,
    flags: u16,
}

#[derive(Clone, Debug)]
struct FuzzCase<'a> {
    queue_size: usize,
    avail_descs: usize,
    driver_event_off_wrap: u16,
    driver_event_flags: u16,
    written_len: u32,
    poll_count: usize,
    io_len: usize,
    descs: Vec<FuzzDesc>,
    mutations: &'a [u8],
}

struct NoopNotifier;

impl Notifier for NoopNotifier {
    fn notify(&self, _: QueueStats) {}
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
/// u8  io_len_minus_one
/// u8  reserved[2]
/// desc[desc_count]:
///   i32 addr_offset
///   u32 len
///   u16 id
///   u16 flags
/// mutation[]:
///   u16 offset
///   u8  value
/// ```
fn parse_case(data: &[u8]) -> Option<FuzzCase<'_>> {
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
            addr_offset: read_u32(offset) as i32,
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
        io_len: usize::from(data[13]) + 1,
        descs,
        mutations: &data[offset..],
    })
}

fn normalize_queue_size(raw: u16) -> usize {
    let raw = usize::from(raw);
    if raw == 0 || !raw.is_power_of_two() {
        return DEFAULT_QUEUE_SIZE;
    }

    raw.min(MAX_QUEUE_SIZE)
}

fn make_ring(case: &FuzzCase<'_>) -> Result<(Layout, FuzzMem), ()> {
    let num_descs = NonZeroU16::new(case.queue_size as u16).ok_or(())?;
    let ring_size = Layout::query_size(case.queue_size);
    let mem = FuzzMem::new(BASE_ADDR, ring_size);

    // SAFETY: The aligned descriptor table and both events fit in the backing.
    let layout = unsafe { Layout::from_base(BASE_ADDR, num_descs) }.map_err(|_| ())?;

    let payload_base = BASE_ADDR + ring_size as u64;

    for (idx, fuzz_desc) in case.descs.iter().enumerate() {
        let desc = Descriptor {
            addr: payload_base.wrapping_add_signed(i64::from(fuzz_desc.addr_offset)),
            len: fuzz_desc.len,
            id: fuzz_desc.id,
            flags: fuzz_desc.flags,
        };
        let desc_addr = layout.desc_table_addr() + idx as u64 * Descriptor::SIZE as u64;
        mem.write_val(desc_addr, desc)?;
    }

    write_event(
        &mem,
        layout.drv_evt_addr(),
        case.driver_event_off_wrap,
        case.driver_event_flags,
    )?;

    Ok((layout, mem))
}

fn fuzz_canon_image(
    mem: &FuzzMem,
    layout: Layout,
    case: &FuzzCase<'_>,
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

fn mutate_memory(
    ring: &FuzzMem,
    payload: &FuzzMem,
    ring_size: usize,
    mutation: &[u8; 3],
) -> Result<(), ()> {
    let offset =
        usize::from(u16::from_le_bytes([mutation[0], mutation[1]])) % (ring_size + PAYLOAD_SIZE);
    let mem = if offset < ring_size { ring } else { payload };
    mem.write(BASE_ADDR + offset as u64, &mutation[2..])
}

fn fuzz_consumer(case: &FuzzCase<'_>) -> Result<(), ()> {
    let (layout, ring_mem) = make_ring(case)?;
    let ring_size = Layout::query_size(case.queue_size);
    let payload_mem = FuzzMem::new(BASE_ADDR + ring_size as u64, PAYLOAD_SIZE);
    let mut consumer =
        VirtqConsumer::new_split(layout, ring_mem.clone(), payload_mem.clone(), NoopNotifier);

    let mut mutations = case.mutations.as_chunks::<3>().0.iter();
    let mut mutate = || {
        if let Some(mutation) = mutations.next() {
            mutate_memory(&ring_mem, &payload_mem, ring_size, mutation).unwrap();
        }
    };

    let mut bytes = [0; 256];
    for _ in 0..case.poll_count {
        mutate();
        let Ok(Some((mut recv, mut reply))) = consumer.poll(PAYLOAD_SIZE) else {
            continue;
        };

        for _ in 0..2 {
            mutate();
            let _ = recv.read(&mut bytes[..case.io_len]);
            mutate();
            if let ReplyChain::Writable(writable) = &mut reply {
                let _ = writable.write(&bytes[..case.io_len]);
            }
        }

        mutate();
        let _ = consumer.complete(recv, reply);
    }

    Ok(())
}

fn run_case(case: FuzzCase<'_>) -> Corpus {
    let Ok((layout, mem)) = make_ring(&case) else {
        return Corpus::Reject;
    };

    let payload_base = BASE_ADDR + Layout::query_size(case.queue_size) as u64;

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

    if fuzz_consumer(&case).is_err() {
        return Corpus::Reject;
    }

    Corpus::Keep
}

#[cfg(not(test))]
libfuzzer_sys::fuzz_target!(|data: &[u8]| -> Corpus {
    let Some(case) = parse_case(data) else {
        return Corpus::Reject;
    };

    run_case(case)
});

#[cfg(test)]
mod tests {
    use hyperlight_common::virtq::DescFlags;

    use super::*;

    fn input(addr_offset: i32, len: u32, flags: DescFlags) -> Vec<u8> {
        let mut data = vec![0; HEADER_SIZE + DESC_SIZE];
        data[..2].copy_from_slice(&1u16.to_le_bytes());
        data[2..4].copy_from_slice(&1u16.to_le_bytes());
        data[12] = 2;
        data[13] = 15;
        data[16..20].copy_from_slice(&addr_offset.to_le_bytes());
        data[20..24].copy_from_slice(&len.to_le_bytes());
        data[26..28].copy_from_slice(&flags.bits().to_le_bytes());
        data
    }

    #[test]
    fn descriptor_addresses_include_ring_and_wrapping_offsets() {
        let payload_base = BASE_ADDR + Layout::query_size(1) as u64;
        for (offset, expected) in [
            (0, payload_base),
            (-1, payload_base - 1),
            (PAYLOAD_SIZE as i32, payload_base + PAYLOAD_SIZE as u64),
            (-(payload_base as i32) - 1, u64::MAX),
        ] {
            let data = input(offset, 16, DescFlags::AVAIL);
            let (layout, ring) = make_ring(&parse_case(&data).unwrap()).unwrap();
            let desc: Descriptor = ring.read_val(layout.desc_table_addr()).unwrap();
            assert_eq!(desc.addr, expected);
        }
    }

    #[test]
    fn mutations_respect_separate_memory_regions() {
        let data = input(0, 16, DescFlags::AVAIL);
        let (_, ring) = make_ring(&parse_case(&data).unwrap()).unwrap();
        let ring_size = Layout::query_size(1);
        let payload_base = BASE_ADDR + ring_size as u64;
        let payload = FuzzMem::new(payload_base, PAYLOAD_SIZE);

        assert!(ring.read(payload_base, &mut [0]).is_err());
        assert!(ring.write(payload_base, &[0]).is_err());
        assert!(payload.read(BASE_ADDR, &mut [0]).is_err());
        assert!(payload.write(BASE_ADDR, &[0]).is_err());
        assert!(ring.read(payload_base - 1, &mut [0; 2]).is_err());
        assert!(
            payload
                .read(payload_base + PAYLOAD_SIZE as u64 - 1, &mut [0; 2])
                .is_err()
        );

        mutate_memory(&ring, &payload, ring_size, &[0, 0, 0xa5]).unwrap();
        let offset = (ring_size as u16).to_le_bytes();
        mutate_memory(&ring, &payload, ring_size, &[offset[0], offset[1], 0x5a]).unwrap();
        assert_eq!(ring.read_val::<u8>(BASE_ADDR).unwrap(), 0xa5);
        assert_eq!(payload.read_val::<u8>(payload_base).unwrap(), 0x5a);
    }

    #[test]
    fn consumer_errors_and_between_call_mutations_are_accepted() {
        let ring_size = Layout::query_size(1);
        let wrapping_offset = -(BASE_ADDR as i32 + ring_size as i32) - 1;
        for flags in [DescFlags::AVAIL, DescFlags::AVAIL | DescFlags::WRITE] {
            for (offset, len) in [
                (0, 16),
                (-1, 16),
                (PAYLOAD_SIZE as i32 - 1, 16),
                (wrapping_offset, 16),
                (0, u32::MAX),
            ] {
                let mut data = input(offset, len, flags);
                assert!(matches!(run_case(parse_case(&data).unwrap()), Corpus::Keep));
                for (offset, value) in [
                    (ring_size as u16, 0xa5),
                    (7, 0xff),
                    (8, 0),
                    (12, 0xff),
                    (14, 0),
                    (18, 0xff),
                ] {
                    data.extend_from_slice(&offset.to_le_bytes());
                    data.push(value);
                }
                assert!(matches!(run_case(parse_case(&data).unwrap()), Corpus::Keep));
            }
        }
    }
}
