// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Canonical packed virtqueue images.
//!
//! A canonical image starts at the initial wrap round. Available descriptors
//! occupy a complete prefix, unused descriptors are zero, and both event
//! structures are enabled at offset zero. This form can be restored as bytes
//! and validated before either peer resumes.
//!
//! Ring resets normalize the structures owned by each peer. Buffer range
//! policy remains with the integration through the validator callback.

use alloc::vec::Vec;

use bytemuck::Zeroable;
use fixedbitset::FixedBitSet;
use smallvec::SmallVec;
use thiserror::Error;

use super::super::desc::{DescFlags, DescTable, Descriptor};
use super::super::event::{EventFlags, EventSuppression};
use super::super::{Layout, MemOps};
use super::{BufferChain, BufferElement, MemOp, RingError};

/// Why a descriptor does not belong to a canonical packed-ring image.
#[derive(Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum DescError {
    /// An unused descriptor was not completely zeroed.
    #[error("unused descriptor is not zeroed")]
    ExpectedZero,
    /// The raw descriptor contains unsupported or reserved flag bits.
    #[error("descriptor contains unknown flags")]
    UnknownFlags,
    /// The descriptor is not available in the initial packed-ring wrap round.
    #[error("descriptor is not initially available")]
    NotAvailable,
    /// Indirect descriptor tables are unsupported.
    #[error("indirect descriptor is unsupported")]
    Indirect,
    /// A chain's NEXT flag extends beyond the available descriptor prefix.
    #[error("chain continues beyond the available descriptor prefix")]
    ChainContinues,
    /// A chain ID is outside the descriptor-table bounds.
    #[error("descriptor ID is out of range")]
    IdOutOfRange,
    /// A tail descriptor does not carry its head descriptor's ID.
    #[error("descriptor ID differs within a chain")]
    IdMismatch,
    /// Two available chains use the same descriptor ID.
    #[error("descriptor ID is already used by another chain")]
    DuplicateId,
    /// A readable descriptor follows a writable descriptor.
    #[error("readable descriptor follows a writable descriptor")]
    ReadableAfterWritable,
}

/// Validation failure for a canonical packed-ring image.
#[derive(Error, Debug)]
pub enum ImageError {
    /// Reading the shared ring image failed.
    #[error(transparent)]
    Ring(#[from] RingError),
    /// The caller supplied an impossible available-descriptor prefix length.
    #[error("available descriptor count {available} exceeds ring capacity {capacity}")]
    DescCount {
        /// Number of descriptors expected to be available.
        available: usize,
        /// Descriptor-table capacity.
        capacity: usize,
    },
    /// An event-suppression structure is not the canonical enabled value.
    #[error("event suppression at address 0x{addr:x} is not canonical")]
    Event {
        /// Address of the invalid event-suppression structure.
        addr: u64,
    },
    /// A descriptor violates the canonical packed-ring structure.
    #[error("descriptor {index} is not canonical: {reason}")]
    Desc {
        /// Descriptor-table index.
        index: u16,
        /// Structural validation failure.
        reason: DescError,
    },
    /// The caller rejected a descriptor's payload range or attributes.
    #[error("descriptor {index} buffer at 0x{addr:x} with length {len} was rejected")]
    Buffer {
        /// Descriptor-table index.
        index: u16,
        /// Buffer address from the descriptor.
        addr: u64,
        /// Buffer length from the descriptor.
        len: u32,
    },
}

impl ImageError {
    fn desc_count(available: usize, capacity: usize) -> Self {
        Self::DescCount {
            available,
            capacity,
        }
    }

    fn event(addr: u64) -> Self {
        Self::Event { addr }
    }

    fn desc(index: u16, reason: DescError) -> Self {
        Self::Desc { index, reason }
    }

    fn buffer(index: u16, addr: u64, len: u32) -> Self {
        Self::Buffer { index, addr, len }
    }
}

/// One available descriptor chain from a validated canonical ring image.
#[derive(Debug, Clone)]
pub struct CanonChain {
    id: u16,
    inner: BufferChain,
}

impl CanonChain {
    fn new(id: u16, chain: BufferChain) -> Self {
        Self { id, inner: chain }
    }

    /// Descriptor ID shared by every buffer in the chain.
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Validated buffers in descriptor order.
    pub fn buffers(&self) -> &BufferChain {
        &self.inner
    }

    /// Consume the image metadata and return its buffer chain.
    pub fn into_buffers(self) -> BufferChain {
        self.inner
    }
}

/// Validate a packed ring while neither peer can modify it.
///
/// The first `avail_descs` descriptors must form complete available chains
/// beginning at descriptor zero. Every remaining descriptor must be zeroed,
/// and both event-suppression structures must be the canonical enabled value.
/// `validate_buf` supplies integration-specific address, length, and
/// direction bounds without embedding them in the ring implementation.
///
/// The returned chains preserve descriptor IDs and chain boundaries for
/// cross-checking against producer and pool ownership.
///
/// # Errors
///
/// Returns [`ImageError`] if event state is not normalized, descriptor
/// structure is malformed, an unused descriptor is not zero, a buffer is
/// rejected by `validate_buf`, or shared memory cannot be read.
pub fn validate_canon_image<M, F>(
    mem: &M,
    layout: Layout,
    avail_descs: usize,
    mut validate_buf: F,
) -> Result<Vec<CanonChain>, ImageError>
where
    M: MemOps,
    F: FnMut(u16, BufferElement) -> bool,
{
    let cap = layout.desc_table_len() as usize;
    if avail_descs > cap {
        return Err(ImageError::desc_count(avail_descs, cap));
    }

    let canon_evt = EventSuppression::new(0, EventFlags::ENABLE);
    for addr in [layout.drv_evt_addr(), layout.dev_evt_addr()] {
        let evt = mem
            .read_val::<EventSuppression>(addr)
            .map_err(|_| RingError::mem_err(MemOp::ReadEvent, addr))?;

        if evt != canon_evt {
            return Err(ImageError::event(addr));
        }
    }

    // SAFETY: `Layout` validates the table base, alignment, and descriptor count.
    let table = unsafe { DescTable::from_raw_parts(layout.desc_table_addr(), cap) };

    let mut seen_ids = FixedBitSet::with_capacity(cap);
    let mut chains = Vec::new();
    let mut pos = 0usize;

    while pos < avail_descs {
        let head_idx = u16::try_from(pos).map_err(|_| RingError::InvalidState)?;
        let (head, _) = read_canon_avail_desc(mem, &table, head_idx)?;
        let id_idx = head.id as usize;
        if id_idx >= cap {
            return Err(ImageError::desc(head_idx, DescError::IdOutOfRange));
        }

        if seen_ids.contains(id_idx) {
            return Err(ImageError::desc(head_idx, DescError::DuplicateId));
        }

        seen_ids.insert(id_idx);

        let mut elems = SmallVec::<[BufferElement; 16]>::new();
        let mut split = 0usize;

        loop {
            let idx = u16::try_from(pos).map_err(|_| RingError::InvalidState)?;
            let (desc, flags) = read_canon_avail_desc(mem, &table, idx)?;
            if desc.id != head.id {
                return Err(ImageError::desc(idx, DescError::IdMismatch));
            }

            let elem = BufferElement::from(&desc);
            if !elem.writable && split != elems.len() {
                return Err(ImageError::desc(idx, DescError::ReadableAfterWritable));
            }

            split += usize::from(!elem.writable);

            if !validate_buf(idx, elem) {
                return Err(ImageError::buffer(idx, elem.addr, elem.len));
            }

            elems.push(elem);
            pos += 1;

            if !flags.contains(DescFlags::NEXT) {
                break;
            }
            if pos >= avail_descs {
                return Err(ImageError::desc(idx, DescError::ChainContinues));
            }
        }

        let canon = CanonChain::new(head.id, BufferChain { elems, split });
        chains.push(canon);
    }

    let empty = Descriptor::zeroed();
    for pos in avail_descs..cap {
        let idx = u16::try_from(pos).map_err(|_| RingError::InvalidState)?;
        let addr = table.desc_addr(idx).ok_or(RingError::InvalidState)?;

        let desc = mem
            .read_val::<Descriptor>(addr)
            .map_err(|_| RingError::mem_err(MemOp::ReadDesc, addr))?;

        if desc != empty {
            return Err(ImageError::desc(idx, DescError::ExpectedZero));
        }
    }

    Ok(chains)
}

fn read_canon_avail_desc<M: MemOps>(
    mem: &M,
    table: &DescTable,
    idx: u16,
) -> Result<(Descriptor, DescFlags), ImageError> {
    let addr = table.desc_addr(idx).ok_or(RingError::InvalidState)?;
    let desc = mem
        .read_val::<Descriptor>(addr)
        .map_err(|_| RingError::mem_err(MemOp::ReadDesc, addr))?;

    let flags = DescFlags::from_bits(desc.flags)
        .ok_or_else(|| ImageError::desc(idx, DescError::UnknownFlags))?;

    if flags.contains(DescFlags::INDIRECT) {
        return Err(ImageError::desc(idx, DescError::Indirect));
    }
    if !flags.is_avail(true) {
        return Err(ImageError::desc(idx, DescError::NotAvailable));
    }

    Ok((desc, flags))
}

#[cfg(test)]
mod tests {
    use super::super::BufferChainBuilder;
    use super::super::tests::{OwnedRing, make_consumer, make_producer, make_ring};
    use super::*;

    fn writable_chain(base: u64, lengths: &[u32]) -> BufferChain {
        BufferChainBuilder::new()
            .writables(lengths.iter().scan(base, |addr, &len| {
                let element = BufferElement {
                    addr: *addr,
                    len,
                    writable: true,
                };
                *addr += len as u64;
                Some(element)
            }))
            .build()
            .unwrap()
    }

    fn validate_all(ring: &OwnedRing, avail_descs: usize) -> Result<Vec<CanonChain>, ImageError> {
        validate_canon_image(&ring.mem(), ring.layout(), avail_descs, |_, _| true)
    }

    #[test]
    fn canon_reset_normalizes_empty_image() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);
        let mut consumer = make_consumer(&ring);

        producer.submit_one(0x1000, 64, true).unwrap();
        producer.enable_used_notifications_desc(3, false).unwrap();
        consumer.enable_avail_notifications_desc(5, false).unwrap();

        producer.reset().unwrap();
        consumer.reset().unwrap();

        assert!(validate_all(&ring, 0).unwrap().is_empty());
        assert_eq!(
            ring.read_driver_event(),
            EventSuppression::new(0, EventFlags::ENABLE)
        );
        assert_eq!(
            ring.read_device_event(),
            EventSuppression::new(0, EventFlags::ENABLE)
        );
        for index in 0..ring.len() as u16 {
            assert_eq!(ring.read_desc(index), Descriptor::zeroed());
        }
    }

    #[test]
    fn canon_multi_desc_refill_is_visible_to_fresh_consumer() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);
        let mut consumer = make_consumer(&ring);

        producer.reset().unwrap();
        consumer.reset().unwrap();

        let chains = [
            writable_chain(0x1000, &[64, 128, 256]),
            writable_chain(0x2000, &[512, 1024]),
            writable_chain(0x4000, &[64, 64, 64]),
        ];
        let mut expected = Vec::new();
        for chain in &chains {
            let id = producer.submit_available(chain).unwrap();
            expected.push((id, chain.len()));
        }

        assert_eq!(producer.num_free(), 0);
        assert_eq!(producer.avail_cursor().head(), 0);
        assert!(!producer.avail_cursor().wrap());

        let image = validate_canon_image(&ring.mem(), ring.layout(), ring.len(), |_, elem| {
            elem.writable
                && elem.len > 0
                && elem
                    .addr
                    .checked_add(elem.len as u64)
                    .is_some_and(|end| end <= 0x5000)
        })
        .unwrap();

        assert_eq!(image.len(), expected.len());
        for (validated, (id, len)) in image.iter().zip(&expected) {
            assert_eq!(validated.id(), *id);
            assert_eq!(validated.buffers().len(), *len);
            assert!(validated.buffers().elems().iter().all(|elem| elem.writable));
            assert_eq!(producer.id_num[*id as usize] as usize, *len);
        }

        let mut fresh = make_consumer(&ring);
        for (expected_id, expected_len) in expected {
            let (id, chain) = fresh.poll_available().unwrap();
            assert_eq!(id, expected_id);
            assert_eq!(chain.len(), expected_len);
        }
        assert!(matches!(fresh.poll_available(), Err(RingError::WouldBlock)));
    }

    #[test]
    fn canon_image_rejects_invalid_ids() {
        let duplicate_ring = make_ring(4);
        let mut producer = make_producer(&duplicate_ring);
        producer.submit_one(0x1000, 64, true).unwrap();
        producer.submit_one(0x2000, 64, true).unwrap();

        let head_id = duplicate_ring.read_desc(0).id;
        let mut duplicate = duplicate_ring.read_desc(1);
        duplicate.id = head_id;
        duplicate_ring.write_desc(1, duplicate);

        assert!(matches!(
            validate_all(&duplicate_ring, 2),
            Err(ImageError::Desc {
                index: 1,
                reason: DescError::DuplicateId,
            })
        ));

        let mismatch_ring = make_ring(4);
        let mut producer = make_producer(&mismatch_ring);
        producer
            .submit_available(&writable_chain(0x3000, &[64, 64]))
            .unwrap();

        let mut tail = mismatch_ring.read_desc(1);
        tail.id = tail.id.wrapping_sub(1);
        mismatch_ring.write_desc(1, tail);

        assert!(matches!(
            validate_all(&mismatch_ring, 2),
            Err(ImageError::Desc {
                index: 1,
                reason: DescError::IdMismatch,
            })
        ));

        let range_ring = make_ring(4);
        let mut producer = make_producer(&range_ring);
        producer.submit_one(0x4000, 64, true).unwrap();

        let mut out_of_range = range_ring.read_desc(0);
        out_of_range.id = range_ring.len() as u16;
        range_ring.write_desc(0, out_of_range);

        assert!(matches!(
            validate_all(&range_ring, 1),
            Err(ImageError::Desc {
                index: 0,
                reason: DescError::IdOutOfRange,
            })
        ));
    }

    #[test]
    fn canon_image_rejects_invalid_flags_and_wrap_state() {
        let unknown_ring = make_ring(4);
        let mut producer = make_producer(&unknown_ring);
        producer.submit_one(0x1000, 64, true).unwrap();

        let mut unknown = unknown_ring.read_desc(0);
        unknown.flags |= 1 << 3;
        unknown_ring.write_desc(0, unknown);

        assert!(matches!(
            validate_all(&unknown_ring, 1),
            Err(ImageError::Desc {
                index: 0,
                reason: DescError::UnknownFlags,
            })
        ));

        let used_ring = make_ring(4);
        let mut producer = make_producer(&used_ring);
        producer.submit_one(0x2000, 64, true).unwrap();

        let mut used = used_ring.read_desc(0);
        used.mark_used(true);
        used_ring.write_desc(0, used);

        assert!(matches!(
            validate_all(&used_ring, 1),
            Err(ImageError::Desc {
                index: 0,
                reason: DescError::NotAvailable,
            })
        ));

        let indirect_ring = make_ring(4);
        let mut producer = make_producer(&indirect_ring);
        producer.submit_one(0x3000, 64, true).unwrap();

        let mut indirect = indirect_ring.read_desc(0);
        indirect.flags |= DescFlags::INDIRECT.bits();
        indirect_ring.write_desc(0, indirect);

        assert!(matches!(
            validate_all(&indirect_ring, 1),
            Err(ImageError::Desc {
                index: 0,
                reason: DescError::Indirect,
            })
        ));
    }

    #[test]
    fn canon_image_rejects_malformed_chain_and_unused_desc() {
        let chain_ring = make_ring(4);
        let mut producer = make_producer(&chain_ring);
        producer
            .submit_available(&writable_chain(0x1000, &[64, 64]))
            .unwrap();

        let mut tail = chain_ring.read_desc(1);
        tail.flags |= DescFlags::NEXT.bits();
        chain_ring.write_desc(1, tail);

        assert!(matches!(
            validate_all(&chain_ring, 2),
            Err(ImageError::Desc {
                index: 1,
                reason: DescError::ChainContinues,
            })
        ));

        let unused_ring = make_ring(4);
        let mut producer = make_producer(&unused_ring);
        producer.submit_one(0x2000, 64, true).unwrap();
        unused_ring.write_desc(3, Descriptor::new(0x3000, 64, 0, DescFlags::empty()));

        assert!(matches!(
            validate_all(&unused_ring, 1),
            Err(ImageError::Desc {
                index: 3,
                reason: DescError::ExpectedZero,
            })
        ));

        let direction_ring = make_ring(4);
        let mut producer = make_producer(&direction_ring);
        producer
            .submit_available(&writable_chain(0x4000, &[64, 64]))
            .unwrap();

        let mut readable_tail = direction_ring.read_desc(1);
        readable_tail.flags &= !DescFlags::WRITE.bits();
        direction_ring.write_desc(1, readable_tail);

        assert!(matches!(
            validate_all(&direction_ring, 2),
            Err(ImageError::Desc {
                index: 1,
                reason: DescError::ReadableAfterWritable,
            })
        ));
    }

    #[test]
    fn canon_image_rejects_noncanon_evt_and_buffer_bounds() {
        let evt_ring = make_ring(4);
        evt_ring
            .mem()
            .write_val(
                evt_ring.layout().drv_evt_addr(),
                EventSuppression::new(1, EventFlags::ENABLE),
            )
            .unwrap();

        match validate_all(&evt_ring, 0) {
            Err(ImageError::Event { addr }) => {
                let expected = evt_ring.layout().drv_evt_addr();
                assert_eq!(addr, expected);
            }
            other => unreachable!("unexpected result: {other:?}"),
        }

        let bounds = make_ring(4);
        let mut producer = make_producer(&bounds);
        producer.submit_one(u64::MAX - 15, 32, true).unwrap();

        let res = validate_canon_image(&bounds.mem(), bounds.layout(), 1, |_, element| {
            element
                .addr
                .checked_add(element.len as u64)
                .is_some_and(|end| end <= 0x8000)
        });

        match res {
            Err(ImageError::Buffer { index, addr, len }) => {
                assert_eq!(index, 0);
                assert_eq!(addr, u64::MAX - 15);
                assert_eq!(len, 32);
            }
            other => unreachable!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn canon_image_rejects_avail_count_over_capacity() {
        let ring = make_ring(4);
        assert!(matches!(
            validate_all(&ring, 5),
            Err(ImageError::DescCount {
                available: 5,
                capacity: 4,
            })
        ));
    }
}
