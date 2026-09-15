// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Owned and segmented virtqueue buffer representations.

use alloc::vec::Vec;

use bytes::{Buf, Bytes};
use smallvec::{SmallVec, smallvec};

use super::{Allocation, SlotPool};

/// Ordered byte segments that make up one virtqueue payload.
///
/// This is the high-level counterpart to the descriptor-oriented
/// [`BufferChain`](super::BufferChain).
#[derive(Debug, Clone, Default)]
pub struct Segments(SmallVec<[Bytes; 4]>);

impl Segments {
    /// Build a segmented payload from ordered byte segments.
    pub fn new(segments: impl IntoIterator<Item = Bytes>) -> Self {
        Self(segments.into_iter().collect())
    }

    /// Build a single-segment payload.
    pub fn single(segment: Bytes) -> Self {
        Self(smallvec![segment])
    }

    pub(crate) fn from_smallvec(segments: SmallVec<[Bytes; 4]>) -> Self {
        Self(segments)
    }

    /// Total payload length across all segments.
    pub fn len(&self) -> usize {
        self.0.iter().map(Bytes::len).sum()
    }

    /// Whether the payload contains zero bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of byte segments.
    pub fn segment_count(&self) -> usize {
        self.0.len()
    }

    /// Borrow all segments.
    pub fn as_slice(&self) -> &[Bytes] {
        &self.0
    }

    /// Iterate over segments.
    pub fn iter(&self) -> impl Iterator<Item = &Bytes> {
        self.0.iter()
    }

    /// Append another payload without copying its bytes.
    pub fn append(&mut self, other: Self) {
        self.0.extend(other.0);
    }

    /// Split off an owned byte prefix without copying payload data.
    ///
    /// Returns `None` and leaves `self` unchanged when `len` exceeds the
    /// remaining payload length. A split within a segment creates shared
    /// [`Bytes`] slices backed by the same owner.
    pub fn split_to(&mut self, len: usize) -> Option<Self> {
        if len > self.len() {
            return None;
        }

        let mut prefix = SmallVec::<[Bytes; 4]>::new();
        let mut remaining = len;

        while remaining != 0 {
            let mut segment = self.0.remove(0);
            if segment.len() <= remaining {
                remaining -= segment.len();
                prefix.push(segment);
            } else {
                prefix.push(segment.split_to(remaining));
                self.0.insert(0, segment);
                remaining = 0;
            }
        }

        Some(Self(prefix))
    }

    /// Borrow this payload as a [`Buf`] cursor.
    pub fn as_buf(&self) -> SegmentsBuf<'_> {
        SegmentsBuf::new(&self.0, self.len())
    }

    /// Return this payload as contiguous bytes.
    ///
    /// This is O(1) for zero or one segment, and allocates/copies for multiple
    /// segments.
    pub fn to_bytes(&self) -> Bytes {
        match self.0.as_slice() {
            [] => Bytes::new(),
            [segment] => segment.clone(),
            _ => self.collect(&self.0, self.len()),
        }
    }

    /// Consume this payload and return contiguous bytes.
    ///
    /// This is O(1) for zero or one segment, and allocates/copies for multiple
    /// segments.
    pub fn into_bytes(mut self) -> Bytes {
        match self.0.len() {
            0 => Bytes::new(),
            1 => self.0.pop().unwrap_or_default(),
            _ => self.collect(&self.0, self.len()),
        }
    }

    /// Consume this payload without flattening its segments.
    pub fn into_chunks(self) -> Vec<Bytes> {
        self.0.into_vec()
    }

    fn collect(&self, sgs: &[Bytes], len: usize) -> Bytes {
        let mut out = Vec::with_capacity(len);
        for seg in sgs {
            out.extend_from_slice(seg);
        }
        Bytes::from(out)
    }
}

/// Borrowed [`Buf`] cursor over [`Segments`].
///
/// Advancing the cursor does not mutate the underlying [`Segments`].
#[derive(Debug, Clone)]
pub struct SegmentsBuf<'a> {
    segments: &'a [Bytes],
    index: usize,
    offset: usize,
    remaining: usize,
}

impl<'a> SegmentsBuf<'a> {
    fn new(segments: &'a [Bytes], len: usize) -> Self {
        let mut this = Self {
            segments,
            index: 0,
            offset: 0,
            remaining: len,
        };

        this.skip_empty_segments();
        this
    }

    fn skip_empty_segments(&mut self) {
        while self.index < self.segments.len() && self.offset >= self.segments[self.index].len() {
            self.index += 1;
            self.offset = 0;
        }
    }
}

impl Buf for SegmentsBuf<'_> {
    fn remaining(&self) -> usize {
        self.remaining
    }

    fn chunk(&self) -> &[u8] {
        if self.remaining == 0 {
            return &[];
        }

        let segment = self.segments[self.index].as_ref();
        &segment[self.offset..]
    }

    fn advance(&mut self, cnt: usize) {
        assert!(cnt <= self.remaining, "cannot advance past remaining bytes");

        self.remaining -= cnt;
        let mut cnt = cnt;

        while cnt > 0 {
            let seg_rem = self.segments[self.index].len() - self.offset;
            let n = seg_rem.min(cnt);
            self.offset += n;
            cnt -= n;
            self.skip_empty_segments();
        }

        if self.remaining == 0 {
            self.index = self.segments.len();
            self.offset = 0;
        }
    }
}

/// An exclusively owned buffer allocation returned to its pool on drop.
pub struct BufferLease {
    /// The pool that allocated the buffer.
    pool: SlotPool,
    /// The buffer's start address and full allocation capacity.
    allocation: Allocation,
}

impl BufferLease {
    /// Create a new buffer lease from a pool and allocation.
    pub fn new(pool: SlotPool, allocation: Allocation) -> Self {
        Self { pool, allocation }
    }

    /// The buffer's start address and full allocation capacity.
    pub fn allocation(&self) -> Allocation {
        self.allocation
    }
}

impl Drop for BufferLease {
    fn drop(&mut self) {
        if let Err(error) = self.pool.dealloc(self.allocation.addr) {
            log::error!("Failed to release a virtqueue buffer: {error}");
            debug_assert!(false, "BufferLease deallocation failed: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use bytes::Buf;

    use super::*;
    use crate::virtq::{SlotLayout, SlotPool};

    #[test]
    fn lease_returns_slot_on_drop() {
        let pool = SlotPool::new(SlotLayout::new(0, 4, 1)).unwrap();
        let allocation = pool.alloc(4).unwrap();
        let lease = BufferLease::new(pool.clone(), allocation);

        assert_eq!(lease.allocation().addr, allocation.addr);
        assert_eq!(lease.allocation().len, 4);
        assert_eq!(pool.num_free(), 0);

        drop(lease);
        assert_eq!(pool.num_free(), 1);

        let reused = pool.alloc(4).unwrap();
        assert_eq!(reused.addr, allocation.addr);
        pool.dealloc(reused.addr).unwrap();
    }

    #[test]
    fn segments_cursor_advances_across_segments() {
        let segments = Segments::new([
            Bytes::from_static(b"abc"),
            Bytes::from_static(b"def"),
            Bytes::from_static(b"ghi"),
        ]);
        let mut cursor = segments.as_buf();

        assert_eq!(cursor.remaining(), 9);
        assert_eq!(cursor.chunk(), b"abc");

        cursor.advance(2);
        assert_eq!(cursor.remaining(), 7);
        assert_eq!(cursor.chunk(), b"c");

        cursor.advance(1);
        assert_eq!(cursor.chunk(), b"def");

        cursor.advance(4);
        assert_eq!(cursor.chunk(), b"hi");

        cursor.advance(2);
        assert_eq!(cursor.remaining(), 0);
        assert_eq!(cursor.chunk(), b"");
    }

    #[test]
    fn segments_cursor_skips_empty_segments() {
        let segments = Segments::new([
            Bytes::new(),
            Bytes::from_static(b"ab"),
            Bytes::new(),
            Bytes::from_static(b"cd"),
            Bytes::new(),
        ]);
        let mut cursor = segments.as_buf();

        assert_eq!(cursor.remaining(), 4);
        assert_eq!(cursor.chunk(), b"ab");

        cursor.advance(2);
        assert_eq!(cursor.remaining(), 2);
        assert_eq!(cursor.chunk(), b"cd");

        cursor.advance(2);
        assert!(!cursor.has_remaining());
        assert_eq!(cursor.chunk(), b"");
    }

    #[test]
    fn segments_cursor_reads_split_header_without_collecting_all_segments() {
        let segments = Segments::new([
            Bytes::from_static(&[0x01, 0x02, 0x03]),
            Bytes::from_static(&[0x04, 0x05]),
            Bytes::from_static(&[0x06, 0x07, 0x08, 0xff]),
        ]);
        let mut cursor = segments.as_buf();
        let mut header = [0u8; 8];

        cursor.try_copy_to_slice(&mut header).unwrap();

        assert_eq!(header, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(cursor.remaining(), 1);
        assert_eq!(cursor.chunk(), &[0xff]);
    }

    #[test]
    fn segments_cursor_copy_to_bytes_collects_only_requested_prefix() {
        let segments = Segments::new([
            Bytes::from_static(b"hello"),
            Bytes::from_static(b" "),
            Bytes::from_static(b"world"),
        ]);
        let mut cursor = segments.as_buf();

        let prefix = cursor.copy_to_bytes(6);

        assert_eq!(prefix.as_ref(), b"hello ");
        assert_eq!(cursor.remaining(), 5);
        assert_eq!(cursor.chunk(), b"world");
    }

    #[test]
    fn segments_split_to_shares_boundary_segment() {
        let boundary = Bytes::from(vec![b'd', b'e', b'f']);
        let boundary_ptr = boundary.as_ptr();
        let mut segments = Segments::new([
            Bytes::from_static(b"abc"),
            boundary,
            Bytes::from_static(b"ghi"),
        ]);

        let prefix = segments.split_to(5).unwrap();

        assert_eq!(prefix.segment_count(), 2);
        assert_eq!(prefix.to_bytes().as_ref(), b"abcde");
        assert_eq!(prefix.as_slice()[1].as_ptr(), boundary_ptr);
        assert_eq!(segments.segment_count(), 2);
        assert_eq!(segments.to_bytes().as_ref(), b"fghi");
        assert_eq!(
            segments.as_slice()[0].as_ptr(),
            boundary_ptr.wrapping_add(2)
        );

        assert!(segments.split_to(5).is_none());
        assert_eq!(segments.to_bytes().as_ref(), b"fghi");
    }

    #[test]
    fn segments_into_bytes_reuses_single_segment() {
        let segment = Bytes::from(vec![1, 2, 3, 4]);
        let ptr = segment.as_ptr();

        let collected = Segments::single(segment).into_bytes();

        assert_eq!(collected.as_ptr(), ptr);
        assert_eq!(collected.as_ref(), &[1, 2, 3, 4]);
    }

    #[test]
    fn segments_into_chunks_preserves_segment_storage() {
        let first = Bytes::from(vec![1, 2]);
        let second = Bytes::from(vec![3, 4]);
        let first_ptr = first.as_ptr();
        let second_ptr = second.as_ptr();

        let chunks = Segments::new([first, second]).into_chunks();

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].as_ptr(), first_ptr);
        assert_eq!(chunks[1].as_ptr(), second_ptr);
    }

    #[test]
    fn segments_append_keeps_small_payloads_inline() {
        let chunks = [
            Bytes::from(vec![1]),
            Bytes::from(vec![2]),
            Bytes::from(vec![3]),
            Bytes::from(vec![4]),
        ];
        let ptrs = chunks.each_ref().map(|chunk| chunk.as_ptr());
        let [first, second, third, fourth] = chunks;
        let mut segments = Segments::new([first, second]);

        // Four segments fit in the inline storage.
        segments.append(Segments::new([third, fourth]));
        assert!(!segments.0.spilled());
        assert_eq!(segments.len(), 4);
        assert_eq!(segments.segment_count(), 4);
        assert_eq!(segments.to_bytes().as_ref(), &[1, 2, 3, 4]);
        for (segment, ptr) in segments.iter().zip(ptrs) {
            assert_eq!(segment.as_ptr(), ptr);
        }
    }

    #[test]
    fn segments_append_spills_in_order() {
        let mut segments = Segments::new((0..4).map(|byte| Bytes::from(vec![byte])));
        let last = Bytes::from(vec![4]);
        let ptr = last.as_ptr();
        assert!(!segments.0.spilled());

        // The fifth segment requires heap storage for the segment list.
        segments.append(Segments::single(last));
        assert!(segments.0.spilled());
        assert_eq!(segments.len(), 5);
        assert_eq!(segments.segment_count(), 5);
        assert_eq!(segments.to_bytes().as_ref(), &[0, 1, 2, 3, 4]);
        assert_eq!(segments.as_slice()[4].as_ptr(), ptr);
    }

    #[test]
    fn segments_append_to_empty() {
        let bytes = Bytes::from(vec![1, 2, 3]);
        let ptr = bytes.as_ptr();
        let mut segments = Segments::default();

        segments.append(Segments::single(bytes));

        assert_eq!(segments.len(), 3);
        assert_eq!(segments.segment_count(), 1);
        assert_eq!(segments.as_slice()[0].as_ptr(), ptr);
        assert_eq!(segments.as_slice()[0].as_ref(), &[1, 2, 3]);
    }

    #[test]
    fn segments_append_empty_payload() {
        let bytes = Bytes::from(vec![1, 2, 3]);
        let ptr = bytes.as_ptr();
        let mut segments = Segments::single(bytes);

        segments.append(Segments::default());

        assert_eq!(segments.len(), 3);
        assert_eq!(segments.segment_count(), 1);
        assert_eq!(segments.as_slice()[0].as_ptr(), ptr);
        assert_eq!(segments.as_slice()[0].as_ref(), &[1, 2, 3]);
    }

    #[test]
    fn segments_append_preserves_owner_lifetime() {
        let storage: Arc<[u8]> = Arc::from(&b"data"[..]);
        let owner = Arc::downgrade(&storage);
        let mut segments = Segments::single(Bytes::from_static(b"header"));

        // The appended segment becomes the only owner of this storage.
        segments.append(Segments::single(Bytes::from_owner(storage)));
        assert_eq!(owner.strong_count(), 1);
        assert_eq!(segments.to_bytes().as_ref(), b"headerdata");

        drop(segments);
        assert!(owner.upgrade().is_none());
    }
}
