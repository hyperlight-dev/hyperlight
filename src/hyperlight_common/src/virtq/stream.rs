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

//! Stream table and flow-control primitives for virtqueue byte streams.
//!
//! This module provides the `no_std`-friendly core types used on both
//! the guest and host sides:
//!
//! - [`StreamId`], [`StreamHandle`]: identification and cross-boundary
//!   handle shape.
//! - [`StreamDirection`]: G2H vs H2G per-direction ID spaces.
//! - [`StreamTable`]: per-direction table of open streams, with a
//!   generation counter (bumped on sandbox reset) that gates stale
//!   messages.
//! - Credit accounting: [`WriterCredit`] / [`ReaderCredit`] wrappers
//!   plus signed-arithmetic helpers that mirror virtio-vsock's
//!   wrap-safe math.
//!
//! Only the data model and arithmetic lives here. Wiring to the
//! producer/consumer virtqueues lives in the guest and host crates
//! (Phase 2/3).

use alloc::vec::Vec;

use crate::virtq::msg::{STREAM_GEN_MASK, STREAM_ID_MAX};

/// Default initial credit (bytes) a newly-created local stream end
/// advertises to its peer. One BufferPool slot's worth for MVP.
pub const STREAM_INITIAL_CREDIT: u32 = 4096;

/// Direction a stream flows over the virtqueue pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamDirection {
    /// Guest produces, host consumes.
    Guest2Host,
    /// Host produces, guest consumes.
    Host2Guest,
}

/// 12-bit stream id within a given direction and generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(u16);

impl StreamId {
    /// Construct from a raw 12-bit value. Returns `None` if out of range.
    pub const fn from_u16(id: u16) -> Option<Self> {
        if id > STREAM_ID_MAX {
            None
        } else {
            Some(Self(id))
        }
    }

    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

/// Opaque handle identifying a stream across the VM boundary.
///
/// Carries the minimum information needed to route messages and to
/// reject stale traffic after sandbox reset. The `initial_credit` is
/// the buffer capacity the receiver advertises at handle-transfer time
/// (bootstraps the peer's `buf_alloc`). `None` means "use the default".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamHandle {
    pub direction: StreamDirection,
    pub generation: u8,
    pub stream_id: StreamId,
    pub initial_credit: Option<u32>,
}

impl StreamHandle {
    pub const fn new(
        direction: StreamDirection,
        generation: u8,
        stream_id: StreamId,
        initial_credit: Option<u32>,
    ) -> Self {
        Self {
            direction,
            generation,
            stream_id,
            initial_credit,
        }
    }
}

/// Writer-side credit accounting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WriterCredit {
    /// Total bytes this writer has transmitted.
    pub tx_cnt: u32,
    /// Last `fwd_cnt` advertised by the reader.
    pub peer_fwd_cnt: u32,
    /// Last `buf_alloc` advertised by the reader.
    pub peer_buf_alloc: u32,
}

impl WriterCredit {
    /// Initial writer state. `peer_buf_alloc` should be seeded to the
    /// reader's bootstrap credit.
    pub const fn new(peer_buf_alloc: u32) -> Self {
        Self {
            tx_cnt: 0,
            peer_fwd_cnt: 0,
            peer_buf_alloc,
        }
    }

    /// Bytes the writer may transmit right now without overrunning the
    /// reader's advertised buffer. Uses signed 64-bit arithmetic so
    /// that a peer shrinking its buffer below the in-flight count
    /// returns 0 instead of underflowing.
    pub fn available(&self) -> u32 {
        available_credit(self.peer_buf_alloc, self.tx_cnt, self.peer_fwd_cnt)
    }

    /// Record that `n` bytes have been placed on the wire. Saturating
    /// to avoid spurious panics on pathological peer state; the writer
    /// is expected to have clamped `n` to `available()` beforehand.
    pub fn record_sent(&mut self, n: u32) {
        self.tx_cnt = self.tx_cnt.wrapping_add(n);
    }

    /// Absorb a preamble observed from the reader.
    ///
    /// Only monotonically-newer counters are adopted: `fwd_cnt` uses
    /// signed wrap-safe comparison; `buf_alloc` is whatever the reader
    /// last said (it can grow or shrink).
    pub fn observe_peer(&mut self, peer_fwd_cnt: u32, peer_buf_alloc: u32) {
        if wrap_gt(peer_fwd_cnt, self.peer_fwd_cnt) {
            self.peer_fwd_cnt = peer_fwd_cnt;
        }
        self.peer_buf_alloc = peer_buf_alloc;
    }
}

/// Reader-side credit accounting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReaderCredit {
    /// Total bytes this reader has delivered to the consumer.
    pub fwd_cnt: u32,
    /// Buffer capacity advertised to the writer. May be lowered by
    /// raising it only when a threshold of space has been freed.
    pub buf_alloc: u32,
}

impl ReaderCredit {
    pub const fn new(buf_alloc: u32) -> Self {
        Self {
            fwd_cnt: 0,
            buf_alloc,
        }
    }

    /// Record that `n` bytes have been consumed by the reader.
    pub fn record_consumed(&mut self, n: u32) {
        self.fwd_cnt = self.fwd_cnt.wrapping_add(n);
    }
}

/// Signed wrap-safe "strictly greater than". Returns `true` if `a` is
/// a newer counter value than `b`, tolerating u32 wraparound.
pub fn wrap_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

/// Available credit (in bytes) given the reader's advertised buffer
/// and the writer's current tx/peer-fwd counters. Implements the
/// vsock-equivalent calculation with signed arithmetic to survive
/// peer_buf_alloc shrinking.
pub fn available_credit(peer_buf_alloc: u32, tx_cnt: u32, peer_fwd_cnt: u32) -> u32 {
    let in_flight = tx_cnt.wrapping_sub(peer_fwd_cnt) as i64;
    let avail = peer_buf_alloc as i64 - in_flight;
    if avail <= 0 {
        0
    } else if avail > u32::MAX as i64 {
        u32::MAX
    } else {
        avail as u32
    }
}

/// Lifecycle state of a single stream entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamLifecycle {
    /// Open - data and control messages flow normally.
    Open,
    /// Writer has sent StreamEnd; reader may still drain buffered
    /// chunks, but no new data will arrive.
    WriterClosed,
    /// Reader has sent Cancel; writer must stop producing.
    Cancelled,
    /// Fully closed; entry will be reaped on the next sweep.
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndRole {
    /// This side is the writer for the stream (peer reads).
    Writer,
    /// This side is the reader for the stream (peer writes).
    Reader,
}

#[derive(Debug)]
struct StreamEntry {
    id: StreamId,
    #[allow(dead_code)] // Used in later phases for role-based routing.
    role: EndRole,
    writer: WriterCredit,
    reader: ReaderCredit,
    state: StreamLifecycle,
}

/// Per-direction stream table.
///
/// - Allocates [`StreamId`]s monotonically (no ID reuse within a
///   generation) to avoid races with late Cancel/CreditUpdate messages.
/// - Tracks a `generation` counter bumped on sandbox reset; inbound
///   messages carrying a mismatched generation are considered stale
///   and dropped by the routing layer.
#[derive(Debug)]
pub struct StreamTable {
    direction: StreamDirection,
    generation: u8,
    next_id: u16,
    entries: Vec<StreamEntry>,
}

/// Errors produced by [`StreamTable`] mutations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamTableError {
    /// All stream IDs for the current generation have been used.
    IdSpaceExhausted,
    /// Referenced stream id is not present in the table.
    Unknown(StreamId),
}

impl StreamTable {
    pub fn new(direction: StreamDirection) -> Self {
        Self {
            direction,
            generation: 0,
            next_id: 0,
            entries: Vec::new(),
        }
    }

    pub fn direction(&self) -> StreamDirection {
        self.direction
    }

    pub fn generation(&self) -> u8 {
        self.generation
    }

    pub fn len(&self) -> usize {
        self.entries.iter().filter(|e| !e.is_reaped()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bump the generation and drop all open streams. Called on sandbox
    /// reset/restore. Returns the new generation.
    pub fn reset(&mut self) -> u8 {
        self.generation = (self.generation.wrapping_add(1)) & (STREAM_GEN_MASK as u8);
        self.next_id = 0;
        self.entries.clear();
        self.generation
    }

    /// Allocate a new stream id and register it as a locally-owned end.
    /// `role_is_writer` indicates whether this side is the writer
    /// (peer reads) or reader (peer writes).
    fn allocate(
        &mut self,
        role: EndRole,
        local_buf_alloc: u32,
        peer_buf_alloc: u32,
    ) -> Result<StreamId, StreamTableError> {
        if self.next_id > STREAM_ID_MAX {
            return Err(StreamTableError::IdSpaceExhausted);
        }
        let id = StreamId(self.next_id);
        self.next_id += 1;
        self.entries.push(StreamEntry {
            id,
            role,
            writer: WriterCredit::new(peer_buf_alloc),
            reader: ReaderCredit::new(local_buf_alloc),
            state: StreamLifecycle::Open,
        });
        Ok(id)
    }

    /// Register a locally-owned writer end. Typically called by the
    /// side that is producing into the stream.
    pub fn open_writer(
        &mut self,
        local_buf_alloc: u32,
        peer_buf_alloc: u32,
    ) -> Result<StreamId, StreamTableError> {
        self.allocate(EndRole::Writer, local_buf_alloc, peer_buf_alloc)
    }

    /// Register a locally-owned reader end.
    pub fn open_reader(
        &mut self,
        local_buf_alloc: u32,
        peer_buf_alloc: u32,
    ) -> Result<StreamId, StreamTableError> {
        self.allocate(EndRole::Reader, local_buf_alloc, peer_buf_alloc)
    }

    fn find_mut(&mut self, id: StreamId) -> Result<&mut StreamEntry, StreamTableError> {
        self.entries
            .iter_mut()
            .find(|e| e.id == id && !e.is_reaped())
            .ok_or(StreamTableError::Unknown(id))
    }

    fn find(&self, id: StreamId) -> Result<&StreamEntry, StreamTableError> {
        self.entries
            .iter()
            .find(|e| e.id == id && !e.is_reaped())
            .ok_or(StreamTableError::Unknown(id))
    }

    pub fn lifecycle(&self, id: StreamId) -> Result<StreamLifecycle, StreamTableError> {
        self.find(id).map(|e| e.state)
    }

    pub fn writer_credit(&self, id: StreamId) -> Result<WriterCredit, StreamTableError> {
        self.find(id).map(|e| e.writer)
    }

    pub fn reader_credit(&self, id: StreamId) -> Result<ReaderCredit, StreamTableError> {
        self.find(id).map(|e| e.reader)
    }

    /// Apply a preamble observed from the peer for this stream. Updates
    /// writer-side peer counters (only fields the peer-as-reader
    /// advertises are meaningful).
    pub fn observe_peer(
        &mut self,
        id: StreamId,
        peer_fwd_cnt: u32,
        peer_buf_alloc: u32,
    ) -> Result<(), StreamTableError> {
        let entry = self.find_mut(id)?;
        entry.writer.observe_peer(peer_fwd_cnt, peer_buf_alloc);
        Ok(())
    }

    /// Record that the local writer end has put `n` bytes on the wire.
    pub fn record_sent(&mut self, id: StreamId, n: u32) -> Result<(), StreamTableError> {
        let entry = self.find_mut(id)?;
        entry.writer.record_sent(n);
        Ok(())
    }

    /// Record that the local reader end has consumed `n` bytes.
    pub fn record_consumed(&mut self, id: StreamId, n: u32) -> Result<(), StreamTableError> {
        let entry = self.find_mut(id)?;
        entry.reader.record_consumed(n);
        Ok(())
    }

    /// Mark the writer as closed (sent StreamEnd).
    pub fn mark_writer_closed(&mut self, id: StreamId) -> Result<(), StreamTableError> {
        let entry = self.find_mut(id)?;
        entry.state = match entry.state {
            StreamLifecycle::Open => StreamLifecycle::WriterClosed,
            other => other,
        };
        Ok(())
    }

    /// Mark the stream as cancelled.
    pub fn mark_cancelled(&mut self, id: StreamId) -> Result<(), StreamTableError> {
        let entry = self.find_mut(id)?;
        entry.state = StreamLifecycle::Cancelled;
        Ok(())
    }

    /// Fully close and reap the entry.
    pub fn close(&mut self, id: StreamId) -> Result<(), StreamTableError> {
        let entry = self.find_mut(id)?;
        entry.state = StreamLifecycle::Closed;
        Ok(())
    }

    /// Returns true if a message with the given generation should be
    /// accepted for this table.
    pub fn accepts_generation(&self, generation: u8) -> bool {
        generation == self.generation
    }
}

impl StreamEntry {
    fn is_reaped(&self) -> bool {
        matches!(self.state, StreamLifecycle::Closed)
    }

    #[cfg(test)]
    fn role(&self) -> EndRole {
        self.role
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn available_credit_basic() {
        assert_eq!(available_credit(100, 0, 0), 100);
        assert_eq!(available_credit(100, 30, 0), 70);
        assert_eq!(available_credit(100, 100, 0), 0);
        assert_eq!(available_credit(100, 100, 30), 30);
    }

    #[test]
    fn available_credit_peer_shrink() {
        // peer shrinks buf_alloc below in-flight bytes
        assert_eq!(available_credit(10, 50, 30), 0);
    }

    #[test]
    fn available_credit_wrap() {
        // tx_cnt has wrapped past peer_fwd_cnt
        let tx = 5u32;
        let peer_fwd = u32::MAX - 10;
        let in_flight = tx.wrapping_sub(peer_fwd);
        assert_eq!(in_flight, 16);
        assert_eq!(available_credit(100, tx, peer_fwd), 84);
    }

    #[test]
    fn wrap_gt_near_zero_and_max() {
        assert!(wrap_gt(10, 5));
        assert!(!wrap_gt(5, 10));
        // 1 is "newer" than u32::MAX despite smaller absolute value
        assert!(wrap_gt(1, u32::MAX));
        assert!(!wrap_gt(u32::MAX, 1));
    }

    #[test]
    fn writer_observe_monotonic() {
        let mut w = WriterCredit::new(100);
        w.observe_peer(10, 200);
        assert_eq!(w.peer_fwd_cnt, 10);
        assert_eq!(w.peer_buf_alloc, 200);
        // Older fwd_cnt is ignored
        w.observe_peer(5, 150);
        assert_eq!(w.peer_fwd_cnt, 10);
        assert_eq!(w.peer_buf_alloc, 150);
    }

    #[test]
    fn writer_record_sent_and_available() {
        let mut w = WriterCredit::new(100);
        assert_eq!(w.available(), 100);
        w.record_sent(60);
        assert_eq!(w.available(), 40);
        w.observe_peer(50, 100);
        assert_eq!(w.available(), 90);
    }

    #[test]
    fn table_allocates_and_closes() {
        let mut t = StreamTable::new(StreamDirection::Guest2Host);
        assert!(t.is_empty());
        let a = t.open_writer(4096, 4096).unwrap();
        let b = t.open_reader(4096, 4096).unwrap();
        assert_ne!(a, b);
        assert_eq!(t.len(), 2);
        assert_eq!(t.lifecycle(a), Ok(StreamLifecycle::Open));
        t.mark_writer_closed(a).unwrap();
        assert_eq!(t.lifecycle(a), Ok(StreamLifecycle::WriterClosed));
        t.close(a).unwrap();
        assert_eq!(t.lifecycle(a), Err(StreamTableError::Unknown(a)));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn table_ids_are_not_reused() {
        let mut t = StreamTable::new(StreamDirection::Host2Guest);
        let a = t.open_writer(4096, 4096).unwrap();
        t.close(a).unwrap();
        let b = t.open_writer(4096, 4096).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn table_reset_bumps_generation_and_drops_entries() {
        let mut t = StreamTable::new(StreamDirection::Guest2Host);
        let _a = t.open_writer(4096, 4096).unwrap();
        let _b = t.open_reader(4096, 4096).unwrap();
        assert_eq!(t.generation(), 0);
        let g = t.reset();
        assert_eq!(g, 1);
        assert!(t.is_empty());
        let c = t.open_writer(4096, 4096).unwrap();
        assert_eq!(c, StreamId(0));
        assert!(t.accepts_generation(1));
        assert!(!t.accepts_generation(0));
    }

    #[test]
    fn table_reset_wraps_generation() {
        let mut t = StreamTable::new(StreamDirection::Guest2Host);
        for _ in 0..16 {
            t.reset();
        }
        assert_eq!(t.generation(), 0);
    }

    #[test]
    fn table_id_space_exhaustion() {
        let mut t = StreamTable::new(StreamDirection::Guest2Host);
        // Drain to the end of the 12-bit space.
        t.next_id = STREAM_ID_MAX;
        let id = t.open_writer(4096, 4096).unwrap();
        assert_eq!(id.as_u16(), STREAM_ID_MAX);
        let err = t.open_writer(4096, 4096).unwrap_err();
        assert_eq!(err, StreamTableError::IdSpaceExhausted);
    }

    #[test]
    fn observe_and_counters_flow() {
        let mut t = StreamTable::new(StreamDirection::Guest2Host);
        let id = t.open_writer(4096, 1024).unwrap();
        t.record_sent(id, 500).unwrap();
        let credit = t.writer_credit(id).unwrap();
        assert_eq!(credit.tx_cnt, 500);
        assert_eq!(credit.available(), 524);

        t.observe_peer(id, 200, 2048).unwrap();
        let credit = t.writer_credit(id).unwrap();
        assert_eq!(credit.peer_fwd_cnt, 200);
        assert_eq!(credit.peer_buf_alloc, 2048);
        assert_eq!(credit.available(), 2048 - (500 - 200));
    }

    #[test]
    fn unknown_ids_are_rejected() {
        let mut t = StreamTable::new(StreamDirection::Guest2Host);
        let fake = StreamId(7);
        assert_eq!(t.lifecycle(fake), Err(StreamTableError::Unknown(fake)));
        assert_eq!(t.record_sent(fake, 1), Err(StreamTableError::Unknown(fake)));
    }

    #[test]
    fn role_is_tracked() {
        let mut t = StreamTable::new(StreamDirection::Guest2Host);
        let a = t.open_writer(4096, 4096).unwrap();
        let b = t.open_reader(4096, 4096).unwrap();
        assert_eq!(t.find(a).unwrap().role(), EndRole::Writer);
        assert_eq!(t.find(b).unwrap().role(), EndRole::Reader);
    }
}
