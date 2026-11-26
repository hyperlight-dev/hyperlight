// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! The stream multiplexer of one session.
//!
//! [`Mux`] prepares outgoing reader transfers and stream records. The transport publishes them,
//! then commits their effects here. Incoming transfers yield readers. Incoming records update
//! pipes and stream state. `Mux` performs no I/O.
//!
//! # Entries
//!
//! A reader moves to the peer in a function call or result. Its stream then has an entry on each
//! side:
//!
//! - A [`SendStream`] at its origin, the writer's side. Its pipe retains uncredited bytes.
//! - A [`RecvStream`] on the reader's side. Received DATA fills a second pipe that the reader
//!   reads.
//!
//! A trip runs from a reader leaving its origin until it returns or closes. Each trip has a fresh
//! sid from the origin, and entry counters count bytes from its start.
//!
//! # Returning readers
//!
//! A reader can return to its writer's side in another call or result. Its transfer carries the
//! trip's sid and its consumed byte position. The peer removes its receive entry after publishing
//! the return. The origin removes its send entry on receipt and makes the original reader local.
//!
//! The position accounts for reads whose CREDIT has not arrived. Reading resumes at the first
//! unread byte in the original pipe. DATA crossing the return is discarded at the peer.
//!
//! # Doorbell
//!
//! Handles leave the Mux work between its calls:
//!
//! - A send stream's writer leaves DATA or END to send when it writes, closes, or aborts.
//! - A receive stream's reader leaves CREDIT or CLOSE_READER to send when it reads or closes.
//!
//! Each rings the session's [`Doorbell`], which wakes the task driving the Mux. Mux calls leave
//! work too, such as DATA that a received CREDIT lets through, so the driver also checks for work
//! after them.
//!
//! # Untrusted input
//!
//! The host treats the guest's Stream messages and reader transfers as untrusted.
//! [`BatchDecoder`] checks individual records. [`Mux::recv_records`] checks stream state,
//! and [`Mux::recv_transfer`] checks reader transfers. A violation is a [`ProtocolError`].
//!
//! The checks also bound what the guest costs the host. Each record touches at most one stream
//! and copies at most a window. Each receive stream buffers at most a window, and a side has at
//! most [`MAX_STREAMS`] receive streams.

use alloc::collections::BTreeMap;
use alloc::collections::btree_map::Entry;
use alloc::sync::Arc;
use core::num::NonZeroU32;
use core::ops::Bound;
use core::task::{Context, Poll};

use bytes::Bytes;
use smallvec::SmallVec;
use thiserror::Error;

use super::pipe::{EndState, Pipe};
use super::record::{BatchDecoder, Record};
use super::sync::Doorbell;
use super::{
    MAX_STREAMS, MAX_TRANSFERS, ProtocolError, Side, StatusFlags, StreamId, StreamReader, Transfer,
    Transfers,
};
use crate::flatbuffer_wrappers::ExternalValueSource;

/// The stream state of one session on one side.
///
/// Function calls and results move stream readers through it as they encode and decode. The host
/// sandbox and the guest transport each own one.
pub struct Mux {
    /// The side this Mux runs on.
    side: Side,
    /// The most unconsumed bytes per stream, the same on both sides.
    window: NonZeroU32,
    /// The index of the next sid this side allocates.
    next_id: u64,
    /// The last STATUS the guest sent or the host received.
    status: StatusFlags,
    /// The [`SendStream`] that sent the last DATA. The next message starts after it.
    cursor: Option<StreamId>,
    /// Rung by handles that leave the Mux work.
    doorbell: Arc<Doorbell>,
    /// [`SendStream`]s by sid. This side allocated their sids.
    send: BTreeMap<StreamId, SendStream>,
    /// [`RecvStream`]s by sid. The peer allocated their sids.
    recv: BTreeMap<StreamId, RecvStream>,
    /// A failed session sends nothing more.
    failed: bool,
}

/// The entry of a stream whose reader is on the peer and whose writer is here.
struct SendStream {
    /// The reader the stream had here, held while the peer reads. Its pipe holds the bytes from
    /// `consumed` on.
    reader: StreamReader<u8>,
    /// Bytes sent in DATA.
    sent: u64,
    /// Bytes the peer reported consumed in CREDIT.
    consumed: u64,
    /// Whether END was sent.
    ended: bool,
}

impl SendStream {
    /// What the stream of `sid` can send within a `window` byte window.
    fn ready(&self, sid: StreamId, window: usize) -> Ready {
        let state = self.reader.pipe().state();
        let offset = (self.sent - self.consumed) as usize;
        let unsent = state.len - offset;

        let end = (!self.ended && state.writer != EndState::Open).then_some(Record::End {
            sid,
            aborted: state.writer == EndState::Aborted,
        });

        Ready {
            offset,
            unsent,
            admitted: unsent.min(window - offset),
            end,
        }
    }
}

/// What a [`SendStream`] can send.
struct Ready {
    /// Bytes sent and not consumed. Unsent bytes start at this pipe offset.
    offset: usize,
    /// Bytes buffered and not sent.
    unsent: usize,
    /// Unsent bytes that fit in the window.
    admitted: usize,
    /// END, once the writer closed or aborted, until it is sent.
    end: Option<Record>,
}

impl Ready {
    /// Whether DATA or END can go now.
    fn is_pending(&self) -> bool {
        self.admitted > 0 || (self.unsent == 0 && self.end.is_some())
    }
}

/// The entry of a stream whose reader is here and whose writer is on the peer.
struct RecvStream {
    /// The pipe that received DATA fills.
    pipe: Arc<Pipe>,
    /// Bytes received in DATA, at most a window past `consumed`.
    received: u64,
    /// Bytes consumed as of the last CREDIT.
    consumed: u64,
}

impl RecvStream {
    /// The control record the stream of `sid` has pending.
    ///
    /// A closed reader sends CLOSE_READER. Otherwise bytes read since the last CREDIT send
    /// CREDIT.
    fn control(&self, sid: StreamId) -> Option<Record> {
        let state = self.pipe.state();

        if state.reader != EndState::Open {
            return Some(Record::CloseReader { sid });
        }

        let bytes = self.received - state.len as u64 - self.consumed;
        let bytes = bytes as u32;

        (bytes > 0).then_some(Record::Credit { sid, bytes })
    }
}

/// Why readers cannot move to the peer.
#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransferError {
    /// A reader belongs to another session.
    #[error("stream reader belongs to another session")]
    WrongSession,
    /// More than [`MAX_TRANSFERS`] readers would move in one message, the leaving readers would
    /// take this side past [`MAX_STREAMS`] [`SendStream`]s, or no sid is left.
    #[error("too many streams to the peer")]
    Limit,
    /// The session failed.
    #[error("stream session failed")]
    Failed,
}

impl Mux {
    /// Create the Mux of a new session on `side`.
    pub fn new(side: Side, window: NonZeroU32) -> Self {
        Self {
            side,
            window,
            next_id: 1,
            cursor: None,
            status: StatusFlags::empty(),
            doorbell: Arc::new(Doorbell::new()),
            send: BTreeMap::new(),
            recv: BTreeMap::new(),
            failed: false,
        }
    }

    /// Whether cross-boundary streams remain, including pending reader closes.
    pub fn has_live_streams(&self) -> bool {
        !self.send.is_empty() || !self.recv.is_empty()
    }

    /// The last STATUS the guest sent or the host received.
    pub fn status(&self) -> StatusFlags {
        self.status
    }

    /// `Ready` while a record is pending. Otherwise `Pending`, with `cx` registered for the next
    /// change a stream handle makes.
    ///
    /// The check runs after the doorbell is armed, so a change before the caller waits still
    /// wakes `cx`. A consumed ring with nothing pending arms the doorbell again.
    pub fn poll_pending(&self, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            let notified = self.doorbell.poll(cx).is_ready();

            if self.is_pending() {
                return Poll::Ready(());
            }

            if !notified {
                return Poll::Pending;
            }
        }
    }

    /// Validate outgoing readers and prepare their transfer metadata.
    ///
    /// Reserves new stream IDs and captures returning readers' consumed positions.
    /// Reader ownership stays with the caller.
    pub(crate) fn prepare_transfers<'r>(
        &mut self,
        readers: impl IntoIterator<Item = &'r StreamReader<u8>>,
    ) -> Result<Transfers, TransferError> {
        if self.failed {
            return Err(TransferError::Failed);
        }

        let mut xfers = Transfers::new();
        let mut stream_cnt = 0;

        for reader in readers {
            if xfers.len() == MAX_TRANSFERS {
                return Err(TransferError::Limit);
            }

            let pipe = reader.pipe();

            let returning = self
                .recv
                .iter()
                .find(|(_, stream)| Arc::ptr_eq(&stream.pipe, pipe))
                .map(|(&sid, stream)| Transfer {
                    sid,
                    position: stream.received - pipe.state().len as u64,
                });

            let xfer = match returning {
                Some(xfer) => xfer,
                None => {
                    if pipe.is_remote() {
                        return Err(TransferError::WrongSession);
                    }

                    stream_cnt += 1;
                    if self.send.len() + stream_cnt > MAX_STREAMS {
                        return Err(TransferError::Limit);
                    }

                    let sid = self.allocate().ok_or(TransferError::Limit)?;
                    Transfer { sid, position: 0 }
                }
            };

            xfers.push(xfer);
        }

        Ok(xfers)
    }

    /// Commit readers with their [`Self::prepare_transfers`] metadata after publication.
    ///
    /// Readers leaving their origin enter the send table. Returning readers leave the receive
    /// table.
    pub(crate) fn commit_transfers(
        &mut self,
        xfers: impl IntoIterator<Item = (StreamReader<u8>, Transfer)>,
    ) {
        for (reader, Transfer { sid, .. }) in xfers {
            if sid.initiator() == self.side {
                let pipe = reader.pipe();
                pipe.set_remote_reader(Arc::clone(&self.doorbell));
                pipe.set_capacity(self.window.get() as usize);

                let stream = SendStream {
                    reader,
                    sent: 0,
                    consumed: 0,
                    ended: false,
                };

                self.send.insert(sid, stream);
            } else {
                self.recv.remove(&sid);
            }
        }
    }

    /// End a failed session. Open readers see an abort after their buffered bytes.
    pub fn fail(&mut self) {
        self.failed = true;
        self.send.clear();

        for (_, stream) in core::mem::take(&mut self.recv) {
            stream.pipe.abort_writer();
        }
    }

    /// Validate an incoming transfer and return its reader.
    ///
    /// New readers enter the receive table at position zero. Returning readers leave the send
    /// table and resume at their reported position, bounded by the credited and sent positions.
    ///
    /// Receive transfers before subsequent stream records.
    pub(crate) fn recv_transfer(
        &mut self,
        xfer: Transfer,
    ) -> Result<StreamReader<u8>, ProtocolError> {
        let Transfer { sid, position } = xfer;

        if sid.initiator() == self.side {
            let Entry::Occupied(entry) = self.send.entry(sid) else {
                return Err(ProtocolError::Transfer);
            };

            let stream = entry.get();

            if !(stream.consumed..=stream.sent).contains(&position) {
                return Err(ProtocolError::Transfer);
            }

            let SendStream {
                reader, consumed, ..
            } = entry.remove();

            let pipe = reader.pipe();
            pipe.set_local_reader();
            pipe.consume((position - consumed) as usize);

            return Ok(reader);
        }

        if position != 0 || self.recv.len() >= MAX_STREAMS || self.recv.contains_key(&sid) {
            return Err(ProtocolError::Transfer);
        }

        let window = self.window.get() as usize;
        let pipe = Arc::new(Pipe::remote(window, Arc::clone(&self.doorbell)));

        let stream = RecvStream {
            pipe: Arc::clone(&pipe),
            received: 0,
            consumed: 0,
        };

        self.recv.insert(sid, stream);
        Ok(StreamReader::from_pipe(pipe))
    }

    /// Validate and apply one incoming stream-record batch and its DATA payloads.
    ///
    /// DATA and END update readers. CREDIT and CLOSE_READER update writers. STATUS reports
    /// guest activity. DATA and END for closed or returned readers are discarded. Their DATA
    /// bytes are still consumed to preserve payload order.
    ///
    /// Host control data must be copied from guest memory. Host payloads must use a copying
    /// source such as [`RecvChain`](crate::virtq::RecvChain).
    ///
    /// An error can leave earlier records applied, so the caller must end the session.
    pub fn recv_records(
        &mut self,
        cntl: &[u8],
        payloads: &mut impl ExternalValueSource,
    ) -> Result<(), ProtocolError> {
        let window = self.window.get() as usize;

        for record in BatchDecoder::new(cntl, self.side, window)? {
            match record? {
                Record::Data { sid, len } => self.recv_data(sid, len, payloads)?,
                Record::CloseReader { sid } => self.close_stream(sid)?,
                Record::Credit { sid, bytes } => self.recv_credit(sid, bytes)?,
                Record::End { sid, aborted } => self.recv_end(sid, aborted)?,
                Record::Status { flags } => self.status = flags,
            }
        }

        payloads.finish().map_err(|_| ProtocolError::Payload)
    }

    /// The STATUS record to publish, or `None` when STATUS is unchanged.
    ///
    /// `status` has the flags for tasks and callbacks. The Mux adds its own:
    ///
    /// - READY while a record is pending.
    /// - ACTIVE while a [`SendStream`] or [`RecvStream`] exists.
    ///
    /// Call it after a turn's last stream batch, so READY covers the records left
    /// pending. A call turn's flush leaves G2H room for it. The host sends no
    /// STATUS and always gets `None`.
    pub(crate) fn pending_status(&self, mut status: StatusFlags) -> Option<Record> {
        if self.side == Side::Host || self.failed {
            return None;
        }

        if self.is_pending() {
            status |= StatusFlags::READY;
        }

        if self.has_live_streams() {
            status |= StatusFlags::ACTIVE;
        }

        if status == self.status {
            return None;
        }

        Some(Record::Status { flags: status })
    }

    /// Commit outgoing records after successful publication.
    ///
    /// Updates counters, end/status flags, and send order. Releases closed receive entries.
    pub(crate) fn commit_records(&mut self, records: SmallVec<[Record; 8]>) {
        for record in records {
            match record {
                Record::Credit { sid, bytes } => {
                    if let Some(stream) = self.recv.get_mut(&sid) {
                        stream.consumed += u64::from(bytes);
                    }
                }
                Record::Data { sid, len } => {
                    if let Some(stream) = self.send.get_mut(&sid) {
                        stream.sent += u64::from(len);
                    }

                    self.cursor = Some(sid);
                }
                Record::End { sid, .. } => {
                    if let Some(stream) = self.send.get_mut(&sid) {
                        stream.ended = true;
                    }
                }
                Record::CloseReader { sid } => {
                    self.recv.remove(&sid);
                }
                Record::Status { flags } => self.status = flags,
            }
        }
    }

    /// Collect outgoing records and DATA payloads within `avail` bytes.
    ///
    /// Control records precede round-robin DATA. Selection leaves stream state unchanged.
    /// Call [`Self::commit_records`] after publication succeeds.
    pub(crate) fn prepare_records(
        &self,
        mut avail: usize,
        records: &mut SmallVec<[Record; 8]>,
        payloads: &mut SmallVec<[Bytes; 4]>,
    ) {
        if self.failed {
            return;
        }

        let window = self.window.get() as usize;
        let controls = self
            .recv
            .iter()
            .filter_map(|(&sid, stream)| stream.control(sid));

        for record in controls {
            let Some(left) = avail.checked_sub(record.encoded_len()) else {
                return;
            };

            avail = left;
            records.push(record);
        }

        let start = self.cursor.map_or(Bound::Unbounded, Bound::Excluded);
        let wrapped = self
            .cursor
            .into_iter()
            .flat_map(|cursor| self.send.range(..=cursor));

        for (&sid, stream) in self.send.range((start, Bound::Unbounded)).chain(wrapped) {
            let ready = stream.ready(sid, window);
            let mut len = 0;

            if ready.admitted > 0 {
                let data_len = Record::Data {
                    sid,
                    len: ready.admitted as u32,
                }
                .encoded_len();

                // DATA carries at least one byte.
                if avail <= data_len {
                    return;
                }

                len = ready.admitted.min(avail - data_len);
                avail -= data_len + len;

                let range = ready.offset..ready.offset + len;
                stream.reader.pipe().peek(range, payloads);

                records.push(Record::Data {
                    sid,
                    len: len as u32,
                });
            }

            if let Some(end) = ready.end
                && len == ready.unsent
            {
                let Some(left) = avail.checked_sub(end.encoded_len()) else {
                    return;
                };

                avail = left;
                records.push(end);
            }
        }
    }

    /// Allocate a sid for a reader leaving this side.
    ///
    /// Sids are never reused. Returns `None` once the indexes run out.
    fn allocate(&mut self) -> Option<StreamId> {
        let sid = StreamId::new(self.side, self.next_id)?;
        self.next_id += 1;
        Some(sid)
    }

    /// Whether a record is pending.
    fn is_pending(&self) -> bool {
        let window = self.window.get() as usize;
        let credit_thresh = self.window.get().div_ceil(2);

        let recv_pend = self
            .recv
            .iter()
            .any(|(&sid, stream)| match stream.control(sid) {
                Some(Record::Credit { bytes, .. }) => {
                    let win = window as u64;
                    // Batch credits to save turns. If a full window is still uncredited,
                    // even one byte of credit can unblock the sender.
                    bytes >= credit_thresh || stream.received - stream.consumed == win
                }
                control => control.is_some(),
            });

        let send_pend = self
            .send
            .iter()
            .any(|(&sid, stream)| stream.ready(sid, window).is_pending());

        recv_pend || send_pend
    }

    /// Apply CREDIT, which frees `bytes` of the window of `sid`.
    fn recv_credit(&mut self, sid: StreamId, bytes: u32) -> Result<(), ProtocolError> {
        let stream = self
            .send
            .get_mut(&sid)
            .ok_or(ProtocolError::UnknownStream(sid))?;

        let bytes = u64::from(bytes);

        if bytes > stream.sent - stream.consumed {
            return Err(ProtocolError::InvalidState(sid));
        }

        stream.consumed += bytes;
        stream.reader.pipe().consume(bytes as usize);

        Ok(())
    }

    /// Apply DATA, which hands the next `len` bytes of `payloads` to the reader of `sid`.
    fn recv_data(
        &mut self,
        sid: StreamId,
        len: u32,
        payloads: &mut impl ExternalValueSource,
    ) -> Result<(), ProtocolError> {
        let chunks = payloads
            .take_chunks(len as usize)
            .map_err(|_| ProtocolError::Payload)?;

        let window = u64::from(self.window.get());
        let len = u64::from(len);

        let Some(stream) = self.recv_stream(sid)? else {
            return Ok(());
        };

        let ended = stream.pipe.state().writer != EndState::Open;

        if ended || stream.received - stream.consumed + len > window {
            return Err(ProtocolError::InvalidState(sid));
        }

        stream.received += len;
        stream.pipe.push(chunks);

        Ok(())
    }

    /// Apply END, which ends the stream of `sid` after its received bytes.
    fn recv_end(&mut self, sid: StreamId, aborted: bool) -> Result<(), ProtocolError> {
        let Some(stream) = self.recv_stream(sid)? else {
            return Ok(());
        };

        if stream.pipe.state().writer != EndState::Open {
            return Err(ProtocolError::InvalidState(sid));
        }

        if aborted {
            stream.pipe.abort_writer();
        } else {
            stream.pipe.close_writer();
        }

        Ok(())
    }

    /// Find the [`RecvStream`] of `sid` for a record from the stream's origin.
    ///
    /// Returns `None` once the reader closed or returned, since the origin sends records until it
    /// learns of it.
    fn recv_stream(&mut self, sid: StreamId) -> Result<Option<&mut RecvStream>, ProtocolError> {
        if sid.initiator() == self.side {
            return Err(ProtocolError::UnknownStream(sid));
        }

        Ok(self.recv.get_mut(&sid))
    }

    /// Close the stream of `sid` and remove its send entry.
    fn close_stream(&mut self, sid: StreamId) -> Result<(), ProtocolError> {
        let stream = self
            .send
            .remove(&sid)
            .ok_or(ProtocolError::UnknownStream(sid))?;

        stream.reader.close();
        Ok(())
    }
}

impl Drop for Mux {
    /// End the session's side of every stream.
    ///
    /// Writes to readers on the peer fail with
    /// [`StreamError::ReaderClosed`](super::StreamError::ReaderClosed). Readers from the peer see
    /// EOF after their buffered bytes.
    fn drop(&mut self) {
        // Send streams close their readers as they drop.
        for stream in self.recv.values() {
            stream.pipe.close_writer();
        }
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use alloc::task::Wake;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, Ordering};
    use core::task::{Context, Poll, Waker};
    use core::{assert_matches, iter};

    use bytes::Buf;

    use super::*;
    use crate::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
    use crate::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};
    use crate::stream::{BatchEncoder, DEFAULT_WINDOW, StreamError};
    use crate::transport::{EncodedMessage, MsgHeader, MsgKind, PendingMessage};
    use crate::virtq::{Segments, VirtqError};

    const WINDOW: NonZeroU32 = NonZeroU32::new(8).unwrap();
    const MAX_LEN: usize = 256;
    const H1: StreamId = StreamId::new(Side::Host, 1).unwrap();
    const H2: StreamId = StreamId::new(Side::Host, 2).unwrap();
    const G1: StreamId = StreamId::new(Side::Guest, 1).unwrap();

    fn noop() -> Context<'static> {
        Context::from_waker(Waker::noop())
    }

    /// A waker that records whether it woke.
    #[derive(Default)]
    struct Flag(AtomicBool);

    impl Wake for Flag {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn pair() -> (Mux, Mux) {
        (Mux::new(Side::Host, WINDOW), Mux::new(Side::Guest, WINDOW))
    }

    /// A local stream holding `data`, and the pipe its writer writes.
    fn local(data: &[u8]) -> (Arc<Pipe>, StreamReader<u8>) {
        let pipe = Arc::new(Pipe::new(16));

        assert_eq!(
            pipe.poll_write(&mut noop(), data),
            Poll::Ready(Ok(data.len()))
        );

        (Arc::clone(&pipe), StreamReader::from_pipe(pipe))
    }

    /// Read the bytes `reader` has buffered.
    fn read(reader: &StreamReader<u8>) -> Poll<Result<Vec<u8>, StreamError>> {
        let mut buf = [0; 64];

        reader
            .pipe()
            .poll_read(&mut noop(), &mut buf)
            .map_ok(|n| buf[..n].to_vec())
    }

    /// Settle `out` as published.
    fn published(out: PendingMessage<'_>) {
        out.settle(Ok(())).unwrap();
    }

    /// Build a function call that moves `readers` out of `mux`.
    fn call(mux: &mut Mux, readers: Vec<StreamReader<u8>>) -> PendingMessage<'_> {
        let call = FunctionCall::new(
            "f".into(),
            Some(
                readers
                    .into_iter()
                    .map(ParameterValue::StreamReader)
                    .collect(),
            ),
            FunctionCallType::Guest,
            ReturnType::Void,
        );

        PendingMessage::new_call(call, 1, mux).unwrap()
    }

    /// Move `readers` out of `mux` in one published function call.
    fn send_call(mux: &mut Mux, readers: Vec<StreamReader<u8>>) {
        call(mux, readers).settle(Ok(())).unwrap();
    }

    /// Move `reader` from `from` to `to` in one function call.
    fn transfer(from: &mut Mux, to: &mut Mux, reader: StreamReader<u8>) -> StreamReader<u8> {
        let xfers = from.prepare_transfers([&reader]).unwrap();
        debug_assert_eq!(xfers.len(), 1);

        let moved = xfers[0];

        from.commit_transfers([(reader, moved)]);
        to.recv_transfer(moved).unwrap()
    }

    /// The transfer of `sid`'s reader at `position`.
    fn at(sid: StreamId, position: u64) -> Transfer {
        Transfer { sid, position }
    }

    fn encode(message: &EncodedMessage<'_>) -> Bytes {
        let mut buf = message.as_buf();
        buf.copy_to_bytes(buf.remaining())
    }

    /// Apply the Stream message in `wire` to `mux`.
    fn recv_message(mux: &mut Mux, mut wire: Bytes) -> Result<(), ProtocolError> {
        let header = MsgHeader::from_bytes(&wire[..MsgHeader::SIZE]).unwrap();
        assert_eq!(header.kind, MsgKind::Stream);

        wire.advance(MsgHeader::SIZE);
        let cntl = wire.split_to(header.control_len as usize);

        mux.recv_records(&cntl, &mut Segments::single(wire))
    }

    /// Publish `out` to `to` and return its records.
    fn publish(out: PendingMessage<'_>, to: &mut Mux) -> Vec<Record> {
        let mut buffer = Vec::new();
        let message = out.encode(&mut buffer).unwrap();
        let records = BatchDecoder::new(message.control(), to.side, to.window.get() as usize)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let wire = encode(&message);

        drop(message);
        published(out);
        recv_message(to, wire).unwrap();

        records
    }

    /// Publish the next message of `from`, of at most `max_len` bytes, to `to`.
    fn transmit(from: &mut Mux, to: &mut Mux, max_len: usize) -> Option<Vec<Record>> {
        let out = PendingMessage::next_stream(from, max_len)?;
        Some(publish(out, to))
    }

    fn batch(records: &[Record]) -> Vec<u8> {
        let mut cntl = Vec::new();
        let mut batch = BatchEncoder::new(&mut cntl);

        for &record in records {
            batch.push(record);
        }

        cntl
    }

    #[test]
    fn window_bounds_unconsumed_bytes() {
        let (mut host, mut guest) = pair();
        let (pipe, reader) = local(b"0123456789");
        let reader = transfer(&mut host, &mut guest, reader);

        assert_eq!(pipe.poll_write(&mut noop(), b"a"), Poll::Pending);

        // A dropped message sends nothing.
        drop(PendingMessage::next_stream(&mut host, MAX_LEN));

        assert_eq!(
            transmit(&mut host, &mut guest, MAX_LEN),
            Some(vec![Record::Data { sid: H1, len: 8 }])
        );
        assert!(PendingMessage::next_stream(&mut host, MAX_LEN).is_none());

        let mut buf = [0; 3];

        assert_eq!(
            reader.pipe().poll_read(&mut noop(), &mut buf),
            Poll::Ready(Ok(3))
        );
        assert_eq!(
            transmit(&mut guest, &mut host, MAX_LEN),
            Some(vec![Record::Credit { sid: H1, bytes: 3 }])
        );

        assert_eq!(pipe.poll_write(&mut noop(), b"ab"), Poll::Ready(Ok(1)));
        pipe.close_writer();

        assert_eq!(
            transmit(&mut host, &mut guest, MAX_LEN),
            Some(vec![
                Record::Data { sid: H1, len: 3 },
                Record::End {
                    sid: H1,
                    aborted: false
                },
            ])
        );
        assert_eq!(read(&reader), Poll::Ready(Ok(b"3456789a".to_vec())));
        assert_eq!(read(&reader), Poll::Ready(Ok(vec![])));
    }

    #[test]
    fn returning_reader_resumes_at_its_first_unread_byte() {
        let (mut host, mut guest) = pair();
        let (pipe, reader) = local(b"abcdef");
        let reader = transfer(&mut host, &mut guest, reader);

        assert_eq!(
            transmit(&mut host, &mut guest, MAX_LEN),
            Some(vec![Record::Data { sid: H1, len: 6 }])
        );

        let mut buf = [0; 2];

        assert_eq!(
            reader.pipe().poll_read(&mut noop(), &mut buf),
            Poll::Ready(Ok(2))
        );
        assert_eq!(pipe.poll_write(&mut noop(), b"gh"), Poll::Ready(Ok(2)));

        // This DATA crosses the returning reader.
        let mut buffer = Vec::new();
        let out = PendingMessage::next_stream(&mut host, MAX_LEN).unwrap();
        let wire = encode(&out.encode(&mut buffer).unwrap());
        published(out);

        let reader = transfer(&mut guest, &mut host, reader);

        assert_matches!(recv_message(&mut guest, wire), Ok(()));
        assert!(guest.recv.is_empty());
        assert!(host.send.is_empty());
        assert_eq!(read(&reader), Poll::Ready(Ok(b"cdefgh".to_vec())));
    }

    #[test]
    fn abort_ends_the_stream_after_its_data() {
        let (mut host, mut guest) = pair();
        let (pipe, reader) = local(b"0123456789");
        let reader = transfer(&mut guest, &mut host, reader);

        pipe.abort_writer();

        assert_eq!(
            transmit(&mut guest, &mut host, MAX_LEN),
            Some(vec![Record::Data { sid: G1, len: 8 }])
        );
        assert_eq!(read(&reader), Poll::Ready(Ok(b"01234567".to_vec())));
        assert_eq!(
            transmit(&mut host, &mut guest, MAX_LEN),
            Some(vec![Record::Credit { sid: G1, bytes: 8 }])
        );
        assert_eq!(
            transmit(&mut guest, &mut host, MAX_LEN),
            Some(vec![
                Record::Data { sid: G1, len: 2 },
                Record::End {
                    sid: G1,
                    aborted: true
                },
            ])
        );
        assert_eq!(transmit(&mut guest, &mut host, MAX_LEN), None);
        assert_eq!(read(&reader), Poll::Ready(Ok(b"89".to_vec())));
        assert_eq!(read(&reader), Poll::Ready(Err(StreamError::Aborted)));
    }

    #[test]
    fn reader_close_releases_both_entries() {
        let (mut host, mut guest) = pair();
        let (pipe, reader) = local(b"abc");

        drop(transfer(&mut host, &mut guest, reader));

        assert_eq!(
            transmit(&mut guest, &mut host, MAX_LEN),
            Some(vec![Record::CloseReader { sid: H1 }])
        );
        assert!(guest.recv.is_empty());
        assert!(host.send.is_empty());
        assert_eq!(
            pipe.poll_write(&mut noop(), b"d"),
            Poll::Ready(Err(StreamError::ReaderClosed))
        );
    }

    #[test]
    fn handles_notify_their_mux() {
        let (mut host, mut guest) = pair();
        let (pipe, reader) = local(b"");
        let reader = transfer(&mut host, &mut guest, reader);

        assert_matches!(host.poll_pending(&mut noop()), Poll::Pending);
        assert_eq!(pipe.poll_write(&mut noop(), b"abcd"), Poll::Ready(Ok(4)));
        assert_matches!(host.poll_pending(&mut noop()), Poll::Ready(()));
        assert_matches!(host.poll_pending(&mut noop()), Poll::Ready(()));
        assert_eq!(
            transmit(&mut host, &mut guest, MAX_LEN),
            Some(vec![Record::Data { sid: H1, len: 4 }])
        );
        assert_matches!(host.poll_pending(&mut noop()), Poll::Pending);

        assert_eq!(read(&reader), Poll::Ready(Ok(b"abcd".to_vec())));
        assert_matches!(guest.poll_pending(&mut noop()), Poll::Ready(()));

        // A returned reader's handle owns its end again, so the Mux hears of no writes.
        let reader = transfer(&mut guest, &mut host, reader);
        assert_matches!(guest.poll_pending(&mut noop()), Poll::Pending);

        assert_eq!(pipe.poll_write(&mut noop(), b"c"), Poll::Ready(Ok(1)));
        assert_matches!(host.poll_pending(&mut noop()), Poll::Pending);
        assert_eq!(read(&reader), Poll::Ready(Ok(b"c".to_vec())));
    }

    #[test]
    fn flushed_changes_leave_the_doorbell_armed() {
        let (mut host, mut guest) = pair();
        let (pipe, reader) = local(b"");
        let _reader = transfer(&mut host, &mut guest, reader);

        assert_eq!(pipe.poll_write(&mut noop(), b"ab"), Poll::Ready(Ok(2)));
        assert_eq!(
            transmit(&mut host, &mut guest, MAX_LEN),
            Some(vec![Record::Data { sid: H1, len: 2 }])
        );

        // The doorbell still holds the ring of a change already flushed.
        let woken = Arc::new(Flag::default());
        let waker = Waker::from(Arc::clone(&woken));
        let mut cx = Context::from_waker(&waker);

        assert_matches!(host.poll_pending(&mut cx), Poll::Pending);
        assert_eq!(pipe.poll_write(&mut noop(), b"c"), Poll::Ready(Ok(1)));
        assert!(woken.0.load(Ordering::SeqCst));
    }

    #[test]
    fn credit_waits_for_half_the_window() {
        let (mut host, mut guest) = pair();
        let (pipe, reader) = local(b"abc");
        let reader = transfer(&mut host, &mut guest, reader);

        assert!(transmit(&mut host, &mut guest, MAX_LEN).is_some());
        assert_eq!(read(&reader), Poll::Ready(Ok(b"abc".to_vec())));
        assert_matches!(guest.poll_pending(&mut noop()), Poll::Pending);

        assert_eq!(pipe.poll_write(&mut noop(), b"d"), Poll::Ready(Ok(1)));
        assert!(transmit(&mut host, &mut guest, MAX_LEN).is_some());
        assert_eq!(read(&reader), Poll::Ready(Ok(b"d".to_vec())));
        assert_matches!(guest.poll_pending(&mut noop()), Poll::Ready(()));
        assert_eq!(
            transmit(&mut guest, &mut host, MAX_LEN),
            Some(vec![Record::Credit { sid: H1, bytes: 4 }])
        );

        // A flush still sends smaller CREDIT.
        assert_eq!(pipe.poll_write(&mut noop(), b"e"), Poll::Ready(Ok(1)));
        assert!(transmit(&mut host, &mut guest, MAX_LEN).is_some());
        assert_eq!(read(&reader), Poll::Ready(Ok(b"e".to_vec())));
        assert_matches!(guest.poll_pending(&mut noop()), Poll::Pending);
        assert_eq!(
            transmit(&mut guest, &mut host, MAX_LEN),
            Some(vec![Record::Credit { sid: H1, bytes: 1 }])
        );

        // CLOSE_READER does not wait.
        drop(reader);
        assert_matches!(guest.poll_pending(&mut noop()), Poll::Ready(()));
    }

    #[test]
    fn streams_take_turns_sending_data() {
        let (mut host, mut guest) = pair();
        let _readers =
            [b"aaaaaaaa", b"bbbbbbbb"].map(|data| transfer(&mut host, &mut guest, local(data).1));

        // DATA takes 3 bytes and carries at least one.
        assert!(PendingMessage::next_stream(&mut host, MsgHeader::SIZE + 3).is_none());

        let max_len = MsgHeader::SIZE + 3 + 4;
        let messages: Vec<_> = iter::from_fn(|| transmit(&mut host, &mut guest, max_len)).collect();
        let data = |sid| vec![Record::Data { sid, len: 4 }];

        assert_eq!(messages, [data(H1), data(H2), data(H1), data(H2)]);
    }

    #[test]
    fn control_records_go_before_data() {
        let (mut host, mut guest) = pair();
        let credited = transfer(&mut host, &mut guest, local(b"ab").1);
        let closed = transfer(&mut host, &mut guest, local(b"").1);
        let _sent = transfer(&mut guest, &mut host, local(b"xyz").1);

        assert_eq!(
            transmit(&mut host, &mut guest, MAX_LEN),
            Some(vec![Record::Data { sid: H1, len: 2 }])
        );
        assert_eq!(read(&credited), Poll::Ready(Ok(b"ab".to_vec())));
        drop(closed);

        let credit = Record::Credit { sid: H1, bytes: 2 };
        let close = Record::CloseReader { sid: H2 };
        let max_len = MsgHeader::SIZE + credit.encoded_len() + close.encoded_len();

        assert_eq!(
            transmit(&mut guest, &mut host, max_len),
            Some(vec![credit, close])
        );
        assert_eq!(
            transmit(&mut guest, &mut host, MAX_LEN),
            Some(vec![Record::Data { sid: G1, len: 3 }])
        );
    }

    #[test]
    fn recv_records_rejects_protocol_violations() {
        let data = |sid, len| Record::Data { sid, len };
        let end = Record::End {
            sid: G1,
            aborted: false,
        };

        // Records, payload length, and error, for a host that sent 4 bytes of H1 and accepted G1.
        let cases: [(&[Record], usize, ProtocolError); 9] = [
            (
                &[Record::Credit { sid: H2, bytes: 1 }],
                0,
                ProtocolError::UnknownStream(H2),
            ),
            (
                &[Record::Credit { sid: H1, bytes: 5 }],
                0,
                ProtocolError::InvalidState(H1),
            ),
            (
                &[Record::CloseReader { sid: G1 }],
                0,
                ProtocolError::UnknownStream(G1),
            ),
            (&[data(H1, 1)], 1, ProtocolError::UnknownStream(H1)),
            (
                &[data(G1, 8), data(G1, 1)],
                9,
                ProtocolError::InvalidState(G1),
            ),
            (&[end, data(G1, 1)], 1, ProtocolError::InvalidState(G1)),
            (&[end, end], 0, ProtocolError::InvalidState(G1)),
            (&[data(G1, 4)], 3, ProtocolError::Payload),
            (&[data(G1, 2)], 3, ProtocolError::Payload),
        ];

        for (records, payload, error) in cases {
            let mut host = Mux::new(Side::Host, WINDOW);

            send_call(&mut host, vec![local(b"abcd").1]);
            published(PendingMessage::next_stream(&mut host, MAX_LEN).unwrap());

            let _reader = host.recv_transfer(at(G1, 0)).unwrap();
            let mut payloads = Segments::single(Bytes::from(vec![0; payload]));

            assert_eq!(
                host.recv_records(&batch(records), &mut payloads),
                Err(error),
                "{records:?}"
            );
        }
    }

    #[test]
    fn unpublished_messages_apply_nothing() {
        let (mut host, mut guest) = pair();

        let (pipe, reader) = local(b"abc");
        let out = call(&mut host, vec![reader]);

        assert_matches!(
            out.settle(Err::<(), _>(VirtqError::Backpressure)),
            Err(VirtqError::Backpressure)
        );
        assert!(host.send.is_empty());
        assert_matches!(
            pipe.poll_write(&mut noop(), b"d"),
            Poll::Ready(Err(StreamError::ReaderClosed))
        );

        // The unpublished call took H1.
        let _reader = transfer(&mut host, &mut guest, local(b"abc").1);
        let out = PendingMessage::next_stream(&mut host, MAX_LEN).unwrap();

        assert_matches!(
            out.settle(Err::<(), _>(VirtqError::Backpressure)),
            Err(VirtqError::Backpressure)
        );
        assert_eq!(
            transmit(&mut host, &mut guest, MAX_LEN),
            Some(vec![Record::Data { sid: H2, len: 3 }])
        );
    }

    #[test]
    fn uncertain_publication_fails_the_session() {
        let (mut host, mut guest) = pair();
        let _reader = transfer(&mut guest, &mut host, local(b"abc").1);
        let out = PendingMessage::next_stream(&mut guest, MAX_LEN).unwrap();

        assert_matches!(
            out.settle(Err::<(), _>(VirtqError::MemoryWriteError)),
            Err(VirtqError::MemoryWriteError)
        );
        assert!(PendingMessage::next_stream(&mut guest, MAX_LEN).is_none());
        assert!(PendingMessage::new_status(&mut guest, StatusFlags::empty()).is_none());
        assert_matches!(
            guest.prepare_transfers([&local(b"").1]),
            Err(TransferError::Failed)
        );
    }

    #[test]
    fn failing_a_session_preserves_buffered_data_and_received_end() {
        let (mut host, mut guest) = pair();
        let (pipe, ended) = local(b"end");
        pipe.close_writer();
        let ended = transfer(&mut guest, &mut host, ended);
        let open = transfer(&mut guest, &mut host, local(b"open").1);
        assert!(transmit(&mut guest, &mut host, MAX_LEN).is_some());

        host.fail();

        assert_eq!(read(&ended), Poll::Ready(Ok(b"end".to_vec())));
        assert_eq!(read(&ended), Poll::Ready(Ok(Vec::new())));
        assert_eq!(read(&open), Poll::Ready(Ok(b"open".to_vec())));
        assert_eq!(read(&open), Poll::Ready(Err(StreamError::Aborted)));
    }

    #[test]
    fn prepare_transfers_checks_readers() {
        let mut host = Mux::new(Side::Host, WINDOW);
        let readers = |n| (0..n).map(|_| local(b"").1).collect::<Vec<_>>();
        let peer = |index| at(StreamId::new(Side::Guest, index).unwrap(), 0);

        let mut other = Mux::new(Side::Host, WINDOW);
        let foreign = other.recv_transfer(peer(1)).unwrap();

        assert_matches!(
            host.prepare_transfers([&foreign]),
            Err(TransferError::WrongSession)
        );

        // One message moves at most MAX_TRANSFERS readers, returning ones included.
        let returning: Vec<_> = (1..=MAX_TRANSFERS as u64)
            .map(|index| host.recv_transfer(peer(index)).unwrap())
            .collect();
        let leaving = local(b"").1;

        assert_matches!(
            host.prepare_transfers(returning.iter().chain([&leaving])),
            Err(TransferError::Limit)
        );

        // At most MAX_STREAMS readers are away, returning ones excluded.
        send_call(&mut host, readers(MAX_STREAMS));

        assert_matches!(
            host.prepare_transfers(&readers(1)),
            Err(TransferError::Limit)
        );
        assert!(host.prepare_transfers(&returning).is_ok());
    }

    #[test]
    fn recv_transfer_checks_positions() {
        let mut host = Mux::new(Side::Host, WINDOW);
        let readers = vec![local(b"abcd").1, local(b"efgh").1];

        send_call(&mut host, readers);
        published(PendingMessage::next_stream(&mut host, MAX_LEN).unwrap());

        let credit = batch(&[Record::Credit { sid: H1, bytes: 2 }]);
        host.recv_records(&credit, &mut Segments::default())
            .unwrap();

        assert_matches!(
            host.recv_transfer(at(StreamId::new(Side::Host, 3).unwrap(), 0)),
            Err(ProtocolError::Transfer)
        );
        assert_matches!(host.recv_transfer(at(H1, 1)), Err(ProtocolError::Transfer));
        assert_matches!(host.recv_transfer(at(H1, 5)), Err(ProtocolError::Transfer));
        assert_matches!(host.recv_transfer(at(G1, 1)), Err(ProtocolError::Transfer));

        // Positions from the last CREDIT through the bytes sent are valid.
        let h1 = host.recv_transfer(at(H1, 2)).unwrap();
        let h2 = host.recv_transfer(at(H2, 4)).unwrap();

        assert_eq!(read(&h1), Poll::Ready(Ok(b"cd".to_vec())));
        assert_eq!(h2.pipe().state().len, 0);
    }

    #[test]
    fn recv_transfer_limits_arriving_readers() {
        let mut host = Mux::new(Side::Host, WINDOW);
        let peer = |index| at(StreamId::new(Side::Guest, index).unwrap(), 0);

        host.recv_transfer(peer(1)).unwrap();
        assert_matches!(host.recv_transfer(peer(1)), Err(ProtocolError::Transfer));

        for index in 2..=MAX_STREAMS as u64 {
            host.recv_transfer(peer(index)).unwrap();
        }

        assert_matches!(
            host.recv_transfer(peer(MAX_STREAMS as u64 + 1)),
            Err(ProtocolError::Transfer)
        );
    }

    #[test]
    fn guest_publishes_status_changes() {
        let (mut host, mut guest) = pair();

        assert!(PendingMessage::new_status(&mut host, StatusFlags::READY).is_none());
        assert!(PendingMessage::new_status(&mut guest, StatusFlags::empty()).is_none());

        let _reader = transfer(&mut guest, &mut host, local(b"abc").1);

        // A dropped message sends nothing.
        drop(PendingMessage::new_status(&mut guest, StatusFlags::empty()));

        let flags = StatusFlags::READY | StatusFlags::ACTIVE;
        let out = PendingMessage::new_status(&mut guest, StatusFlags::empty()).unwrap();

        assert_eq!(publish(out, &mut host), [Record::Status { flags }]);
        assert_eq!(host.status, flags);
        assert!(PendingMessage::new_status(&mut guest, StatusFlags::empty()).is_none());
        assert!(transmit(&mut guest, &mut host, MAX_LEN).is_some());

        let out = PendingMessage::new_status(&mut guest, StatusFlags::empty()).unwrap();
        let flags = StatusFlags::ACTIVE;

        assert_eq!(publish(out, &mut host), [Record::Status { flags }]);
    }

    #[test]
    fn sids_run_out_without_reuse() {
        let mut mux = Mux::new(Side::Guest, DEFAULT_WINDOW);
        assert_eq!(mux.allocate(), StreamId::new(Side::Guest, 1));

        let last = u64::MAX >> 1;
        mux.next_id = last;

        assert_eq!(mux.allocate(), StreamId::new(Side::Guest, last));
        assert_eq!(mux.allocate(), None);
        assert_eq!(mux.allocate(), None);
    }

    #[test]
    fn drop_ends_bridged_streams() {
        let mut cx = Context::from_waker(Waker::noop());
        let mut buf = [0; 4];
        let mut mux = Mux::new(Side::Host, DEFAULT_WINDOW);

        let send_pipe = Arc::new(Pipe::new(4));
        let sid = StreamId::new(Side::Host, 1).unwrap();

        mux.send.insert(
            sid,
            SendStream {
                reader: StreamReader::from_pipe(Arc::clone(&send_pipe)),
                sent: 0,
                consumed: 0,
                ended: false,
            },
        );

        let recv_pipe = Arc::new(Pipe::new(4));
        let sid = StreamId::new(Side::Guest, 1).unwrap();

        mux.recv.insert(
            sid,
            RecvStream {
                pipe: Arc::clone(&recv_pipe),
                received: 2,
                consumed: 0,
            },
        );

        assert_eq!(recv_pipe.poll_write(&mut cx, b"ab"), Poll::Ready(Ok(2)));
        drop(mux);

        assert_eq!(
            send_pipe.poll_write(&mut cx, b"a"),
            Poll::Ready(Err(StreamError::ReaderClosed))
        );
        assert_eq!(recv_pipe.poll_read(&mut cx, &mut buf), Poll::Ready(Ok(2)));
        assert_eq!(recv_pipe.poll_read(&mut cx, &mut buf), Poll::Ready(Ok(0)));
    }
}
