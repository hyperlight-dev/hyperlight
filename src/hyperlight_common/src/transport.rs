// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Shared guest and host transport protocol.
//!
//! Every logical message starts with this fixed header. It enables message type
//! discrimination, request/response correlation, and payload length validation.

use alloc::vec::Vec;

use anyhow::Result;
pub use bytes::Buf;
use bytes::Bytes;

use crate::flatbuffer_wrappers::{ExternalValueSink, ExternalValueSource};
use crate::virtq::{MemOps, RecvChain, Segments, VirtqError, zeroed_vec};

/// Length of a FlatBuffer size prefix.
pub const SIZE_PREFIX_LEN: usize = core::mem::size_of::<u32>();

/// Message types for the virtqueue wire protocol.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, bytemuck::CheckedBitPattern, bytemuck::NoUninit)]
pub enum MsgKind {
    /// A function call request (FunctionCall payload follows).
    Request = 0x01,
    /// A function call response (FunctionCallResult payload follows).
    Response = 0x02,
    /// A stream data chunk.
    StreamChunk = 0x03,
    /// End-of-stream marker.
    StreamEnd = 0x04,
    /// Cancel a pending request.
    Cancel = 0x05,
    /// A guest log message (GuestLogData payload follows).
    Log = 0x06,
    /// Internal request to prepare canonical transport state for snapshotting.
    SnapshotCheckpoint = 0x07,
}

impl TryFrom<u8> for MsgKind {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Request),
            0x02 => Ok(Self::Response),
            0x03 => Ok(Self::StreamChunk),
            0x04 => Ok(Self::StreamEnd),
            0x05 => Ok(Self::Cancel),
            0x06 => Ok(Self::Log),
            0x07 => Ok(Self::SnapshotCheckpoint),
            other => Err(other),
        }
    }
}

/// Wire header for all virtqueue messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, bytemuck::CheckedBitPattern, bytemuck::NoUninit)]
#[repr(C)]
pub struct MsgHeader {
    /// Discriminates the message type.
    pub kind: MsgKind,
    /// Keep the header aligned to four bytes.
    reserved: [u8; 3],
    /// Caller-assigned correlation ID. Responses echo the request's ID.
    pub cid: u32,
    /// Total number of payload bytes in this logical message.
    pub payload_len: u32,
}

impl MsgHeader {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Create a message header.
    pub const fn new(kind: MsgKind, cid: u32, payload_len: u32) -> Self {
        Self {
            kind,
            reserved: [0; 3],
            cid,
            payload_len,
        }
    }

    /// Return the wire representation.
    pub fn as_bytes(&self) -> &[u8] {
        bytemuck::bytes_of(self)
    }

    /// Parse and validate a wire header.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let header: Self = bytemuck::checked::try_pod_read_unaligned(bytes).ok()?;
        (header.reserved == [0; 3]).then_some(header)
    }
}

/// Borrowed wire message split into transport-ready chunks.
#[derive(Debug)]
pub struct EncodedMessage<'a> {
    header: MsgHeader,
    control: &'a [u8],
    externals: ExternalValues<'a>,
    total_len: usize,
}

impl<'a> EncodedMessage<'a> {
    /// Build a message, returning `None` if its payload exceeds the wire field.
    pub fn new(
        kind: MsgKind,
        cid: u32,
        control: &'a [u8],
        externals: ExternalValues<'a>,
    ) -> Option<Self> {
        let payload_len = control.len().checked_add(externals.total_len())?;
        let payload_len = u32::try_from(payload_len).ok()?;
        let total_len = MsgHeader::SIZE.checked_add(payload_len as usize)?;

        Some(Self {
            header: MsgHeader::new(kind, cid, payload_len),
            control,
            externals,
            total_len,
        })
    }

    // Build a snapshot checkpoint message with no payload.
    pub fn new_snapshot_cp() -> Self {
        let total_len = MsgHeader::SIZE;
        let externals = ExternalValues::new();

        Self {
            header: MsgHeader::new(MsgKind::SnapshotCheckpoint, 0, 0),
            control: &[],
            externals,
            total_len,
        }
    }

    /// Borrow the complete wire message as a zero-copy byte cursor.
    pub fn as_buf(&self) -> impl Buf + '_ {
        EncodedMessageBuf::new(
            self.header.as_bytes(),
            self.control,
            &self.externals.chunks,
            self.total_len,
        )
    }

    /// Iterate over the complete wire message in transmission order.
    pub fn chunks(&self) -> impl Iterator<Item = &[u8]> + '_ {
        core::iter::once(self.header.as_bytes())
            .chain(core::iter::once(self.control))
            .chain(self.externals.chunks())
    }

    /// Iterate over external transport chunks in wire order.
    pub fn external_chunks(&self) -> impl Iterator<Item = &[u8]> + '_ {
        self.externals.chunks()
    }

    /// Message header.
    pub const fn header(&self) -> &MsgHeader {
        &self.header
    }

    /// Size-prefixed FlatBuffer control data.
    pub const fn control(&self) -> &[u8] {
        self.control
    }

    /// Total external byte-stream length.
    pub const fn external_len(&self) -> usize {
        self.payload_len() - self.control.len()
    }

    /// Length of the header and control prefix before external bytes.
    pub const fn prefix_len(&self) -> usize {
        MsgHeader::SIZE + self.control.len()
    }

    /// Logical payload length after the header.
    pub const fn payload_len(&self) -> usize {
        self.header.payload_len as usize
    }

    /// Total wire length of all chunks.
    pub const fn total_len(&self) -> usize {
        self.total_len
    }
}

/// Borrowed [`Buf`] cursor over an [`EncodedMessage`].
///
/// Advancing the cursor does not mutate the message or copy its chunks.
struct EncodedMessageBuf<'a> {
    header: &'a [u8],
    control: &'a [u8],
    externals: &'a [&'a [u8]],
    index: usize,
    offset: usize,
    remaining: usize,
}

impl<'a> EncodedMessageBuf<'a> {
    fn new(
        header: &'a [u8],
        control: &'a [u8],
        externals: &'a [&'a [u8]],
        remaining: usize,
    ) -> Self {
        let mut this = Self {
            header,
            control,
            externals,
            index: 0,
            offset: 0,
            remaining,
        };

        this.skip_empty_chunks();
        this
    }

    fn current(&self) -> Option<&[u8]> {
        match self.index {
            0 => Some(self.header),
            1 => Some(self.control),
            index => self.externals.get(index - 2).copied(),
        }
    }

    fn skip_empty_chunks(&mut self) {
        while self
            .current()
            .is_some_and(|chunk| self.offset >= chunk.len())
        {
            self.index += 1;
            self.offset = 0;
        }
    }
}

impl Buf for EncodedMessageBuf<'_> {
    fn remaining(&self) -> usize {
        self.remaining
    }

    fn chunk(&self) -> &[u8] {
        if self.remaining == 0 {
            return &[];
        }

        #[allow(clippy::expect_used)] // `remaining` is derived from the chunks.
        let chunk = self.current().expect("message length mismatch");
        &chunk[self.offset..]
    }

    fn advance(&mut self, cnt: usize) {
        assert!(cnt <= self.remaining, "cannot advance past remaining bytes");

        self.remaining -= cnt;
        let mut cnt = cnt;

        while cnt != 0 {
            #[allow(clippy::expect_used)] // `remaining` advances with `index`.
            let chunk = self.current().expect("message length mismatch");
            let advanced = cnt.min(chunk.len() - self.offset);

            self.offset += advanced;
            cnt -= advanced;
            self.skip_empty_chunks();
        }
    }
}

/// Borrowed external values collected while encoding a FlatBuffer.
#[derive(Debug, Default)]
pub struct ExternalValues<'a> {
    chunks: Vec<&'a [u8]>,
    total_len: usize,
}

impl<'a> ExternalValues<'a> {
    /// Create an empty collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Iterate over transport chunks in wire order.
    fn chunks(&self) -> impl Iterator<Item = &[u8]> + '_ {
        self.chunks.iter().copied()
    }

    /// Total byte length of all collected values.
    pub const fn total_len(&self) -> usize {
        self.total_len
    }
}

impl<'a> ExternalValueSink<'a> for ExternalValues<'a> {
    fn push_bytes(&mut self, value: &'a [u8]) -> Result<()> {
        if value.is_empty() {
            return Ok(());
        }

        self.total_len = self
            .total_len
            .checked_add(value.len())
            .ok_or_else(|| anyhow::anyhow!("external value length overflow"))?;

        self.chunks.push(value);
        Ok(())
    }

    fn push_chunks(&mut self, value: &'a [Bytes]) -> Result<()> {
        let total_len = value
            .iter()
            .try_fold(self.total_len, |len, chunk| len.checked_add(chunk.len()))
            .ok_or_else(|| anyhow::anyhow!("external value length overflow"))?;

        let chunks = value
            .iter()
            .map(Bytes::as_ref)
            .filter(|chunk| !chunk.is_empty());

        self.chunks.extend(chunks);
        self.total_len = total_len;
        Ok(())
    }
}

/// Copies values so later shared-memory writes cannot change decoded arguments.
impl<M: MemOps> ExternalValueSource for RecvChain<M> {
    fn take_bytes(&mut self, length: usize) -> Result<Vec<u8>> {
        let mut value = external_buffer(length, self.remaining())?;
        self.read_exact(&mut value)?;
        Ok(value)
    }

    fn take_chunks(&mut self, length: usize) -> Result<Vec<Bytes>> {
        if length == 0 {
            return Ok(Vec::new());
        }

        let mut value = external_buffer(length, self.remaining())?;
        let mut chunks = Vec::new();

        chunks
            .try_reserve_exact(1)
            .map_err(|_| VirtqError::Bookkeeping)?;

        self.read_exact(&mut value)?;

        chunks.push(Bytes::from(value));
        Ok(chunks)
    }

    fn finish(&mut self) -> Result<()> {
        finish_external_values(self.remaining())
    }
}

impl ExternalValueSource for Segments {
    fn take_bytes(&mut self, length: usize) -> Result<Vec<u8>> {
        let segments = take_external_segments(self, length)?;
        let mut value = Vec::new();

        value
            .try_reserve_exact(length)
            .map_err(|_| VirtqError::Bookkeeping)?;

        for seg in segments.iter() {
            value.extend_from_slice(seg);
        }

        Ok(value)
    }

    fn take_chunks(&mut self, length: usize) -> Result<Vec<Bytes>> {
        Ok(take_external_segments(self, length)?.into_chunks())
    }

    fn finish(&mut self) -> Result<()> {
        finish_external_values(self.len())
    }
}

fn external_buffer(length: usize, remaining: usize) -> Result<Vec<u8>> {
    if length > remaining {
        return Err(VirtqError::ReceiveTooShort {
            requested: length,
            remaining,
        }
        .into());
    }
    Ok(zeroed_vec(length)?)
}

fn take_external_segments(segments: &mut Segments, length: usize) -> Result<Segments> {
    segments.split_to(length).ok_or_else(|| {
        VirtqError::ReceiveTooShort {
            requested: length,
            remaining: segments.len(),
        }
        .into()
    })
}

fn finish_external_values(remaining: usize) -> Result<()> {
    if remaining != 0 {
        anyhow::bail!("Virtqueue message has {remaining} trailing external bytes");
    }
    Ok(())
}

/// Decode a FlatBuffer size prefix.
pub fn size_prefix_payload_len(prefix: &[u8]) -> Option<usize> {
    // TODO: this is flatbuffer-specific and should be moved probably somewhere else.
    let prefix = <[u8; SIZE_PREFIX_LEN]>::try_from(prefix).ok()?;
    usize::try_from(u32::from_le_bytes(prefix)).ok()
}

/// Add the FlatBuffer size prefix to a payload length.
pub const fn size_prefixed_len(payload_len: usize) -> Option<usize> {
    // TODO: this is flatbuffer-specific and should be moved probably somewhere else.
    SIZE_PREFIX_LEN.checked_add(payload_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flatbuffer_wrappers::ExternalValueSink;

    #[test]
    fn header_contains_framing_fields() {
        let header = MsgHeader::new(MsgKind::Response, 0x1234_5678, 4096);

        assert_eq!(MsgHeader::SIZE, 12);
        assert_eq!(header.kind, MsgKind::Response);
        assert_eq!(header.cid, 0x1234_5678);
        assert_eq!(header.payload_len, 4096);
        assert_eq!(header.reserved, [0; 3]);
        assert_eq!(
            header.as_bytes(),
            &[0x02, 0, 0, 0, 0x78, 0x56, 0x34, 0x12, 0, 0x10, 0, 0]
        );
        assert_eq!(MsgHeader::from_bytes(header.as_bytes()), Some(header));
    }

    #[test]
    fn header_decodes_unaligned_bytes() {
        let header = MsgHeader::new(MsgKind::Response, 7, 4096);
        let mut storage = [0u32; 4];
        let bytes = &mut bytemuck::cast_slice_mut(&mut storage)[1..1 + MsgHeader::SIZE];
        bytes.copy_from_slice(header.as_bytes());

        assert_eq!(MsgHeader::from_bytes(bytes), Some(header));
    }

    #[test]
    fn rejects_invalid_wire_headers() {
        let header = MsgHeader::new(MsgKind::Request, 1, 4);
        let mut bytes = [0; MsgHeader::SIZE];
        bytes.copy_from_slice(header.as_bytes());

        for index in 1..4 {
            bytes[index] = 1;
            assert_eq!(MsgHeader::from_bytes(&bytes), None);
            bytes[index] = 0;
        }

        bytes[0] = u8::MAX;
        assert_eq!(MsgHeader::from_bytes(&bytes), None);

        bytes[0] = MsgKind::Request as u8;
        for len in 0..MsgHeader::SIZE {
            assert_eq!(MsgHeader::from_bytes(&bytes[..len]), None);
        }

        let mut oversized = [0; MsgHeader::SIZE + 1];
        oversized[..MsgHeader::SIZE].copy_from_slice(&bytes);
        assert_eq!(MsgHeader::from_bytes(&oversized), None);
    }

    #[test]
    fn encoded_message_yields_wire_chunks_in_order() {
        let chunks = [
            bytes::Bytes::from_static(b"ef"),
            bytes::Bytes::from_static(b"gh"),
        ];
        let mut external_values = ExternalValues::new();
        external_values.push_bytes(b"cd").unwrap();
        external_values.push_chunks(&chunks).unwrap();

        let message = EncodedMessage::new(MsgKind::Request, 7, b"ab", external_values).unwrap();
        let visited: Vec<_> = message.chunks().map(<[u8]>::to_vec).collect();

        assert_eq!(message.total_len(), MsgHeader::SIZE + 8);
        assert_eq!(message.prefix_len(), MsgHeader::SIZE + 2);
        assert_eq!(message.payload_len(), 8);
        assert_eq!(visited[1..], [b"ab", b"cd", b"ef", b"gh"]);
    }

    #[test]
    fn encoded_message_buf_skips_empty_chunks() {
        let mut external_values = ExternalValues::new();
        external_values.chunks.push(&[]);
        external_values.push_bytes(b"ab").unwrap();

        let message = EncodedMessage::new(MsgKind::Request, 7, &[], external_values).unwrap();
        let expected = message.chunks().flatten().copied().collect::<Vec<_>>();
        let mut cursor = message.as_buf();
        let mut actual = vec![0; cursor.remaining()];

        cursor.copy_to_slice(&mut actual);

        assert_eq!(actual, expected);
        assert!(!cursor.has_remaining());
    }

    #[test]
    fn encoded_message_rejects_length_overflow() {
        let external_values = ExternalValues {
            chunks: Vec::new(),
            total_len: usize::MAX,
        };

        assert!(EncodedMessage::new(MsgKind::Request, 7, b"x", external_values).is_none());

        let mut external_values = ExternalValues {
            chunks: Vec::new(),
            total_len: usize::MAX,
        };
        assert!(external_values.push_bytes(b"x").is_err());
        assert!(external_values.chunks.is_empty());

        let chunks = [Bytes::from_static(b"x")];
        assert!(external_values.push_chunks(&chunks).is_err());
        assert!(external_values.chunks.is_empty());
    }

    #[test]
    fn segments_source_flattens_only_contiguous_values() {
        let first = Bytes::from_static(b"ab");
        let second = Bytes::from_static(b"cd");
        let second_ptr = second.as_ptr();
        let mut source = Segments::new([first, second]);

        assert!(source.take_bytes(usize::MAX).is_err());
        assert!(source.take_chunks(usize::MAX).is_err());
        assert!(source.take_bytes(0).unwrap().is_empty());
        assert!(source.take_chunks(0).unwrap().is_empty());
        assert_eq!(source.len(), 4);
        assert!(source.finish().is_err());

        let contiguous = source.take_bytes(3).unwrap();
        let chunks = source.take_chunks(1).unwrap();
        source.finish().unwrap();

        assert_eq!(contiguous, b"abc");
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].as_ref(), b"d");
        assert_eq!(chunks[0].as_ptr(), second_ptr.wrapping_add(1));
    }

    #[test]
    fn size_prefix_helpers_validate_length() {
        assert_eq!(size_prefix_payload_len(&4u32.to_le_bytes()), Some(4));
        assert_eq!(size_prefix_payload_len(&[0; 3]), None);
        assert_eq!(size_prefixed_len(4), Some(SIZE_PREFIX_LEN + 4));
        assert_eq!(size_prefixed_len(usize::MAX), None);
    }
}
