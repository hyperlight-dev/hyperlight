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

//! Shared guest and host transport protocol.
//!
//! Every logical message starts with this fixed header. It enables message type
//! discrimination, request/response correlation, and payload length validation.

use alloc::vec::Vec;

use anyhow::Result;
pub use bytes::Buf;
use bytes::Bytes;

use crate::flatbuffer_wrappers::ExternalValueSink;

/// Length of a FlatBuffer size prefix.
pub const SIZE_PREFIX_LEN: usize = core::mem::size_of::<u32>();

/// Message types for the virtqueue wire protocol.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub struct MsgHeader {
    /// Discriminates the message type.
    pub kind: u8,
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
            kind: kind as u8,
            reserved: [0; 3],
            cid,
            payload_len,
        }
    }

    /// Parse the kind field into a [`MsgKind`] enum.
    pub fn msg_kind(&self) -> Result<MsgKind, u8> {
        MsgKind::try_from(self.kind)
    }

    /// Return the wire representation.
    pub fn as_bytes(&self) -> &[u8] {
        bytemuck::bytes_of(self)
    }

    /// Parse and validate a wire header.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::SIZE {
            return None;
        }

        let header: Self = bytemuck::pod_read_unaligned(bytes);
        (header.reserved == [0; 3] && header.msg_kind().is_ok()).then_some(header)
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
        assert_eq!(header.msg_kind(), Ok(MsgKind::Response));
        assert_eq!(header.cid, 0x1234_5678);
        assert_eq!(header.payload_len, 4096);
        assert_eq!(header.reserved, [0; 3]);
    }

    #[test]
    fn rejects_invalid_wire_headers() {
        let header = MsgHeader::new(MsgKind::Request, 1, 4);
        let mut bytes = [0; MsgHeader::SIZE];
        bytes.copy_from_slice(header.as_bytes());

        bytes[1] = 1;
        assert_eq!(MsgHeader::from_bytes(&bytes), None);

        bytes[1] = 0;
        bytes[0] = u8::MAX;
        assert_eq!(MsgHeader::from_bytes(&bytes), None);

        bytes[0] = MsgKind::Request as u8;
        assert_eq!(MsgHeader::from_bytes(&bytes[..MsgHeader::SIZE - 1]), None);
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
    fn size_prefix_helpers_validate_length() {
        assert_eq!(size_prefix_payload_len(&4u32.to_le_bytes()), Some(4));
        assert_eq!(size_prefix_payload_len(&[0; 3]), None);
        assert_eq!(size_prefixed_len(4), Some(SIZE_PREFIX_LEN + 4));
        assert_eq!(size_prefixed_len(usize::MAX), None);
    }
}
