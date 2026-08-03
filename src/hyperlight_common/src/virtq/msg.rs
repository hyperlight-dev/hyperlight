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

//! Wire framing for virtqueue messages.
//!
//! Every message chain on both the G2H and H2G queues starts with this fixed
//! 8-byte header, enabling message type discrimination and request/response
//! correlation. Payload lengths come from the size-prefixed FlatBuffer and its
//! external-byte declarations.

use crate::flatbuffer_wrappers::{ExternalValueRef, ExternalValueRefs};

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
            other => Err(other),
        }
    }
}

/// Wire header for all virtqueue messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub struct VirtqMsgHeader {
    /// Discriminates the message type.
    pub kind: u8,
    /// keep the header 8 bytes long and aligned to 4 bytes.
    reserved: [u8; 3],
    /// Caller-assigned correlation ID. Responses echo the request's ID.
    pub cid: u32,
}

impl VirtqMsgHeader {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Create a message header.
    pub const fn new(kind: MsgKind, cid: u32) -> Self {
        Self {
            kind: kind as u8,
            reserved: [0; 3],
            cid,
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
    header: VirtqMsgHeader,
    control: &'a [u8],
    externals: ExternalValueRefs<'a>,
    wire_len: usize,
}

impl<'a> EncodedMessage<'a> {
    /// Build a message, returning `None` if its wire length overflows.
    pub fn new(
        kind: MsgKind,
        cid: u32,
        control: &'a [u8],
        externals: ExternalValueRefs<'a>,
    ) -> Option<Self> {
        let wire_len = VirtqMsgHeader::SIZE
            .checked_add(control.len())?
            .checked_add(externals.total_len()?)?;

        Some(Self {
            header: VirtqMsgHeader::new(kind, cid),
            control,
            externals,
            wire_len,
        })
    }

    /// Visit wire chunks in transmission order.
    pub fn try_for_each_chunk<E>(
        &self,
        mut visit: impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        visit(self.header.as_bytes())?;
        visit(self.control)?;

        for val in self.externals.as_slice() {
            match val {
                ExternalValueRef::Bytes(value) => visit(value)?,
                ExternalValueRef::Chunks(chunks) => chunks.iter().try_for_each(|c| visit(c))?,
            }
        }

        Ok(())
    }

    /// Total wire length of all chunks.
    pub const fn wire_len(&self) -> usize {
        self.wire_len
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
    fn header_contains_only_kind_and_cid() {
        let header = VirtqMsgHeader::new(MsgKind::Response, 0x1234_5678);

        assert_eq!(VirtqMsgHeader::SIZE, 8);
        assert_eq!(header.msg_kind(), Ok(MsgKind::Response));
        assert_eq!(header.cid, 0x1234_5678);
        assert_eq!(header.reserved, [0; 3]);
    }

    #[test]
    fn rejects_invalid_wire_headers() {
        let header = VirtqMsgHeader::new(MsgKind::Request, 1);
        let mut bytes = [0; VirtqMsgHeader::SIZE];
        bytes.copy_from_slice(header.as_bytes());

        bytes[1] = 1;
        assert_eq!(VirtqMsgHeader::from_bytes(&bytes), None);

        bytes[1] = 0;
        bytes[0] = u8::MAX;
        assert_eq!(VirtqMsgHeader::from_bytes(&bytes), None);
        assert_eq!(VirtqMsgHeader::from_bytes(&bytes[..7]), None);
    }

    #[test]
    fn encoded_message_visits_wire_chunks_in_order() {
        let chunks = [
            bytes::Bytes::from_static(b"ef"),
            bytes::Bytes::from_static(b"gh"),
        ];
        let mut external_values = ExternalValueRefs::new();
        external_values.push_bytes(b"cd").unwrap();
        external_values.push_chunks(&chunks).unwrap();

        let message = EncodedMessage::new(MsgKind::Request, 7, b"ab", external_values).unwrap();
        let mut visited = Vec::new();
        message
            .try_for_each_chunk(|chunk| {
                visited.push(chunk.to_vec());
                Ok::<_, ()>(())
            })
            .unwrap();

        assert_eq!(message.wire_len(), VirtqMsgHeader::SIZE + 8);
        assert_eq!(visited[1..], [b"ab", b"cd", b"ef", b"gh"]);
    }

    #[test]
    fn size_prefix_helpers_validate_length() {
        assert_eq!(size_prefix_payload_len(&4u32.to_le_bytes()), Some(4));
        assert_eq!(size_prefix_payload_len(&[0; 3]), None);
        assert_eq!(size_prefixed_len(4), Some(SIZE_PREFIX_LEN + 4));
        assert_eq!(size_prefixed_len(usize::MAX), None);
    }
}
