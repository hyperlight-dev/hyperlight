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

//! Wire format header for all virtqueue messages.
//!
//! Every message chain on both the G2H and H2G queues starts with this fixed
//! 8-byte header, enabling message type discrimination and request/response
//! correlation. Payload lengths come from the size-prefixed FlatBuffer and its
//! external-byte declarations.

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
