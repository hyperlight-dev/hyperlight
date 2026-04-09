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
//! Every payload on both the G2H and H2G queues starts with this
//! fixed 8-byte header, enabling message type discrimination and
//! request/response correlation.

use bitflags::bitflags;

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

bitflags! {
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct MsgFlags: u8 {
        /// More descriptors follow for this message.
        const MORE = 1 << 0;
    }
}

/// Wire header for all virtqueue messages
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub struct VirtqMsgHeader {
    /// Discriminates the message type.
    pub kind: u8,
    /// Per-message flags (see [`MsgFlags`]).
    pub flags: u8,
    /// Caller-assigned correlation ID. Responses echo the request's ID.
    pub req_id: u16,
    /// Byte length of the payload following this header in this descriptor.
    pub payload_len: u32,
}

impl VirtqMsgHeader {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Create a new message header with no flags set.
    pub const fn new(kind: MsgKind, req_id: u16, payload_len: u32) -> Self {
        Self {
            kind: kind as u8,
            flags: 0,
            req_id,
            payload_len,
        }
    }

    /// Create a new header with flags.
    pub const fn with_flags(kind: MsgKind, flags: MsgFlags, req_id: u16, payload_len: u32) -> Self {
        Self {
            kind: kind as u8,
            flags: flags.bits(),
            req_id,
            payload_len,
        }
    }

    /// Parse the kind field into a [`MsgKind`] enum.
    pub fn msg_kind(&self) -> Result<MsgKind, u8> {
        MsgKind::try_from(self.kind)
    }

    /// Interpret the raw flags field as [`MsgFlags`].
    pub fn msg_flags(&self) -> MsgFlags {
        MsgFlags::from_bits_truncate(self.flags)
    }

    /// Returns true if [`MsgFlags::MORE`] is set, indicating more
    /// descriptors follow for this message.
    pub const fn has_more(&self) -> bool {
        self.flags & MsgFlags::MORE.bits() != 0
    }
}
