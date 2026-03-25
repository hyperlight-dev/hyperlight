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
}

/// Wire header for all virtqueue messages
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub struct VirtqMsgHeader {
    /// Discriminates the message type.
    pub kind: u8,
    /// Per-type flags TODO(ring): add flags type.
    pub flags: u8,
    /// Caller-assigned correlation ID. Responses echo the request's ID.
    pub req_id: u16,
    /// Byte length of the payload following this header.
    pub payload_len: u32,
}

impl VirtqMsgHeader {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Create a new message header.
    pub const fn new(kind: MsgKind, req_id: u16, payload_len: u32) -> Self {
        Self {
            kind: kind as u8,
            flags: 0,
            req_id,
            payload_len,
        }
    }

    /// Create a new header with flags.
    pub const fn with_flags(kind: MsgKind, flags: u8, req_id: u16, payload_len: u32) -> Self {
        Self {
            kind: kind as u8,
            flags,
            req_id,
            payload_len,
        }
    }
}
