// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Stream operation errors and protocol violations.

use thiserror::Error;

use super::StreamId;

/// Errors returned by stream operations.
#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamError {
    /// The reader closed, so the stream accepts no more bytes.
    #[error("stream reader closed")]
    ReaderClosed,
    /// The stream ended before the read was filled.
    #[error("stream ended early")]
    UnexpectedEof,
    /// The writer aborted the stream to report a failure.
    #[error("stream writer aborted")]
    Aborted,
}

/// A peer broke the stream protocol. The session fails when it finds one.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtocolError {
    /// A call-only mux cannot exchange stream records or readers.
    #[error("streams are disabled")]
    Disabled,
    /// A batch has no records.
    #[error("empty stream batch")]
    EmptyBatch,
    /// A message's external bytes do not match its DATA records.
    #[error("stream payload does not match its DATA records")]
    Payload,
    /// A record has invalid fields. Holds the first byte of its tag.
    #[error("malformed stream record with tag {0:#04x}")]
    Malformed(u8),
    /// A record names a sid that its receiver does not know.
    #[error("unknown stream {0:#x}")]
    UnknownStream(StreamId),
    /// A record does not fit the state of its stream.
    #[error("unexpected record for stream {0:#x}")]
    InvalidState(StreamId),
    /// A reader transfer is invalid, or a message moves too many readers.
    #[error("invalid reader transfer")]
    Transfer,
    /// A serialization or deserialization error from Serde.
    #[error("serde error: {0}")]
    SerdeError(#[from] postcard::Error),
}
