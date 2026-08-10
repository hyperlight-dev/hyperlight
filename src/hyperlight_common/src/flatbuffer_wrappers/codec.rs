// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use alloc::vec::Vec;

use anyhow::Result;
use bytes::Bytes;

/// Receives external byte values while their FlatBuffer metadata is encoded.
///
/// Values are delivered in their logical order without flattening chunked
/// values. The value lifetime allows a sink to retain references until the
/// control buffer has been written, without copying payload bytes.
pub trait ExternalValueSink<'a> {
    /// Receive one contiguous byte value.
    fn push_bytes(&mut self, value: &'a [u8]) -> Result<()>;

    /// Receive one chunk-preserving byte value.
    fn push_chunks(&mut self, value: &'a [Bytes]) -> Result<()>;
}

/// Supplies complete external byte values while a FlatBuffer is decoded.
pub trait ExternalValueSource {
    /// Take the next external value as contiguous bytes.
    fn take_bytes(&mut self, length: usize) -> Result<Vec<u8>>;

    /// Take the next external value as owned byte chunks.
    fn take_chunks(&mut self, length: usize) -> Result<Vec<Bytes>>;

    /// Finish decoding and reject any unused external values.
    fn finish(&mut self) -> Result<()>;
}
