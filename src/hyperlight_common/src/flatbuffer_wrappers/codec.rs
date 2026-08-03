// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use alloc::vec::Vec;

use anyhow::Result;
use bytes::Bytes;

/// One borrowed external byte value emitted alongside a FlatBuffer.
#[derive(Clone, Copy, Debug)]
pub enum ExternalValueRef<'a> {
    /// A logically contiguous value.
    Bytes(&'a [u8]),
    /// A logically chunked value.
    Chunks(&'a [Bytes]),
}

impl ExternalValueRef<'_> {
    /// Total byte length of this value.
    pub fn len(&self) -> Option<usize> {
        match self {
            Self::Bytes(value) => Some(value.len()),
            Self::Chunks(chunks) => chunks
                .iter()
                .try_fold(0usize, |len, chunk| len.checked_add(chunk.len())),
        }
    }

    /// Whether this value contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == Some(0)
    }
}

/// Borrowed external values collected while encoding a FlatBuffer.
#[derive(Debug, Default)]
pub struct ExternalValueRefs<'a> {
    values: Vec<ExternalValueRef<'a>>,
}

impl<'a> ExternalValueRefs<'a> {
    /// Create an empty collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrow the collected values in wire order.
    pub fn as_slice(&self) -> &[ExternalValueRef<'a>] {
        &self.values
    }

    /// Number of collected logical values.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether no logical values were collected.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Total byte length of all collected values.
    pub fn total_len(&self) -> Option<usize> {
        self.values
            .iter()
            .try_fold(0usize, |len, value| len.checked_add(value.len()?))
    }
}

impl<'a> ExternalValueSink<'a> for ExternalValueRefs<'a> {
    fn push_bytes(&mut self, value: &'a [u8]) -> Result<()> {
        self.values.push(ExternalValueRef::Bytes(value));
        Ok(())
    }

    fn push_chunks(&mut self, value: &'a [Bytes]) -> Result<()> {
        self.values.push(ExternalValueRef::Chunks(value));
        Ok(())
    }
}

/// Receives external byte values while their FlatBuffer metadata is encoded.
///
/// Values are delivered in their logical order without flattening chunked
/// values. The value lifetime allows a sink to retain references until the
/// control buffer has been written, without copying payload bytes.
pub trait ExternalValueSink<'a> {
    /// Receive one contiguous byte value.
    fn push_bytes(&mut self, value: &'a [u8]) -> Result<()>;

    /// Receive one logical byte sequence represented as chunks.
    fn push_chunks(&mut self, value: &'a [Bytes]) -> Result<()>;
}

/// Supplies complete external byte values while a FlatBuffer is decoded.
///
/// Implementations must validate `length` against available input and the
/// resource budget before allocating.
pub trait ExternalValueSource {
    /// Take the next external value as contiguous bytes.
    fn take_bytes(&mut self, length: usize) -> Result<Vec<u8>>;

    /// Take the next external value as owned byte chunks.
    fn take_chunks(&mut self, length: usize) -> Result<Vec<Bytes>>;

    /// Finish decoding and reject any unused external values.
    fn finish(&mut self) -> Result<()>;
}
