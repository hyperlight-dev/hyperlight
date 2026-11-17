// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Values that futures carry.

use alloc::string::String;
use alloc::vec::Vec;

use bytes::Bytes;

/// A value that a future carries as bytes.
///
/// `()` encodes to no bytes, so a `()` future and an empty stream look the same. `Bytes` and
/// `Vec<u8>` encode to their bytes, and `String` to its UTF-8.
pub trait FutureValue: Sized {
    /// Encode the value.
    fn encode(self) -> Bytes;

    /// Decode a value from `bytes`, or return `None` when they hold no valid value.
    ///
    /// A valid value uses every byte, so trailing bytes make it invalid.
    fn decode(bytes: Bytes) -> Option<Self>;
}

impl FutureValue for () {
    fn encode(self) -> Bytes {
        Bytes::new()
    }

    fn decode(bytes: Bytes) -> Option<Self> {
        bytes.is_empty().then_some(())
    }
}

impl FutureValue for Bytes {
    fn encode(self) -> Bytes {
        self
    }

    fn decode(bytes: Bytes) -> Option<Self> {
        Some(bytes)
    }
}

impl FutureValue for Vec<u8> {
    fn encode(self) -> Bytes {
        Bytes::from(self)
    }

    fn decode(bytes: Bytes) -> Option<Self> {
        Some(Vec::from(bytes))
    }
}

impl FutureValue for String {
    fn encode(self) -> Bytes {
        Bytes::from(self)
    }

    fn decode(bytes: Bytes) -> Option<Self> {
        String::from_utf8(Vec::from(bytes)).ok()
    }
}
