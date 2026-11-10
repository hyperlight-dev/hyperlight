// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use alloc::vec;
use alloc::vec::Vec;

use bytes::Bytes;

/// Wrap contiguous bytes as one chunk without copying.
pub fn byte_chunks_from_bytes(value: Bytes) -> Vec<Bytes> {
    if value.is_empty() {
        Vec::new()
    } else {
        vec![value]
    }
}

/// Wrap a contiguous vector as one chunk without copying.
pub fn byte_chunks_from_vec(value: Vec<u8>) -> Vec<Bytes> {
    byte_chunks_from_bytes(Bytes::from(value))
}

/// Return the complete logical length of a chunked byte value.
pub(crate) fn byte_chunks_len(value: &[Bytes]) -> usize {
    value.iter().map(Bytes::len).sum()
}

/// Return the complete logical length, or `None` if the sum overflows.
pub(crate) fn try_byte_chunks_len(value: &[Bytes]) -> Option<usize> {
    value
        .iter()
        .try_fold(0usize, |length, chunk| length.checked_add(chunk.len()))
}

/// Materialize byte chunks as contiguous [`Bytes`].
///
/// This is O(1) for zero or one chunk and copies once for multiple chunks.
pub fn byte_chunks_to_bytes(value: &[Bytes]) -> Bytes {
    match value {
        [] => Bytes::new(),
        [chunk] => chunk.clone(),
        chunks => Bytes::from(byte_chunks_to_vec(chunks)),
    }
}

/// Materialize byte chunks as one contiguous vector.
///
/// This always allocates a new vector and copies the complete logical value.
pub fn byte_chunks_to_vec(value: &[Bytes]) -> Vec<u8> {
    let mut output = Vec::with_capacity(byte_chunks_len(value));
    for chunk in value {
        output.extend_from_slice(chunk);
    }
    output
}

#[cfg(feature = "fuzzing")]
pub(crate) fn arbitrary_byte_chunks(
    input: &mut arbitrary::Unstructured<'_>,
) -> arbitrary::Result<Vec<Bytes>> {
    <Vec<u8> as arbitrary::Arbitrary>::arbitrary(input).map(byte_chunks_from_vec)
}
