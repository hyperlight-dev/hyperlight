// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Guest-side virtqueue message decoding.

use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::{Bytes, FunctionCallResult};
use hyperlight_common::transport::{
    Buf, MsgHeader, MsgKind, SIZE_PREFIX_LEN, size_prefix_payload_len, size_prefixed_len,
};
use hyperlight_common::virtq::Segments;

use crate::bail;
use crate::error::{GuestErrorContext, Result};

/// Decode one H2G guest-function request payload.
///
/// Chunked external values retain their H2G slot owners until their final
/// [`Bytes`] clone drops.
pub(super) fn decode_request(segments: Segments) -> Result<FunctionCall> {
    let (control, mut external_values) = decode_payload(segments)?;
    FunctionCall::decode(&control, &mut external_values)
        .with_context(|| "failed to decode guest function request")
}

/// Decode one G2H host-function response.
///
/// Contiguous byte values are flattened into `Vec<u8>`. Chunked values retain
/// their transport-backed [`Bytes`] owners.
pub(super) fn decode_response(segments: Segments, cid: u32) -> Result<FunctionCallResult> {
    let (header, payload) = split_header(segments)?;
    if header.kind != MsgKind::Response {
        bail!("Host function response has an invalid message kind");
    }

    if header.cid != cid {
        bail!("Host function response correlation ID mismatch");
    }

    let (control, mut external_values) = decode_payload(payload)?;
    FunctionCallResult::decode(&control, &mut external_values)
        .with_context(|| "failed to decode host function response")
}

fn split_header(mut segments: Segments) -> Result<(MsgHeader, Segments)> {
    let header = segments
        .split_to(MsgHeader::SIZE)
        .context("virtqueue message is missing its header")?
        .into_bytes();

    let Some(header) = MsgHeader::from_bytes(&header) else {
        bail!("Virtqueue message has an invalid header");
    };

    if usize::try_from(header.payload_len).ok() != Some(segments.len()) {
        bail!("Virtqueue message payload length mismatch");
    }

    Ok((header, segments))
}

/// Split control data into a contiguous view while retaining external owners.
fn decode_payload(mut segments: Segments) -> Result<(Bytes, Segments)> {
    let mut prefix = [0u8; SIZE_PREFIX_LEN];
    segments
        .as_buf()
        .try_copy_to_slice(&mut prefix)
        .context("virtqueue message is missing its size prefix")?;

    let payload_len =
        size_prefix_payload_len(&prefix).context("virtqueue message has an invalid prefix")?;

    let control_len =
        size_prefixed_len(payload_len).context("virtqueue message control length overflow")?;
    let control = segments
        .split_to(control_len)
        .context("virtqueue message control data is truncated")?
        .into_bytes();

    Ok((control, segments))
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use flatbuffers::FlatBufferBuilder;
    use hyperlight_common::flatbuffer_wrappers::ExternalValueSource;
    use hyperlight_common::flatbuffer_wrappers::function_types::ReturnValue;
    use hyperlight_common::transport::ExternalValues;

    use super::*;

    #[test]
    fn payload_contiguous_control_reuses_storage() {
        // Control and external data share one transport allocation.
        let bytes = Bytes::from(vec![
            4, 0, 0, 0, b'c', b't', b'r', b'l', b'd', b'a', b't', b'a',
        ]);
        let ptr = bytes.as_ptr();
        let (control, mut source) = decode_payload(Segments::single(bytes)).unwrap();

        assert_eq!(&control[..], b"\x04\0\0\0ctrl");
        assert_eq!(control.as_ptr(), ptr);

        // External data outlives the control view.
        let chunks = source.take_chunks(4).unwrap();
        source.finish().unwrap();
        drop(control);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].as_ptr(), ptr.wrapping_add(8));
        assert_eq!(chunks[0].as_ref(), b"data");
    }

    #[test]
    fn payload_fragmented_control_preserves_external_storage() {
        // Both the size prefix and control body cross segment boundaries.
        let boundary = Bytes::from(vec![b'r', b'l', b'd', b'a', b't', b'a']);
        let ptr = boundary.as_ptr();
        let segments = Segments::new([
            Bytes::new(),
            Bytes::from_static(b"\x04\0"),
            Bytes::new(),
            Bytes::from_static(b"\0\0ct"),
            boundary,
        ]);

        let (control, mut source) = decode_payload(segments).unwrap();
        assert_eq!(&control[..], b"\x04\0\0\0ctrl");

        // Only the control bytes are collected into contiguous storage.
        let chunks = source.take_chunks(4).unwrap();
        source.finish().unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].as_ptr(), ptr.wrapping_add(2));
        assert_eq!(chunks[0].as_ref(), b"data");
    }

    #[test]
    fn payload_rejects_short_size_prefix() {
        let prefix = 4u32.to_le_bytes();
        for len in 0..SIZE_PREFIX_LEN {
            let segments = Segments::new([Bytes::new(), Bytes::copy_from_slice(&prefix[..len])]);
            assert!(decode_payload(segments).is_err(), "prefix length {len}");
        }
    }

    #[test]
    fn payload_rejects_truncated_control() {
        // The prefix declares four control bytes, but only three follow.
        let segments = Segments::single(Bytes::from_static(b"\x04\0\0\0ctr"));
        assert!(decode_payload(segments).is_err());
    }

    #[test]
    fn response_byte_chunks_retain_transport_storage() {
        let external = Bytes::from(vec![1, 2, 3, 4]);
        let external_ptr = external.as_ptr();

        let result = FunctionCallResult::new(Ok(ReturnValue::ByteChunks(vec![external.clone()])));
        let mut builder = FlatBufferBuilder::new();
        let mut external_values = ExternalValues::new();

        let control = result.encode(&mut builder, &mut external_values).unwrap();

        let payload_len = u32::try_from(control.len() + external_values.total_len()).unwrap();
        let header = MsgHeader::new(MsgKind::Response, 7, payload_len);

        let segments = Segments::new([
            Bytes::copy_from_slice(header.as_bytes()),
            Bytes::copy_from_slice(control),
            external,
        ]);

        let decoded = decode_response(segments, 7).unwrap().into_inner().unwrap();
        let ReturnValue::ByteChunks(chunks) = decoded else {
            panic!("expected ByteChunks response");
        };

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].as_ptr(), external_ptr);
        assert_eq!(chunks[0].as_ref(), &[1, 2, 3, 4]);
    }

    #[test]
    fn response_rejects_payload_length_mismatch() {
        let result = FunctionCallResult::new(Ok(ReturnValue::UInt(17)));
        let mut builder = FlatBufferBuilder::new();
        let mut external_values = ExternalValues::new();

        let control = result.encode(&mut builder, &mut external_values).unwrap();

        let payload_len = u32::try_from(control.len()).unwrap();

        let segments = |length| {
            let header = MsgHeader::new(MsgKind::Response, 7, length);
            Segments::new([
                Bytes::copy_from_slice(header.as_bytes()),
                Bytes::copy_from_slice(control),
            ])
        };

        assert!(decode_response(segments(payload_len), 7).is_ok());
        for length in [payload_len - 1, payload_len + 1] {
            assert!(decode_response(segments(length), 7).is_err());
        }
    }

    #[test]
    fn request_byte_chunks_retain_transport_storage() {
        use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCallType;
        use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};

        let external = Bytes::from(vec![1, 2, 3, 4]);
        let external_ptr = external.as_ptr();
        let call = FunctionCall::new(
            "echo".into(),
            Some(vec![ParameterValue::ByteChunks(vec![external.clone()])]),
            FunctionCallType::Guest,
            ReturnType::ByteChunks,
        );
        let mut builder = FlatBufferBuilder::new();
        let mut external_values = ExternalValues::new();
        let control = call.encode(&mut builder, &mut external_values).unwrap();
        let segments = Segments::new([Bytes::copy_from_slice(control), external]);

        let decoded = decode_request(segments).unwrap();
        assert_eq!(decoded.function_name, "echo");
        let ParameterValue::ByteChunks(chunks) =
            decoded.parameters.unwrap().into_iter().next().unwrap()
        else {
            panic!("expected ByteChunks parameter");
        };

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].as_ptr(), external_ptr);
        assert_eq!(chunks[0].as_ref(), &[1, 2, 3, 4]);
    }
}
