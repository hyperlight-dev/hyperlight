// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Guest-side virtqueue message decoding.

use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::{Bytes, FunctionCallResult};
use hyperlight_common::transport::{MsgHeader, MsgKind};
use hyperlight_common::virtq::Segments;

use crate::bail;
use crate::error::{GuestErrorContext, Result};

/// Decode one H2G guest-function request payload.
///
/// Chunked external values retain their H2G slot owners until their final
/// [`Bytes`] clone drops.
pub(super) fn decode_request(header: &MsgHeader, segments: Segments) -> Result<FunctionCall> {
    let (control, mut external_values) = decode_payload(header, segments)?;
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

    let (control, mut external_values) = decode_payload(&header, payload)?;
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
fn decode_payload(header: &MsgHeader, mut segments: Segments) -> Result<(Bytes, Segments)> {
    let control = segments
        .split_to(header.control_len as usize)
        .context("virtqueue message control data is truncated")?
        .into_bytes();

    Ok((control, segments))
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use hyperlight_common::flatbuffer_wrappers::ExternalValueSource;
    use hyperlight_common::flatbuffer_wrappers::function_types::ReturnValue;
    use hyperlight_common::transport::ExternalValues;

    use super::*;

    fn header(payload_len: u32, control_len: u32) -> MsgHeader {
        MsgHeader::new(MsgKind::Request, 1, payload_len, control_len)
    }

    #[test]
    fn payload_contiguous_control_reuses_storage() {
        // Control and external data share one transport allocation.
        let bytes = Bytes::from_static(b"ctrldata");
        let ptr = bytes.as_ptr();
        let (control, mut source) = decode_payload(&header(8, 4), Segments::single(bytes)).unwrap();

        assert_eq!(&control[..], b"ctrl");
        assert_eq!(control.as_ptr(), ptr);

        // External data outlives the control view.
        let chunks = source.take_chunks(4).unwrap();
        source.finish().unwrap();
        drop(control);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].as_ptr(), ptr.wrapping_add(4));
        assert_eq!(chunks[0].as_ref(), b"data");
    }

    #[test]
    fn payload_fragmented_control_preserves_external_storage() {
        // The control data crosses segment boundaries.
        let boundary = Bytes::from_static(b"rldata");
        let ptr = boundary.as_ptr();
        let segments = Segments::new([
            Bytes::new(),
            Bytes::from_static(b"c"),
            Bytes::new(),
            Bytes::from_static(b"t"),
            boundary,
        ]);

        let (control, mut source) = decode_payload(&header(8, 4), segments).unwrap();
        assert_eq!(&control[..], b"ctrl");

        // Only the control bytes are collected into contiguous storage.
        let chunks = source.take_chunks(4).unwrap();
        source.finish().unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].as_ptr(), ptr.wrapping_add(2));
        assert_eq!(chunks[0].as_ref(), b"data");
    }

    #[test]
    fn payload_rejects_truncated_control() {
        let segments = Segments::single(Bytes::from_static(b"ctr"));
        assert!(decode_payload(&header(4, 4), segments).is_err());
    }

    #[test]
    fn response_byte_chunks_retain_transport_storage() {
        let external = Bytes::from(vec![1, 2, 3, 4]);
        let external_ptr = external.as_ptr();

        let result = FunctionCallResult::new(Ok(ReturnValue::ByteChunks(vec![external.clone()])));
        let mut buffer = Vec::new();
        let mut external_values = ExternalValues::new();

        let control = result.encode(&mut buffer, &mut external_values).unwrap();

        let control_len = u32::try_from(control.len()).unwrap();
        let payload_len = u32::try_from(control.len() + external_values.total_len()).unwrap();
        let header = MsgHeader::new(MsgKind::Response, 7, payload_len, control_len);

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
        let mut buffer = Vec::new();
        let mut external_values = ExternalValues::new();

        let control = result.encode(&mut buffer, &mut external_values).unwrap();

        let len = u32::try_from(control.len()).unwrap();

        let segments = |payload_len, control_len| {
            let header = MsgHeader::new(MsgKind::Response, 7, payload_len, control_len);
            Segments::new([
                Bytes::copy_from_slice(header.as_bytes()),
                Bytes::copy_from_slice(control),
            ])
        };
        let error =
            |payload_len, control_len| match decode_response(segments(payload_len, control_len), 7)
            {
                Ok(_) => panic!("expected a decode error"),
                Err(error) => error.message,
            };

        assert!(decode_response(segments(len, len), 7).is_ok());
        for payload_len in [len - 1, len + 1] {
            assert_eq!(
                error(payload_len, len - 1),
                "Virtqueue message payload length mismatch"
            );
        }
        assert_eq!(
            error(len, len + 1),
            "Virtqueue message has an invalid header"
        );
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
        let mut buffer = Vec::new();
        let mut external_values = ExternalValues::new();
        let control = call.encode(&mut buffer, &mut external_values).unwrap();
        let control_len = u32::try_from(control.len()).unwrap();
        let header = MsgHeader::new(MsgKind::Request, 1, control_len + 4, control_len);
        let segments = Segments::new([Bytes::copy_from_slice(control), external]);

        let decoded = decode_request(&header, segments).unwrap();
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
