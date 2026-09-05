// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Guest-side virtqueue message decoding.

use alloc::vec::Vec;

use hyperlight_common::flatbuffer_wrappers::ExternalValueSource;
use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::{Bytes, FunctionCallResult};
use hyperlight_common::transport::{
    MsgHeader, MsgKind, SIZE_PREFIX_LEN, size_prefix_payload_len, size_prefixed_len,
};
use hyperlight_common::virtq::Segments;

use crate::bail;
use crate::error::{GuestErrorContext, Result};

/// Decode one H2G guest-function request payload.
///
/// Chunked external values retain their H2G slot owners until their final
/// [`Bytes`] clone drops.
pub(super) fn decode_request(cid: u32, segments: Segments) -> Result<(u32, FunctionCall)> {
    if cid == 0 {
        bail!("Guest function request has correlation ID zero");
    }

    let (control, mut external_values) = decode_payload(segments)?;
    let call = FunctionCall::decode(&control, &mut external_values)
        .with_context(|| "failed to decode guest function request")?;

    Ok((cid, call))
}

/// Decode one G2H host-function response.
///
/// Contiguous byte values are flattened into `Vec<u8>`. Chunked values retain
/// their transport-backed [`Bytes`] owners.
pub(super) fn decode_response(segments: Segments, cid: u32) -> Result<FunctionCallResult> {
    let (header, payload) = split_header(segments)?;
    if header.msg_kind() != Ok(MsgKind::Response) {
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

/// Copy FlatBuffer control data while retaining external payload owners.
fn decode_payload(mut segments: Segments) -> Result<(Vec<u8>, SegmentSource)> {
    let prefix = segments
        .split_to(SIZE_PREFIX_LEN)
        .context("virtqueue message is missing its size prefix")?
        .into_bytes();

    let payload_len =
        size_prefix_payload_len(&prefix).context("virtqueue message has an invalid prefix")?;

    let payload = segments
        .split_to(payload_len)
        .context("virtqueue message control data is truncated")?;

    let control_len =
        size_prefixed_len(payload_len).context("virtqueue message control length overflow")?;

    let mut control = Vec::with_capacity(control_len);
    control.extend_from_slice(&prefix);

    for segment in payload.iter() {
        control.extend_from_slice(segment);
    }

    Ok((control, SegmentSource::new(segments)))
}

/// Supplies complete logical external values from transport segments.
struct SegmentSource {
    segments: Segments,
}

impl SegmentSource {
    fn new(segments: Segments) -> Self {
        Self { segments }
    }

    fn take(&mut self, length: usize) -> anyhow::Result<Segments> {
        self.segments.split_to(length).ok_or_else(|| {
            anyhow::anyhow!(
                "External value requires {length} bytes, only {} remain",
                self.segments.len()
            )
        })
    }
}

impl ExternalValueSource for SegmentSource {
    fn take_bytes(&mut self, length: usize) -> anyhow::Result<Vec<u8>> {
        let segments = self.take(length)?;
        let mut value = Vec::with_capacity(length);
        for segment in segments.iter() {
            value.extend_from_slice(segment);
        }
        Ok(value)
    }

    fn take_chunks(&mut self, length: usize) -> anyhow::Result<Vec<Bytes>> {
        Ok(self.take(length)?.into_chunks())
    }

    fn finish(&mut self) -> anyhow::Result<()> {
        if !self.segments.is_empty() {
            anyhow::bail!(
                "Virtqueue message has {} trailing external bytes",
                self.segments.len()
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use flatbuffers::FlatBufferBuilder;
    use hyperlight_common::flatbuffer_wrappers::function_types::ReturnValue;
    use hyperlight_common::transport::ExternalValues;

    use super::*;

    #[test]
    fn response_byte_chunks_retain_transport_storage() {
        let external = Bytes::from(vec![1, 2, 3, 4]);
        let external_ptr = external.as_ptr();
        let result = FunctionCallResult::new(Ok(ReturnValue::ByteChunks(vec![external.clone()])));
        let mut builder = FlatBufferBuilder::new();
        let mut external_values = ExternalValues::new();
        let control = result.encode(&mut builder, &mut external_values).unwrap();
        let payload_len = control.len() + external.len();
        let header = MsgHeader::new(MsgKind::Response, 7, u32::try_from(payload_len).unwrap());
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
    fn segment_source_flattens_only_contiguous_values() {
        let first = Bytes::from_static(b"ab");
        let second = Bytes::from_static(b"cd");
        let second_ptr = second.as_ptr();
        let mut source = SegmentSource::new(Segments::new([first, second]));

        let contiguous = source.take_bytes(3).unwrap();
        let chunks = source.take_chunks(1).unwrap();
        source.finish().unwrap();

        assert_eq!(contiguous, b"abc");
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].as_ref(), b"d");
        assert_eq!(chunks[0].as_ptr(), second_ptr.wrapping_add(1));
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

        let (cid, decoded) = decode_request(9, segments).unwrap();
        let ParameterValue::ByteChunks(chunks) =
            decoded.parameters.unwrap().into_iter().next().unwrap()
        else {
            panic!("expected ByteChunks parameter");
        };

        assert_eq!(cid, 9);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].as_ptr(), external_ptr);
        assert_eq!(chunks[0].as_ref(), &[1, 2, 3, 4]);
    }
}
