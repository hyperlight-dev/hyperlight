// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Guest-side virtqueue message decoding.

use alloc::vec;
use alloc::vec::Vec;

use hyperlight_common::flatbuffer_wrappers::ExternalValueSource;
use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::{Bytes, FunctionCallResult};
use hyperlight_common::stream::{GOOD_COPY_LEN, Mux};
use hyperlight_common::transport::{MsgHeader, MsgKind};
use hyperlight_common::virtq::Segments;

use crate::bail;
use crate::error::{GuestErrorContext, Result};

/// Decode one H2G guest-function request payload, accepting its readers
/// through `mux`.
///
/// Chunked external values retain their H2G slot owners until their final
/// [`Bytes`] clone drops.
pub(super) fn decode_request(
    control_len: u32,
    segments: Segments,
    mux: &mut Mux,
) -> Result<FunctionCall> {
    let (control, mut external_values) = decode_payload(control_len, segments)?;
    FunctionCall::decode(&control, &mut external_values, mux)
        .with_context(|| "failed to decode guest function request")
}

/// Decode one G2H host-function response, accepting a returned reader
/// through `mux`.
///
/// Contiguous byte values are flattened into `Vec<u8>`. Chunked values retain
/// their transport-backed [`Bytes`] owners.
pub(super) fn decode_response(
    segments: Segments,
    cid: u32,
    mux: &mut Mux,
) -> Result<FunctionCallResult> {
    let (header, payload) = split_header(segments)?;
    if header.kind != MsgKind::Response {
        bail!("Host function response has an invalid message kind");
    }

    if header.cid != cid {
        bail!("Host function response correlation ID mismatch");
    }

    let (control, mut external_values) = decode_payload(header.control_len, payload)?;
    FunctionCallResult::decode(&control, &mut external_values, mux)
        .with_context(|| "failed to decode host function response")
}

/// Apply one H2G `Stream` message payload to `mux`.
pub(super) fn recv_stream(control_len: u32, segments: Segments, mux: &mut Mux) -> Result<()> {
    let (control, payloads) = decode_payload(control_len, segments)?;

    mux.recv_records(&control, &mut StreamSource(payloads))
        .with_context(|| "invalid H2G stream message")
}

/// Copies small DATA records so they do not pin a slot. Larger records keep their slot owners.
struct StreamSource(Segments);

impl ExternalValueSource for StreamSource {
    fn take_bytes(&mut self, length: usize) -> anyhow::Result<Vec<u8>> {
        self.0.take_bytes(length)
    }

    fn take_chunks(&mut self, length: usize) -> anyhow::Result<Vec<Bytes>> {
        if (1..=GOOD_COPY_LEN).contains(&length) {
            return Ok(vec![Bytes::from(self.0.take_bytes(length)?)]);
        }

        self.0.take_chunks(length)
    }

    fn finish(&mut self) -> anyhow::Result<()> {
        self.0.finish()
    }
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
fn decode_payload(control_len: u32, mut segments: Segments) -> Result<(Bytes, Segments)> {
    let control = segments
        .split_to(control_len as usize)
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
    use hyperlight_common::stream::{DEFAULT_WINDOW, Side};
    use hyperlight_common::transport::PendingMessage;

    use super::*;

    fn mux(side: Side) -> Mux {
        Mux::new(side, DEFAULT_WINDOW)
    }

    #[test]
    fn payload_contiguous_control_reuses_storage() {
        // Control and external data share one transport allocation.
        let bytes = Bytes::from_static(b"ctrldata");
        let ptr = bytes.as_ptr();
        let (control, mut source) = decode_payload(4, Segments::single(bytes)).unwrap();

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

        let (control, mut source) = decode_payload(4, segments).unwrap();
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
        assert!(decode_payload(4, segments).is_err());
    }

    #[test]
    fn response_byte_chunks_retain_transport_storage() {
        let external = Bytes::from(vec![1, 2, 3, 4]);
        let external_ptr = external.as_ptr();

        let result = FunctionCallResult::new(Ok(ReturnValue::ByteChunks(vec![external.clone()])));
        let mut host = mux(Side::Host);
        let mut buffer = Vec::new();
        let pending = PendingMessage::new_result(result, 7, &mut host).unwrap();
        let msg = pending.encode(&mut buffer).unwrap();

        let segments = Segments::new([
            Bytes::copy_from_slice(msg.header().as_bytes()),
            Bytes::copy_from_slice(msg.control()),
            external,
        ]);

        let decoded = decode_response(segments, 7, &mut mux(Side::Guest))
            .unwrap()
            .into_inner()
            .unwrap();
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
        let mut host = mux(Side::Host);
        let mut buffer = Vec::new();
        let pending = PendingMessage::new_result(result, 7, &mut host).unwrap();
        let message = pending.encode(&mut buffer).unwrap();
        let control = message.control();

        let len = u32::try_from(control.len()).unwrap();

        let segments = |payload_len, control_len| {
            let header = MsgHeader::new(MsgKind::Response, 7, payload_len, control_len);
            Segments::new([
                Bytes::copy_from_slice(header.as_bytes()),
                Bytes::copy_from_slice(control),
            ])
        };

        let decode = |payload_len, control_len| {
            decode_response(segments(payload_len, control_len), 7, &mut mux(Side::Guest))
        };

        let error = |payload_len, control_len| match decode(payload_len, control_len) {
            Ok(_) => panic!("expected a decode error"),
            Err(error) => error.message,
        };

        assert!(decode(len, len).is_ok());
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
        let mut host = mux(Side::Host);
        let mut buffer = Vec::new();
        let pending = PendingMessage::new_call(call, 1, &mut host).unwrap();
        let msg = pending.encode(&mut buffer).unwrap();
        let control_len = msg.header().control_len;
        let segments = Segments::new([Bytes::copy_from_slice(msg.control()), external]);

        let decoded = decode_request(control_len, segments, &mut mux(Side::Guest)).unwrap();
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

    #[cfg(feature = "streams")]
    #[test]
    fn only_large_stream_records_pin_a_shared_slot() {
        use core::pin::pin;
        use core::task::{Context, Poll, Waker};

        use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCallType;
        use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};
        use hyperlight_common::stream;

        let mut host = mux(Side::Host);
        let mut guest = mux(Side::Guest);
        let mut buffer = Vec::new();
        let mut cx = Context::from_waker(Waker::noop());

        let small_data = [0x5a; GOOD_COPY_LEN];
        let large_data = [0xa5; GOOD_COPY_LEN + 1];
        let (small, mut small_writer) = stream::new::<u8>();
        let (large, mut large_writer) = stream::new::<u8>();

        assert_eq!(
            pin!(small_writer.write(&small_data)).poll(&mut cx),
            Poll::Ready(Ok(small_data.len()))
        );
        assert_eq!(
            pin!(large_writer.write(&large_data)).poll(&mut cx),
            Poll::Ready(Ok(large_data.len()))
        );

        let call = FunctionCall::new(
            "read".into(),
            Some(vec![
                ParameterValue::StreamReader(small),
                ParameterValue::StreamReader(large),
            ]),
            FunctionCallType::Guest,
            ReturnType::Void,
        );

        let pending = PendingMessage::new_call(call, 1, &mut host).unwrap();
        let msg = pending.encode(&mut buffer).unwrap();
        let segments = Segments::single(Bytes::copy_from_slice(msg.control()));
        let mut call = decode_request(msg.header().control_len, segments, &mut guest).unwrap();

        drop(msg);
        pending.settle(Ok(())).unwrap();

        let Some(
            [
                ParameterValue::StreamReader(small),
                ParameterValue::StreamReader(large),
            ],
        ) = call.parameters.as_deref_mut()
        else {
            panic!("expected two reader parameters");
        };

        let pending = PendingMessage::next_stream(&mut host, 4096).unwrap();
        let msg = pending.encode(&mut buffer).unwrap();
        let mut slot = msg.control().to_vec();

        for chunk in msg.external_chunks() {
            slot.extend_from_slice(chunk);
        }

        let slot = Bytes::from(slot);
        let segments = Segments::single(slot.clone());
        recv_stream(msg.header().control_len, segments, &mut guest).unwrap();

        let Poll::Ready(Ok(Some(small))) = pin!(small.read_chunk()).poll(&mut cx) else {
            panic!("expected the small DATA record");
        };

        let Poll::Ready(Ok(Some(large))) = pin!(large.read_chunk()).poll(&mut cx) else {
            panic!("expected the large DATA record");
        };

        assert_eq!(large.as_ref(), large_data);
        assert!(slot.as_ptr_range().contains(&large.as_ptr()));
        drop(large);

        assert!(slot.is_unique());
        assert_eq!(small.as_ref(), small_data);
    }
}
