// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use alloc::vec::Vec;

use anyhow::{Result, anyhow};
use bytes::Bytes;

/// The control data room in a message that carries `external_len` bytes of external values.
///
/// A message's payload length is a `u32`.
pub(super) fn control_cap(external_len: usize) -> Result<usize> {
    (u32::MAX as usize)
        .checked_sub(external_len)
        .ok_or_else(|| anyhow!("External values of {external_len} bytes do not fit one message"))
}

/// Receives external byte values while their control data is encoded.
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

/// Supplies complete external byte values while control data is decoded.
///
/// [`RecvChain`](crate::virtq::RecvChain) copies values out of shared memory.
/// [`Segments`](crate::virtq::Segments) retains existing chunk owners.
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

#[cfg(all(test, not(loom), feature = "streams"))]
mod tests {
    use alloc::string::ToString;
    use alloc::sync::Arc;
    use alloc::vec;
    use core::assert_matches;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};

    use super::*;
    use crate::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
    use crate::flatbuffer_wrappers::function_types::{
        FunctionCallResult, ParameterValue, ReturnType, ReturnValue,
    };
    use crate::flatbuffer_wrappers::wire::WireValue;
    use crate::stream::{
        self, DEFAULT_WINDOW, MAX_TRANSFERS, Mux, ProtocolError, Side, StreamError, StreamId,
        StreamReader, StreamWriter, Transfer,
    };
    use crate::transport::{MsgHeader, MsgKind, PendingMessage};
    use crate::virtq::{Segments, VirtqError};

    const G1: StreamId = StreamId::new(Side::Guest, 1).unwrap();

    /// A host Mux and a guest Mux.
    fn pair() -> (Mux, Mux) {
        (
            Mux::new(Side::Host, DEFAULT_WINDOW),
            Mux::new(Side::Guest, DEFAULT_WINDOW),
        )
    }

    /// The transfer of host stream `index`'s reader at position 0.
    fn arriving(index: u64) -> Transfer {
        let sid = StreamId::new(Side::Host, index).unwrap();
        Transfer { sid, position: 0 }
    }

    /// A guest call to `f` with `params`.
    fn call(params: Vec<ParameterValue>) -> FunctionCall {
        FunctionCall::new(
            "f".to_string(),
            Some(params),
            FunctionCallType::Guest,
            ReturnType::Void,
        )
    }

    /// Publish `out` and return its header, control data, and external values.
    fn publish(out: PendingMessage<'_>) -> (MsgHeader, Vec<u8>, Segments) {
        let (header, control, externals) = {
            let mut buffer = Vec::new();
            let message = out.encode(&mut buffer).unwrap();
            let externals = message.external_chunks().map(Bytes::copy_from_slice);

            (
                *message.header(),
                message.control().to_vec(),
                Segments::new(externals),
            )
        };

        out.settle(Ok(())).unwrap();
        (header, control, externals)
    }

    /// Decode a guest call to `f` with forged `params` through `mux`.
    fn decode_forged(mux: &mut Mux, params: &[WireValue<'_>]) -> Result<()> {
        let call = ("f", false, ReturnType::Void, params);
        let control = postcard::to_extend(&call, Vec::new())?;

        FunctionCall::decode(&control, &mut Segments::default(), mux).map(drop)
    }

    /// Poll one write to `writer`.
    fn write(writer: &mut StreamWriter<u8>) -> Poll<Result<usize, StreamError>> {
        pin!(writer.write(b"x")).poll(&mut Context::from_waker(Waker::noop()))
    }

    #[test]
    fn readers_move_inline_and_return_to_origin() {
        let (mut host, mut guest) = pair();
        let (a, _a) = stream::new();
        let (b, _b) = stream::new();
        let b_pipe = Arc::clone(b.pipe());

        let call = FunctionCall::new(
            "f".to_string(),
            Some(vec![
                ParameterValue::StreamReader(a),
                ParameterValue::Int(1),
                ParameterValue::StreamReader(b),
            ]),
            FunctionCallType::Guest,
            ReturnType::StreamReader,
        );
        let (header, control, mut externals) =
            publish(PendingMessage::new_call(call, 1, &mut host).unwrap());

        #[rustfmt::skip]
        let expected = [
            1, b'f', 0, 11, // name, guest, ReturnType::StreamReader
            3,              // parameter count
            10, 2, 0,       // StreamReader, host sid 1 at position 0
            0, 2,           // Int(1)
            10, 4, 0,       // StreamReader, host sid 2 at position 0
        ];
        assert_eq!((header.kind, header.cid), (MsgKind::Request, 1));
        assert_eq!(control, expected);

        let mut params = FunctionCall::decode(&control, &mut externals, &mut guest)
            .unwrap()
            .parameters
            .unwrap();
        let b = StreamReader::<u8>::try_from(params.pop().unwrap()).unwrap();

        assert_matches!(params[0], ParameterValue::StreamReader(_));
        assert_eq!(params[1], ParameterValue::Int(1));

        let result = FunctionCallResult::new(Ok(ReturnValue::StreamReader(b)));
        let (header, control, mut externals) =
            publish(PendingMessage::new_result(result, 1, &mut guest).unwrap());

        // Ok, StreamReader, host sid 2 at position 0.
        assert_eq!((header.kind, header.cid), (MsgKind::Response, 1));
        assert_eq!(control, [0, 10, 4, 0]);

        let result = FunctionCallResult::decode(&control, &mut externals, &mut host).unwrap();
        let b = StreamReader::<u8>::try_from(result.into_inner().unwrap()).unwrap();

        assert!(Arc::ptr_eq(b.pipe(), &b_pipe));
    }

    #[test]
    fn byte_values_travel_beside_readers() {
        let (mut host, mut guest) = pair();
        let (reader, _writer) = stream::new();
        let chunks = || vec![Bytes::from_static(b"ab"), Bytes::from_static(b"c")];

        let call = call(vec![
            ParameterValue::VecBytes(vec![1, 2]),
            ParameterValue::StreamReader(reader),
            ParameterValue::ByteChunks(chunks()),
        ]);
        let (_, control, mut externals) =
            publish(PendingMessage::new_call(call, 1, &mut host).unwrap());

        assert_eq!(externals.len(), 5);

        let params = FunctionCall::decode(&control, &mut externals, &mut guest)
            .unwrap()
            .parameters
            .unwrap();

        assert_eq!(params[0], ParameterValue::VecBytes(vec![1, 2]));
        assert_matches!(params[1], ParameterValue::StreamReader(_));
        assert_eq!(params[2], ParameterValue::ByteChunks(chunks()));

        let result = FunctionCallResult::new(Ok(ReturnValue::ByteChunks(chunks())));
        let (_, control, mut externals) =
            publish(PendingMessage::new_result(result, 1, &mut guest).unwrap());

        let result = FunctionCallResult::decode(&control, &mut externals, &mut host).unwrap();
        assert_eq!(
            result.into_inner().unwrap(),
            ReturnValue::ByteChunks(chunks())
        );
    }

    #[test]
    fn pending_message_keeps_byte_owners() {
        let (mut host, _) = pair();
        let mut buffer = Vec::new();
        let bytes = vec![1, 2, 3];
        let bytes_ptr = bytes.as_ptr();
        let chunk = Bytes::from(vec![4, 5]);
        let params = vec![
            ParameterValue::VecBytes(bytes),
            ParameterValue::ByteChunks(vec![chunk.clone()]),
        ];
        let pending = PendingMessage::new_call(call(params), 1, &mut host).unwrap();
        let message = pending.encode(&mut buffer).unwrap();

        assert!(!chunk.is_unique());

        for _ in 0..2 {
            let mut chunks = message.external_chunks();

            assert_eq!(chunks.next().unwrap().as_ptr(), bytes_ptr);
            assert_eq!(chunks.next().unwrap().as_ptr(), chunk.as_ptr());
            assert!(chunks.next().is_none());
        }

        drop(message);
        assert!(!chunk.is_unique());

        assert_matches!(
            pending.settle(Err::<(), _>(VirtqError::Backpressure)),
            Err(VirtqError::Backpressure)
        );
        assert!(chunk.is_unique());
    }

    #[test]
    fn reader_transfers_are_checked() {
        let reader = |index| WireValue::StreamReader(arriving(index));

        let (_, mut guest) = pair();
        let invalid = WireValue::StreamReader(Transfer {
            position: 1,
            ..arriving(1)
        });
        let error = decode_forged(&mut guest, &[invalid]).err().unwrap();
        assert_matches!(
            error.downcast_ref::<ProtocolError>(),
            Some(ProtocolError::Transfer)
        );

        let (_, mut guest) = pair();
        assert!(decode_forged(&mut guest, &[reader(1), reader(1)]).is_err());

        let (_, mut guest) = pair();
        let mut readers: Vec<_> = (1..=MAX_TRANSFERS as u64).map(reader).collect();
        assert!(decode_forged(&mut guest, &readers).is_ok());

        // Each transfer would pass `Mux::recv_transfer`, since 16 readers arrive and one returns.
        // The count rejects the returning reader before its transfer is received.
        let (_, mut guest) = pair();
        let (sent, mut writer) = stream::new();
        let params = vec![ParameterValue::StreamReader(sent)];
        publish(PendingMessage::new_call(call(params), 1, &mut guest).unwrap());

        readers.push(WireValue::StreamReader(Transfer {
            sid: G1,
            position: 0,
        }));
        let error = decode_forged(&mut guest, &readers).err().unwrap();
        assert_matches!(
            error.downcast_ref::<ProtocolError>(),
            Some(ProtocolError::Transfer)
        );
        assert_matches!(
            write(&mut writer),
            Poll::Ready(Err(StreamError::ReaderClosed))
        );
    }

    #[test]
    fn failed_call_decode_closes_readers_and_fails_the_session() {
        let (mut host, _) = pair();
        let (reader, mut writer) = stream::new();
        let params = vec![ParameterValue::StreamReader(reader)];

        publish(PendingMessage::new_call(call(params), 1, &mut host).unwrap());

        let params = [
            WireValue::StreamReader(arriving(1)),
            WireValue::ExternalBytes {
                length: 1,
                chunked: false,
            },
        ];

        assert!(decode_forged(&mut host, &params).is_err());
        assert_matches!(
            write(&mut writer),
            Poll::Ready(Err(StreamError::ReaderClosed))
        );
        assert!(PendingMessage::new_call(call(Vec::new()), 2, &mut host).is_err());
    }

    #[test]
    fn failed_result_decode_closes_its_reader_and_keeps_the_session() {
        let (mut host, _) = pair();
        let (reader, mut writer) = stream::new();
        let params = vec![ParameterValue::StreamReader(reader)];

        publish(PendingMessage::new_call(call(params), 1, &mut host).unwrap());

        // Ok, StreamReader, host sid 1 at position 0, followed by an unused external value.
        let mut externals = Segments::new([Bytes::from_static(b"x")]);

        assert!(FunctionCallResult::decode(&[0, 10, 2, 0], &mut externals, &mut host).is_err());
        assert_matches!(
            write(&mut writer),
            Poll::Ready(Err(StreamError::ReaderClosed))
        );
        assert!(PendingMessage::new_call(call(Vec::new()), 2, &mut host).is_ok());
    }

    #[test]
    fn failed_transfer_preparation_closes_readers() {
        let (_, mut guest) = pair();
        let (_, mut other) = pair();
        let foreign = other.recv_transfer(arriving(1)).unwrap();
        let (reader, mut writer) = stream::new();

        let params = vec![
            ParameterValue::StreamReader(reader),
            ParameterValue::StreamReader(foreign),
        ];

        assert!(PendingMessage::new_call(call(params), 1, &mut guest).is_err());
        assert_matches!(
            write(&mut writer),
            Poll::Ready(Err(StreamError::ReaderClosed))
        );
    }
}
