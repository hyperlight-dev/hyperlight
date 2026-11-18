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
    use crate::flatbuffer_wrappers::wire::{WireResult, WireValue};
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

    /// Decode a guest call to `f` with raw `params` through `mux`, bypassing the encoder.
    fn decode_raw(mux: &mut Mux, params: &[WireValue<'_>]) -> Result<()> {
        let call = ("f", false, ReturnType::Void, params);
        let control = postcard::to_extend(&call, Vec::new())?;

        FunctionCall::decode(&control, &mut Segments::default(), mux).map(drop)
    }

    /// Decode a tuple result of raw `values` through `mux`, bypassing the encoder.
    fn decode_raw_tuple(mux: &mut Mux, values: &[WireValue<'_>]) -> Result<()> {
        let control = postcard::to_extend(&WireResult::Tuple(values), Vec::new())?;
        FunctionCallResult::decode(&control, &mut Segments::default(), mux).map(drop)
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
    fn tuples_move_in_order_and_return_to_origin() {
        let (mut host, mut guest) = pair();
        let (a, _a) = stream::new();
        let (b, _b) = stream::new();
        let a_pipe = Arc::clone(a.pipe());
        let b_pipe = Arc::clone(b.pipe());
        let chunks = || vec![Bytes::from_static(b"ab"), Bytes::from_static(b"c")];

        let params = vec![
            ParameterValue::StreamReader(a),
            ParameterValue::StreamReader(b),
        ];
        let (_, control, mut externals) =
            publish(PendingMessage::new_call(call(params), 1, &mut host).unwrap());
        let mut readers = FunctionCall::decode(&control, &mut externals, &mut guest)
            .unwrap()
            .parameters
            .unwrap()
            .into_iter()
            .map(|param| ReturnValue::StreamReader(StreamReader::try_from(param).unwrap()));

        let values = vec![
            readers.next().unwrap(),
            ReturnValue::VecBytes(vec![7, 8]),
            ReturnValue::Int(1),
            readers.next().unwrap(),
            ReturnValue::ByteChunks(chunks()),
        ];
        let result = FunctionCallResult::new(Ok(ReturnValue::Tuple(values)));
        let (_, control, mut externals) =
            publish(PendingMessage::new_result(result, 1, &mut guest).unwrap());

        #[rustfmt::skip]
        let expected = [
            2, 5,     // Tuple of 5 elements
            10, 2, 0, // StreamReader, host sid 1 at position 0
            9, 2, 0,  // ExternalBytes { length: 2, chunked: false }
            0, 2,     // Int(1)
            10, 4, 0, // StreamReader, host sid 2 at position 0
            9, 3, 1,  // ExternalBytes { length: 3, chunked: true }
        ];
        assert_eq!(control, expected);
        assert_eq!(externals.len(), 5);

        let result = FunctionCallResult::decode(&control, &mut externals, &mut host).unwrap();
        let Ok(ReturnValue::Tuple(values)) = result.into_inner() else {
            panic!("expected a tuple");
        };

        assert_eq!(values.len(), 5);

        assert_matches!(&values[0], ReturnValue::StreamReader(a) if Arc::ptr_eq(a.pipe(), &a_pipe));
        assert_eq!(values[1], ReturnValue::VecBytes(vec![7, 8]));
        assert_eq!(values[2], ReturnValue::Int(1));
        assert_matches!(&values[3], ReturnValue::StreamReader(b) if Arc::ptr_eq(b.pipe(), &b_pipe));
        assert_eq!(values[4], ReturnValue::ByteChunks(chunks()));
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
        let error = decode_raw(&mut guest, &[invalid]).err().unwrap();
        assert_matches!(
            error.downcast_ref::<ProtocolError>(),
            Some(ProtocolError::Transfer)
        );

        let (_, mut guest) = pair();
        assert!(decode_raw(&mut guest, &[reader(1), reader(1)]).is_err());

        let (_, mut guest) = pair();
        let mut readers: Vec<_> = (1..=MAX_TRANSFERS as u64).map(reader).collect();
        assert!(decode_raw(&mut guest, &readers).is_ok());

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
        let error = decode_raw(&mut guest, &readers).err().unwrap();
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
    fn tuple_transfers_are_bounded() {
        let reader = |index| WireValue::StreamReader(arriving(index));

        let (_, mut guest) = pair();
        let readers: Vec<_> = (1..=MAX_TRANSFERS as u64).map(reader).collect();
        assert!(decode_raw_tuple(&mut guest, &readers).is_ok());

        // A returning reader leads, so receiving any transfer before the count check closes it.
        let (_, mut guest) = pair();
        let (sent, mut writer) = stream::new();
        let params = vec![ParameterValue::StreamReader(sent)];
        publish(PendingMessage::new_call(call(params), 1, &mut guest).unwrap());

        let returning = WireValue::StreamReader(Transfer {
            sid: G1,
            position: 0,
        });
        let readers: Vec<_> = core::iter::once(returning)
            .chain((1..=MAX_TRANSFERS as u64).map(reader))
            .collect();
        let error = decode_raw_tuple(&mut guest, &readers).err().unwrap();

        assert_matches!(
            error.downcast_ref::<ProtocolError>(),
            Some(ProtocolError::Transfer)
        );
        assert_matches!(write(&mut writer), Poll::Ready(Ok(1)));
    }

    #[test]
    fn tuple_trailing_bytes_fail_before_any_transfer() {
        let (_, mut guest) = pair();
        let (sent, mut writer) = stream::new();
        let params = vec![ParameterValue::StreamReader(sent)];
        publish(PendingMessage::new_call(call(params), 1, &mut guest).unwrap());

        let returning = WireValue::StreamReader(Transfer {
            sid: G1,
            position: 0,
        });
        let values = [returning, WireValue::Int(1)];
        let mut control = postcard::to_extend(&WireResult::Tuple(&values[..]), Vec::new()).unwrap();
        control.push(0);

        let decoded = FunctionCallResult::decode(&control, &mut Segments::default(), &mut guest);

        assert!(decoded.is_err());
        assert_matches!(write(&mut writer), Poll::Ready(Ok(1)));

        // The transfer stayed unreceived, so the tuple decodes without the trailing byte.
        assert!(decode_raw_tuple(&mut guest, &values).is_ok());
    }

    #[test]
    fn tuples_reject_void_elements() {
        let (mut host, mut guest) = pair();
        let tuple = ReturnValue::Tuple(vec![ReturnValue::Int(1), ReturnValue::Void(())]);
        let result = FunctionCallResult::new(Ok(tuple));
        let pending = PendingMessage::new_result(result, 1, &mut guest).unwrap();

        assert!(pending.encode(&mut Vec::new()).is_err());

        let values = [WireValue::Int(1), WireValue::Void];
        assert!(decode_raw_tuple(&mut host, &values).is_err());
    }

    #[test]
    fn tuples_reject_nested_tuples() {
        let (_, mut guest) = pair();
        let nested = ReturnValue::Tuple(vec![ReturnValue::Int(1), ReturnValue::Int(2)]);
        let tuple = ReturnValue::Tuple(vec![ReturnValue::Int(0), nested]);
        let result = FunctionCallResult::new(Ok(tuple));
        let pending = PendingMessage::new_result(result, 1, &mut guest).unwrap();

        assert!(pending.encode(&mut Vec::new()).is_err());
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

        assert!(decode_raw(&mut host, &params).is_err());
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
    fn failed_tuple_decode_closes_its_readers_and_keeps_the_session() {
        let (mut host, _) = pair();
        let (a, mut a_writer) = stream::new();
        let (b, mut b_writer) = stream::new();
        let params = vec![
            ParameterValue::StreamReader(a),
            ParameterValue::StreamReader(b),
        ];

        publish(PendingMessage::new_call(call(params), 1, &mut host).unwrap());

        // The byte value between the readers has no external value.
        let values = [
            WireValue::StreamReader(arriving(1)),
            WireValue::ExternalBytes {
                length: 1,
                chunked: false,
            },
            WireValue::StreamReader(arriving(2)),
        ];

        assert!(decode_raw_tuple(&mut host, &values).is_err());
        assert_matches!(
            write(&mut a_writer),
            Poll::Ready(Err(StreamError::ReaderClosed))
        );
        assert_matches!(
            write(&mut b_writer),
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
