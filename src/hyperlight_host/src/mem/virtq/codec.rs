// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Host message encoding and decoding over virtqueue chains.

use anyhow::{Context, bail};
use hyperlight_common::flatbuffer_wrappers::ExternalValueSource;
use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::FunctionCallResult;
use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
use hyperlight_common::stream::Mux;
use hyperlight_common::transport::{EncodedMessage, MsgHeader, MsgKind};
use hyperlight_common::virtq::{RecvChain, ReplyChain, WritableChain};

use super::G2hConsumer;
use super::mem::HostMemOps;

/// One received G2H message with a validated header.
///
/// Control data and external values are copied out of guest-writable scratch.
/// Unconsumed trailing bytes are rejected.
pub(crate) struct RecvMessage {
    header: MsgHeader,
    chain: RecvChain<HostMemOps>,
}

impl RecvMessage {
    /// Read the header and check its payload length against the chain.
    pub(crate) fn new(mut chain: RecvChain<HostMemOps>) -> anyhow::Result<Self> {
        let mut bytes = [0u8; MsgHeader::SIZE];
        chain.read_exact(&mut bytes)?;

        let header = MsgHeader::from_bytes(&bytes).context("G2H message has an invalid header")?;
        if header.payload_len as usize != chain.remaining() {
            bail!(
                "G2H message declares {} payload bytes, received {}",
                header.payload_len,
                chain.remaining()
            );
        }

        Ok(Self { header, chain })
    }

    pub(crate) fn kind(&self) -> MsgKind {
        self.header.kind
    }

    pub(crate) fn cid(&self) -> u32 {
        self.header.cid
    }

    /// Decode a host function call, accepting the readers it moves through `mux`.
    pub(crate) fn decode_call(&mut self, mux: &mut Mux) -> anyhow::Result<FunctionCall> {
        let control = self.read_control()?;
        FunctionCall::decode(&control, &mut self.chain, mux)
    }

    /// Decode a guest function result, accepting the reader it moves through `mux`.
    pub(crate) fn decode_result(&mut self, mux: &mut Mux) -> anyhow::Result<FunctionCallResult> {
        let control = self.read_control()?;
        FunctionCallResult::decode(&control, &mut self.chain, mux)
    }

    /// Logs carry no external values.
    pub(crate) fn decode_log(&mut self) -> anyhow::Result<GuestLogData> {
        let control = self.read_control()?;
        self.chain.finish()?;
        GuestLogData::try_from(control.as_slice())
    }

    /// Apply a Stream message's records and DATA to `mux`.
    pub(crate) fn recv_records(&mut self, mux: &mut Mux) -> anyhow::Result<()> {
        let control = self.read_control()?;
        mux.recv_records(&control, &mut self.chain)?;
        Ok(())
    }

    /// Return the chain for completion.
    pub(crate) fn into_chain(self) -> RecvChain<HostMemOps> {
        self.chain
    }

    /// Copy the control data and leave external values unread.
    fn read_control(&mut self) -> anyhow::Result<Vec<u8>> {
        let mut control = zeroed_vec(self.header.control_len as usize, "G2H control data")?;
        self.chain.read_exact(&mut control)?;
        Ok(control)
    }
}

/// Process one G2H `Log` or `Stream` message and complete its chain.
pub(crate) fn recv_one_way(
    consumer: &mut G2hConsumer,
    mux: &mut Mux,
    mut message: RecvMessage,
    reply: ReplyChain<HostMemOps>,
) -> anyhow::Result<()> {
    let kind = message.kind();

    if !matches!(kind, MsgKind::Log | MsgKind::Stream) {
        bail!("Unexpected G2H {kind:?} message");
    }

    if message.cid() != 0 {
        bail!("G2H {kind:?} message has a correlation ID");
    }

    if !matches!(reply, ReplyChain::Ack(_)) {
        bail!("G2H {kind:?} message has writable buffers");
    }

    let log = if kind == MsgKind::Log {
        Some(message.decode_log().context("Invalid G2H log")?)
    } else {
        message
            .recv_records(mux)
            .context("Invalid G2H stream message")?;
        None
    };

    consumer
        .complete(message.into_chain(), reply)
        .context("Failed to complete G2H message")?;

    if let Some(log) = log {
        crate::sandbox::outb::emit_guest_log(&log);
    }

    Ok(())
}

/// Append a complete response when it fits the remaining writable space.
///
/// `false` leaves the chain unchanged. The caller settles the message after completing the chain.
pub(crate) fn try_write_response(
    reply: &mut WritableChain<HostMemOps>,
    message: &EncodedMessage<'_>,
) -> anyhow::Result<bool> {
    if message.total_len() > reply.remaining() {
        return Ok(false);
    }

    for chunk in message.chunks() {
        reply.write_all(chunk)?;
    }

    Ok(true)
}

/// Allocate zeroed host-owned storage without panicking on reserve failure.
fn zeroed_vec(length: usize, what: &str) -> anyhow::Result<Vec<u8>> {
    let mut value = Vec::new();
    value
        .try_reserve_exact(length)
        .with_context(|| format!("Failed to allocate {length} bytes for {what}"))?;

    value.resize(length, 0);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use hyperlight_common::flatbuffer_wrappers::function_types::ReturnValue;
    use hyperlight_common::stream::{DEFAULT_WINDOW, Side};
    use hyperlight_common::transport::PendingMessage;
    use hyperlight_common::virtq::{BufferChainBuilder, MemOps, RingProducer};

    use super::*;
    use crate::mem::virtq::tests::TestCase;

    /// Submit `message` as readable descriptors of `lens` bytes and poll it.
    fn with_message(message: &[u8], lens: &[u32], test: impl FnOnce(RecvChain<HostMemOps>)) {
        let case = TestCase::new();

        let mut producer = RingProducer::new(case.g2h_layout, case.mem.clone());
        case.mem.write(case.g2h_pool_base, message).unwrap();

        let mut builder = BufferChainBuilder::new();
        let mut addr = case.g2h_pool_base;
        for &len in lens {
            builder = builder.readable(addr, len);
            addr += u64::from(len);
        }
        producer
            .submit_available(&builder.build().unwrap())
            .unwrap();

        let mut consumer = case.g2h_consumer();
        let (request, _reply) = consumer.poll(message.len()).unwrap().unwrap();
        test(request);
    }

    #[test]
    fn oversized_allocation_fails_without_panicking() {
        assert!(zeroed_vec(usize::MAX, "test buffer").is_err());
    }

    fn message(payload_len: u32, control_len: u32, payload: &[u8]) -> Vec<u8> {
        let header = MsgHeader::new(MsgKind::Request, 1, payload_len, control_len);
        let mut message = header.as_bytes().to_vec();
        message.extend_from_slice(payload);
        message
    }

    #[test]
    fn rejects_payload_length_mismatch() {
        let message = message(4, 4, b"ctr");
        with_message(&message, &[message.len() as u32], |request| {
            let Err(error) = RecvMessage::new(request) else {
                panic!("expected an invalid message");
            };
            assert_eq!(
                error.to_string(),
                "G2H message declares 4 payload bytes, received 3"
            );
        });
    }

    #[test]
    fn rejects_control_longer_than_payload() {
        let message = message(3, 4, b"ext");
        with_message(&message, &[message.len() as u32], |request| {
            let Err(error) = RecvMessage::new(request) else {
                panic!("expected an invalid message");
            };
            assert_eq!(error.to_string(), "G2H message has an invalid header");
        });
    }

    #[test]
    fn rejects_invalid_one_way_messages() {
        let cases = [
            (MsgKind::Request, 0, false, "Unexpected"),
            (MsgKind::Stream, 1, false, "correlation ID"),
            (MsgKind::Log, 0, true, "writable buffers"),
        ];

        for (kind, cid, writable, expected) in cases {
            let case = TestCase::new();
            let addr = case.g2h_pool_base;
            let len = MsgHeader::SIZE as u32;

            case.mem
                .write(addr, MsgHeader::new(kind, cid, 0, 0).as_bytes())
                .unwrap();

            let readable = BufferChainBuilder::new().readable(addr, len);
            let chain = if writable {
                readable.writable(addr + u64::from(len), len).build()
            } else {
                readable.build()
            };

            let mut producer = RingProducer::new(case.g2h_layout, case.mem.clone());
            producer.submit_available(&chain.unwrap()).unwrap();

            let mut consumer = case.g2h_consumer();
            let (request, reply) = consumer.poll(MsgHeader::SIZE).unwrap().unwrap();
            let message = RecvMessage::new(request).unwrap();
            let mut mux = Mux::new(Side::Host, DEFAULT_WINDOW);

            let error = recv_one_way(&mut consumer, &mut mux, message, reply).unwrap_err();
            assert!(error.to_string().contains(expected), "{kind:?}: {error:#}");
        }
    }

    #[test]
    fn read_control_leaves_external_bytes_unread() {
        let message = message(7, 4, b"ctrlext");
        // Control and external bytes both cross descriptor boundaries.
        let lens = [MsgHeader::SIZE as u32 + 2, 3, 2];
        with_message(&message, &lens, |request| {
            let mut message = RecvMessage::new(request).unwrap();
            assert_eq!(message.read_control().unwrap(), b"ctrl");

            let mut chain = message.into_chain();
            assert_eq!(chain.remaining(), 3);

            let mut external = [0; 3];
            chain.read_exact(&mut external).unwrap();
            assert_eq!(&external, b"ext");
        });
    }

    /// The message `try_write_response` writes for call 7 returning 17.
    fn response(mux: &mut Mux) -> Vec<u8> {
        let mut buffer = Vec::new();
        let pending = PendingMessage::new_result(result(), 7, mux).unwrap();
        let message = pending.encode(&mut buffer).unwrap();

        message.chunks().flatten().copied().collect()
    }

    fn result() -> FunctionCallResult {
        FunctionCallResult::new(Ok(ReturnValue::UInt(17)))
    }

    #[test]
    fn response_preflight_leaves_short_reply_unchanged() {
        let queue = TestCase::new();
        let mut consumer = queue.h2g_consumer();
        let (request, reply) = consumer.poll(0).unwrap().unwrap();

        let Ok(mut reply) = reply.into_writable() else {
            panic!("expected writable reply");
        };

        let mut mux = Mux::new(Side::Host, DEFAULT_WINDOW);
        let message = response(&mut mux);
        let mut buffer = Vec::new();
        let pending = PendingMessage::new_result(result(), 7, &mut mux).unwrap();

        let prefix = vec![0xa5; reply.capacity() - message.len() + 1];
        reply.write_all(&prefix).unwrap();
        let addr = queue.h2g_desc(0).addr;
        let before = queue.h2g_buffer(0, addr);

        assert!(!try_write_response(&mut reply, &pending.encode(&mut buffer).unwrap()).unwrap());
        assert_eq!(reply.written(), prefix.len());
        assert_eq!(queue.h2g_buffer(0, addr), before);

        consumer.complete(request, reply).unwrap();
    }

    #[test]
    fn response_fits_remaining_capacity_exactly() {
        let queue = TestCase::new();
        let mut consumer = queue.h2g_consumer();
        let (request, reply) = consumer.poll(0).unwrap().unwrap();
        let Ok(mut reply) = reply.into_writable() else {
            panic!("expected writable reply");
        };

        let mut mux = Mux::new(Side::Host, DEFAULT_WINDOW);
        let expected = response(&mut mux);
        let mut buffer = Vec::new();
        let pending = PendingMessage::new_result(result(), 7, &mut mux).unwrap();

        let prefix = vec![0xa5; reply.capacity() - expected.len()];
        reply.write_all(&prefix).unwrap();

        assert!(try_write_response(&mut reply, &pending.encode(&mut buffer).unwrap()).unwrap());
        assert_eq!(reply.remaining(), 0);

        let actual = queue.h2g_buffer(0, queue.h2g_desc(0).addr);
        assert_eq!(&actual[..prefix.len()], prefix);
        assert_eq!(&actual[prefix.len()..], expected);

        pending.settle(consumer.complete(request, reply)).unwrap();
    }

    #[cfg(feature = "streams")]
    #[test]
    fn unpublished_response_closes_returned_reader() {
        use std::assert_matches;
        use std::pin::pin;
        use std::task::{Context, Poll, Waker};

        use hyperlight_common::stream::{self, StreamError};

        let queue = TestCase::new();
        let mut consumer = queue.h2g_consumer();
        let (_request, reply) = consumer.poll(0).unwrap().unwrap();
        let Ok(mut reply) = reply.into_writable() else {
            panic!("expected writable reply");
        };

        let mut mux = Mux::new(Side::Host, DEFAULT_WINDOW);
        let mut buffer = Vec::new();
        let (reader, mut writer) = stream::new();
        let result = FunctionCallResult::new(Ok(ReturnValue::StreamReader(reader)));
        let pending = PendingMessage::new_result(result, 7, &mut mux).unwrap();

        assert!(try_write_response(&mut reply, &pending.encode(&mut buffer).unwrap()).unwrap());
        drop(pending);

        let mut cx = Context::from_waker(Waker::noop());
        assert_matches!(
            pin!(writer.write(b"x")).poll(&mut cx),
            Poll::Ready(Err(StreamError::ReaderClosed))
        );
    }
}
