// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Host RPC encoding and decoding over virtqueue chains.

use anyhow::{Context, bail};
use hyperlight_common::flatbuffer_wrappers::ExternalValueSource;
use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::FunctionCallResult;
use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
use hyperlight_common::transport::{EncodedMessage, ExternalValues, MsgHeader, MsgKind};
use hyperlight_common::virtq::{RecvChain, WritableChain};

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

    pub(crate) fn decode_call(&mut self) -> anyhow::Result<FunctionCall> {
        let control = self.read_control()?;
        FunctionCall::decode(&control, &mut self.chain)
    }

    pub(crate) fn decode_result(&mut self) -> anyhow::Result<FunctionCallResult> {
        let control = self.read_control()?;
        FunctionCallResult::decode(&control, &mut self.chain)
    }

    /// Logs carry no external values.
    pub(crate) fn decode_log(&mut self) -> anyhow::Result<GuestLogData> {
        let control = self.read_control()?;
        self.chain.finish()?;
        GuestLogData::try_from(control.as_slice())
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

/// Append a complete response when it fits the remaining writable space.
///
/// `false` leaves the writable chain unchanged.
pub(crate) fn try_write_response(
    reply: &mut WritableChain<HostMemOps>,
    cid: u32,
    result: &FunctionCallResult,
) -> anyhow::Result<bool> {
    let mut buffer = Vec::new();
    let mut externals = ExternalValues::new();

    let control = result.encode(&mut buffer, &mut externals)?;
    let msg = EncodedMessage::new(MsgKind::Response, cid, control, externals)
        .context("Host function response length overflow")?;

    if msg.total_len() > reply.remaining() {
        return Ok(false);
    }

    for chunk in msg.chunks() {
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

    #[test]
    fn response_preflight_leaves_short_reply_unchanged() {
        let queue = TestCase::new();
        let mut consumer = queue.h2g_consumer();
        let (request, reply) = consumer.poll(0).unwrap().unwrap();

        let Ok(mut reply) = reply.into_writable() else {
            panic!("expected writable reply");
        };

        let result = FunctionCallResult::new(Ok(ReturnValue::UInt(17)));
        let mut buffer = Vec::new();
        let mut externals = ExternalValues::new();

        let control = result.encode(&mut buffer, &mut externals).unwrap();
        let message = EncodedMessage::new(MsgKind::Response, 7, control, externals).unwrap();

        let prefix = vec![0xa5; reply.capacity() - message.total_len() + 1];
        reply.write_all(&prefix).unwrap();
        let addr = queue.h2g_desc(0).addr;
        let before = queue.h2g_buffer(0, addr);

        assert!(!try_write_response(&mut reply, 7, &result).unwrap());
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

        let result = FunctionCallResult::new(Ok(ReturnValue::UInt(17)));
        let mut buffer = Vec::new();
        let mut externals = ExternalValues::new();

        let control = result.encode(&mut buffer, &mut externals).unwrap();
        let message = EncodedMessage::new(MsgKind::Response, 7, control, externals).unwrap();

        let expected: Vec<_> = message.chunks().flatten().copied().collect();

        let prefix = vec![0xa5; reply.capacity() - expected.len()];
        reply.write_all(&prefix).unwrap();

        assert!(try_write_response(&mut reply, 7, &result).unwrap());
        assert_eq!(reply.remaining(), 0);

        let actual = queue.h2g_buffer(0, queue.h2g_desc(0).addr);
        assert_eq!(&actual[..prefix.len()], prefix);
        assert_eq!(&actual[prefix.len()..], expected);

        consumer.complete(request, reply).unwrap();
    }
}
