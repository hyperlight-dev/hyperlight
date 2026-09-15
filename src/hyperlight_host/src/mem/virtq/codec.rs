// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Host RPC encoding and decoding over virtqueue chains.

use anyhow::{Context, bail};
use flatbuffers::FlatBufferBuilder;
use hyperlight_common::flatbuffer_wrappers::ExternalValueSource;
use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::FunctionCallResult;
use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
use hyperlight_common::transport::{
    EncodedMessage, ExternalValues, MsgHeader, MsgKind, SIZE_PREFIX_LEN,
};
use hyperlight_common::virtq::{RecvChain, WritableChain};

use super::mem::HostMemOps;

/// Decode one complete host function call from a G2H request.
///
/// Control data and external values are copied out of guest-writable scratch.
/// Unconsumed trailing bytes are rejected.
pub(crate) fn get_host_function_call(
    chain: &mut RecvChain<HostMemOps>,
) -> anyhow::Result<FunctionCall> {
    let control = read_control(chain)?;
    FunctionCall::decode(&control, chain)
}

/// Read and validate one complete G2H message header.
pub(crate) fn read_message_header(
    request: &mut RecvChain<HostMemOps>,
) -> anyhow::Result<MsgHeader> {
    let mut bytes = [0u8; MsgHeader::SIZE];
    request.read_exact(&mut bytes)?;

    let header = MsgHeader::from_bytes(&bytes).context("G2H message has an invalid header")?;
    if header.payload_len as usize != request.remaining() {
        bail!(
            "G2H message declares {} payload bytes, received {}",
            header.payload_len,
            request.remaining()
        );
    }

    Ok(header)
}

/// Decode a guest-function result body after its G2H header.
pub(crate) fn read_guest_function_call_result(
    request: &mut RecvChain<HostMemOps>,
) -> anyhow::Result<FunctionCallResult> {
    let control = read_control(request)?;
    FunctionCallResult::decode(&control, request)
}

/// Append a complete response when it fits the remaining writable space.
///
/// `false` leaves the writable chain unchanged.
pub(crate) fn try_write_response(
    reply: &mut WritableChain<HostMemOps>,
    cid: u32,
    result: &FunctionCallResult,
) -> anyhow::Result<bool> {
    let mut builder = FlatBufferBuilder::new();
    let mut externals = ExternalValues::new();

    let control = result.encode(&mut builder, &mut externals)?;
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

/// Decode guest log data and reject trailing external bytes.
pub(crate) fn read_guest_log_data(
    chain: &mut RecvChain<HostMemOps>,
) -> anyhow::Result<GuestLogData> {
    let control = read_control(chain)?;
    chain.finish()?;
    GuestLogData::try_from(control.as_slice())
}

/// Copy size-prefixed control data and leave external values unread.
fn read_control(request: &mut RecvChain<HostMemOps>) -> anyhow::Result<Vec<u8>> {
    let mut prefix = [0u8; SIZE_PREFIX_LEN];
    request.read_exact(&mut prefix)?;

    let payload_len = u32::from_le_bytes(prefix) as usize;
    if payload_len > request.remaining() {
        bail!(
            "G2H control data declares {payload_len} bytes, only {} remain",
            request.remaining()
        );
    }

    // The prefix and payload fit within the original chain length.
    let control_len = SIZE_PREFIX_LEN + payload_len;
    let mut control = zeroed_vec(control_len, "G2H control data")?;

    control[..SIZE_PREFIX_LEN].copy_from_slice(&prefix);
    request.read_exact(&mut control[SIZE_PREFIX_LEN..])?;

    Ok(control)
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
    use hyperlight_common::virtq::{BufferChainBuilder, MemOps, RingProducer, VirtqError};

    use super::*;
    use crate::mem::virtq::tests::TestVirtq;

    fn with_control(payload: &[u8], test: impl FnOnce(&mut RecvChain<HostMemOps>)) {
        let queue = TestVirtq::new();
        let pool = HostMemOps::new(&queue.scratch, queue.g2h_pool.clone()).unwrap();

        let mut producer = RingProducer::new(queue.g2h_layout, queue.g2h_mem.clone());
        pool.write(queue.g2h_pool.start, payload).unwrap();

        let chain = BufferChainBuilder::new()
            .readable(queue.g2h_pool.start, payload.len() as u32)
            .build()
            .unwrap();

        producer.submit_available(&chain).unwrap();

        let mut consumer = queue.g2h_consumer();
        let (mut request, reply) = consumer.poll(payload.len()).unwrap().unwrap();

        test(&mut request);
        consumer.complete(request, reply).unwrap();
    }

    #[test]
    fn oversized_allocation_fails_without_panicking() {
        assert!(zeroed_vec(usize::MAX, "test buffer").is_err());
    }

    #[test]
    fn read_control_rejects_truncated_prefix() {
        with_control(b"\x04\0\0", |request| {
            let error = read_control(request).unwrap_err();
            assert!(matches!(
                error.downcast_ref::<VirtqError>(),
                Some(VirtqError::ReceiveTooShort {
                    requested: SIZE_PREFIX_LEN,
                    remaining: 3,
                })
            ));
            assert_eq!(request.consumed(), 0);
        });
    }

    #[test]
    fn read_control_rejects_truncated_body() {
        with_control(b"\x04\0\0\0ctr", |request| {
            let error = read_control(request).unwrap_err();
            assert_eq!(
                error.to_string(),
                "G2H control data declares 4 bytes, only 3 remain"
            );
            assert_eq!(request.remaining(), 3);
        });
    }

    #[test]
    fn read_control_leaves_external_bytes_unread() {
        let queue = TestVirtq::new();
        let pool = HostMemOps::new(&queue.scratch, queue.g2h_pool.clone()).unwrap();
        let mut producer = RingProducer::new(queue.g2h_layout, queue.g2h_mem.clone());
        let payload = b"\x04\0\0\0ctrlext";
        let addr = queue.g2h_pool.start;
        pool.write(addr, payload).unwrap();

        let chain = BufferChainBuilder::new()
            .readable(addr, 2)
            .readable(addr + 2, 5)
            .readable(addr + 7, 4)
            .build()
            .unwrap();
        producer.submit_available(&chain).unwrap();

        let mut consumer = queue.g2h_consumer();
        let (mut request, reply) = consumer.poll(payload.len()).unwrap().unwrap();
        assert_eq!(read_control(&mut request).unwrap(), b"\x04\0\0\0ctrl");
        assert_eq!(request.remaining(), 3);

        let mut external = [0; 3];
        request.read_exact(&mut external).unwrap();
        assert_eq!(&external, b"ext");
        consumer.complete(request, reply).unwrap();
    }

    #[test]
    fn response_preflight_leaves_short_reply_unchanged() {
        let queue = TestVirtq::new();
        let mut consumer = queue.h2g_consumer();
        let (request, reply) = consumer.poll(0).unwrap().unwrap();

        let Ok(mut reply) = reply.into_writable() else {
            panic!("expected writable reply");
        };

        let result = FunctionCallResult::new(Ok(ReturnValue::UInt(17)));
        let mut builder = FlatBufferBuilder::new();
        let mut externals = ExternalValues::new();

        let control = result.encode(&mut builder, &mut externals).unwrap();
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
        let queue = TestVirtq::new();
        let mut consumer = queue.h2g_consumer();
        let (request, reply) = consumer.poll(0).unwrap().unwrap();
        let Ok(mut reply) = reply.into_writable() else {
            panic!("expected writable reply");
        };

        let result = FunctionCallResult::new(Ok(ReturnValue::UInt(17)));
        let mut builder = FlatBufferBuilder::new();
        let mut externals = ExternalValues::new();

        let control = result.encode(&mut builder, &mut externals).unwrap();
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
