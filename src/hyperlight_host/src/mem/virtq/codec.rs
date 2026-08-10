/*
Copyright 2026  The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//! Host RPC encoding and decoding over virtqueue chains.

use anyhow::{Context, bail};
use flatbuffers::FlatBufferBuilder;
use hyperlight_common::flatbuffer_wrappers::ExternalValueSource;
use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::{Bytes, FunctionCallResult};
use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
use hyperlight_common::transport::{
    EncodedMessage, ExternalValueRefs, MsgHeader, MsgKind, SIZE_PREFIX_LEN,
    size_prefix_payload_len, size_prefixed_len,
};
use hyperlight_common::virtq::{RecvChain, WritableChain};

use super::mem::HostMemOps;

/// Copies external values from guest-writable scratch into host-owned storage.
///
/// Chunked values become one owned chunk because host calls cannot retain
/// references into untrusted guest memory.
struct ChainExternalValues<'a> {
    request: &'a mut RecvChain<HostMemOps>,
}

impl<'a> ChainExternalValues<'a> {
    fn new(request: &'a mut RecvChain<HostMemOps>) -> Self {
        Self { request }
    }
}

impl ExternalValueSource for ChainExternalValues<'_> {
    fn take_bytes(&mut self, length: usize) -> anyhow::Result<Vec<u8>> {
        let remain = self.request.remaining();
        if length > remain {
            bail!("External VecBytes requires {length} bytes, only {remain} remain");
        }

        let mut value = zeroed_vec(length)?;
        self.request.read_exact(&mut value)?;

        Ok(value)
    }

    fn take_chunks(&mut self, length: usize) -> anyhow::Result<Vec<Bytes>> {
        if length == 0 {
            return Ok(Vec::new());
        }

        let rem = self.request.remaining();
        if length > rem {
            bail!("External ByteChunks requires {length} bytes, only {rem} remain");
        }

        let mut value = zeroed_vec(length)?;
        self.request.read_exact(&mut value)?;

        Ok(vec![Bytes::from(value)])
    }

    fn finish(&mut self) -> anyhow::Result<()> {
        if self.request.remaining() != 0 {
            bail!(
                "G2H message has {} trailing external bytes",
                self.request.remaining()
            );
        }
        Ok(())
    }
}

/// Decode one complete host function call from a G2H request.
///
/// Control data and external values are copied out of guest-writable scratch.
/// Unconsumed trailing bytes are rejected.
pub(crate) fn get_host_function_call(
    chain: &mut RecvChain<HostMemOps>,
) -> anyhow::Result<FunctionCall> {
    let control = read_control(chain)?;
    let mut exts = ChainExternalValues::new(chain);
    FunctionCall::decode(&control, &mut exts)
}

/// Read and validate one complete G2H message header.
pub(crate) fn read_message_header(
    request: &mut RecvChain<HostMemOps>,
) -> anyhow::Result<MsgHeader> {
    let mut bytes = [0u8; MsgHeader::SIZE];
    request.read_exact(&mut bytes)?;

    let header = MsgHeader::from_bytes(&bytes).context("G2H message has an invalid header")?;
    if header.payload_len as usize != request.remaining() {
        bail!("G2H message payload length mismatch");
    }

    Ok(header)
}

/// Decode a guest-function result body after its G2H header.
pub(crate) fn read_guest_function_call_result(
    request: &mut RecvChain<HostMemOps>,
) -> anyhow::Result<FunctionCallResult> {
    let control = read_control(request)?;
    let mut exts = ChainExternalValues::new(request);
    FunctionCallResult::decode(&control, &mut exts)
}

/// Encode and write a response when its complete wire message fits.
///
/// `false` leaves the writable chain unchanged.
pub(crate) fn try_write_response(
    reply: &mut WritableChain<HostMemOps>,
    cid: u32,
    result: &FunctionCallResult,
) -> anyhow::Result<bool> {
    let mut builder = FlatBufferBuilder::new();
    let mut external_values = ExternalValueRefs::new();

    let control = result.encode(&mut builder, &mut external_values)?;
    let Some(message) = EncodedMessage::new(MsgKind::Response, cid, control, external_values)
    else {
        anyhow::bail!("Host function response length overflow");
    };

    if message.total_len() > reply.capacity() {
        return Ok(false);
    }

    for chunk in message.chunks() {
        reply.write_all(chunk)?;
    }

    Ok(true)
}

/// Decode guest log data and reject trailing external bytes.
pub(crate) fn read_guest_log_data(
    chain: &mut RecvChain<HostMemOps>,
) -> anyhow::Result<GuestLogData> {
    let control = read_control(chain)?;
    let remain = chain.remaining();

    if remain != 0 {
        bail!("G2H log has {remain} trailing external bytes");
    }

    GuestLogData::try_from(control.as_slice())
}

/// Copy size-prefixed control data and leave external values unread.
fn read_control(request: &mut RecvChain<HostMemOps>) -> anyhow::Result<Vec<u8>> {
    let mut prefix = [0u8; SIZE_PREFIX_LEN];
    request.read_exact(&mut prefix)?;

    let payload_len = size_prefix_payload_len(&prefix).expect("size prefix length is fixed");
    if payload_len > request.remaining() {
        bail!(
            "G2H control data declares {payload_len} bytes, only {} remain",
            request.remaining()
        );
    }

    let control_len = size_prefixed_len(payload_len).context("G2H control length overflow")?;
    // Do not trust control_len to be small enough to allocate.
    let mut control = zeroed_vec(control_len)?;

    control[..SIZE_PREFIX_LEN].copy_from_slice(&prefix);
    request.read_exact(&mut control[SIZE_PREFIX_LEN..])?;

    Ok(control)
}

/// Allocate zeroed host-owned storage without panicking on reserve failure.
pub fn zeroed_vec(length: usize) -> anyhow::Result<Vec<u8>> {
    let mut value = Vec::new();
    value
        .try_reserve_exact(length)
        .with_context(|| format!("Failed to allocate {length} bytes"))?;

    value.resize(length, 0);
    Ok(value)
}
