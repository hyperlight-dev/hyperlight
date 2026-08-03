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

//! Guest G2H response decoding.

use alloc::vec::Vec;

use hyperlight_common::flatbuffer_wrappers::ExternalValueSource;
use hyperlight_common::flatbuffer_wrappers::function_types::{Bytes, FunctionCallResult};
use hyperlight_common::virtq::Segments;
use hyperlight_common::virtq::msg::{
    MsgKind, SIZE_PREFIX_LEN, VirtqMsgHeader, size_prefix_payload_len, size_prefixed_len,
};

use crate::bail;
use crate::error::{GuestErrorContext, Result};

/// Decode `header | size-prefixed control | external values`.
///
/// Contiguous byte values are flattened into `Vec<u8>`. Chunked values retain
/// their transport-backed `Bytes` owners and return pool slots when dropped.
pub(super) fn decode(mut segments: Segments, cid: u32) -> Result<FunctionCallResult> {
    // Validate the transport envelope before interpreting the response body.
    let header = segments
        .split_to(VirtqMsgHeader::SIZE)
        .context("host function response is missing its header")?
        .into_bytes();

    let Some(header) = VirtqMsgHeader::from_bytes(&header) else {
        bail!("Host function response has an invalid header");
    };

    if header.msg_kind() != Ok(MsgKind::Response) {
        bail!("Host function response has an invalid message kind");
    }

    if header.cid != cid {
        bail!("Host function response correlation ID mismatch");
    }

    // Flatten only the FlatBuffer control data. External byte values remain
    // segmented for `SegmentSource`.
    let prefix = segments
        .split_to(SIZE_PREFIX_LEN)
        .context("host function response is missing its size prefix")?
        .into_bytes();

    let payload_len =
        size_prefix_payload_len(&prefix).context("host function response has an invalid prefix")?;

    let payload = segments
        .split_to(payload_len)
        .context("host function response control data is truncated")?;

    let control_len =
        size_prefixed_len(payload_len).context("host function response control length overflow")?;

    let mut control = Vec::with_capacity(control_len);
    control.extend_from_slice(&prefix);

    for segment in payload.iter() {
        control.extend_from_slice(segment);
    }

    let mut external_values = SegmentSource::new(segments);
    FunctionCallResult::decode_external(&control, &mut external_values)
        .with_context(|| "failed to decode host function response")
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
                "Host function response has {} trailing external bytes",
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
    use hyperlight_common::flatbuffer_wrappers::ExternalValueRefs;
    use hyperlight_common::flatbuffer_wrappers::function_types::ReturnValue;

    use super::*;

    #[test]
    fn response_byte_chunks_retain_transport_storage() {
        let external = Bytes::from(vec![1, 2, 3, 4]);
        let external_ptr = external.as_ptr();
        let result = FunctionCallResult::new(Ok(ReturnValue::ByteChunks(vec![external.clone()])));
        let mut builder = FlatBufferBuilder::new();
        let mut external_values = ExternalValueRefs::new();
        let control = result
            .encode_external(&mut builder, &mut external_values)
            .unwrap();
        let header = VirtqMsgHeader::new(MsgKind::Response, 7);
        let segments = Segments::new([
            Bytes::copy_from_slice(header.as_bytes()),
            Bytes::copy_from_slice(control),
            external,
        ]);

        let decoded = decode(segments, 7).unwrap().into_inner().unwrap();
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
}
