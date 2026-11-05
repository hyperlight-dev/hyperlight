#![no_main]

use bytes::Bytes;
use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::FunctionCallResult;
use hyperlight_common::flatbuffer_wrappers::ExternalValueSource;
use hyperlight_common::transport::{size_prefix_payload_len, SIZE_PREFIX_LEN};
use libfuzzer_sys::fuzz_target;

// Bounded external-value source mirroring `RecvChain` semantics: it yields only
// the trailing external payload (the bytes after the size-prefixed control
// buffer), rejects reads past the end, and rejects unconsumed trailing bytes in
// `finish`. This matches production and avoids false OOM positives from
// unbounded allocation.
struct BoundedSource<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BoundedSource<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
}

impl ExternalValueSource for BoundedSource<'_> {
    fn take_bytes(&mut self, length: usize) -> anyhow::Result<Vec<u8>> {
        if length > self.remaining() {
            anyhow::bail!("not enough data");
        }
        let bytes = self.data[self.pos..self.pos + length].to_vec();
        self.pos += length;
        Ok(bytes)
    }

    fn take_chunks(&mut self, length: usize) -> anyhow::Result<Vec<Bytes>> {
        let bytes = self.take_bytes(length)?;
        Ok(vec![Bytes::from(bytes)])
    }

    fn finish(&mut self) -> anyhow::Result<()> {
        // Mirror production (`RecvChain` / `finish_external_values`): any
        // external payload the decoder did not consume means the message was
        // malformed, so reject it instead of silently accepting trailing data.
        if self.remaining() != 0 {
            anyhow::bail!("trailing external data");
        }
        Ok(())
    }
}

// Split the fuzzer input into (control, external) exactly the way the production
// host does in `read_control`: a size prefix (4-byte little-endian length), then
// that many payload bytes form the size-prefixed control FlatBuffer; everything
// after is the external payload that `RecvChain` supplies separately.
//
// Returns `None` for inputs that cannot describe a valid G2H control/payload
// layout (too short for the prefix, or a declared control length larger than the
// available bytes) — the same cases `read_control` rejects before any decode.
fn split_control(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let prefix = data.get(..SIZE_PREFIX_LEN)?;
    let payload_len = size_prefix_payload_len(prefix)?;
    let control_len = SIZE_PREFIX_LEN.checked_add(payload_len)?;
    if control_len > data.len() {
        return None;
    }
    Some(data.split_at(control_len))
}

fuzz_target!(|data: &[u8]| {
    let Some((control, external)) = split_control(data) else {
        return;
    };
    // A given G2H message is one kind; trying both decoders on the same split is
    // a cheap way to exercise both parse paths without a running hypervisor.
    let _ = FunctionCall::decode(control, &mut BoundedSource::new(external));
    let _ = FunctionCallResult::decode(control, &mut BoundedSource::new(external));
});
