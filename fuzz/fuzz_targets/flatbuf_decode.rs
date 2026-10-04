#![no_main]

use bytes::Bytes;
use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::FunctionCallResult;
use hyperlight_common::flatbuffer_wrappers::ExternalValueSource;
use libfuzzer_sys::fuzz_target;

// Bounded source — simulates real RecvChain behavior
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
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = FunctionCall::decode(data, &mut BoundedSource::new(data));
    let _ = FunctionCallResult::decode(data, &mut BoundedSource::new(data));
});
