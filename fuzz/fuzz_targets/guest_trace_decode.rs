// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.
#![no_main]

#[cfg(not(feature = "trace"))]
compile_error!("feature `trace` must be enabled to fuzz guest trace decoding");

use hyperlight_common::flatbuffer_wrappers::guest_trace_data::{
    EventKeyValue, EventsBatchDecoder, EventsBatchEncoder, EventsDecoder, EventsEncoder,
    GuestEvent, MAX_TRACE_DATA_SIZE,
};
use libfuzzer_sys::arbitrary::{Arbitrary, Result as FuzzResult, Unstructured};
use libfuzzer_sys::fuzz_target;

const MAX_STRING_LEN: usize = 1 << 10; // 1024 bytes
const MAX_FIELDS: usize = 32;

/// An event to round trip and raw bytes to decode as a batch.
#[derive(Debug)]
struct Input<'a> {
    event: GuestEvent,
    raw: &'a [u8],
}

impl<'a> Arbitrary<'a> for Input<'a> {
    fn arbitrary(u: &mut Unstructured<'a>) -> FuzzResult<Self> {
        // Choose a variant of GuestEvent to generate
        let discriminator = u.arbitrary::<u8>()? % 5;

        // Generate each variant with appropriate random data
        let event = match discriminator {
            0 => GuestEvent::OpenSpan {
                id: u.arbitrary::<u64>()?,
                parent_id: arbitrary_parent(u)?,
                name: limited_string(u, MAX_STRING_LEN)?,
                target: limited_string(u, MAX_STRING_LEN)?,
                tsc: u.arbitrary::<u64>()?,
                fields: arbitrary_fields(u)?,
            },
            1 => GuestEvent::CloseSpan {
                id: u.arbitrary::<u64>()?,
                tsc: u.arbitrary::<u64>()?,
            },
            2 => GuestEvent::LogEvent {
                parent_id: u.arbitrary::<u64>()?,
                name: limited_string(u, MAX_STRING_LEN)?,
                tsc: u.arbitrary::<u64>()?,
                fields: arbitrary_fields(u)?,
            },
            3 => GuestEvent::EditSpan {
                id: u.arbitrary::<u64>()?,
                fields: arbitrary_fields(u)?,
            },
            _ => GuestEvent::GuestStart {
                tsc: u.arbitrary::<u64>()?,
            },
        };

        Ok(Input {
            event,
            raw: u.arbitrary()?,
        })
    }
}

/// Generates an optional parent ID
fn arbitrary_parent(u: &mut Unstructured<'_>) -> FuzzResult<Option<u64>> {
    let has_parent = u.arbitrary::<bool>()?;
    if has_parent {
        Ok(Some(u.arbitrary::<u64>()?))
    } else {
        Ok(None)
    }
}

/// Generates a String with a maximum length of `max_len`
fn limited_string(u: &mut Unstructured<'_>, max_len: usize) -> FuzzResult<String> {
    let bytes = u.arbitrary::<&[u8]>()?;
    let s = std::str::from_utf8(bytes)
        // Fallback to repeating 'x' if not valid UTF-8
        .unwrap_or(&"x".repeat(bytes.len() % max_len))
        .chars()
        .take(max_len)
        .collect::<String>();

    Ok(s)
}

/// Generates a vector of EventKeyValue pairs
fn arbitrary_fields(u: &mut Unstructured<'_>) -> FuzzResult<Vec<EventKeyValue>> {
    let field_count = (u.arbitrary::<u8>()? as usize).min(MAX_FIELDS);
    let mut fields = Vec::with_capacity(field_count);
    for _ in 0..field_count {
        let key = limited_string(u, MAX_STRING_LEN)?;
        let value = limited_string(u, MAX_STRING_LEN)?;
        fields.push(EventKeyValue { key, value });
    }
    Ok(fields)
}

fuzz_target!(|input: Input<'_>| {
    // Arbitrary batches must decode or fail without panicking.
    let _ = EventsBatchDecoder.decode(input.raw);

    let mut encoder = EventsBatchEncoder::new(MAX_TRACE_DATA_SIZE, |_| {});
    encoder.encode(&input.event);
    let decoded = EventsBatchDecoder
        .decode(encoder.finish())
        .expect("decoding failed");
    assert_eq!(decoded, [input.event]);
});
