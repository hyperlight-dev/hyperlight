/*
Copyright 2025  The Hyperlight Authors.

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
#![no_main]

#[cfg(not(feature = "trace"))]
compile_error!("feature `trace` must be enabled to fuzz guest trace event estimation");

use hyperlight_common::flatbuffer_wrappers::guest_trace_data::{
    EventKeyValue, EventsBatchDecoder, EventsBatchEncoder, EventsDecoder, EventsEncoder,
    GuestEvent, estimate_event,
};
use libfuzzer_sys::arbitrary::{Arbitrary, Result as FuzzResult, Unstructured};
use libfuzzer_sys::fuzz_target;

const MAX_STRING_LEN: usize = 1 << 10; // 1024 bytes
const MAX_FIELDS: usize = 32;

/// Wrapper around GuestEvent to implement Arbitrary
#[derive(Debug)]
struct EventInput(GuestEvent);

impl EventInput {
    /// Consumes the wrapper and returns the inner GuestEvent
    fn into_inner(self) -> GuestEvent {
        self.0
    }
}

impl<'a> Arbitrary<'a> for EventInput {
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

        Ok(EventInput(event))
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

/// Encodes a GuestEvent into a byte vector
fn encode(event: &GuestEvent) -> Vec<u8> {
    // Use the estimate plus some slack to avoid reallocation during encoding
    let mut encoder = EventsBatchEncoder::new(estimate_event(event).saturating_add(256), |_| {});
    encoder.encode(event);
    encoder.finish().to_vec()
}

/// Decodes a byte slice into a GuestEvent
fn decode(data: &[u8]) -> Option<GuestEvent> {
    let decoder = EventsBatchDecoder {};
    let mut events = decoder.decode(data).ok()?;

    if events.len() == 1 {
        events.pop()
    } else {
        None
    }
}

/// Asserts that the estimated size is within acceptable bounds of the actual size
/// Allows for a 10% slack or minimum of 128 bytes
fn assert_estimate_bounds(actual: usize, estimate: usize) {
    assert!(
        estimate >= actual,
        "estimate {} smaller than actual {}",
        estimate,
        actual,
    );

    let slack = (actual / 10).max(128);
    let upper_bound = actual + slack;
    assert!(
        estimate <= upper_bound,
        "estimate {} larger than allowable upper bound {} (actual {})",
        estimate,
        upper_bound,
        actual,
    );
}

fuzz_target!(|input: EventInput| {
    let event = input.into_inner();

    // Get the size estimate
    let estimate = estimate_event(&event);
    // Encode the event
    let encoded_data = encode(&event);
    // Assert that the estimate is within bounds
    assert_estimate_bounds(encoded_data.len(), estimate);

    // Decode the event back
    let decoded = decode(&encoded_data).expect("decoding failed");
    // Assert that the decoded event matches the original
    assert_eq!(event, decoded);
});
