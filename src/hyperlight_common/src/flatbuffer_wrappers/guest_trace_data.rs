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

//! Guest trace data structures and (de)serialization logic.
//! This module defines the data structures used for tracing spans and events
//! within a guest environment, along with the logic for serializing and
//! deserializing these structures using FlatBuffers.
//!
//! Schema definitions can be found in `src/schema/guest_trace_data.fbs`.

use alloc::string::String;
use alloc::vec::Vec;

use anyhow::{Error, Result};
use serde::{Deserialize, Serialize};

use crate::flatbuffer_wrappers::util::{decode_rest, encode_extend, encoded_size};

/// Key-Value pair structure used in tracing spans/events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventKeyValue {
    /// Key of the key-value pair
    pub key: String,
    /// Value of the key-value pair
    pub value: String,
}

/// Enum representing different types of guest events for tracing
/// such as opening/closing spans and logging events.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuestEvent {
    /// Event representing the opening of a new tracing span.
    OpenSpan {
        /// Unique identifier for the span.
        /// This ID is used to correlate open and close events.
        /// It should be unique within the context of a sandboxed guest execution.
        id: u64,
        /// Optional parent span ID, if this span is nested within another span.
        parent_id: Option<u64>,
        /// Name of the span.
        name: String,
        /// Target associated with the span.
        target: String,
        /// Timestamp Counter (TSC) value when the span was opened.
        tsc: u64,
        /// Additional key-value fields associated with the span.
        fields: Vec<EventKeyValue>,
    },
    /// Event representing the closing of a tracing span.
    CloseSpan {
        /// Unique identifier for the span being closed.
        id: u64,
        /// Timestamp Counter (TSC) value when the span was closed.
        tsc: u64,
    },
    /// Event representing a log entry within a tracing span.
    LogEvent {
        /// Identifier of the parent span for this log event.
        parent_id: u64,
        /// Name of the log event.
        name: String,
        /// Timestamp Counter (TSC) value when the log event occurred.
        tsc: u64,
        /// Additional key-value fields associated with the log event.
        fields: Vec<EventKeyValue>,
    },
    /// Event representing an edit to an existing span.
    /// Corresponds to the `record` method in the tracing subscriber trait.
    EditSpan {
        /// Unique identifier for the span to edit.
        id: u64,
        /// Fields to add or modify in the span.
        fields: Vec<EventKeyValue>,
    },
    /// Event representing the start of the guest environment.
    GuestStart {
        /// Timestamp Counter (TSC) value when the guest started.
        tsc: u64,
    },
}

/// Trait defining the interface for encoding guest events.
/// Implementors of this trait should provide methods for encoding events,
/// finishing the encoding process, flushing the buffer, and resetting the encoder.
pub trait EventsEncoder {
    /// Encode a single guest event into the encoder's buffer.
    fn encode(&mut self, event: &GuestEvent);
    /// Finalize the encoding process and return the serialized buffer.
    fn finish(&self) -> &[u8];
    /// Flush the encoder's buffer, typically sending or processing the data.
    fn flush(&mut self);
    /// Reset the encoder's internal state, clearing any buffered data.
    fn reset(&mut self);
}

/// Trait defining the interface for decoding guest events.
/// Implementors of this trait should provide methods for decoding a buffer
/// of bytes into a collection of guest events.
pub trait EventsDecoder {
    /// Decode a buffer of bytes into guest events.
    fn decode(&self, buffer: &[u8]) -> Result<Vec<GuestEvent>, Error>;
}

pub struct EventsBatchDecoder;

impl EventsDecoder for EventsBatchDecoder {
    fn decode(&self, data: &[u8]) -> Result<Vec<GuestEvent>, Error> {
        let mut events = Vec::new();

        let mut data = data;

        while !data.is_empty() {
            let (event, rest) = decode_rest::<GuestEvent>(data)?;
            events.push(event);
            data = rest;
        }

        Ok(events)
    }
}

pub type EventsBatchEncoder = EventsBatchEncoderGeneric<fn(&[u8])>;

/// Encoder for batching and serializing guest events into a buffer.
/// When the buffer reaches its capacity, the provided `report_full` callback
/// is invoked with the current buffer contents.
///
/// This encoder uses FlatBuffers for serialization.
/// This encoder is a lossless encoder; no events are dropped.
pub struct EventsBatchEncoderGeneric<T: Fn(&[u8])> {
    /// Internal buffer for serialized events
    buffer: Vec<u8>,
    /// Maximum capacity of the buffer
    capacity: usize,
    /// Callback function to report when the buffer is full
    report_full: T,
    /// Current used capacity of the buffer
    used_capacity: usize,
}

impl<T: Fn(&[u8])> EventsBatchEncoderGeneric<T> {
    /// Create a new EventsBatchEncoder with the specified initial capacity
    pub fn new(initial_capacity: usize, report_full: T) -> Self {
        Self {
            buffer: Vec::with_capacity(initial_capacity),
            capacity: initial_capacity,
            report_full,
            used_capacity: 0,
        }
    }
}

impl<T: Fn(&[u8])> EventsEncoder for EventsBatchEncoderGeneric<T> {
    /// Serialize a single GuestEvent and append it to the internal buffer.
    /// If the appending of the serialized data exceeds buffer capacity, the
    /// `report_full` callback is invoked with the current buffer contents,
    /// and the buffer is cleared for new data.
    fn encode(&mut self, event: &GuestEvent) {
        // Optimization heuristic that helps minimize reallocations during FlatBuffer building.
        // The estimate is not exact but should be an upper bound.
        // The following behavior can happen:
        // - If the estimate is accurate or slightly over, the builder uses the preallocated
        // space.
        // - If the estimate is too low, the FlatBuffer builder reallocates as needed.
        let estimated_size = estimate_event(event);
        let serialized = Vec::with_capacity(estimated_size);
        #[allow(clippy::unwrap_used)]
        let serialized = encode_extend(event, serialized).unwrap();

        // Check if adding this event would exceed capacity
        if self.used_capacity + serialized.len() > self.capacity {
            (self.report_full)(&self.buffer);
            self.buffer.clear();
            self.used_capacity = 0;
        }
        // Append serialized data to buffer
        self.buffer.extend_from_slice(&serialized);
        self.used_capacity += serialized.len();
    }

    /// Get a reference to the internal buffer containing serialized events.
    /// This buffer can be sent or processed as needed.
    fn finish(&self) -> &[u8] {
        &self.buffer
    }

    /// Flush the internal buffer by invoking the `report_full` callback
    /// with the current buffer contents, then resetting the buffer.
    fn flush(&mut self) {
        if !self.buffer.is_empty() {
            (self.report_full)(&self.buffer);
            self.reset();
        }
    }
    /// Reset the internal buffer, clearing all serialized data.
    /// This prepares the encoder for new events.
    fn reset(&mut self) {
        self.buffer.clear();
        self.used_capacity = 0;
    }
}

pub fn estimate_event(event: &GuestEvent) -> usize {
    #[allow(clippy::unwrap_used)]
    encoded_size(event).unwrap()
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;
    use crate::flatbuffer_wrappers::util::{decode, encode};

    /// Utility function to check an original GuestTraceData against a deserialized one
    fn check_fb_guest_trace_data(orig: &[GuestEvent], deserialized: &[GuestEvent]) {
        for (original, deserialized) in orig.iter().zip(deserialized.iter()) {
            match (original, deserialized) {
                (
                    GuestEvent::OpenSpan {
                        id: oid,
                        parent_id: opid,
                        name: oname,
                        target: otarget,
                        tsc: otsc,
                        fields: ofields,
                    },
                    GuestEvent::OpenSpan {
                        id: did,
                        parent_id: dpid,
                        name: dname,
                        target: dtarget,
                        tsc: dtsc,
                        fields: dfields,
                    },
                ) => {
                    assert_eq!(oid, did);
                    assert_eq!(opid, dpid);
                    assert_eq!(oname, dname);
                    assert_eq!(otarget, dtarget);
                    assert_eq!(otsc, dtsc);
                    assert_eq!(ofields.len(), dfields.len());
                    for (o_field, d_field) in ofields.iter().zip(dfields.iter()) {
                        assert_eq!(o_field.key, d_field.key);
                        assert_eq!(o_field.value, d_field.value);
                    }
                }
                (
                    GuestEvent::LogEvent {
                        parent_id: opid,
                        name: oname,
                        tsc: otsc,
                        fields: ofields,
                    },
                    GuestEvent::LogEvent {
                        parent_id: dpid,
                        name: dname,
                        tsc: dtsc,
                        fields: dfields,
                    },
                ) => {
                    assert_eq!(opid, dpid);
                    assert_eq!(oname, dname);
                    assert_eq!(otsc, dtsc);
                    assert_eq!(ofields.len(), dfields.len());
                    for (o_field, d_field) in ofields.iter().zip(dfields.iter()) {
                        assert_eq!(o_field.key, d_field.key);
                        assert_eq!(o_field.value, d_field.value);
                    }
                }
                (
                    GuestEvent::CloseSpan { id: oid, tsc: otsc },
                    GuestEvent::CloseSpan { id: did, tsc: dtsc },
                ) => {
                    assert_eq!(oid, did);
                    assert_eq!(otsc, dtsc);
                }
                (GuestEvent::GuestStart { tsc: otsc }, GuestEvent::GuestStart { tsc: dtsc }) => {
                    assert_eq!(otsc, dtsc);
                }
                (
                    GuestEvent::EditSpan {
                        id: oid,
                        fields: ofields,
                    },
                    GuestEvent::EditSpan {
                        id: did,
                        fields: dfields,
                    },
                ) => {
                    assert_eq!(oid, did);
                    assert_eq!(ofields.len(), dfields.len());
                    for (o_field, d_field) in ofields.iter().zip(dfields.iter()) {
                        assert_eq!(o_field.key, d_field.key);
                        assert_eq!(o_field.value, d_field.value);
                    }
                }
                _ => panic!("Mismatched event types"),
            }
        }
    }

    #[test]
    fn test_fb_key_value_serialization() {
        let kv = EventKeyValue {
            key: "test_key".to_string(),
            value: "test_value".to_string(),
        };

        let serialized = encode(&kv).expect("Serialization failed");
        let deserialized: EventKeyValue = decode(&serialized).expect("Deserialization failed");

        assert_eq!(kv.key, deserialized.key);
        assert_eq!(kv.value, deserialized.value);
    }

    #[test]
    fn test_fb_guest_trace_data_open_span_serialization() {
        let mut serializer = EventsBatchEncoder::new(1024, |_| {});
        let kv1 = EventKeyValue {
            key: "test_key1".to_string(),
            value: "test_value1".to_string(),
        };
        let kv2 = EventKeyValue {
            key: "test_key1".to_string(),
            value: "test_value2".to_string(),
        };

        let events = [
            GuestEvent::GuestStart { tsc: 50 },
            GuestEvent::OpenSpan {
                id: 1,
                parent_id: None,
                name: "span_name".to_string(),
                target: "span_target".to_string(),
                tsc: 100,
                fields: Vec::from([kv1, kv2]),
            },
        ];

        for event in &events {
            serializer.encode(event);
        }

        let serialized = serializer.finish();

        let deserialized: Vec<GuestEvent> = EventsBatchDecoder {}
            .decode(serialized)
            .expect("Deserialization failed");

        check_fb_guest_trace_data(&events, &deserialized);
    }

    #[test]
    fn test_fb_guest_trace_data_close_span_serialization() {
        let events = [GuestEvent::CloseSpan { id: 1, tsc: 200 }];

        let mut serializer = EventsBatchEncoder::new(1024, |_| {});
        for event in &events {
            serializer.encode(event);
        }
        let serialized = serializer.finish();

        let deserialized = EventsBatchDecoder {}
            .decode(serialized)
            .expect("Deserialization failed");

        check_fb_guest_trace_data(&events, &deserialized);
    }

    #[test]
    fn test_fb_guest_trace_data_log_event_serialization() {
        let kv1 = EventKeyValue {
            key: "log_key1".to_string(),
            value: "log_value1".to_string(),
        };
        let kv2 = EventKeyValue {
            key: "log_key2".to_string(),
            value: "log_value2".to_string(),
        };

        let events = [GuestEvent::LogEvent {
            parent_id: 2,
            name: "log_name".to_string(),
            tsc: 300,
            fields: Vec::from([kv1, kv2]),
        }];

        let mut serializer = EventsBatchEncoder::new(1024, |_| {});
        for event in &events {
            serializer.encode(event);
        }
        let serialized = serializer.finish();

        let deserialized = EventsBatchDecoder {}
            .decode(serialized)
            .expect("Deserialization failed");

        check_fb_guest_trace_data(&events, &deserialized);
    }

    /// Test serialization and deserialization of GuestTraceData with multiple events
    /// [OpenSpan, LogEvent, CloseSpan]
    #[test]
    fn test_fb_guest_trace_data_multiple_events_serialization_0() {
        let kv1 = EventKeyValue {
            key: "span_field1".to_string(),
            value: "span_value1".to_string(),
        };
        let kv2 = EventKeyValue {
            key: "log_field1".to_string(),
            value: "log_value1".to_string(),
        };

        let events = [
            GuestEvent::OpenSpan {
                id: 1,
                parent_id: None,
                name: "span_name".to_string(),
                target: "span_target".to_string(),
                tsc: 100,
                fields: Vec::from([kv1]),
            },
            GuestEvent::LogEvent {
                parent_id: 1,
                name: "log_name".to_string(),
                tsc: 150,
                fields: Vec::from([kv2]),
            },
            GuestEvent::CloseSpan { id: 1, tsc: 200 },
        ];

        let mut serializer = EventsBatchEncoder::new(2048, |_| {});
        for event in &events {
            serializer.encode(event);
        }
        let serialized = serializer.finish();
        let deserialized = EventsBatchDecoder {}
            .decode(serialized)
            .expect("Deserialization failed");

        check_fb_guest_trace_data(&events, &deserialized);
    }

    /// Test serialization and deserialization of GuestTraceData with multiple events
    /// [OpenSpan, LogEvent, OpenSpan, LogEvent, CloseSpan]
    #[test]
    fn test_fb_guest_trace_data_multiple_events_serialization_1() {
        let kv1 = EventKeyValue {
            key: "span_field1".to_string(),
            value: "span_value1".to_string(),
        };
        let kv2 = EventKeyValue {
            key: "log_field1".to_string(),
            value: "log_value1".to_string(),
        };

        let events = [
            GuestEvent::OpenSpan {
                id: 1,
                parent_id: None,
                name: "span_name_1".to_string(),
                target: "span_target_1".to_string(),
                tsc: 100,
                fields: Vec::from([kv1]),
            },
            GuestEvent::OpenSpan {
                id: 2,
                parent_id: Some(1),
                name: "span_name_2".to_string(),
                target: "span_target_2".to_string(),
                tsc: 1000,
                fields: Vec::from([kv2.clone()]),
            },
            GuestEvent::LogEvent {
                parent_id: 1,
                name: "log_name_1".to_string(),
                tsc: 150,
                fields: Vec::from([kv2.clone()]),
            },
            GuestEvent::LogEvent {
                parent_id: 2,
                name: "log_name".to_string(),
                tsc: 1050,
                fields: Vec::from([kv2]),
            },
            GuestEvent::CloseSpan { id: 2, tsc: 2000 },
        ];

        let mut serializer = EventsBatchEncoder::new(4096, |_| {});
        for event in &events {
            serializer.encode(event);
        }
        let serialized = serializer.finish();
        let deserialized = EventsBatchDecoder {}
            .decode(serialized)
            .expect("Deserialization failed");

        check_fb_guest_trace_data(&events, &deserialized);
    }

    /// Test serialization and deserialization of GuestTraceData with EditSpan event
    #[test]
    fn test_fb_guest_trace_data_edit_span_serialization_00() {
        let kv1 = EventKeyValue {
            key: "edit_key1".to_string(),
            value: "edit_value1".to_string(),
        };
        let kv2 = EventKeyValue {
            key: "edit_key2".to_string(),
            value: "edit_value2".to_string(),
        };
        let events = [GuestEvent::EditSpan {
            id: 1,
            fields: Vec::from([kv1, kv2]),
        }];
        let mut serializer = EventsBatchEncoder::new(1024, |_| {});
        for event in &events {
            serializer.encode(event);
        }
        let serialized = serializer.finish();
        let deserialized = EventsBatchDecoder {}
            .decode(serialized)
            .expect("Deserialization failed");

        check_fb_guest_trace_data(&events, &deserialized);
    }

    /// Test serialization and deserialization of GuestTraceData with GuestStart event
    /// open span and edit span
    #[test]
    fn test_fb_guest_trace_data_edit_span_with_guest_start_serialization() {
        let kv1 = EventKeyValue {
            key: "span_field1".to_string(),
            value: "span_value1".to_string(),
        };
        let kv2 = EventKeyValue {
            key: "edit_key1".to_string(),
            value: "edit_value1".to_string(),
        };
        let events = [
            GuestEvent::GuestStart { tsc: 50 },
            GuestEvent::OpenSpan {
                id: 1,
                parent_id: None,
                name: "span_name".to_string(),
                target: "span_target".to_string(),
                tsc: 100,
                fields: Vec::from([kv1]),
            },
            GuestEvent::EditSpan {
                id: 1,
                fields: Vec::from([kv2]),
            },
        ];
        let mut serializer = EventsBatchEncoder::new(2048, |_| {});
        for event in &events {
            serializer.encode(event);
        }
        let serialized = serializer.finish();
        let deserialized = EventsBatchDecoder {}
            .decode(serialized)
            .expect("Deserialization failed");

        check_fb_guest_trace_data(&events, &deserialized);
    }

    /// Test serialization and deserialization of GuestTraceData with GuestStart event,
    /// open span, log event, open span, edit span, and close span
    #[test]
    fn test_fb_guest_trace_data_edit_span_with_others_serialization() {
        let kv1 = EventKeyValue {
            key: "span_field1".to_string(),
            value: "span_value1".to_string(),
        };
        let kv2 = EventKeyValue {
            key: "log_field1".to_string(),
            value: "log_value1".to_string(),
        };
        let kv3 = EventKeyValue {
            key: "edit_key1".to_string(),
            value: "edit_value1".to_string(),
        };

        let events = [
            GuestEvent::GuestStart { tsc: 50 },
            GuestEvent::OpenSpan {
                id: 1,
                parent_id: None,
                name: "span_name".to_string(),
                target: "span_target".to_string(),
                tsc: 100,
                fields: Vec::from([kv1]),
            },
            GuestEvent::LogEvent {
                parent_id: 1,
                name: "log_name".to_string(),
                tsc: 150,
                fields: Vec::from([kv2]),
            },
            GuestEvent::EditSpan {
                id: 1,
                fields: Vec::from([kv3]),
            },
            GuestEvent::CloseSpan { id: 1, tsc: 200 },
        ];

        let mut serializer = EventsBatchEncoder::new(4096, |_| {});
        for event in &events {
            serializer.encode(event);
        }
        let serialized = serializer.finish();
        let deserialized = EventsBatchDecoder {}
            .decode(serialized)
            .expect("Deserialization failed");

        check_fb_guest_trace_data(&events, &deserialized);
    }

    #[test]
    fn test_events_batch_decoder_errors_on_truncated_buffer() {
        let events = [GuestEvent::LogEvent {
            parent_id: 42,
            name: "log".to_string(),
            tsc: 9001,
            fields: Vec::new(),
        }];

        let mut serializer = EventsBatchEncoder::new(512, |_| {});
        for event in &events {
            serializer.encode(event);
        }
        let mut truncated = serializer.finish().to_vec();
        assert!(
            truncated.pop().is_some(),
            "serialized buffer must be non-empty"
        );

        EventsBatchDecoder {}
            .decode(&truncated)
            .expect_err("Decoder must fail when payload is truncated");
    }

    #[test]
    fn test_event_key_value_try_from_rejects_short_buffer() {
        let buffer = [0x00_u8, 0x01];
        decode::<EventKeyValue>(&buffer)
            .expect_err("Deserialization must fail for undersized buffer");
    }
}
