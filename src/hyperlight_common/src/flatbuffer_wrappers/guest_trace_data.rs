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

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use anyhow::{Error, Result, anyhow};
use flatbuffers::size_prefixed_root;

use crate::flatbuffers::hyperlight::generated::{
    CloseSpanType as FbCloseSpanType, CloseSpanTypeArgs as FbCloseSpanTypeArgs,
    GuestEventEnvelopeType as FbGuestEventEnvelopeType,
    GuestEventEnvelopeTypeArgs as FbGuestEventEnvelopeTypeArgs, GuestEventType as FbGuestEventType,
    GuestTraceDataType as FbGuestTraceDataType, GuestTraceDataTypeArgs as FbGuestTraceDataTypeArgs,
    EventKeyValue as FbKeyValue, KeyValueArgs as FbKeyValueArgs, LogEventType as FbLogEventType,
    LogEventTypeArgs as FbLogEventTypeArgs, OpenSpanType as FbOpenSpanType,
    OpenSpanTypeArgs as FbOpenSpanTypeArgs,
};

/// Key-Value pair structure used in tracing spans/events
#[derive(Debug, Clone)]
pub struct EventKeyValue {
    /// Key of the key-value pair
    pub key: String,
    /// Value of the key-value pair
    pub value: String,
}

impl From<FbKeyValue<'_>> for EventKeyValue {
    fn from(value: FbKeyValue<'_>) -> Self {
        let key = value.key().to_string();
        let value = value.value().to_string();

        EventKeyValue { key, value }
    }
}

impl TryFrom<&[u8]> for EventKeyValue {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let gld_gen = size_prefixed_root::<FbKeyValue>(value)
            .map_err(|e| anyhow!("Error while reading EventKeyValue: {:?}", e))?;
        let key = gld_gen.key().to_string();
        let value = gld_gen.value().to_string();

        Ok(EventKeyValue { key, value })
    }
}

impl From<&EventKeyValue> for Vec<u8> {
    fn from(value: &EventKeyValue) -> Self {
        let mut builder = flatbuffers::FlatBufferBuilder::new();

        let key_offset = builder.create_string(&value.key);
        let value_offset = builder.create_string(&value.value);

        let kv_args = FbKeyValueArgs {
            key: Some(key_offset),
            value: Some(value_offset),
        };

        let kv_fb = FbKeyValue::create(&mut builder, &kv_args);
        builder.finish_size_prefixed(kv_fb, None);

        builder.finished_data().to_vec()
    }
}

impl From<EventKeyValue> for Vec<u8> {
    fn from(value: EventKeyValue) -> Self {
        Vec::from(&value)
    }
}

/// Enum representing different types of guest events for tracing
/// such as opening/closing spans and logging events.
#[derive(Debug)]
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

impl TryFrom<&[u8]> for GuestTraceData {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let gtd_gen = size_prefixed_root::<FbGuestTraceDataType>(value)
            .map_err(|e| anyhow!("Error while reading GuestTraceData: {:?}", e))?;
        // Extract start_tsc
        let start_tsc = gtd_gen.start_tsc();

        // Extract events
        let mut events = Vec::new();

        // Iterate over each event in the FlatBuffer and convert to GuestEvent
        if let Some(fb_events) = gtd_gen.events() {
            for i in 0..fb_events.len() {
                // Get the event envelope and determine its type
                // to extract the specific event data from the union.
                let envelope = fb_events.get(i);
                let event_type = envelope.event_type();

                // Match on the event type to extract the appropriate event data
                let event = match event_type {
                    FbGuestEventType::OpenSpanType => {
                        // Extract OpenSpanType event data
                        let ost_fb = envelope
                            .event_as_open_span_type()
                            .ok_or_else(|| anyhow!("Failed to cast to OpenSpanType"))?;

                        // Extract fields
                        let id = ost_fb.id();
                        let parent = ost_fb.parent();
                        let name = ost_fb.name().to_string();
                        let target = ost_fb.target().to_string();
                        let tsc = ost_fb.tsc();

                        // Extract key-value fields
                        let mut fields = Vec::new();
                        if let Some(fb_fields) = ost_fb.fields() {
                            for j in 0..fb_fields.len() {
                                let kv: EventKeyValue = EventKeyValue::from(fb_fields.get(j));
                                fields.push(kv);
                            }
                        }

                        // Construct OpenSpan event
                        GuestEvent::OpenSpan {
                            id,
                            parent_id: parent,
                            name,
                            target,
                            tsc,
                            fields,
                        }
                    }
                    FbGuestEventType::CloseSpanType => {
                        // Extract CloseSpanType event data
                        let cst_fb = envelope
                            .event_as_close_span_type()
                            .ok_or_else(|| anyhow!("Failed to cast to CloseSpanType"))?;
                        // Extract fields
                        let id = cst_fb.id();
                        let tsc = cst_fb.tsc();

                        // Construct CloseSpan event
                        GuestEvent::CloseSpan { id, tsc }
                    }
                    FbGuestEventType::LogEventType => {
                        // Extract LogEventType event data
                        let le_fb = envelope
                            .event_as_log_event_type()
                            .ok_or_else(|| anyhow!("Failed to cast to LogEventType"))?;

                        // Extract fields
                        let parent_id = le_fb.parent_id();
                        let name = le_fb.name().to_string();
                        let tsc = le_fb.tsc();

                        // Extract key-value fields
                        let mut fields = Vec::new();
                        if let Some(fb_fields) = le_fb.fields() {
                            for j in 0..fb_fields.len() {
                                let kv: EventKeyValue = EventKeyValue::from(fb_fields.get(j));
                                fields.push(kv);
                            }
                        }

                        // Construct LogEvent
                        GuestEvent::LogEvent {
                            parent_id,
                            name,
                            tsc,
                            fields,
                        }
                    }
                    _ => {
                        return Err(anyhow!("Unknown GuestEventType variant at index {}", i));
                    }
                };
                events.push(event);
            }
        }
        Ok(GuestTraceData { start_tsc, events })
    }
}

impl From<&GuestTraceData> for Vec<u8> {
    fn from(value: &GuestTraceData) -> Self {
        // Create a FlatBuffer builder
        let mut builder = flatbuffers::FlatBufferBuilder::new();

        // Serialize each GuestEvent into its corresponding FlatBuffer representation
        let mut event_offsets = Vec::new();
        for event in &value.events {
            // Serialize the event based on its type
            let event_offset: flatbuffers::WIPOffset<FbGuestEventEnvelopeType> = match event {
                GuestEvent::OpenSpan {
                    id,
                    parent_id,
                    name,
                    target,
                    tsc,
                    fields,
                } => {
                    // Serialize strings
                    let name_offset = builder.create_string(name);
                    let target_offset = builder.create_string(target);

                    // Serialize key-value fields
                    let mut field_offsets = Vec::new();
                    for field in fields {
                        let field_offset: flatbuffers::WIPOffset<FbKeyValue> = {
                            let key_offset = builder.create_string(&field.key);
                            let value_offset = builder.create_string(&field.value);
                            let kv_args = FbKeyValueArgs {
                                key: Some(key_offset),
                                value: Some(value_offset),
                            };
                            FbKeyValue::create(&mut builder, &kv_args)
                        };
                        field_offsets.push(field_offset);
                    }

                    // Create fields vector
                    let fields_vector = if !field_offsets.is_empty() {
                        Some(builder.create_vector(&field_offsets))
                    } else {
                        None
                    };

                    let ost_args = FbOpenSpanTypeArgs {
                        id: *id,
                        parent: *parent_id,
                        name: Some(name_offset),
                        target: Some(target_offset),
                        tsc: *tsc,
                        fields: fields_vector,
                    };

                    // Create the OpenSpanType FlatBuffer object
                    let ost_fb = FbOpenSpanType::create(&mut builder, &ost_args);

                    // Create the GuestEventEnvelopeType
                    let guest_event_fb = FbGuestEventType::OpenSpanType;
                    let envelope_args = FbGuestEventEnvelopeTypeArgs {
                        event_type: guest_event_fb,
                        event: Some(ost_fb.as_union_value()),
                    };

                    // Create the envelope using the union value
                    FbGuestEventEnvelopeType::create(&mut builder, &envelope_args)
                }
                GuestEvent::CloseSpan { id, tsc } => {
                    // Create CloseSpanType FlatBuffer object
                    let cst_args = FbCloseSpanTypeArgs { id: *id, tsc: *tsc };
                    let cst_fb = FbCloseSpanType::create(&mut builder, &cst_args);

                    // Create the GuestEventEnvelopeType
                    let guest_event_fb = FbGuestEventType::CloseSpanType;
                    let envelope_args = FbGuestEventEnvelopeTypeArgs {
                        event_type: guest_event_fb,
                        event: Some(cst_fb.as_union_value()),
                    };
                    // Create the envelope using the union value
                    FbGuestEventEnvelopeType::create(&mut builder, &envelope_args)
                }
                GuestEvent::LogEvent {
                    parent_id,
                    name,
                    tsc,
                    fields,
                } => {
                    // Serialize strings
                    let name_offset = builder.create_string(name);

                    // Serialize key-value fields
                    let mut field_offsets = Vec::new();
                    for field in fields {
                        let field_offset: flatbuffers::WIPOffset<FbKeyValue> = {
                            let key_offset = builder.create_string(&field.key);
                            let value_offset = builder.create_string(&field.value);
                            let kv_args = FbKeyValueArgs {
                                key: Some(key_offset),
                                value: Some(value_offset),
                            };
                            FbKeyValue::create(&mut builder, &kv_args)
                        };
                        field_offsets.push(field_offset);
                    }

                    let fields_vector = if !field_offsets.is_empty() {
                        Some(builder.create_vector(&field_offsets))
                    } else {
                        None
                    };

                    let le_args = FbLogEventTypeArgs {
                        parent_id: *parent_id,
                        name: Some(name_offset),
                        tsc: *tsc,
                        fields: fields_vector,
                    };

                    let le_fb = FbLogEventType::create(&mut builder, &le_args);

                    // Create the GuestEventEnvelopeType
                    let guest_event_fb = FbGuestEventType::LogEventType;
                    let envelope_args = FbGuestEventEnvelopeTypeArgs {
                        event_type: guest_event_fb,
                        event: Some(le_fb.as_union_value()),
                    };
                    // Create the envelope using the union value
                    FbGuestEventEnvelopeType::create(&mut builder, &envelope_args)
                }
            };

            // Collect the event offset
            event_offsets.push(event_offset);
        }

        let events_vector = if !event_offsets.is_empty() {
            Some(builder.create_vector(&event_offsets))
        } else {
            None
        };

        let gtd_args = FbGuestTraceDataTypeArgs {
            start_tsc: value.start_tsc,
            events: events_vector,
        };

        // Create the GuestTraceDataType FlatBuffer object
        let gtd_fb = FbGuestTraceDataType::create(&mut builder, &gtd_args);
        builder.finish_size_prefixed(gtd_fb, None);
        builder.finished_data().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Utility function to check an original GuestTraceData against a deserialized one
    fn check_fb_guest_trace_data(orig: &GuestTraceData, deserialized: &GuestTraceData) {
        assert_eq!(orig.start_tsc, deserialized.start_tsc);
        assert_eq!(orig.events.len(), deserialized.events.len());
        for (original, deserialized) in orig.events.iter().zip(deserialized.events.iter()) {
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

        let serialized: Vec<u8> = Vec::from(&kv);
        let deserialized: EventKeyValue =
            EventKeyValue::try_from(serialized.as_slice()).expect("Deserialization failed");

        assert_eq!(kv.key, deserialized.key);
        assert_eq!(kv.value, deserialized.value);
    }

    #[test]
    fn test_fb_guest_trace_data_open_span_serialization() {
        let kv1 = EventKeyValue {
            key: "test_key1".to_string(),
            value: "test_value1".to_string(),
        };
        let kv2 = EventKeyValue {
            key: "test_key1".to_string(),
            value: "test_value2".to_string(),
        };

        let open_span = GuestEvent::OpenSpan {
            id: 1,
            parent_id: None,
            name: "span_name".to_string(),
            target: "span_target".to_string(),
            tsc: 100,
            fields: Vec::from([kv1, kv2]),
        };

        let guest_trace_data = GuestTraceData {
            start_tsc: 50,
            events: Vec::from([open_span]),
        };

        let serialized: Vec<u8> = Vec::from(&guest_trace_data);
        let deserialized: GuestTraceData =
            GuestTraceData::try_from(serialized.as_slice()).expect("Deserialization failed");

        check_fb_guest_trace_data(&guest_trace_data, &deserialized);
    }

    #[test]
    fn test_fb_guest_trace_data_close_span_serialization() {
        let close_span = GuestEvent::CloseSpan { id: 1, tsc: 200 };

        let guest_trace_data = GuestTraceData {
            start_tsc: 150,
            events: Vec::from([close_span]),
        };

        let serialized: Vec<u8> = Vec::from(&guest_trace_data);
        let deserialized: GuestTraceData =
            GuestTraceData::try_from(serialized.as_slice()).expect("Deserialization failed");

        check_fb_guest_trace_data(&guest_trace_data, &deserialized);
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

        let log_event = GuestEvent::LogEvent {
            parent_id: 2,
            name: "log_name".to_string(),
            tsc: 300,
            fields: Vec::from([kv1, kv2]),
        };

        let guest_trace_data = GuestTraceData {
            start_tsc: 250,
            events: Vec::from([log_event]),
        };

        let serialized: Vec<u8> = Vec::from(&guest_trace_data);
        let deserialized: GuestTraceData =
            GuestTraceData::try_from(serialized.as_slice()).expect("Deserialization failed");

        check_fb_guest_trace_data(&guest_trace_data, &deserialized);
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

        let open_span = GuestEvent::OpenSpan {
            id: 1,
            parent_id: None,
            name: "span_name".to_string(),
            target: "span_target".to_string(),
            tsc: 100,
            fields: Vec::from([kv1]),
        };

        let log_event = GuestEvent::LogEvent {
            parent_id: 1,
            name: "log_name".to_string(),
            tsc: 150,
            fields: Vec::from([kv2]),
        };

        let close_span = GuestEvent::CloseSpan { id: 1, tsc: 200 };

        let guest_trace_data = GuestTraceData {
            start_tsc: 50,
            events: Vec::from([open_span, log_event, close_span]),
        };

        let serialized: Vec<u8> = Vec::from(&guest_trace_data);
        let deserialized: GuestTraceData =
            GuestTraceData::try_from(serialized.as_slice()).expect("Deserialization failed");

        check_fb_guest_trace_data(&guest_trace_data, &deserialized);
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

        let open_span1 = GuestEvent::OpenSpan {
            id: 1,
            parent_id: None,
            name: "span_name_1".to_string(),
            target: "span_target_1".to_string(),
            tsc: 100,
            fields: Vec::from([kv1]),
        };
        let open_span2 = GuestEvent::OpenSpan {
            id: 2,
            parent_id: Some(1),
            name: "span_name_2".to_string(),
            target: "span_target_2".to_string(),
            tsc: 1000,
            fields: Vec::from([kv2.clone()]),
        };

        let log_event1 = GuestEvent::LogEvent {
            parent_id: 1,
            name: "log_name_1".to_string(),
            tsc: 150,
            fields: Vec::from([kv2.clone()]),
        };
        let log_event2 = GuestEvent::LogEvent {
            parent_id: 2,
            name: "log_name".to_string(),
            tsc: 1050,
            fields: Vec::from([kv2]),
        };

        let close_span = GuestEvent::CloseSpan { id: 2, tsc: 2000 };

        let guest_trace_data = GuestTraceData {
            start_tsc: 50,
            events: Vec::from([open_span1, log_event1, open_span2, log_event2, close_span]),
        };

        let serialized: Vec<u8> = Vec::from(&guest_trace_data);
        let deserialized: GuestTraceData =
            GuestTraceData::try_from(serialized.as_slice()).expect("Deserialization failed");

        check_fb_guest_trace_data(&guest_trace_data, &deserialized);
    }
}
