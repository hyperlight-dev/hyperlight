// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Tests that pin the wire format of host-guest messages.
//!
//! Snapshots contain guest code built against this format, so a failure means
//! the new encoding breaks existing snapshots. Keep the old encoding, or bump
//! `SNAPSHOT_ABI_VERSION` and the goldens version as described in
//! `docs/snapshot-versioning.md`.

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use super::function_call::{FunctionCall, FunctionCallType};
use super::function_types::{FunctionCallResult, ParameterValue, ReturnType, ReturnValue};
use super::guest_error::{ErrorCode, GuestError};
use super::guest_log_data::GuestLogData;
use super::guest_log_level::LogLevel;
use super::wire::WireValue;
use crate::stream::{Side, StreamId, Transfer};
use crate::transport::{ExternalValues, MsgHeader, MsgKind};

#[track_caller]
fn assert_wire_bytes(what: &str, actual: &[u8], expected: &[u8]) {
    assert_eq!(
        actual, expected,
        "wire format of {what} changed. This breaks existing snapshots. Keep the old \
         encoding, or bump SNAPSHOT_ABI_VERSION and the goldens version. See \
         docs/snapshot-versioning.md."
    );
}

fn encode<T: serde::Serialize>(value: &T) -> Vec<u8> {
    postcard::to_extend(value, Vec::new()).unwrap()
}

#[test]
fn message_header() {
    let header = MsgHeader::new(MsgKind::Response, 0x1234_5678, 4096, 16);

    #[rustfmt::skip]
    let expected = [
        0x02, 0, 0, 0,          // kind, reserved
        0x78, 0x56, 0x34, 0x12, // cid
        0, 0x10, 0, 0,          // payload_len
        16, 0, 0, 0,            // control_len
    ];
    assert_wire_bytes("MsgHeader", header.as_bytes(), &expected);
    assert_eq!(MsgHeader::from_bytes(header.as_bytes()), Some(header));
}

#[test]
fn function_call() {
    let call = FunctionCall::new(
        "add".to_string(),
        Some(vec![
            ParameterValue::Int(-1),
            ParameterValue::String("hi".to_string()),
            ParameterValue::VecBytes(vec![1, 2, 3]),
        ]),
        FunctionCallType::Host,
        ReturnType::Long,
    );
    let mut buffer = Vec::new();
    let mut external_values = ExternalValues::new();
    let encoded = call.encode(&mut buffer, &mut external_values, &[]).unwrap();

    #[rustfmt::skip]
    let expected = [
        3, b'a', b'd', b'd', // name
        1,                   // host
        2,                   // ReturnType::Long
        3,                   // parameter count
        0, 1,                // Int(-1), zigzag varint
        6, 2, b'h', b'i',    // String("hi")
        9, 3, 0,             // ExternalBytes { length: 3, chunked: false }
    ];
    assert_wire_bytes("FunctionCall", encoded, &expected);
    assert_eq!(external_values.total_len(), 3);
}

#[test]
fn function_result() {
    let mut buffer = Vec::new();
    let mut external_values = ExternalValues::new();

    let ok = FunctionCallResult::new(Ok(ReturnValue::UInt(300)));
    let encoded = ok.encode(&mut buffer, &mut external_values, None).unwrap();
    // Ok, UInt, varint 300.
    assert_wire_bytes("FunctionCallResult::Ok", encoded, &[0, 1, 0xac, 0x02]);

    let err = FunctionCallResult::new(Err(GuestError::new(
        ErrorCode::GuestFunctionNotFound,
        "no".to_string(),
    )));
    let encoded = err.encode(&mut buffer, &mut external_values, None).unwrap();
    // Err, code 4, message "no".
    assert_wire_bytes("FunctionCallResult::Err", encoded, &[1, 4, 2, b'n', b'o']);
    assert_eq!(external_values.total_len(), 0);
}

#[test]
fn value_tags() {
    let cases = [
        (WireValue::Int(0), 0u8),
        (WireValue::UInt(0), 1),
        (WireValue::Long(0), 2),
        (WireValue::ULong(0), 3),
        (WireValue::Float(0.0), 4),
        (WireValue::Double(0.0), 5),
        (WireValue::String(""), 6),
        (WireValue::Bool(false), 7),
        (WireValue::Void, 8),
        (
            WireValue::ExternalBytes {
                length: 0,
                chunked: false,
            },
            9,
        ),
        (
            WireValue::StreamReader(Transfer {
                sid: StreamId::new(Side::Host, 1).unwrap(),
                position: 0,
            }),
            10,
        ),
    ];
    for (value, tag) in cases {
        let what = alloc::format!("{value:?}");
        assert_wire_bytes(&what, &encode(&value)[..1], &[tag]);
    }
}

#[test]
fn return_type_tags() {
    let types = [
        ReturnType::Int,
        ReturnType::UInt,
        ReturnType::Long,
        ReturnType::ULong,
        ReturnType::Float,
        ReturnType::Double,
        ReturnType::String,
        ReturnType::Bool,
        ReturnType::Void,
        ReturnType::VecBytes,
        ReturnType::ByteChunks,
        ReturnType::StreamReader,
    ];
    for (tag, value) in types.into_iter().enumerate() {
        let what = alloc::format!("ReturnType::{value:?}");
        assert_wire_bytes(&what, &encode(&value), &[tag as u8]);
        assert_eq!(
            postcard::from_bytes::<ReturnType>(&[tag as u8]).unwrap(),
            value
        );
    }
    assert!(postcard::from_bytes::<ReturnType>(&[types.len() as u8]).is_err());
}

#[test]
fn float_bits() {
    // Little-endian IEEE 754 after the tag.
    assert_wire_bytes(
        "Float",
        &encode(&WireValue::Float(-0.0)),
        &[4, 0, 0, 0, 0x80],
    );
    assert_wire_bytes(
        "Double",
        &encode(&WireValue::Double(-0.0)),
        &[5, 0, 0, 0, 0, 0, 0, 0, 0x80],
    );
}

#[test]
fn error_codes() {
    let codes = [
        (ErrorCode::NoError, 0),
        (ErrorCode::UnsupportedParameterType, 2),
        (ErrorCode::GuestFunctionNameNotProvided, 3),
        (ErrorCode::GuestFunctionNotFound, 4),
        (ErrorCode::GuestFunctionIncorrecNoOfParameters, 5),
        (ErrorCode::GispatchFunctionPointerNotSet, 6),
        (ErrorCode::OutbError, 7),
        (ErrorCode::UnknownError, 8),
        (ErrorCode::GsCheckFailed, 10),
        (ErrorCode::TooManyGuestFunctions, 11),
        (ErrorCode::FailureInDlmalloc, 12),
        (ErrorCode::MallocFailed, 13),
        (ErrorCode::GuestFunctionParameterTypeMismatch, 14),
        (ErrorCode::GuestError, 15),
        (ErrorCode::ArrayLengthParamIsMissing, 16),
        (ErrorCode::HostFunctionError, 17),
    ];
    for (code, value) in codes {
        let what = alloc::format!("ErrorCode::{code:?}");
        assert_wire_bytes(
            &what,
            &u64::from(code).to_le_bytes(),
            &u64::to_le_bytes(value),
        );
        assert_eq!(ErrorCode::from(value), code);
    }
    for unknown in [1, 9, 18, u64::MAX] {
        assert_eq!(ErrorCode::from(unknown), ErrorCode::UnknownError);
    }
}

#[test]
fn guest_log() {
    let log = GuestLogData::new(
        "m".to_string(),
        "s".to_string(),
        LogLevel::Warning,
        "c".to_string(),
        "f".to_string(),
        300,
    );
    let encoded: Vec<u8> = log.try_into().unwrap();

    #[rustfmt::skip]
    let expected = [
        1, b'm', // message
        1, b's', // source
        3,       // LogLevel::Warning
        1, b'c', // caller
        1, b'f', // source_file
        0xac, 2, // line, varint 300
    ];
    assert_wire_bytes("GuestLogData", &encoded, &expected);
}

#[test]
fn log_level_tags() {
    let levels = [
        LogLevel::Trace,
        LogLevel::Debug,
        LogLevel::Information,
        LogLevel::Warning,
        LogLevel::Error,
        LogLevel::Critical,
        LogLevel::None,
    ];
    for (tag, level) in levels.into_iter().enumerate() {
        let what = alloc::format!("LogLevel::{level:?}");
        assert_wire_bytes(&what, &encode(&level), &[tag as u8]);
        assert_eq!(
            postcard::from_bytes::<LogLevel>(&[tag as u8]).unwrap(),
            level
        );
    }
    assert!(postcard::from_bytes::<LogLevel>(&[levels.len() as u8]).is_err());
}

#[cfg(feature = "trace_guest")]
#[test]
fn trace_events() {
    use super::guest_trace_data::{EventKeyValue, GuestEvent};

    let field = || EventKeyValue {
        key: "k".to_string(),
        value: "v".to_string(),
    };
    #[rustfmt::skip]
    let cases: [(GuestEvent, &[u8]); 5] = [
        (
            GuestEvent::OpenSpan {
                id: 2,
                parent_id: Some(1),
                name: "n".to_string(),
                target: "t".to_string(),
                tsc: 300,
                fields: vec![field()],
            },
            &[0, 2, 1, 1, 1, b'n', 1, b't', 0xac, 2, 1, 1, b'k', 1, b'v'],
        ),
        (GuestEvent::CloseSpan { id: 2, tsc: 3 }, &[1, 2, 3]),
        (
            GuestEvent::LogEvent {
                parent_id: 2,
                name: "n".to_string(),
                tsc: 3,
                fields: vec![],
            },
            &[2, 2, 1, b'n', 3, 0],
        ),
        (
            GuestEvent::EditSpan { id: 2, fields: vec![field()] },
            &[3, 2, 1, 1, b'k', 1, b'v'],
        ),
        (GuestEvent::GuestStart { tsc: 1 }, &[4, 1]),
    ];

    for (event, expected) in cases {
        let what = alloc::format!("{event:?}");
        assert_wire_bytes(&what, &encode(&event), expected);
    }
}
