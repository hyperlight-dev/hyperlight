// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use anyhow::{Error, Result, anyhow, bail};
pub use bytes::Bytes;
use serde::{Deserialize, Serialize};
#[cfg(feature = "tracing")]
use tracing::{Span, instrument};

use super::codec::{ExternalValueSink, ExternalValueSource};
use super::guest_error::GuestError;
#[cfg(feature = "fuzzing")]
use super::util::arbitrary_byte_chunks;
use super::util::try_byte_chunks_len;
use super::wire::{WireResult, WireValue, decode_value, encode_value};

pub struct FunctionCallResult(core::result::Result<ReturnValue, GuestError>);

impl FunctionCallResult {
    /// Encode control data and collect a byte return as an external value.
    pub fn encode<'a, 'b, S>(
        &'a self,
        buffer: &'b mut Vec<u8>,
        external_values: &mut S,
    ) -> Result<&'b [u8]>
    where
        S: ExternalValueSink<'a> + ?Sized,
    {
        let result = match &self.0 {
            Ok(value) => {
                match value {
                    ReturnValue::VecBytes(v) => {
                        u64::try_from(v.len())
                            .map_err(|_| anyhow!("External VecBytes length does not fit in u64"))?;
                        external_values.push_bytes(v)?;
                    }
                    ReturnValue::ByteChunks(v) => {
                        let length = try_byte_chunks_len(v)
                            .ok_or_else(|| anyhow!("External ByteChunks length overflow"))?;
                        u64::try_from(length).map_err(|_| {
                            anyhow!("External ByteChunks length does not fit in u64")
                        })?;
                        external_values.push_chunks(v)?;
                    }
                    _ => {}
                }
                WireResult::Ok(WireValue::from_return(value))
            }
            Err(error) => WireResult::Err {
                code: error.code.into(),
                message: &error.message,
            },
        };
        encode_value(&result, buffer)
    }

    pub fn new(value: core::result::Result<ReturnValue, GuestError>) -> Self {
        FunctionCallResult(value)
    }

    pub fn into_inner(self) -> core::result::Result<ReturnValue, GuestError> {
        self.0
    }

    /// Decode control data and consume an external byte return.
    pub fn decode<S>(value: &[u8], external_values: &mut S) -> Result<Self>
    where
        S: ExternalValueSource + ?Sized,
    {
        let result = match decode_value(value)? {
            WireResult::Ok(value) => Ok(decode_return_value(value, external_values)?),
            WireResult::Err { code, message } => {
                Err(GuestError::new(code.into(), message.to_string()))
            }
        };

        external_values.finish()?;
        Ok(FunctionCallResult(result))
    }
}

/// Supported parameter types with values for function calling.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq)]
pub enum ParameterValue {
    /// i32
    Int(i32),
    /// u32
    UInt(u32),
    /// i64
    Long(i64),
    /// i64
    ULong(u64),
    /// f32
    Float(f32),
    /// f64
    Double(f64),
    /// String
    String(String),
    /// bool
    Bool(bool),
    /// `Vec<u8>`
    VecBytes(Vec<u8>),
    /// One logical byte sequence represented as chunks.
    ///
    /// Chunk boundaries are a storage detail and may change during transport.
    /// They do not delimit messages or values.
    ByteChunks(
        #[cfg_attr(feature = "fuzzing", arbitrary(with = arbitrary_byte_chunks))] Vec<Bytes>,
    ),
}

/// Supported parameter types for function calling.
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
pub enum ParameterType {
    /// i32
    Int,
    /// u32
    UInt,
    /// i64
    Long,
    /// u64
    ULong,
    /// f32
    Float,
    /// f64
    Double,
    /// String
    String,
    /// bool
    Bool,
    /// `Vec<u8>`
    VecBytes,
    /// One logical byte sequence represented as chunks.
    ByteChunks,
}

/// Supported return types with values from function calling.
#[derive(Debug, Clone, PartialEq)]
pub enum ReturnValue {
    /// i32
    Int(i32),
    /// u32
    UInt(u32),
    /// i64
    Long(i64),
    /// u64
    ULong(u64),
    /// f32
    Float(f32),
    /// f64
    Double(f64),
    /// String
    String(String),
    /// bool
    Bool(bool),
    /// ()
    Void(()),
    /// `Vec<u8>`
    VecBytes(Vec<u8>),
    /// One logical byte sequence represented as chunks.
    ///
    /// Chunk boundaries are a storage detail and may change during transport.
    /// They do not delimit messages or values.
    ByteChunks(Vec<Bytes>),
}

/// Supported return types from function calling. Variant order is the wire tag.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[repr(C)]
pub enum ReturnType {
    /// i32
    #[default]
    Int,
    /// u32
    UInt,
    /// i64
    Long,
    /// u64
    ULong,
    /// f32
    Float,
    /// f64
    Double,
    /// String
    String,
    /// bool
    Bool,
    /// ()
    Void,
    /// `Vec<u8>`
    VecBytes,
    /// One logical byte sequence represented as chunks.
    ByteChunks,
}

enum DecodedExternalBytes {
    VecBytes(Vec<u8>),
    ByteChunks(Vec<Bytes>),
}

fn decode_external_bytes<S>(
    length: u64,
    chunked: bool,
    externals: &mut S,
) -> Result<DecodedExternalBytes>
where
    S: ExternalValueSource + ?Sized,
{
    // The length delimits this value in the ordered external payload stream.
    let length = usize::try_from(length)
        .map_err(|_| anyhow!("External byte length {length} does not fit in usize"))?;

    // `chunked` selects the logical API type. Sources define chunk boundaries.
    if chunked {
        let value = externals.take_chunks(length)?;
        let actual = try_byte_chunks_len(&value)
            .ok_or_else(|| anyhow!("External ByteChunks length overflow"))?;

        if actual != length {
            bail!("External ByteChunks length mismatch: declared {length}, received {actual}",);
        }
        Ok(DecodedExternalBytes::ByteChunks(value))
    } else {
        let value = externals.take_bytes(length)?;
        let value_len = value.len();

        if value_len != length {
            bail!("External VecBytes length mismatch: declared {length}, received {value_len}",);
        }
        Ok(DecodedExternalBytes::VecBytes(value))
    }
}

pub(super) fn decode_parameter_value<S>(
    value: WireValue<'_>,
    externals: &mut S,
) -> Result<ParameterValue>
where
    S: ExternalValueSource + ?Sized,
{
    Ok(match value {
        WireValue::Int(v) => ParameterValue::Int(v),
        WireValue::UInt(v) => ParameterValue::UInt(v),
        WireValue::Long(v) => ParameterValue::Long(v),
        WireValue::ULong(v) => ParameterValue::ULong(v),
        WireValue::Float(v) => ParameterValue::Float(v),
        WireValue::Double(v) => ParameterValue::Double(v),
        WireValue::String(v) => ParameterValue::String(v.to_string()),
        WireValue::Bool(v) => ParameterValue::Bool(v),
        WireValue::Void => bail!("Void is not a valid parameter value"),
        WireValue::ExternalBytes { length, chunked } => {
            match decode_external_bytes(length, chunked, externals)? {
                DecodedExternalBytes::VecBytes(v) => ParameterValue::VecBytes(v),
                DecodedExternalBytes::ByteChunks(v) => ParameterValue::ByteChunks(v),
            }
        }
    })
}

fn decode_return_value<S>(value: WireValue<'_>, externals: &mut S) -> Result<ReturnValue>
where
    S: ExternalValueSource + ?Sized,
{
    Ok(match value {
        WireValue::Int(v) => ReturnValue::Int(v),
        WireValue::UInt(v) => ReturnValue::UInt(v),
        WireValue::Long(v) => ReturnValue::Long(v),
        WireValue::ULong(v) => ReturnValue::ULong(v),
        WireValue::Float(v) => ReturnValue::Float(v),
        WireValue::Double(v) => ReturnValue::Double(v),
        WireValue::String(v) => ReturnValue::String(v.to_string()),
        WireValue::Bool(v) => ReturnValue::Bool(v),
        WireValue::Void => ReturnValue::Void(()),
        WireValue::ExternalBytes { length, chunked } => {
            match decode_external_bytes(length, chunked, externals)? {
                DecodedExternalBytes::VecBytes(v) => ReturnValue::VecBytes(v),
                DecodedExternalBytes::ByteChunks(v) => ReturnValue::ByteChunks(v),
            }
        }
    })
}

impl From<&ParameterValue> for ParameterType {
    #[cfg_attr(feature = "tracing", instrument(skip_all, parent = Span::current(), level= "Trace"))]
    fn from(value: &ParameterValue) -> Self {
        match *value {
            ParameterValue::Int(_) => ParameterType::Int,
            ParameterValue::UInt(_) => ParameterType::UInt,
            ParameterValue::Long(_) => ParameterType::Long,
            ParameterValue::ULong(_) => ParameterType::ULong,
            ParameterValue::Float(_) => ParameterType::Float,
            ParameterValue::Double(_) => ParameterType::Double,
            ParameterValue::String(_) => ParameterType::String,
            ParameterValue::Bool(_) => ParameterType::Bool,
            ParameterValue::VecBytes(_) => ParameterType::VecBytes,
            ParameterValue::ByteChunks(_) => ParameterType::ByteChunks,
        }
    }
}

impl TryFrom<ParameterValue> for i32 {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: ParameterValue) -> Result<Self> {
        match value {
            ParameterValue::Int(v) => Ok(v),
            _ => {
                bail!("Unexpected parameter value type: {:?}", value)
            }
        }
    }
}

impl TryFrom<ParameterValue> for u32 {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: ParameterValue) -> Result<Self> {
        match value {
            ParameterValue::UInt(v) => Ok(v),
            _ => {
                bail!("Unexpected parameter value type: {:?}", value)
            }
        }
    }
}

impl TryFrom<ParameterValue> for i64 {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: ParameterValue) -> Result<Self> {
        match value {
            ParameterValue::Long(v) => Ok(v),
            _ => {
                bail!("Unexpected parameter value type: {:?}", value)
            }
        }
    }
}

impl TryFrom<ParameterValue> for u64 {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: ParameterValue) -> Result<Self> {
        match value {
            ParameterValue::ULong(v) => Ok(v),
            _ => {
                bail!("Unexpected parameter value type: {:?}", value)
            }
        }
    }
}

impl TryFrom<ParameterValue> for f32 {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: ParameterValue) -> Result<Self> {
        match value {
            ParameterValue::Float(v) => Ok(v),
            _ => {
                bail!("Unexpected parameter value type: {:?}", value)
            }
        }
    }
}

impl TryFrom<ParameterValue> for f64 {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: ParameterValue) -> Result<Self> {
        match value {
            ParameterValue::Double(v) => Ok(v),
            _ => {
                bail!("Unexpected parameter value type: {:?}", value)
            }
        }
    }
}

impl TryFrom<ParameterValue> for String {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: ParameterValue) -> Result<Self> {
        match value {
            ParameterValue::String(v) => Ok(v),
            _ => {
                bail!("Unexpected parameter value type: {:?}", value)
            }
        }
    }
}

impl TryFrom<ParameterValue> for bool {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: ParameterValue) -> Result<Self> {
        match value {
            ParameterValue::Bool(v) => Ok(v),
            _ => {
                bail!("Unexpected parameter value type: {:?}", value)
            }
        }
    }
}

impl TryFrom<ParameterValue> for Vec<u8> {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: ParameterValue) -> Result<Self> {
        match value {
            ParameterValue::VecBytes(v) => Ok(v),
            _ => {
                bail!("Unexpected parameter value type: {:?}", value)
            }
        }
    }
}

impl TryFrom<ParameterValue> for Vec<Bytes> {
    type Error = Error;

    fn try_from(value: ParameterValue) -> Result<Self> {
        match value {
            ParameterValue::ByteChunks(v) => Ok(v),
            _ => bail!("Unexpected parameter value type: {:?}", value),
        }
    }
}

impl TryFrom<ReturnValue> for i32 {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: ReturnValue) -> Result<Self> {
        match value {
            ReturnValue::Int(v) => Ok(v),
            _ => {
                bail!("Unexpected return value type: {:?}", value)
            }
        }
    }
}

impl TryFrom<ReturnValue> for u32 {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: ReturnValue) -> Result<Self> {
        match value {
            ReturnValue::UInt(v) => Ok(v),
            _ => {
                bail!("Unexpected return value type: {:?}", value)
            }
        }
    }
}

impl TryFrom<ReturnValue> for i64 {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: ReturnValue) -> Result<Self> {
        match value {
            ReturnValue::Long(v) => Ok(v),
            _ => {
                bail!("Unexpected return value type: {:?}", value)
            }
        }
    }
}

impl TryFrom<ReturnValue> for u64 {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: ReturnValue) -> Result<Self> {
        match value {
            ReturnValue::ULong(v) => Ok(v),
            _ => {
                bail!("Unexpected return value type: {:?}", value)
            }
        }
    }
}

impl TryFrom<ReturnValue> for f32 {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: ReturnValue) -> Result<Self> {
        match value {
            ReturnValue::Float(v) => Ok(v),
            _ => {
                bail!("Unexpected return value type: {:?}", value)
            }
        }
    }
}

impl TryFrom<ReturnValue> for f64 {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: ReturnValue) -> Result<Self> {
        match value {
            ReturnValue::Double(v) => Ok(v),
            _ => {
                bail!("Unexpected return value type: {:?}", value)
            }
        }
    }
}

impl TryFrom<ReturnValue> for String {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: ReturnValue) -> Result<Self> {
        match value {
            ReturnValue::String(v) => Ok(v),
            _ => {
                bail!("Unexpected return value type: {:?}", value)
            }
        }
    }
}

impl TryFrom<ReturnValue> for bool {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: ReturnValue) -> Result<Self> {
        match value {
            ReturnValue::Bool(v) => Ok(v),
            _ => {
                bail!("Unexpected return value type: {:?}", value)
            }
        }
    }
}

impl TryFrom<ReturnValue> for Vec<u8> {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: ReturnValue) -> Result<Self> {
        match value {
            ReturnValue::VecBytes(v) => Ok(v),
            _ => {
                bail!("Unexpected return value type: {:?}", value)
            }
        }
    }
}

impl TryFrom<ReturnValue> for Vec<Bytes> {
    type Error = Error;

    fn try_from(value: ReturnValue) -> Result<Self> {
        match value {
            ReturnValue::ByteChunks(v) => Ok(v),
            _ => bail!("Unexpected return value type: {:?}", value),
        }
    }
}

impl TryFrom<ReturnValue> for () {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: ReturnValue) -> Result<Self> {
        match value {
            ReturnValue::Void(()) => Ok(()),
            _ => {
                bail!("Unexpected return value type: {:?}", value)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::VecDeque;
    use alloc::vec;

    use super::super::guest_error::ErrorCode;
    use super::*;

    #[derive(Debug, Clone, PartialEq)]
    enum TestExternalValue {
        VecBytes(Vec<u8>),
        ByteChunks(Vec<Bytes>),
    }

    #[derive(Default)]
    struct TestExternalValues {
        values: VecDeque<TestExternalValue>,
    }

    impl TestExternalValues {
        fn from_values(values: impl IntoIterator<Item = TestExternalValue>) -> Self {
            Self {
                values: values.into_iter().collect(),
            }
        }
    }

    impl<'a> ExternalValueSink<'a> for TestExternalValues {
        fn push_bytes(&mut self, value: &'a [u8]) -> Result<()> {
            self.values
                .push_back(TestExternalValue::VecBytes(value.to_vec()));
            Ok(())
        }

        fn push_chunks(&mut self, value: &'a [Bytes]) -> Result<()> {
            self.values
                .push_back(TestExternalValue::ByteChunks(value.to_vec()));
            Ok(())
        }
    }

    impl ExternalValueSource for TestExternalValues {
        fn take_bytes(&mut self, _length: usize) -> Result<Vec<u8>> {
            match self.values.pop_front() {
                Some(TestExternalValue::VecBytes(value)) => Ok(value),
                Some(TestExternalValue::ByteChunks(_)) => {
                    anyhow::bail!("Expected external VecBytes value")
                }
                None => anyhow::bail!("Missing external VecBytes value"),
            }
        }

        fn take_chunks(&mut self, _length: usize) -> Result<Vec<Bytes>> {
            match self.values.pop_front() {
                Some(TestExternalValue::ByteChunks(value)) => Ok(value),
                Some(TestExternalValue::VecBytes(_)) => {
                    anyhow::bail!("Expected external ByteChunks value")
                }
                None => anyhow::bail!("Missing external ByteChunks value"),
            }
        }

        fn finish(&mut self) -> Result<()> {
            if self.values.is_empty() {
                Ok(())
            } else {
                anyhow::bail!("Unused external values")
            }
        }
    }

    #[test]
    fn encode_success_result() {
        let mut buffer = Vec::new();
        let mut external_values = TestExternalValues::default();

        let test_data = FunctionCallResult::new(Ok(ReturnValue::Int(42)))
            .encode(&mut buffer, &mut external_values)
            .unwrap();

        let function_call_result =
            FunctionCallResult::decode(test_data, &mut external_values).unwrap();

        let result = function_call_result.into_inner().unwrap();
        assert_eq!(result, ReturnValue::Int(42));
    }

    #[test]
    fn encode_error_result() {
        let mut buffer = Vec::new();
        let test_error = GuestError::new(
            ErrorCode::GuestFunctionNotFound,
            "Function not found".to_string(),
        );

        let mut external_values = TestExternalValues::default();
        let test_data = FunctionCallResult::new(Err(test_error.clone()))
            .encode(&mut buffer, &mut external_values)
            .unwrap();

        let function_call_result =
            FunctionCallResult::decode(test_data, &mut external_values).unwrap();

        let error = function_call_result.into_inner().unwrap_err();
        assert_eq!(error.code, test_error.code);
        assert_eq!(error.message, test_error.message);
    }

    #[test]
    fn byte_returns_round_trip_as_external_values() {
        for expected in [
            ReturnValue::VecBytes(vec![0xa5; 4096]),
            ReturnValue::ByteChunks(vec![
                Bytes::from_static(b"chunk one"),
                Bytes::from_static(b" and two"),
            ]),
            ReturnValue::VecBytes(Vec::new()),
            ReturnValue::ByteChunks(Vec::new()),
        ] {
            let mut buffer = Vec::new();
            let mut external_values = TestExternalValues::default();

            let encoded = FunctionCallResult::new(Ok(expected.clone()))
                .encode(&mut buffer, &mut external_values)
                .unwrap();

            assert!(encoded.len() < 4096);
            let (length, chunked) = match &expected {
                ReturnValue::VecBytes(value) => (value.len(), false),
                ReturnValue::ByteChunks(value) => (try_byte_chunks_len(value).unwrap(), true),
                _ => unreachable!(),
            };
            assert_eq!(
                decode_value::<WireResult>(encoded).unwrap(),
                WireResult::Ok(WireValue::ExternalBytes {
                    length: length as u64,
                    chunked,
                })
            );

            let decoded = FunctionCallResult::decode(encoded, &mut external_values)
                .unwrap()
                .into_inner()
                .unwrap();

            assert_eq!(decoded, expected);
            assert!(external_values.values.is_empty());
        }
    }

    #[test]
    fn external_return_decoder_rejects_invalid_values() {
        let mut buffer = Vec::new();
        let mut encoded_values = TestExternalValues::default();
        let encoded =
            FunctionCallResult::new(Ok(ReturnValue::ByteChunks(vec![Bytes::from_static(
                b"123",
            )])))
            .encode(&mut buffer, &mut encoded_values)
            .unwrap();

        let mut missing = TestExternalValues::default();
        assert!(FunctionCallResult::decode(encoded, &mut missing).is_err());

        let mut wrong_type =
            TestExternalValues::from_values([TestExternalValue::VecBytes(vec![1, 2, 3])]);

        assert!(FunctionCallResult::decode(encoded, &mut wrong_type).is_err());

        let mut wrong_length =
            TestExternalValues::from_values([TestExternalValue::ByteChunks(vec![
                Bytes::from_static(b"12"),
            ])]);

        assert!(FunctionCallResult::decode(encoded, &mut wrong_length).is_err());
    }

    #[test]
    fn external_result_decoder_rejects_unused_values() {
        let result = FunctionCallResult::new(Ok(ReturnValue::Int(42)));
        let mut buffer = Vec::new();
        let mut external_values = TestExternalValues::default();
        let encoded = result.encode(&mut buffer, &mut external_values).unwrap();
        assert!(external_values.values.is_empty());

        external_values
            .values
            .push_back(TestExternalValue::VecBytes(Vec::new()));
        assert!(FunctionCallResult::decode(encoded, &mut external_values).is_err());
    }
}
