// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::slice;

use anyhow::{Error, Result, anyhow, bail};
pub use bytes::Bytes;
use serde::{Deserialize, Serialize};
#[cfg(feature = "tracing")]
use tracing::{Span, instrument};

use super::codec::{ExternalValueSink, ExternalValueSource, control_cap};
use super::guest_error::GuestError;
#[cfg(feature = "fuzzing")]
use super::util::arbitrary_byte_chunks;
use super::util::try_byte_chunks_len;
use super::wire::{TupleOut, WireResult, WireValue, decode_result, encode_capped};
use crate::future::{FutureReader, FutureValue};
use crate::stream::{Mux, StreamReader, Transfer};

pub struct FunctionCallResult(core::result::Result<ReturnValue, GuestError>);

impl FunctionCallResult {
    /// Encode control data and supply borrowed byte values to `external_values`.
    ///
    /// `transfers` describes the result's readers in their wire order.
    pub(crate) fn encode<'a, 'b, S>(
        &'a self,
        buffer: &'b mut Vec<u8>,
        external_values: &mut S,
        transfers: &[Transfer],
    ) -> Result<&'b [u8]>
    where
        S: ExternalValueSink<'a> + ?Sized,
    {
        let mut external_len = 0usize;

        for value in self.values() {
            let length = match value {
                ReturnValue::VecBytes(v) => v.len(),
                ReturnValue::ByteChunks(v) => try_byte_chunks_len(v)
                    .ok_or_else(|| anyhow!("External ByteChunks length overflow"))?,
                _ => continue,
            };

            external_len = external_len
                .checked_add(length)
                .ok_or_else(|| anyhow!("External values length overflow"))?;
        }

        let cap = control_cap(external_len)?;
        encode_capped(&self.wire(transfers)?, buffer, cap)?;

        for value in self.values() {
            match value {
                ReturnValue::VecBytes(value) => external_values.push_bytes(value)?,
                ReturnValue::ByteChunks(value) => external_values.push_chunks(value)?,
                _ => {}
            }
        }

        Ok(buffer.as_slice())
    }

    pub fn new(value: core::result::Result<ReturnValue, GuestError>) -> Self {
        FunctionCallResult(value)
    }

    pub fn into_inner(self) -> core::result::Result<ReturnValue, GuestError> {
        self.0
    }

    /// Decode control data, receiving readers and taking byte values from `external_values`.
    ///
    /// A tuple receives its readers before taking its byte values. A failure closes the received
    /// readers and keeps `streams` usable. Only a malformed result leaves transfers unreceived.
    pub fn decode<S>(control: &[u8], external_values: &mut S, streams: &mut Mux) -> Result<Self>
    where
        S: ExternalValueSource + ?Sized,
    {
        let result = decode_result(control, external_values, streams)?;

        external_values.finish()?;
        Ok(FunctionCallResult(result))
    }

    /// Borrow the returned readers in their wire order.
    pub fn readers(&self) -> impl Iterator<Item = &StreamReader<u8>> {
        self.values().iter().filter_map(|value| match value {
            ReturnValue::StreamReader(reader) => Some(reader),
            _ => None,
        })
    }

    /// Take the returned readers to commit their transfers.
    pub(crate) fn into_readers(self) -> impl Iterator<Item = StreamReader<u8>> {
        let (value, tuple) = match self.0 {
            Ok(ReturnValue::Tuple(values)) => (None, values),
            Ok(value) => (Some(value), Vec::new()),
            Err(_) => (None, Vec::new()),
        };

        value
            .into_iter()
            .chain(tuple)
            .filter_map(|value| match value {
                ReturnValue::StreamReader(reader) => Some(reader),
                _ => None,
            })
    }

    /// Borrow the returned values in their wire order. An error has none.
    fn values(&self) -> &[ReturnValue] {
        match &self.0 {
            Ok(ReturnValue::Tuple(values)) => values,
            Ok(value) => slice::from_ref(value),
            Err(_) => &[],
        }
    }

    /// The result's control data with its prepared reader transfers.
    fn wire<'w>(&'w self, transfers: &'w [Transfer]) -> Result<WireResult<'w, TupleOut<'w>>> {
        Ok(match &self.0 {
            Ok(ReturnValue::Tuple(values)) => WireResult::Tuple(TupleOut {
                values,
                xfers: transfers,
            }),
            Ok(value) => {
                let mut xfers = transfers.iter().copied();
                WireResult::Ok(WireValue::from_return(value, &mut xfers)?)
            }
            Err(error) => WireResult::Err {
                code: error.code.into(),
                message: &error.message,
            },
        })
    }
}

/// Supported parameter types with values for function calling.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq)]
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
    /// A stream reader, which moves to the callee.
    #[cfg_attr(feature = "fuzzing", arbitrary(skip))]
    StreamReader(StreamReader<u8>),
}

/// Supported parameter types for function calling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// A stream reader.
    StreamReader,
}

/// Supported return types with values from function calling.
#[derive(Debug, PartialEq)]
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
    /// A stream reader, which moves to the caller.
    StreamReader(StreamReader<u8>),
    /// Values in order. An element is neither `Void` nor a tuple.
    Tuple(Vec<ReturnValue>),
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
    /// A stream reader.
    StreamReader,
    /// A tuple of values.
    Tuple,
}

impl ReturnType {
    /// A reader result requires stream support even when the call takes no readers.
    pub(crate) fn check_supported(self) -> Result<()> {
        if !cfg!(feature = "streams") && self == Self::StreamReader {
            return Err(crate::stream::ProtocolError::Disabled.into());
        }

        Ok(())
    }
}

/// Convert a declared external byte length, which delimits the value in the ordered external
/// values.
fn external_length(length: u64) -> Result<usize> {
    usize::try_from(length)
        .map_err(|_| anyhow!("External byte length {length} does not fit in usize"))
}

/// Take a `VecBytes` value of the declared `length`.
fn decode_vec_bytes<S>(length: u64, externals: &mut S) -> Result<Vec<u8>>
where
    S: ExternalValueSource + ?Sized,
{
    let length = external_length(length)?;
    let value = externals.take_bytes(length)?;
    let value_len = value.len();

    if value_len != length {
        bail!("External VecBytes length mismatch: declared {length}, received {value_len}",);
    }
    Ok(value)
}

/// Take a `ByteChunks` value of the declared `length`. Sources define chunk boundaries.
fn decode_byte_chunks<S>(length: u64, externals: &mut S) -> Result<Vec<Bytes>>
where
    S: ExternalValueSource + ?Sized,
{
    let length = external_length(length)?;
    let value = externals.take_chunks(length)?;
    let actual = try_byte_chunks_len(&value)
        .ok_or_else(|| anyhow!("External ByteChunks length overflow"))?;

    if actual != length {
        bail!("External ByteChunks length mismatch: declared {length}, received {actual}",);
    }
    Ok(value)
}

pub(super) fn decode_parameter_value<S>(
    value: WireValue<'_>,
    externals: &mut S,
    streams: &mut Mux,
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
        WireValue::ExternalBytes {
            length,
            chunked: false,
        } => ParameterValue::VecBytes(decode_vec_bytes(length, externals)?),
        WireValue::ExternalBytes {
            length,
            chunked: true,
        } => ParameterValue::ByteChunks(decode_byte_chunks(length, externals)?),
        WireValue::StreamReader(xfer) => ParameterValue::StreamReader(streams.recv_transfer(xfer)?),
    })
}

pub(super) fn decode_return_value<S>(
    value: WireValue<'_>,
    externals: &mut S,
    streams: &mut Mux,
) -> Result<ReturnValue>
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
        WireValue::ExternalBytes {
            length,
            chunked: false,
        } => ReturnValue::VecBytes(decode_vec_bytes(length, externals)?),
        WireValue::ExternalBytes {
            length,
            chunked: true,
        } => ReturnValue::ByteChunks(decode_byte_chunks(length, externals)?),
        WireValue::StreamReader(xfer) => ReturnValue::StreamReader(streams.recv_transfer(xfer)?),
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
            ParameterValue::StreamReader(_) => ParameterType::StreamReader,
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

impl TryFrom<ParameterValue> for StreamReader<u8> {
    type Error = Error;

    fn try_from(value: ParameterValue) -> Result<Self> {
        match value {
            ParameterValue::StreamReader(v) => Ok(v),
            _ => bail!("Unexpected parameter value type: {:?}", value),
        }
    }
}

impl<T: FutureValue> TryFrom<ParameterValue> for FutureReader<T> {
    type Error = Error;

    fn try_from(value: ParameterValue) -> Result<Self> {
        StreamReader::try_from(value).map(Self::from_stream)
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

impl TryFrom<ReturnValue> for StreamReader<u8> {
    type Error = Error;

    fn try_from(value: ReturnValue) -> Result<Self> {
        match value {
            ReturnValue::StreamReader(v) => Ok(v),
            _ => bail!("Unexpected return value type: {:?}", value),
        }
    }
}

impl<T: FutureValue> TryFrom<ReturnValue> for FutureReader<T> {
    type Error = Error;

    fn try_from(value: ReturnValue) -> Result<Self> {
        StreamReader::try_from(value).map(Self::from_stream)
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

#[cfg(all(test, not(loom)))]
mod tests {
    use alloc::collections::VecDeque;
    use alloc::vec;

    use super::super::guest_error::ErrorCode;
    use super::super::wire::decode_value;
    use super::*;
    use crate::stream::{DEFAULT_WINDOW, Side};
    use crate::transport::PendingMessage;
    use crate::virtq::Segments;

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

    /// Encode `result` and return its control data and external values.
    fn encode(result: FunctionCallResult) -> Result<(Vec<u8>, Segments)> {
        let mut mux = Mux::new(Side::Guest, DEFAULT_WINDOW);
        let mut buffer = Vec::new();
        let pending = PendingMessage::new_result(result, 1, &mut mux)?;
        let message = pending.encode(&mut buffer)?;

        Ok((
            message.control().to_vec(),
            Segments::new(message.external_chunks().map(Bytes::copy_from_slice)),
        ))
    }

    /// Decode a result from `control` and `external_values`.
    fn decode(
        control: &[u8],
        external_values: &mut impl ExternalValueSource,
    ) -> Result<FunctionCallResult> {
        let mut mux = Mux::new(Side::Host, DEFAULT_WINDOW);
        FunctionCallResult::decode(control, external_values, &mut mux)
    }

    #[test]
    fn encode_success_result() {
        let (control, mut external_values) =
            encode(FunctionCallResult::new(Ok(ReturnValue::Int(42)))).unwrap();

        let function_call_result = decode(&control, &mut external_values).unwrap();

        let result = function_call_result.into_inner().unwrap();
        assert_eq!(result, ReturnValue::Int(42));
    }

    #[test]
    fn encode_error_result() {
        let test_error = GuestError::new(
            ErrorCode::GuestFunctionNotFound,
            "Function not found".to_string(),
        );

        let (control, mut external_values) =
            encode(FunctionCallResult::new(Err(test_error.clone()))).unwrap();

        let function_call_result = decode(&control, &mut external_values).unwrap();

        let error = function_call_result.into_inner().unwrap_err();
        assert_eq!(error.code, test_error.code);
        assert_eq!(error.message, test_error.message);
    }

    #[test]
    fn byte_returns_round_trip_as_external_values() {
        let values: [fn() -> ReturnValue; 4] = [
            || ReturnValue::VecBytes(vec![0xa5; 4096]),
            || {
                ReturnValue::ByteChunks(vec![
                    Bytes::from_static(b"chunk one"),
                    Bytes::from_static(b" and two"),
                ])
            },
            || ReturnValue::VecBytes(Vec::new()),
            || ReturnValue::ByteChunks(Vec::new()),
        ];

        for value in values {
            let expected = value();
            let (encoded, mut external_values) =
                encode(FunctionCallResult::new(Ok(value()))).unwrap();

            assert!(encoded.len() < 4096);
            let wire = match &expected {
                ReturnValue::VecBytes(value) => WireValue::ExternalBytes {
                    length: value.len() as u64,
                    chunked: false,
                },
                ReturnValue::ByteChunks(value) => WireValue::ExternalBytes {
                    length: try_byte_chunks_len(value).unwrap() as u64,
                    chunked: true,
                },
                _ => unreachable!(),
            };
            let result: WireResult<'_, usize> = decode_value(&encoded).unwrap();
            assert_eq!(result, WireResult::Ok(wire));

            let decoded = decode(&encoded, &mut external_values)
                .unwrap()
                .into_inner()
                .unwrap();

            assert_eq!(decoded, expected);
            assert!(external_values.is_empty());
        }
    }

    #[test]
    fn external_return_decoder_rejects_invalid_values() {
        let (encoded, _) = encode(FunctionCallResult::new(Ok(ReturnValue::ByteChunks(vec![
            Bytes::from_static(b"123"),
        ]))))
        .unwrap();

        let mut missing = TestExternalValues::default();
        assert!(decode(&encoded, &mut missing).is_err());

        let mut wrong_type =
            TestExternalValues::from_values([TestExternalValue::VecBytes(vec![1, 2, 3])]);

        assert!(decode(&encoded, &mut wrong_type).is_err());

        let mut wrong_length =
            TestExternalValues::from_values([TestExternalValue::ByteChunks(vec![
                Bytes::from_static(b"12"),
            ])]);

        assert!(decode(&encoded, &mut wrong_length).is_err());
    }

    #[test]
    fn external_result_decoder_rejects_unused_values() {
        let (encoded, mut external_values) =
            encode(FunctionCallResult::new(Ok(ReturnValue::Int(42)))).unwrap();
        assert!(external_values.is_empty());

        external_values.append(Segments::single(Bytes::from_static(b"x")));
        assert!(decode(&encoded, &mut external_values).is_err());
    }
}
