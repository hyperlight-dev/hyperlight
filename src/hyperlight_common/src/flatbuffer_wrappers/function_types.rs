// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use anyhow::{Error, Result, anyhow, bail};
pub use bytes::Bytes;
use flatbuffers::size_prefixed_root;
#[cfg(feature = "tracing")]
use tracing::{Span, instrument};

use super::codec::{ExternalValueSink, ExternalValueSource};
use super::guest_error::GuestError;
#[cfg(feature = "fuzzing")]
use super::util::arbitrary_byte_chunks;
use super::util::try_byte_chunks_len;
use crate::flatbuffers::hyperlight::generated::{
    FunctionCallResult as FbFunctionCallResult, FunctionCallResultArgs as FbFunctionCallResultArgs,
    FunctionCallResultType, Parameter, ParameterType as FbParameterType,
    ParameterValue as FbParameterValue, ReturnType as FbReturnType, ReturnValue as FbReturnValue,
    ReturnValueBox, ReturnValueBoxArgs, hlbool, hlboolArgs, hldouble, hldoubleArgs,
    hlexternalbytes, hlexternalbytesArgs, hlfloat, hlfloatArgs, hlint, hlintArgs, hllong,
    hllongArgs, hlstring, hlstringArgs, hluint, hluintArgs, hlulong, hlulongArgs, hlvoid,
    hlvoidArgs,
};

pub struct FunctionCallResult(core::result::Result<ReturnValue, GuestError>);

impl FunctionCallResult {
    /// Encode control data and collect a byte return as an external value.
    pub fn encode<'a, 'b, S>(
        &'a self,
        builder: &'b mut flatbuffers::FlatBufferBuilder,
        external_values: &mut S,
    ) -> Result<&'b [u8]>
    where
        S: ExternalValueSink<'a> + ?Sized,
    {
        match &self.0 {
            Ok(rv) => {
                // Encode ReturnValue as ReturnValueBox
                let (value, value_type) = match rv {
                    ReturnValue::Int(i) => {
                        let off = hlint::create(builder, &hlintArgs { value: *i });
                        (Some(off.as_union_value()), FbReturnValue::hlint)
                    }
                    ReturnValue::UInt(ui) => {
                        let off = hluint::create(builder, &hluintArgs { value: *ui });
                        (Some(off.as_union_value()), FbReturnValue::hluint)
                    }
                    ReturnValue::Long(l) => {
                        let off = hllong::create(builder, &hllongArgs { value: *l });
                        (Some(off.as_union_value()), FbReturnValue::hllong)
                    }
                    ReturnValue::ULong(ul) => {
                        let off = hlulong::create(builder, &hlulongArgs { value: *ul });
                        (Some(off.as_union_value()), FbReturnValue::hlulong)
                    }
                    ReturnValue::Float(f) => {
                        let off = hlfloat::create(builder, &hlfloatArgs { value: *f });
                        (Some(off.as_union_value()), FbReturnValue::hlfloat)
                    }
                    ReturnValue::Double(d) => {
                        let off = hldouble::create(builder, &hldoubleArgs { value: *d });
                        (Some(off.as_union_value()), FbReturnValue::hldouble)
                    }
                    ReturnValue::Bool(b) => {
                        let off = hlbool::create(builder, &hlboolArgs { value: *b });
                        (Some(off.as_union_value()), FbReturnValue::hlbool)
                    }
                    ReturnValue::String(s) => {
                        let val = builder.create_string(s.as_str());
                        let off = hlstring::create(builder, &hlstringArgs { value: Some(val) });
                        (Some(off.as_union_value()), FbReturnValue::hlstring)
                    }
                    ReturnValue::VecBytes(v) => {
                        let length = u64::try_from(v.len())
                            .map_err(|_| anyhow!("External VecBytes length does not fit in u64"))?;

                        external_values.push_bytes(v)?;
                        let off = hlexternalbytes::create(
                            builder,
                            &hlexternalbytesArgs {
                                length,
                                chunked: false,
                            },
                        );
                        (Some(off.as_union_value()), FbReturnValue::hlexternalbytes)
                    }
                    ReturnValue::ByteChunks(v) => {
                        let length = try_byte_chunks_len(v)
                            .ok_or_else(|| anyhow!("External ByteChunks length overflow"))?;

                        let length = u64::try_from(length).map_err(|_| {
                            anyhow!("External ByteChunks length does not fit in u64")
                        })?;

                        external_values.push_chunks(v)?;
                        let off = hlexternalbytes::create(
                            builder,
                            &hlexternalbytesArgs {
                                length,
                                chunked: true,
                            },
                        );
                        (Some(off.as_union_value()), FbReturnValue::hlexternalbytes)
                    }
                    ReturnValue::Void(()) => {
                        let off = hlvoid::create(builder, &hlvoidArgs {});
                        (Some(off.as_union_value()), FbReturnValue::hlvoid)
                    }
                };
                let rv_box =
                    ReturnValueBox::create(builder, &ReturnValueBoxArgs { value, value_type });
                let fcr = FbFunctionCallResult::create(
                    builder,
                    &FbFunctionCallResultArgs {
                        result: Some(rv_box.as_union_value()),
                        result_type: FunctionCallResultType::ReturnValueBox,
                    },
                );
                builder.finish_size_prefixed(fcr, None);
                Ok(builder.finished_data())
            }
            Err(ge) => {
                // Encode GuestError
                let code: crate::flatbuffers::hyperlight::generated::ErrorCode = ge.code.into();
                let msg = builder.create_string(&ge.message);
                let guest_error = crate::flatbuffers::hyperlight::generated::GuestError::create(
                    builder,
                    &crate::flatbuffers::hyperlight::generated::GuestErrorArgs {
                        code,
                        message: Some(msg),
                    },
                );
                let fcr = FbFunctionCallResult::create(
                    builder,
                    &FbFunctionCallResultArgs {
                        result: Some(guest_error.as_union_value()),
                        result_type: FunctionCallResultType::GuestError,
                    },
                );
                builder.finish_size_prefixed(fcr, None);
                Ok(builder.finished_data())
            }
        }
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
        let function_call_result_fb = size_prefixed_root::<FbFunctionCallResult>(value)
            .map_err(|e| anyhow!("Failed to get FunctionCallResult from bytes: {:?}", e))?;

        let result = match function_call_result_fb.result_type() {
            FunctionCallResultType::ReturnValueBox => {
                let boxed = function_call_result_fb
                    .result_as_return_value_box()
                    .ok_or_else(|| {
                        anyhow!("Failed to get ReturnValueBox from function call result")
                    })?;
                Ok(decode_return_value(boxed, external_values)?)
            }
            FunctionCallResultType::GuestError => {
                let guest_error_table = function_call_result_fb
                    .result_as_guest_error()
                    .ok_or_else(|| anyhow!("Failed to get GuestError from function call result"))?;
                let code = guest_error_table.code();
                let message = guest_error_table
                    .message()
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                Err(GuestError::new(code.into(), message))
            }
            other => {
                bail!("Unexpected function call result type: {:?}", other)
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
    /// One complete chunk-preserving byte value.
    ///
    /// Chunk boundaries are not framing and are not guaranteed to survive
    /// transport.
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
    /// One complete chunk-preserving byte value.
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
    /// One complete chunk-preserving byte value.
    ///
    /// Chunk boundaries are not framing and are not guaranteed to survive
    /// transport.
    ByteChunks(Vec<Bytes>),
}

/// Supported return types from function calling.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
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
    /// One complete chunk-preserving byte value.
    ByteChunks,
}

enum DecodedExternalBytes {
    VecBytes(Vec<u8>),
    ByteChunks(Vec<Bytes>),
}

fn decode_external_bytes<S>(
    metadata: hlexternalbytes<'_>,
    externals: &mut S,
) -> Result<DecodedExternalBytes>
where
    S: ExternalValueSource + ?Sized,
{
    // The length delimits this value in the ordered external payload stream.
    let length = usize::try_from(metadata.length()).map_err(|_| {
        anyhow!(
            "External byte length {} does not fit in usize",
            metadata.length()
        )
    })?;

    // `chunked` selects the logical API type. Sources define chunk boundaries.
    if metadata.chunked() {
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

pub(crate) fn decode_parameter_value<S>(
    param: Parameter<'_>,
    externals: &mut S,
) -> Result<ParameterValue>
where
    S: ExternalValueSource + ?Sized,
{
    match param.value_type() {
        FbParameterValue::hlexternalbytes => {
            let Some(metadata) = param.value_as_hlexternalbytes() else {
                bail!("External byte parameter metadata is missing");
            };

            match decode_external_bytes(metadata, externals)? {
                DecodedExternalBytes::VecBytes(value) => Ok(ParameterValue::VecBytes(value)),
                DecodedExternalBytes::ByteChunks(value) => Ok(ParameterValue::ByteChunks(value)),
            }
        }
        FbParameterValue::hlvecbytes => {
            bail!("Embedded byte parameters are not supported")
        }
        _ => param.try_into(),
    }
}

fn decode_return_value<S>(
    return_value: ReturnValueBox<'_>,
    externals: &mut S,
) -> Result<ReturnValue>
where
    S: ExternalValueSource + ?Sized,
{
    match return_value.value_type() {
        FbReturnValue::hlexternalbytes => {
            let Some(metadata) = return_value.value_as_hlexternalbytes() else {
                bail!("External byte parameter metadata is missing");
            };

            match decode_external_bytes(metadata, externals)? {
                DecodedExternalBytes::VecBytes(value) => Ok(ReturnValue::VecBytes(value)),
                DecodedExternalBytes::ByteChunks(value) => Ok(ReturnValue::ByteChunks(value)),
            }
        }
        FbReturnValue::hlsizeprefixedbuffer => {
            bail!("Embedded byte returns are not supported")
        }
        _ => return_value.try_into(),
    }
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

impl TryFrom<Parameter<'_>> for ParameterValue {
    type Error = Error;

    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(param: Parameter<'_>) -> Result<Self> {
        let value = param.value_type();
        let result = match value {
            FbParameterValue::hlint => param
                .value_as_hlint()
                .map(|hlint| ParameterValue::Int(hlint.value())),
            FbParameterValue::hluint => param
                .value_as_hluint()
                .map(|hluint| ParameterValue::UInt(hluint.value())),
            FbParameterValue::hllong => param
                .value_as_hllong()
                .map(|hllong| ParameterValue::Long(hllong.value())),
            FbParameterValue::hlulong => param
                .value_as_hlulong()
                .map(|hlulong| ParameterValue::ULong(hlulong.value())),
            FbParameterValue::hlfloat => param
                .value_as_hlfloat()
                .map(|hlfloat| ParameterValue::Float(hlfloat.value())),
            FbParameterValue::hldouble => param
                .value_as_hldouble()
                .map(|hldouble| ParameterValue::Double(hldouble.value())),
            FbParameterValue::hlbool => param
                .value_as_hlbool()
                .map(|hlbool| ParameterValue::Bool(hlbool.value())),
            FbParameterValue::hlstring => param.value_as_hlstring().map(|hlstring| {
                ParameterValue::String(hlstring.value().unwrap_or_default().to_string())
            }),
            FbParameterValue::hlvecbytes => {
                bail!("Embedded byte parameters are not supported")
            }
            FbParameterValue::hlexternalbytes => {
                bail!("External byte parameter requires an external value source")
            }
            other => {
                bail!("Unexpected flatbuffer parameter value type: {:?}", other);
            }
        };
        result.ok_or_else(|| anyhow!("Failed to get parameter value"))
    }
}

impl From<ParameterType> for FbParameterType {
    #[cfg_attr(feature = "tracing", instrument(skip_all, parent = Span::current(), level= "Trace"))]
    fn from(value: ParameterType) -> Self {
        match value {
            ParameterType::Int => FbParameterType::hlint,
            ParameterType::UInt => FbParameterType::hluint,
            ParameterType::Long => FbParameterType::hllong,
            ParameterType::ULong => FbParameterType::hlulong,
            ParameterType::Float => FbParameterType::hlfloat,
            ParameterType::Double => FbParameterType::hldouble,
            ParameterType::String => FbParameterType::hlstring,
            ParameterType::Bool => FbParameterType::hlbool,
            ParameterType::VecBytes => FbParameterType::hlvecbytes,
            ParameterType::ByteChunks => FbParameterType::hlbytechunks,
        }
    }
}

impl From<ReturnType> for FbReturnType {
    #[cfg_attr(feature = "tracing", instrument(skip_all, parent = Span::current(), level= "Trace"))]
    fn from(value: ReturnType) -> Self {
        match value {
            ReturnType::Int => FbReturnType::hlint,
            ReturnType::UInt => FbReturnType::hluint,
            ReturnType::Long => FbReturnType::hllong,
            ReturnType::ULong => FbReturnType::hlulong,
            ReturnType::Float => FbReturnType::hlfloat,
            ReturnType::Double => FbReturnType::hldouble,
            ReturnType::String => FbReturnType::hlstring,
            ReturnType::Bool => FbReturnType::hlbool,
            ReturnType::Void => FbReturnType::hlvoid,
            ReturnType::VecBytes => FbReturnType::hlsizeprefixedbuffer,
            ReturnType::ByteChunks => FbReturnType::hlbytechunks,
        }
    }
}

impl TryFrom<FbParameterType> for ParameterType {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: FbParameterType) -> Result<Self> {
        match value {
            FbParameterType::hlint => Ok(ParameterType::Int),
            FbParameterType::hluint => Ok(ParameterType::UInt),
            FbParameterType::hllong => Ok(ParameterType::Long),
            FbParameterType::hlulong => Ok(ParameterType::ULong),
            FbParameterType::hlfloat => Ok(ParameterType::Float),
            FbParameterType::hldouble => Ok(ParameterType::Double),
            FbParameterType::hlstring => Ok(ParameterType::String),
            FbParameterType::hlbool => Ok(ParameterType::Bool),
            FbParameterType::hlvecbytes => Ok(ParameterType::VecBytes),
            FbParameterType::hlbytechunks => Ok(ParameterType::ByteChunks),
            _ => {
                bail!("Unexpected flatbuffer parameter type: {:?}", value)
            }
        }
    }
}

impl TryFrom<FbReturnType> for ReturnType {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: FbReturnType) -> Result<Self> {
        match value {
            FbReturnType::hlint => Ok(ReturnType::Int),
            FbReturnType::hluint => Ok(ReturnType::UInt),
            FbReturnType::hllong => Ok(ReturnType::Long),
            FbReturnType::hlulong => Ok(ReturnType::ULong),
            FbReturnType::hlfloat => Ok(ReturnType::Float),
            FbReturnType::hldouble => Ok(ReturnType::Double),
            FbReturnType::hlstring => Ok(ReturnType::String),
            FbReturnType::hlbool => Ok(ReturnType::Bool),
            FbReturnType::hlvoid => Ok(ReturnType::Void),
            FbReturnType::hlsizeprefixedbuffer => Ok(ReturnType::VecBytes),
            FbReturnType::hlbytechunks => Ok(ReturnType::ByteChunks),
            _ => {
                bail!("Unexpected flatbuffer return type: {:?}", value)
            }
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

impl TryFrom<ReturnValueBox<'_>> for ReturnValue {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(return_value_box: ReturnValueBox<'_>) -> Result<Self> {
        match return_value_box.value_type() {
            FbReturnValue::hlint => {
                let hlint = return_value_box
                    .value_as_hlint()
                    .ok_or_else(|| anyhow!("Failed to get hlint from return value"))?;
                Ok(ReturnValue::Int(hlint.value()))
            }
            FbReturnValue::hluint => {
                let hluint = return_value_box
                    .value_as_hluint()
                    .ok_or_else(|| anyhow!("Failed to get hluint from return value"))?;
                Ok(ReturnValue::UInt(hluint.value()))
            }
            FbReturnValue::hllong => {
                let hllong = return_value_box
                    .value_as_hllong()
                    .ok_or_else(|| anyhow!("Failed to get hllong from return value"))?;
                Ok(ReturnValue::Long(hllong.value()))
            }
            FbReturnValue::hlulong => {
                let hlulong = return_value_box
                    .value_as_hlulong()
                    .ok_or_else(|| anyhow!("Failed to get hlulong from return value"))?;
                Ok(ReturnValue::ULong(hlulong.value()))
            }
            FbReturnValue::hlfloat => {
                let hlfloat = return_value_box
                    .value_as_hlfloat()
                    .ok_or_else(|| anyhow!("Failed to get hlfloat from return value"))?;
                Ok(ReturnValue::Float(hlfloat.value()))
            }
            FbReturnValue::hldouble => {
                let hldouble = return_value_box
                    .value_as_hldouble()
                    .ok_or_else(|| anyhow!("Failed to get hldouble from return value"))?;
                Ok(ReturnValue::Double(hldouble.value()))
            }
            FbReturnValue::hlbool => {
                let hlbool = return_value_box
                    .value_as_hlbool()
                    .ok_or_else(|| anyhow!("Failed to get hlbool from return value"))?;
                Ok(ReturnValue::Bool(hlbool.value()))
            }
            FbReturnValue::hlstring => {
                let hlstring = match return_value_box.value_as_hlstring() {
                    Some(hlstring) => hlstring.value().map(|v| v.to_string()),
                    None => None,
                };
                Ok(ReturnValue::String(hlstring.unwrap_or("".to_string())))
            }
            FbReturnValue::hlvoid => Ok(ReturnValue::Void(())),
            FbReturnValue::hlsizeprefixedbuffer => {
                bail!("Embedded byte returns are not supported")
            }
            FbReturnValue::hlexternalbytes => {
                bail!("External byte return requires an external value source")
            }
            other => {
                bail!("Unexpected flatbuffer return value type: {:?}", other)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::VecDeque;
    use alloc::vec;

    use flatbuffers::FlatBufferBuilder;

    use super::super::guest_error::ErrorCode;
    use super::*;
    use crate::flatbuffers::hyperlight::generated::{hlexternalbytes, hlexternalbytesArgs};

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
        let mut builder = FlatBufferBuilder::new();
        let mut external_values = TestExternalValues::default();

        let test_data = FunctionCallResult::new(Ok(ReturnValue::Int(42)))
            .encode(&mut builder, &mut external_values)
            .unwrap();

        let function_call_result =
            FunctionCallResult::decode(test_data, &mut external_values).unwrap();

        let result = function_call_result.into_inner().unwrap();
        assert_eq!(result, ReturnValue::Int(42));
    }

    #[test]
    fn encode_error_result() {
        let mut builder = FlatBufferBuilder::new();
        let test_error = GuestError::new(
            ErrorCode::GuestFunctionNotFound,
            "Function not found".to_string(),
        );

        let mut external_values = TestExternalValues::default();
        let test_data = FunctionCallResult::new(Err(test_error.clone()))
            .encode(&mut builder, &mut external_values)
            .unwrap();

        let function_call_result =
            FunctionCallResult::decode(test_data, &mut external_values).unwrap();

        let error = function_call_result.into_inner().unwrap_err();
        assert_eq!(error.code, test_error.code);
        assert_eq!(error.message, test_error.message);
    }

    #[test]
    fn external_bytes_marks_chunked_values_only() {
        fn round_trip(chunked: bool) -> bool {
            let mut builder = FlatBufferBuilder::new();
            let value = hlexternalbytes::create(
                &mut builder,
                &hlexternalbytesArgs {
                    length: 42,
                    chunked,
                },
            );
            builder.finish(value, None);
            let value = flatbuffers::root::<hlexternalbytes>(builder.finished_data()).unwrap();

            assert_eq!(value.length(), 42);
            value.chunked()
        }

        assert!(!round_trip(false));
        assert!(round_trip(true));
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
            let mut builder = FlatBufferBuilder::new();
            let mut external_values = TestExternalValues::default();

            let encoded = FunctionCallResult::new(Ok(expected.clone()))
                .encode(&mut builder, &mut external_values)
                .unwrap();

            assert!(encoded.len() < 4096);
            let encoded_result = size_prefixed_root::<FbFunctionCallResult>(encoded).unwrap();
            let return_value = encoded_result.result_as_return_value_box().unwrap();

            assert_eq!(return_value.value_type(), FbReturnValue::hlexternalbytes);

            let metadata = return_value.value_as_hlexternalbytes().unwrap();
            let (length, chunked) = match &expected {
                ReturnValue::VecBytes(value) => (value.len(), false),
                ReturnValue::ByteChunks(value) => (try_byte_chunks_len(value).unwrap(), true),
                _ => unreachable!(),
            };

            assert_eq!(metadata.length(), length as u64);
            assert_eq!(metadata.chunked(), chunked);

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
        let mut builder = FlatBufferBuilder::new();
        let mut encoded_values = TestExternalValues::default();
        let encoded =
            FunctionCallResult::new(Ok(ReturnValue::ByteChunks(vec![Bytes::from_static(
                b"123",
            )])))
            .encode(&mut builder, &mut encoded_values)
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
        let mut builder = FlatBufferBuilder::new();
        let mut external_values = TestExternalValues::default();
        let encoded = result.encode(&mut builder, &mut external_values).unwrap();
        assert!(external_values.values.is_empty());

        external_values
            .values
            .push_back(TestExternalValue::VecBytes(Vec::new()));
        assert!(FunctionCallResult::decode(encoded, &mut external_values).is_err());
    }
}
