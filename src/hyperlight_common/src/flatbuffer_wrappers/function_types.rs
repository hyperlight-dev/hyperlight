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
use super::util::{byte_chunks_from_bytes, byte_chunks_to_bytes, try_byte_chunks_len};
use crate::flatbuffers::hyperlight::generated::{
    FunctionCallResult as FbFunctionCallResult, FunctionCallResultArgs as FbFunctionCallResultArgs,
    FunctionCallResultType, Parameter, ParameterType as FbParameterType,
    ParameterValue as FbParameterValue, ReturnType as FbReturnType, ReturnValue as FbReturnValue,
    ReturnValueBox, ReturnValueBoxArgs, hlbool, hlboolArgs, hldouble, hldoubleArgs,
    hlexternalbytes, hlexternalbytesArgs, hlfloat, hlfloatArgs, hlint, hlintArgs, hllong,
    hllongArgs, hlsizeprefixedbuffer, hlsizeprefixedbufferArgs, hlsizeprefixedbytechunks,
    hlsizeprefixedbytechunksArgs, hlstring, hlstringArgs, hluint, hluintArgs, hlulong, hlulongArgs,
    hlvoid, hlvoidArgs,
};

pub struct FunctionCallResult(core::result::Result<ReturnValue, GuestError>);

impl FunctionCallResult {
    /// Encodes self into the given builder and returns the encoded data.
    ///
    /// # Notes
    ///
    /// The builder should not be reused after a call to encode, since this function
    /// does not reset the state of the builder. If you want to reuse the builder,
    /// you'll need to reset it first.
    pub fn encode<'a>(&self, builder: &'a mut flatbuffers::FlatBufferBuilder) -> &'a [u8] {
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
                        let val = builder.create_vector(v);
                        let off = hlsizeprefixedbuffer::create(
                            builder,
                            &hlsizeprefixedbufferArgs {
                                value: Some(val),
                                size: v.len() as i32,
                            },
                        );
                        (
                            Some(off.as_union_value()),
                            FbReturnValue::hlsizeprefixedbuffer,
                        )
                    }
                    ReturnValue::ByteChunks(v) => {
                        let value = byte_chunks_to_bytes(v);
                        let val = builder.create_vector(value.as_ref());
                        let off = hlsizeprefixedbytechunks::create(
                            builder,
                            &hlsizeprefixedbytechunksArgs {
                                value: Some(val),
                                size: value.len() as i32,
                            },
                        );
                        (
                            Some(off.as_union_value()),
                            FbReturnValue::hlsizeprefixedbytechunks,
                        )
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
                builder.finished_data()
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
                builder.finished_data()
            }
        }
    }

    /// Encodes byte returns as external markers and sends their payload to
    /// `external_values`.
    ///
    /// Non-byte returns and guest errors retain their existing embedded
    /// encoding.
    pub fn encode_external<'a, 'b, S>(
        &'a self,
        builder: &'b mut flatbuffers::FlatBufferBuilder,
        external_values: &mut S,
    ) -> Result<&'b [u8]>
    where
        S: ExternalValueSink<'a> + ?Sized,
    {
        let Ok(return_value) = &self.0 else {
            return Ok(self.encode(builder));
        };

        let (length, chunked) = match return_value {
            ReturnValue::VecBytes(value) => {
                let length = u64::try_from(value.len())
                    .map_err(|_| anyhow!("External VecBytes length does not fit in u64"))?;
                external_values.push_bytes(value)?;
                (length, false)
            }
            ReturnValue::ByteChunks(value) => {
                let length = try_byte_chunks_len(value)
                    .ok_or_else(|| anyhow!("External ByteChunks length overflow"))?;
                let length = u64::try_from(length)
                    .map_err(|_| anyhow!("External ByteChunks length does not fit in u64"))?;
                external_values.push_chunks(value)?;
                (length, true)
            }
            _ => return Ok(self.encode(builder)),
        };

        let value = hlexternalbytes::create(builder, &hlexternalbytesArgs { length, chunked });
        let return_value = ReturnValueBox::create(
            builder,
            &ReturnValueBoxArgs {
                value: Some(value.as_union_value()),
                value_type: FbReturnValue::hlexternalbytes,
            },
        );
        let result = FbFunctionCallResult::create(
            builder,
            &FbFunctionCallResultArgs {
                result: Some(return_value.as_union_value()),
                result_type: FunctionCallResultType::ReturnValueBox,
            },
        );
        builder.finish_size_prefixed(result, None);
        Ok(builder.finished_data())
    }

    pub fn new(value: core::result::Result<ReturnValue, GuestError>) -> Self {
        FunctionCallResult(value)
    }

    pub fn into_inner(self) -> core::result::Result<ReturnValue, GuestError> {
        self.0
    }

    /// Decodes a function-call result using `external_values` for external byte
    /// markers.
    pub fn decode_external<S>(value: &[u8], external_values: &mut S) -> Result<Self>
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
                Ok(decode_external_return_value(boxed, external_values)?)
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

impl TryFrom<&[u8]> for FunctionCallResult {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        let function_call_result_fb = size_prefixed_root::<FbFunctionCallResult>(value)
            .map_err(|e| anyhow!("Failed to get FunctionCallResult from bytes: {:?}", e))?;

        match function_call_result_fb.result_type() {
            FunctionCallResultType::ReturnValueBox => {
                let boxed = function_call_result_fb
                    .result_as_return_value_box()
                    .ok_or_else(|| {
                        anyhow!("Failed to get ReturnValueBox from function call result")
                    })?;
                let return_value = ReturnValue::try_from(boxed)?;
                Ok(FunctionCallResult(Ok(return_value)))
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
                Ok(FunctionCallResult(Err(GuestError::new(
                    code.into(),
                    message,
                ))))
            }
            other => {
                bail!("Unexpected function call result type: {:?}", other)
            }
        }
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

pub(crate) fn decode_external_parameter_value<S>(
    parameter: Parameter<'_>,
    external_values: &mut S,
) -> Result<ParameterValue>
where
    S: ExternalValueSource + ?Sized,
{
    if parameter.value_type() != FbParameterValue::hlexternalbytes {
        return parameter.try_into();
    }

    let marker = parameter
        .value_as_hlexternalbytes()
        .ok_or_else(|| anyhow!("Failed to get external byte parameter marker"))?;
    let length = usize::try_from(marker.length()).map_err(|_| {
        anyhow!(
            "External byte parameter length {} does not fit in usize",
            marker.length()
        )
    })?;

    if marker.chunked() {
        let value = external_values.take_chunks(length)?;
        let actual_length = try_byte_chunks_len(&value)
            .ok_or_else(|| anyhow!("External ByteChunks parameter length overflow"))?;
        if actual_length != length {
            bail!(
                "External ByteChunks parameter length mismatch: declared {}, received {}",
                length,
                actual_length
            );
        }
        Ok(ParameterValue::ByteChunks(value))
    } else {
        let value = external_values.take_bytes(length)?;
        if value.len() != length {
            bail!(
                "External VecBytes parameter length mismatch: declared {}, received {}",
                length,
                value.len()
            );
        }
        Ok(ParameterValue::VecBytes(value))
    }
}

fn decode_external_return_value<S>(
    return_value: ReturnValueBox<'_>,
    external_values: &mut S,
) -> Result<ReturnValue>
where
    S: ExternalValueSource + ?Sized,
{
    if return_value.value_type() != FbReturnValue::hlexternalbytes {
        return return_value.try_into();
    }

    let marker = return_value
        .value_as_hlexternalbytes()
        .ok_or_else(|| anyhow!("Failed to get external byte return marker"))?;
    let length = usize::try_from(marker.length()).map_err(|_| {
        anyhow!(
            "External byte return length {} does not fit in usize",
            marker.length()
        )
    })?;

    if marker.chunked() {
        let value = external_values.take_chunks(length)?;
        let actual_length = try_byte_chunks_len(&value)
            .ok_or_else(|| anyhow!("External ByteChunks return length overflow"))?;
        if actual_length != length {
            bail!(
                "External ByteChunks return length mismatch: declared {}, received {}",
                length,
                actual_length
            );
        }
        Ok(ReturnValue::ByteChunks(value))
    } else {
        let value = external_values.take_bytes(length)?;
        if value.len() != length {
            bail!(
                "External VecBytes return length mismatch: declared {}, received {}",
                length,
                value.len()
            );
        }
        Ok(ReturnValue::VecBytes(value))
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
            FbParameterValue::hlvecbytes => param.value_as_hlvecbytes().map(|hlvecbytes| {
                ParameterValue::VecBytes(hlvecbytes.value().unwrap_or_default().bytes().to_vec())
            }),
            FbParameterValue::hlbytechunks => param.value_as_hlbytechunks().map(|hlbytechunks| {
                ParameterValue::ByteChunks(byte_chunks_from_bytes(Bytes::copy_from_slice(
                    hlbytechunks.value().unwrap_or_default().bytes(),
                )))
            }),
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
                let hlvecbytes = match return_value_box.value_as_hlsizeprefixedbuffer() {
                    Some(hlvecbytes) => hlvecbytes
                        .value()
                        .map(|val| val.iter().collect::<Vec<u8>>()),
                    None => None,
                };
                Ok(ReturnValue::VecBytes(hlvecbytes.unwrap_or(Vec::new())))
            }
            FbReturnValue::hlsizeprefixedbytechunks => {
                let value = return_value_box
                    .value_as_hlsizeprefixedbytechunks()
                    .and_then(|value| value.value())
                    .map(|value| byte_chunks_from_bytes(Bytes::copy_from_slice(value.bytes())))
                    .unwrap_or_default();
                Ok(ReturnValue::ByteChunks(value))
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

impl TryFrom<&ReturnValue> for Vec<u8> {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: &ReturnValue) -> Result<Vec<u8>> {
        let mut builder = flatbuffers::FlatBufferBuilder::new();
        let result_bytes = match value {
            ReturnValue::Int(i) => {
                let hlint_off = hlint::create(&mut builder, &hlintArgs { value: *i });
                let rv_box = ReturnValueBox::create(
                    &mut builder,
                    &ReturnValueBoxArgs {
                        value: Some(hlint_off.as_union_value()),
                        value_type: FbReturnValue::hlint,
                    },
                );
                let fcr = FbFunctionCallResult::create(
                    &mut builder,
                    &FbFunctionCallResultArgs {
                        result: Some(rv_box.as_union_value()),
                        result_type: FunctionCallResultType::ReturnValueBox,
                    },
                );
                builder.finish_size_prefixed(fcr, None);
                builder.finished_data().to_vec()
            }
            ReturnValue::UInt(ui) => {
                let off = hluint::create(&mut builder, &hluintArgs { value: *ui });
                let rv_box = ReturnValueBox::create(
                    &mut builder,
                    &ReturnValueBoxArgs {
                        value: Some(off.as_union_value()),
                        value_type: FbReturnValue::hluint,
                    },
                );
                let fcr = FbFunctionCallResult::create(
                    &mut builder,
                    &FbFunctionCallResultArgs {
                        result: Some(rv_box.as_union_value()),
                        result_type: FunctionCallResultType::ReturnValueBox,
                    },
                );
                builder.finish_size_prefixed(fcr, None);
                builder.finished_data().to_vec()
            }
            ReturnValue::Long(l) => {
                let off = hllong::create(&mut builder, &hllongArgs { value: *l });
                let rv_box = ReturnValueBox::create(
                    &mut builder,
                    &ReturnValueBoxArgs {
                        value: Some(off.as_union_value()),
                        value_type: FbReturnValue::hllong,
                    },
                );
                let fcr = FbFunctionCallResult::create(
                    &mut builder,
                    &FbFunctionCallResultArgs {
                        result: Some(rv_box.as_union_value()),
                        result_type: FunctionCallResultType::ReturnValueBox,
                    },
                );
                builder.finish_size_prefixed(fcr, None);
                builder.finished_data().to_vec()
            }
            ReturnValue::ULong(ul) => {
                let off = hlulong::create(&mut builder, &hlulongArgs { value: *ul });
                let rv_box = ReturnValueBox::create(
                    &mut builder,
                    &ReturnValueBoxArgs {
                        value: Some(off.as_union_value()),
                        value_type: FbReturnValue::hlulong,
                    },
                );
                let fcr = FbFunctionCallResult::create(
                    &mut builder,
                    &FbFunctionCallResultArgs {
                        result: Some(rv_box.as_union_value()),
                        result_type: FunctionCallResultType::ReturnValueBox,
                    },
                );
                builder.finish_size_prefixed(fcr, None);
                builder.finished_data().to_vec()
            }
            ReturnValue::Float(f) => {
                let off = hlfloat::create(&mut builder, &hlfloatArgs { value: *f });
                let rv_box = ReturnValueBox::create(
                    &mut builder,
                    &ReturnValueBoxArgs {
                        value: Some(off.as_union_value()),
                        value_type: FbReturnValue::hlfloat,
                    },
                );
                let fcr = FbFunctionCallResult::create(
                    &mut builder,
                    &FbFunctionCallResultArgs {
                        result: Some(rv_box.as_union_value()),
                        result_type: FunctionCallResultType::ReturnValueBox,
                    },
                );
                builder.finish_size_prefixed(fcr, None);
                builder.finished_data().to_vec()
            }
            ReturnValue::Double(d) => {
                let off = hldouble::create(&mut builder, &hldoubleArgs { value: *d });
                let rv_box = ReturnValueBox::create(
                    &mut builder,
                    &ReturnValueBoxArgs {
                        value: Some(off.as_union_value()),
                        value_type: FbReturnValue::hldouble,
                    },
                );
                let fcr = FbFunctionCallResult::create(
                    &mut builder,
                    &FbFunctionCallResultArgs {
                        result: Some(rv_box.as_union_value()),
                        result_type: FunctionCallResultType::ReturnValueBox,
                    },
                );
                builder.finish_size_prefixed(fcr, None);
                builder.finished_data().to_vec()
            }
            ReturnValue::Bool(b) => {
                let off = hlbool::create(&mut builder, &hlboolArgs { value: *b });
                let rv_box = ReturnValueBox::create(
                    &mut builder,
                    &ReturnValueBoxArgs {
                        value: Some(off.as_union_value()),
                        value_type: FbReturnValue::hlbool,
                    },
                );
                let fcr = FbFunctionCallResult::create(
                    &mut builder,
                    &FbFunctionCallResultArgs {
                        result: Some(rv_box.as_union_value()),
                        result_type: FunctionCallResultType::ReturnValueBox,
                    },
                );
                builder.finish_size_prefixed(fcr, None);
                builder.finished_data().to_vec()
            }
            ReturnValue::String(s) => {
                let off = {
                    let val = builder.create_string(s.as_str());
                    hlstring::create(&mut builder, &hlstringArgs { value: Some(val) })
                };
                let rv_box = ReturnValueBox::create(
                    &mut builder,
                    &ReturnValueBoxArgs {
                        value: Some(off.as_union_value()),
                        value_type: FbReturnValue::hlstring,
                    },
                );
                let fcr = FbFunctionCallResult::create(
                    &mut builder,
                    &FbFunctionCallResultArgs {
                        result: Some(rv_box.as_union_value()),
                        result_type: FunctionCallResultType::ReturnValueBox,
                    },
                );
                builder.finish_size_prefixed(fcr, None);
                builder.finished_data().to_vec()
            }
            ReturnValue::VecBytes(v) => {
                let off = {
                    let val = builder.create_vector(v.as_slice());
                    hlsizeprefixedbuffer::create(
                        &mut builder,
                        &hlsizeprefixedbufferArgs {
                            value: Some(val),
                            size: v.len() as i32,
                        },
                    )
                };
                let rv_box = ReturnValueBox::create(
                    &mut builder,
                    &ReturnValueBoxArgs {
                        value: Some(off.as_union_value()),
                        value_type: FbReturnValue::hlsizeprefixedbuffer,
                    },
                );
                let fcr = FbFunctionCallResult::create(
                    &mut builder,
                    &FbFunctionCallResultArgs {
                        result: Some(rv_box.as_union_value()),
                        result_type: FunctionCallResultType::ReturnValueBox,
                    },
                );
                builder.finish_size_prefixed(fcr, None);
                builder.finished_data().to_vec()
            }
            ReturnValue::ByteChunks(v) => {
                let off = {
                    let value = byte_chunks_to_bytes(v);
                    let val = builder.create_vector(value.as_ref());
                    hlsizeprefixedbytechunks::create(
                        &mut builder,
                        &hlsizeprefixedbytechunksArgs {
                            value: Some(val),
                            size: value.len() as i32,
                        },
                    )
                };
                let rv_box = ReturnValueBox::create(
                    &mut builder,
                    &ReturnValueBoxArgs {
                        value: Some(off.as_union_value()),
                        value_type: FbReturnValue::hlsizeprefixedbytechunks,
                    },
                );
                let fcr = FbFunctionCallResult::create(
                    &mut builder,
                    &FbFunctionCallResultArgs {
                        result: Some(rv_box.as_union_value()),
                        result_type: FunctionCallResultType::ReturnValueBox,
                    },
                );
                builder.finish_size_prefixed(fcr, None);
                builder.finished_data().to_vec()
            }
            ReturnValue::Void(()) => {
                let off = hlvoid::create(&mut builder, &hlvoidArgs {});
                let rv_box = ReturnValueBox::create(
                    &mut builder,
                    &ReturnValueBoxArgs {
                        value: Some(off.as_union_value()),
                        value_type: FbReturnValue::hlvoid,
                    },
                );
                let fcr = FbFunctionCallResult::create(
                    &mut builder,
                    &FbFunctionCallResultArgs {
                        result: Some(rv_box.as_union_value()),
                        result_type: FunctionCallResultType::ReturnValueBox,
                    },
                );
                builder.finish_size_prefixed(fcr, None);
                builder.finished_data().to_vec()
            }
        };

        Ok(result_bytes)
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::VecDeque;
    use alloc::vec;

    use flatbuffers::FlatBufferBuilder;

    use super::super::guest_error::ErrorCode;
    use super::super::util::{byte_chunks_to_vec, get_flatbuffer_result};
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
        let test_data = FunctionCallResult::new(Ok(ReturnValue::Int(42))).encode(&mut builder);

        let function_call_result = FunctionCallResult::try_from(test_data).unwrap();
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
        let test_data = FunctionCallResult::new(Err(test_error.clone())).encode(&mut builder);

        let function_call_result = FunctionCallResult::try_from(test_data).unwrap();
        let error = function_call_result.into_inner().unwrap_err();
        assert_eq!(error.code, test_error.code);
        assert_eq!(error.message, test_error.message);
    }

    #[test]
    fn embedded_byte_chunks_return_round_trips() {
        let mut builder = FlatBufferBuilder::new();
        let expected = vec![Bytes::from_static(b"hello"), Bytes::from_static(b" world")];
        let encoded =
            FunctionCallResult::new(Ok(ReturnValue::ByteChunks(expected))).encode(&mut builder);

        let decoded = FunctionCallResult::try_from(encoded)
            .unwrap()
            .into_inner()
            .unwrap();
        let ReturnValue::ByteChunks(decoded) = decoded else {
            panic!("expected byte chunks return value");
        };
        assert_eq!(byte_chunks_to_vec(&decoded), b"hello world");
    }

    #[test]
    fn direct_byte_chunks_return_encoding_preserves_logical_type() {
        let encoded = get_flatbuffer_result(vec![
            Bytes::from_static(b"hello"),
            Bytes::from_static(b" world"),
        ]);

        let decoded = FunctionCallResult::try_from(encoded.as_slice())
            .unwrap()
            .into_inner()
            .unwrap();
        assert!(matches!(decoded, ReturnValue::ByteChunks(_)));
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
    fn external_byte_returns_round_trip_without_embedding_payloads() {
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
                .encode_external(&mut builder, &mut external_values)
                .unwrap();

            assert!(encoded.len() < 4096);
            let encoded_result = size_prefixed_root::<FbFunctionCallResult>(encoded).unwrap();
            let return_value = encoded_result.result_as_return_value_box().unwrap();
            assert_eq!(return_value.value_type(), FbReturnValue::hlexternalbytes);
            let marker = return_value.value_as_hlexternalbytes().unwrap();
            let (length, chunked) = match &expected {
                ReturnValue::VecBytes(value) => (value.len(), false),
                ReturnValue::ByteChunks(value) => (try_byte_chunks_len(value).unwrap(), true),
                _ => unreachable!(),
            };
            assert_eq!(marker.length(), length as u64);
            assert_eq!(marker.chunked(), chunked);

            assert!(FunctionCallResult::try_from(encoded).is_err());
            let decoded = FunctionCallResult::decode_external(encoded, &mut external_values)
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
            .encode_external(&mut builder, &mut encoded_values)
            .unwrap();

        let mut missing = TestExternalValues::default();
        assert!(FunctionCallResult::decode_external(encoded, &mut missing).is_err());

        let mut wrong_type =
            TestExternalValues::from_values([TestExternalValue::VecBytes(vec![1, 2, 3])]);
        assert!(FunctionCallResult::decode_external(encoded, &mut wrong_type).is_err());

        let mut wrong_length =
            TestExternalValues::from_values([TestExternalValue::ByteChunks(vec![
                Bytes::from_static(b"12"),
            ])]);
        assert!(FunctionCallResult::decode_external(encoded, &mut wrong_length).is_err());
    }

    #[test]
    fn external_result_decoder_rejects_unused_values() {
        let result = FunctionCallResult::new(Ok(ReturnValue::Int(42)));
        let mut embedded_builder = FlatBufferBuilder::new();
        let embedded = result.encode(&mut embedded_builder).to_vec();

        let mut external_builder = FlatBufferBuilder::new();
        let mut external_values = TestExternalValues::default();
        let external = result
            .encode_external(&mut external_builder, &mut external_values)
            .unwrap();
        assert_eq!(external, embedded);
        assert!(external_values.values.is_empty());

        external_values
            .values
            .push_back(TestExternalValue::VecBytes(Vec::new()));
        assert!(FunctionCallResult::decode_external(external, &mut external_values).is_err());
    }
}
