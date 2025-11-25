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
use flatbuffers::size_prefixed_root;
use tracing::{Span, instrument};

use super::guest_error::GuestError;
use crate::flatbuffers::hyperlight::generated::{
    FunctionCallResult as FbFunctionCallResult, FunctionCallResultArgs as FbFunctionCallResultArgs,
    FunctionCallResultType, Parameter, ParameterType as FbParameterType,
    ParameterValue as FbParameterValue, ReturnType as FbReturnType, ReturnValue as FbReturnValue,
    ReturnValueBox, ReturnValueBoxArgs, hlbool, hlboolArgs, hldouble, hldoubleArgs, hlfloat,
    hlfloatArgs, hlint, hlintArgs, hllong, hllongArgs, hlsizeprefixedbuffer,
    hlsizeprefixedbufferArgs, hlstring, hlstringArgs, hluint, hluintArgs, hlulong, hlulongArgs,
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
    pub fn new(value: core::result::Result<ReturnValue, GuestError>) -> Self {
        FunctionCallResult(value)
    }

    pub fn into_inner(self) -> core::result::Result<ReturnValue, GuestError> {
        self.0
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
}

impl From<&ParameterValue> for ParameterType {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
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
        }
    }
}

impl TryFrom<Parameter<'_>> for ParameterValue {
    type Error = Error;

    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
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
            other => {
                bail!("Unexpected flatbuffer parameter value type: {:?}", other);
            }
        };
        result.ok_or_else(|| anyhow!("Failed to get parameter value"))
    }
}

impl From<ParameterType> for FbParameterType {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
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
        }
    }
}

impl From<ReturnType> for FbReturnType {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
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
        }
    }
}

impl TryFrom<FbParameterType> for ParameterType {
    type Error = Error;
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
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
            _ => {
                bail!("Unexpected flatbuffer parameter type: {:?}", value)
            }
        }
    }
}

impl TryFrom<FbReturnType> for ReturnType {
    type Error = Error;
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
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
            _ => {
                bail!("Unexpected flatbuffer return type: {:?}", value)
            }
        }
    }
}

impl TryFrom<ParameterValue> for i32 {
    type Error = Error;
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
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
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
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
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
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
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
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
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
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
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
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
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
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
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
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
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn try_from(value: ParameterValue) -> Result<Self> {
        match value {
            ParameterValue::VecBytes(v) => Ok(v),
            _ => {
                bail!("Unexpected parameter value type: {:?}", value)
            }
        }
    }
}

impl TryFrom<ReturnValue> for i32 {
    type Error = Error;
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
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
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
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
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
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
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
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
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
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
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
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
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
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
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
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
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn try_from(value: ReturnValue) -> Result<Self> {
        match value {
            ReturnValue::VecBytes(v) => Ok(v),
            _ => {
                bail!("Unexpected return value type: {:?}", value)
            }
        }
    }
}

impl TryFrom<ReturnValue> for () {
    type Error = Error;
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
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
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
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
            other => {
                bail!("Unexpected flatbuffer return value type: {:?}", other)
            }
        }
    }
}

impl TryFrom<&ReturnValue> for Vec<u8> {
    type Error = Error;
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
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
    use flatbuffers::FlatBufferBuilder;

    use super::super::guest_error::ErrorCode;
    use super::*;

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
}
