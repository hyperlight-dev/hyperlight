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

use alloc::string::String;
use alloc::vec::Vec;

use anyhow::{Error, Result, bail};
use serde::{Deserialize, Serialize};
#[cfg(feature = "tracing")]
use tracing::{Span, instrument};

use super::guest_error::GuestError;

#[derive(Serialize, Deserialize)]
pub struct FunctionCallResult(core::result::Result<ReturnValue, GuestError>);

impl FunctionCallResult {
    pub fn new(value: core::result::Result<ReturnValue, GuestError>) -> Self {
        FunctionCallResult(value)
    }

    pub fn into_inner(self) -> core::result::Result<ReturnValue, GuestError> {
        self.0
    }
}

/// Supported parameter types with values for function calling.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
}

/// Supported return types with values from function calling.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

impl From<()> for ReturnValue {
    #[cfg_attr(feature = "tracing", instrument(skip_all, parent = Span::current(), level= "Trace"))]
    fn from(_: ()) -> Self {
        ReturnValue::Void(())
    }
}
impl From<i32> for ReturnValue {
    #[cfg_attr(feature = "tracing", instrument(skip_all, parent = Span::current(), level= "Trace"))]
    fn from(val: i32) -> Self {
        ReturnValue::Int(val)
    }
}
impl From<u32> for ReturnValue {
    #[cfg_attr(feature = "tracing", instrument(skip_all, parent = Span::current(), level= "Trace"))]
    fn from(val: u32) -> Self {
        ReturnValue::UInt(val)
    }
}
impl From<i64> for ReturnValue {
    #[cfg_attr(feature = "tracing", instrument(skip_all, parent = Span::current(), level= "Trace"))]
    fn from(val: i64) -> Self {
        ReturnValue::Long(val)
    }
}
impl From<u64> for ReturnValue {
    #[cfg_attr(feature = "tracing", instrument(skip_all, parent = Span::current(), level= "Trace"))]
    fn from(val: u64) -> Self {
        ReturnValue::ULong(val)
    }
}
impl From<f32> for ReturnValue {
    #[cfg_attr(feature = "tracing", instrument(skip_all, parent = Span::current(), level= "Trace"))]
    fn from(val: f32) -> Self {
        ReturnValue::Float(val)
    }
}
impl From<f64> for ReturnValue {
    #[cfg_attr(feature = "tracing", instrument(skip_all, parent = Span::current(), level= "Trace"))]
    fn from(val: f64) -> Self {
        ReturnValue::Double(val)
    }
}
impl From<String> for ReturnValue {
    #[cfg_attr(feature = "tracing", instrument(skip_all, parent = Span::current(), level= "Trace"))]
    fn from(val: String) -> Self {
        ReturnValue::String(val)
    }
}
impl From<bool> for ReturnValue {
    #[cfg_attr(feature = "tracing", instrument(skip_all, parent = Span::current(), level= "Trace"))]
    fn from(val: bool) -> Self {
        ReturnValue::Bool(val)
    }
}
impl From<Vec<u8>> for ReturnValue {
    #[cfg_attr(feature = "tracing", instrument(skip_all, parent = Span::current(), level= "Trace"))]
    fn from(val: Vec<u8>) -> Self {
        ReturnValue::VecBytes(val)
    }
}
impl From<&[u8]> for ReturnValue {
    #[cfg_attr(feature = "tracing", instrument(skip_all, parent = Span::current(), level= "Trace"))]
    fn from(val: &[u8]) -> Self {
        ReturnValue::VecBytes(val.to_vec())
    }
}
impl From<&str> for ReturnValue {
    #[cfg_attr(feature = "tracing", instrument(skip_all, parent = Span::current(), level= "Trace"))]
    fn from(val: &str) -> Self {
        ReturnValue::String(val.into())
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::super::guest_error::ErrorCode;
    use super::*;
    use crate::flatbuffer_wrappers::util::{decode, encode};

    #[test]
    fn encode_success_result() {
        let test_data = encode(&FunctionCallResult::new(Ok(ReturnValue::Int(42)))).unwrap();
        let function_call_result: FunctionCallResult = decode(&test_data).unwrap();
        let result = function_call_result.into_inner().unwrap();
        assert_eq!(result, ReturnValue::Int(42));
    }

    #[test]
    fn encode_error_result() {
        let test_error = GuestError::new(
            ErrorCode::GuestFunctionNotFound,
            "Function not found".to_string(),
        );
        let test_data = encode(&FunctionCallResult::new(Err(test_error.clone()))).unwrap();
        let function_call_result: FunctionCallResult = decode(&test_data).unwrap();
        let error = function_call_result.into_inner().unwrap_err();
        assert_eq!(error.code, test_error.code);
        assert_eq!(error.message, test_error.message);
    }
}
