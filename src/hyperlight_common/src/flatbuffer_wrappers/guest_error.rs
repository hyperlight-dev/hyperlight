/*
Copyright 2024 The Hyperlight Authors.

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

extern crate flatbuffers;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use anyhow::{Error, Result};
use flatbuffers::size_prefixed_root;
#[cfg(feature = "tracing")]
use tracing::{instrument, Span};

use crate::flatbuffers::hyperlight::generated::{
    ErrorCode as FbErrorCode, GuestError as FbGuestError, GuestErrorArgs,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(C)]
/// `ErrorCode` represents an error that occurred in the Hyperlight Guest.
pub enum ErrorCode {
    NoError = 0,
    UnsupportedParameterType = 2,
    GuestFunctionNameNotProvided = 3,
    GuestFunctionNotFound = 4,
    GuestFunctionIncorrecNoOfParameters = 5,
    GispatchFunctionPointerNotSet = 6,
    OutbError = 7,
    UnknownError = 8,
    StackOverflow = 9,
    GsCheckFailed = 10,
    TooManyGuestFunctions = 11,
    FailureInDlmalloc = 12,
    MallocFailed = 13,
    GuestFunctionParameterTypeMismatch = 14,
    GuestError = 15,
    ArrayLengthParamIsMissing = 16,
}

impl From<ErrorCode> for FbErrorCode {
    fn from(error_code: ErrorCode) -> Self {
        match error_code {
            ErrorCode::NoError => Self::NoError,
            ErrorCode::UnsupportedParameterType => Self::UnsupportedParameterType,
            ErrorCode::GuestFunctionNameNotProvided => Self::GuestFunctionNameNotProvided,
            ErrorCode::GuestFunctionNotFound => Self::GuestFunctionNotFound,
            ErrorCode::GuestFunctionIncorrecNoOfParameters => {
                Self::GuestFunctionIncorrecNoOfParameters
            }
            ErrorCode::GispatchFunctionPointerNotSet => Self::GispatchFunctionPointerNotSet,
            ErrorCode::OutbError => Self::OutbError,
            ErrorCode::UnknownError => Self::UnknownError,
            ErrorCode::StackOverflow => Self::StackOverflow,
            ErrorCode::GsCheckFailed => Self::GsCheckFailed,
            ErrorCode::TooManyGuestFunctions => Self::TooManyGuestFunctions,
            ErrorCode::FailureInDlmalloc => Self::FailureInDlmalloc,
            ErrorCode::MallocFailed => Self::MallocFailed,
            ErrorCode::GuestFunctionParameterTypeMismatch => {
                Self::GuestFunctionParameterTypeMismatch
            }
            ErrorCode::GuestError => Self::GuestError,
            ErrorCode::ArrayLengthParamIsMissing => Self::ArrayLengthParamIsMissing,
        }
    }
}

impl From<FbErrorCode> for ErrorCode {
    fn from(error_code: FbErrorCode) -> Self {
        match error_code {
            FbErrorCode::NoError => Self::NoError,
            FbErrorCode::UnsupportedParameterType => Self::UnsupportedParameterType,
            FbErrorCode::GuestFunctionNameNotProvided => Self::GuestFunctionNameNotProvided,
            FbErrorCode::GuestFunctionNotFound => Self::GuestFunctionNotFound,
            FbErrorCode::GuestFunctionIncorrecNoOfParameters => {
                Self::GuestFunctionIncorrecNoOfParameters
            }
            FbErrorCode::GispatchFunctionPointerNotSet => Self::GispatchFunctionPointerNotSet,
            FbErrorCode::OutbError => Self::OutbError,
            FbErrorCode::StackOverflow => Self::StackOverflow,
            FbErrorCode::GsCheckFailed => Self::GsCheckFailed,
            FbErrorCode::TooManyGuestFunctions => Self::TooManyGuestFunctions,
            FbErrorCode::FailureInDlmalloc => Self::FailureInDlmalloc,
            FbErrorCode::MallocFailed => Self::MallocFailed,
            FbErrorCode::GuestFunctionParameterTypeMismatch => {
                Self::GuestFunctionParameterTypeMismatch
            }
            FbErrorCode::GuestError => Self::GuestError,
            FbErrorCode::ArrayLengthParamIsMissing => Self::ArrayLengthParamIsMissing,
            _ => Self::UnknownError,
        }
    }
}

impl From<u64> for ErrorCode {
    fn from(error_code: u64) -> Self {
        match error_code {
            0 => Self::NoError,
            2 => Self::UnsupportedParameterType,
            3 => Self::GuestFunctionNameNotProvided,
            4 => Self::GuestFunctionNotFound,
            5 => Self::GuestFunctionIncorrecNoOfParameters,
            6 => Self::GispatchFunctionPointerNotSet,
            7 => Self::OutbError,
            8 => Self::UnknownError,
            9 => Self::StackOverflow,
            10 => Self::GsCheckFailed,
            11 => Self::TooManyGuestFunctions,
            12 => Self::FailureInDlmalloc,
            13 => Self::MallocFailed,
            14 => Self::GuestFunctionParameterTypeMismatch,
            15 => Self::GuestError,
            16 => Self::ArrayLengthParamIsMissing,
            _ => Self::UnknownError,
        }
    }
}

impl From<ErrorCode> for u64 {
    fn from(error_code: ErrorCode) -> Self {
        match error_code {
            ErrorCode::NoError => 0,
            ErrorCode::UnsupportedParameterType => 2,
            ErrorCode::GuestFunctionNameNotProvided => 3,
            ErrorCode::GuestFunctionNotFound => 4,
            ErrorCode::GuestFunctionIncorrecNoOfParameters => 5,
            ErrorCode::GispatchFunctionPointerNotSet => 6,
            ErrorCode::OutbError => 7,
            ErrorCode::UnknownError => 8,
            ErrorCode::StackOverflow => 9,
            ErrorCode::GsCheckFailed => 10,
            ErrorCode::TooManyGuestFunctions => 11,
            ErrorCode::FailureInDlmalloc => 12,
            ErrorCode::MallocFailed => 13,
            ErrorCode::GuestFunctionParameterTypeMismatch => 14,
            ErrorCode::GuestError => 15,
            ErrorCode::ArrayLengthParamIsMissing => 16,
        }
    }
}

impl From<ErrorCode> for String {
    fn from(error_code: ErrorCode) -> Self {
        match error_code {
            ErrorCode::NoError => "NoError".to_string(),
            ErrorCode::UnsupportedParameterType => "UnsupportedParameterType".to_string(),
            ErrorCode::GuestFunctionNameNotProvided => "GuestFunctionNameNotProvided".to_string(),
            ErrorCode::GuestFunctionNotFound => "GuestFunctionNotFound".to_string(),
            ErrorCode::GuestFunctionIncorrecNoOfParameters => {
                "GuestFunctionIncorrecNoOfParameters".to_string()
            }
            ErrorCode::GispatchFunctionPointerNotSet => "GispatchFunctionPointerNotSet".to_string(),
            ErrorCode::OutbError => "OutbError".to_string(),
            ErrorCode::UnknownError => "UnknownError".to_string(),
            ErrorCode::StackOverflow => "StackOverflow".to_string(),
            ErrorCode::GsCheckFailed => "GsCheckFailed".to_string(),
            ErrorCode::TooManyGuestFunctions => "TooManyGuestFunctions".to_string(),
            ErrorCode::FailureInDlmalloc => "FailureInDlmalloc".to_string(),
            ErrorCode::MallocFailed => "MallocFailed".to_string(),
            ErrorCode::GuestFunctionParameterTypeMismatch => {
                "GuestFunctionParameterTypeMismatch".to_string()
            }
            ErrorCode::GuestError => "GuestError".to_string(),
            ErrorCode::ArrayLengthParamIsMissing => "ArrayLengthParamIsMissing".to_string(),
        }
    }
}

/// `GuestError` represents an error that occurred in the Hyperlight Guest.
#[derive(Debug, Clone)]
pub struct GuestError {
    /// The error code.
    pub code: ErrorCode,
    /// The error message.
    pub message: String,
}

impl GuestError {
    #[cfg_attr(feature = "tracing", instrument(skip_all, parent = Span::current(), level= "Trace"))]
    pub fn new(code: ErrorCode, message: String) -> Self {
        Self { code, message }
    }
}

impl TryFrom<&[u8]> for GuestError {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: &[u8]) -> Result<Self> {
        let guest_error_fb = size_prefixed_root::<FbGuestError>(value)
            .map_err(|e| anyhow::anyhow!("Error while reading GuestError: {:?}", e))?;
        let code = guest_error_fb.code();
        let message = match guest_error_fb.message() {
            Some(message) => message.to_string(),
            None => String::new(),
        };
        Ok(Self {
            code: code.into(),
            message,
        })
    }
}

impl TryFrom<&GuestError> for Vec<u8> {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: &GuestError) -> Result<Vec<u8>> {
        let mut builder = flatbuffers::FlatBufferBuilder::new();
        let message = builder.create_string(&value.message);

        let guest_error_fb = FbGuestError::create(
            &mut builder,
            &GuestErrorArgs {
                code: value.code.into(),
                message: Some(message),
            },
        );
        builder.finish_size_prefixed(guest_error_fb, None);
        let res = builder.finished_data().to_vec();

        Ok(res)
    }
}

impl Default for GuestError {
    #[cfg_attr(feature = "tracing", instrument(parent = Span::current(), level= "Trace"))]
    fn default() -> Self {
        Self {
            code: ErrorCode::NoError,
            message: String::new(),
        }
    }
}
