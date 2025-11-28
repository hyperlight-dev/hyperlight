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

use alloc::format;
use alloc::string::String;

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use {anyhow, serde_json};

pub type Result<T> = core::result::Result<T, HyperlightGuestError>;

#[derive(Debug)]
pub struct HyperlightGuestError {
    pub kind: ErrorCode,
    pub message: String,
}

impl HyperlightGuestError {
    pub fn new(kind: ErrorCode, message: String) -> Self {
        Self { kind, message }
    }
}

impl From<anyhow::Error> for HyperlightGuestError {
    fn from(error: anyhow::Error) -> Self {
        Self {
            kind: ErrorCode::GuestError,
            message: format!("Error: {:?}", error),
        }
    }
}

impl From<serde_json::Error> for HyperlightGuestError {
    fn from(error: serde_json::Error) -> Self {
        Self {
            kind: ErrorCode::GuestError,
            message: format!("Error: {:?}", error),
        }
    }
}

pub trait GuestErrorContext {
    type Ok;
    fn context(self, ctx: impl Into<String>) -> Result<Self::Ok>;
    fn context_and_code(self, ec: ErrorCode, ctx: impl Into<String>) -> Result<Self::Ok>;
    fn with_context<S: Into<String>>(self, ctx: impl FnOnce() -> S) -> Result<Self::Ok>;
    fn with_context_and_code<S: Into<String>>(
        self,
        ec: ErrorCode,
        ctx: impl FnOnce() -> S,
    ) -> Result<Self::Ok>;
}

impl<T> GuestErrorContext for Option<T> {
    type Ok = T;
    #[inline]
    fn context(self, ctx: impl Into<String>) -> Result<T> {
        self.with_context_and_code(ErrorCode::GuestError, || ctx)
    }
    #[inline]
    fn context_and_code(self, ec: ErrorCode, ctx: impl Into<String>) -> Result<T> {
        self.with_context_and_code(ec, || ctx)
    }
    #[inline]
    fn with_context<S: Into<String>>(self, ctx: impl FnOnce() -> S) -> Result<T> {
        self.with_context_and_code(ErrorCode::GuestError, ctx)
    }
    #[inline]
    fn with_context_and_code<S: Into<String>>(
        self,
        ec: ErrorCode,
        ctx: impl FnOnce() -> S,
    ) -> Result<Self::Ok> {
        match self {
            Some(s) => Ok(s),
            None => Err(HyperlightGuestError::new(ec, ctx().into())),
        }
    }
}

impl<T, E: core::fmt::Debug> GuestErrorContext for core::result::Result<T, E> {
    type Ok = T;
    #[inline]
    fn context(self, ctx: impl Into<String>) -> Result<T> {
        self.with_context_and_code(ErrorCode::GuestError, || ctx)
    }
    #[inline]
    fn context_and_code(self, ec: ErrorCode, ctx: impl Into<String>) -> Result<T> {
        self.with_context_and_code(ec, || ctx)
    }
    #[inline]
    fn with_context<S: Into<String>>(self, ctx: impl FnOnce() -> S) -> Result<T> {
        self.with_context_and_code(ErrorCode::GuestError, ctx)
    }
    #[inline]
    fn with_context_and_code<S: Into<String>>(
        self,
        ec: ErrorCode,
        ctx: impl FnOnce() -> S,
    ) -> Result<T> {
        match self {
            Ok(s) => Ok(s),
            Err(e) => Err(HyperlightGuestError::new(
                ec,
                format!("{}.\nCaused by: {e:?}", ctx().into()),
            )),
        }
    }
}
