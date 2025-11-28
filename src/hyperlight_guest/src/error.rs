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

/// Extension trait to add context to `Option<T>` and `Result<T, E>` types in guest code,
/// converting them to `Result<T, HyperlightGuestError>`.
///
/// This is similar to anyhow::Context.
pub trait GuestErrorContext {
    type Ok;
    /// Adds context to the error if `self` is `None` or `Err`.
    fn context(self, ctx: impl Into<String>) -> Result<Self::Ok>;
    /// Adds context and a specific error code to the error if `self` is `None` or `Err`.
    fn context_and_code(self, ec: ErrorCode, ctx: impl Into<String>) -> Result<Self::Ok>;
    /// Lazily adds context to the error if `self` is `None` or `Err`.
    ///
    /// This is useful if constructing the context message is expensive.
    fn with_context<S: Into<String>>(self, ctx: impl FnOnce() -> S) -> Result<Self::Ok>;
    /// Lazily adds context and a specific error code to the error if `self` is `None` or `Err`.
    ///
    /// This is useful if constructing the context message is expensive.
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

/// Macro to return early with a `Err(HyperlightGuestError)`.
/// Usage:
/// ```ignore
/// bail!(ErrorCode::UnknownError => "An error occurred: {}", details);
/// // or
/// bail!("A guest error occurred: {}", details); // defaults to ErrorCode::GuestError
/// ```
#[macro_export]
macro_rules! bail {
    ($ec:expr => $($msg:tt)*) => {
        return ::core::result::Result::Err($crate::error::HyperlightGuestError::new($ec, ::alloc::format!($($msg)*)));
    };
    ($($msg:tt)*) => {
        $crate::bail!($crate::error::ErrorCode::GuestError => $($msg)*);
    };
}

/// Macro to ensure a condition is true, otherwise returns early with a `Err(HyperlightGuestError)`.
/// Usage:
/// ```ignore
/// ensure!(1 + 1 == 3, ErrorCode::UnknownError => "Maths is broken: {}", details);
/// // or
/// ensure!(1 + 1 == 3, "Maths is broken: {}", details); // defaults to ErrorCode::GuestError
/// // or
/// ensure!(1 + 1 == 3); // defaults to ErrorCode::GuestError with a default message
/// ```
#[macro_export]
macro_rules! ensure {
    ($cond:expr) => {
        if !($cond) {
            $crate::bail!(::core::concat!("Condition failed: `", ::core::stringify!($cond), "`"));
        }
    };
    ($cond:expr, $ec:expr => $($msg:tt)*) => {
        if !($cond) {
            $crate::bail!($ec => ::core::concat!("{}\nCaused by failed condition: `", ::core::stringify!($cond), "`"), ::core::format_args!($($msg)*));
        }
    };
    ($cond:expr, $($msg:tt)*) => {
        $crate::ensure!($cond, $crate::error::ErrorCode::GuestError => $($msg)*);
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_option_some() {
        let value: Option<u32> = Some(42);
        let result = value.context("Should be Some");
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_context_option_none() {
        let value: Option<u32> = None;
        let result = value.context("Should be Some");
        let err = result.unwrap_err();
        assert_eq!(err.kind, ErrorCode::GuestError);
        assert_eq!(err.message, "Should be Some");
    }

    #[test]
    fn test_context_and_code_option_none() {
        let value: Option<u32> = None;
        let result = value.context_and_code(ErrorCode::MallocFailed, "Should be Some");
        let err = result.unwrap_err();
        assert_eq!(err.kind, ErrorCode::MallocFailed);
        assert_eq!(err.message, "Should be Some");
    }

    #[test]
    fn test_with_context_option_none() {
        let value: Option<u32> = None;
        let result = value.with_context(|| "Lazy context message");
        let err = result.unwrap_err();
        assert_eq!(err.kind, ErrorCode::GuestError);
        assert_eq!(err.message, "Lazy context message");
    }

    #[test]
    fn test_with_context_and_code_option_none() {
        let value: Option<u32> = None;
        let result =
            value.with_context_and_code(ErrorCode::MallocFailed, || "Lazy context message");
        let err = result.unwrap_err();
        assert_eq!(err.kind, ErrorCode::MallocFailed);
        assert_eq!(err.message, "Lazy context message");
    }

    #[test]
    fn test_context_result_ok() {
        let value: core::result::Result<u32, &str> = Ok(42);
        let result = value.context("Should be Ok");
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_context_result_err() {
        let value: core::result::Result<u32, &str> = Err("Some error");
        let result = value.context("Should be Ok");
        let err = result.unwrap_err();
        assert_eq!(err.kind, ErrorCode::GuestError);
        assert_eq!(err.message, "Should be Ok.\nCaused by: \"Some error\"");
    }

    #[test]
    fn test_context_and_code_result_err() {
        let value: core::result::Result<u32, &str> = Err("Some error");
        let result = value.context_and_code(ErrorCode::MallocFailed, "Should be Ok");
        let err = result.unwrap_err();
        assert_eq!(err.kind, ErrorCode::MallocFailed);
        assert_eq!(err.message, "Should be Ok.\nCaused by: \"Some error\"");
    }

    #[test]
    fn test_with_context_result_err() {
        let value: core::result::Result<u32, &str> = Err("Some error");
        let result = value.with_context(|| "Lazy context message");
        let err = result.unwrap_err();
        assert_eq!(err.kind, ErrorCode::GuestError);
        assert_eq!(
            err.message,
            "Lazy context message.\nCaused by: \"Some error\""
        );
    }

    #[test]
    fn test_with_context_and_code_result_err() {
        let value: core::result::Result<u32, &str> = Err("Some error");
        let result =
            value.with_context_and_code(ErrorCode::MallocFailed, || "Lazy context message");
        let err = result.unwrap_err();
        assert_eq!(err.kind, ErrorCode::MallocFailed);
        assert_eq!(
            err.message,
            "Lazy context message.\nCaused by: \"Some error\""
        );
    }

    #[test]
    fn test_bail_macro() {
        let result: Result<u32> = (|| {
            bail!("A guest error occurred");
        })();
        let err = result.unwrap_err();
        assert_eq!(err.kind, ErrorCode::GuestError);
        assert_eq!(err.message, "A guest error occurred");
    }

    #[test]
    fn test_bail_macro_with_error_code() {
        let result: Result<u32> = (|| {
            bail!(ErrorCode::MallocFailed => "Memory allocation failed");
        })();
        let err = result.unwrap_err();
        assert_eq!(err.kind, ErrorCode::MallocFailed);
        assert_eq!(err.message, "Memory allocation failed");
    }

    #[test]
    fn test_ensure_macro_pass() {
        let result: Result<u32> = (|| {
            ensure!(1 + 1 == 2, "Math works");
            Ok(42)
        })();
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_ensure_macro_fail() {
        let result: Result<u32> = (|| {
            ensure!(1 + 1 == 3, "Math is broken");
            Ok(42)
        })();
        let err = result.unwrap_err();
        assert_eq!(err.kind, ErrorCode::GuestError);
        assert_eq!(
            err.message,
            "Math is broken\nCaused by failed condition: `1 + 1 == 3`"
        );
    }

    #[test]
    fn test_ensure_macro_fail_no_message() {
        let result: Result<u32> = (|| {
            ensure!(1 + 1 == 3);
            Ok(42)
        })();
        let err = result.unwrap_err();
        assert_eq!(err.kind, ErrorCode::GuestError);
        assert_eq!(err.message, "Condition failed: `1 + 1 == 3`");
    }

    #[test]
    fn test_ensure_macro_fail_with_error_code() {
        let result: Result<u32> = (|| {
            ensure!(1 + 1 == 3, ErrorCode::UnknownError => "Math is broken");
            Ok(42)
        })();
        let err = result.unwrap_err();
        assert_eq!(err.kind, ErrorCode::UnknownError);
        assert_eq!(
            err.message,
            "Math is broken\nCaused by failed condition: `1 + 1 == 3`"
        );
    }
}
