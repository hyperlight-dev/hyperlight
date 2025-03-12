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

use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterType, ParameterValue};
use tracing::{Span, instrument};

use crate::HyperlightError::ParameterValueConversionFailure;
use crate::{Result, log_then_return};

/// This is a marker trait that is used to indicate that a type is a
/// valid Hyperlight parameter type.
///
/// For each parameter type Hyperlight supports in host functions, we
/// provide an implementation for `SupportedParameterType<SupportedType>`
pub trait SupportedParameterType<T> {
    /// Get the underlying Hyperlight parameter type representing this
    /// `SupportedParameterType`
    fn get_hyperlight_type() -> ParameterType;
    /// Get the underling Hyperlight parameter value representing this
    /// `SupportedParameterType`
    fn get_hyperlight_value(&self) -> ParameterValue;
    /// Get the actual inner value of this `SupportedParameterType`
    fn get_inner(a: ParameterValue) -> Result<T>;
}

// We can then implement these traits for each type that Hyperlight supports as a parameter or return type
impl SupportedParameterType<String> for String {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_hyperlight_type() -> ParameterType {
        ParameterType::String
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_hyperlight_value(&self) -> ParameterValue {
        ParameterValue::String(self.clone())
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn get_inner(a: ParameterValue) -> Result<String> {
        match a {
            ParameterValue::String(i) => Ok(i),
            other => {
                log_then_return!(ParameterValueConversionFailure(other.clone(), "String"));
            }
        }
    }
}

impl SupportedParameterType<i32> for i32 {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_hyperlight_type() -> ParameterType {
        ParameterType::Int
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_hyperlight_value(&self) -> ParameterValue {
        ParameterValue::Int(*self)
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn get_inner(a: ParameterValue) -> Result<i32> {
        match a {
            ParameterValue::Int(i) => Ok(i),
            other => {
                log_then_return!(ParameterValueConversionFailure(other.clone(), "i32"));
            }
        }
    }
}

impl SupportedParameterType<u32> for u32 {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_hyperlight_type() -> ParameterType {
        ParameterType::UInt
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_hyperlight_value(&self) -> ParameterValue {
        ParameterValue::UInt(*self)
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn get_inner(a: ParameterValue) -> Result<u32> {
        match a {
            ParameterValue::UInt(ui) => Ok(ui),
            other => {
                log_then_return!(ParameterValueConversionFailure(other.clone(), "u32"));
            }
        }
    }
}

impl SupportedParameterType<i64> for i64 {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_hyperlight_type() -> ParameterType {
        ParameterType::Long
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_hyperlight_value(&self) -> ParameterValue {
        ParameterValue::Long(*self)
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn get_inner(a: ParameterValue) -> Result<i64> {
        match a {
            ParameterValue::Long(l) => Ok(l),
            other => {
                log_then_return!(ParameterValueConversionFailure(other.clone(), "i64"));
            }
        }
    }
}

impl SupportedParameterType<u64> for u64 {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_hyperlight_type() -> ParameterType {
        ParameterType::ULong
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_hyperlight_value(&self) -> ParameterValue {
        ParameterValue::ULong(*self)
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn get_inner(a: ParameterValue) -> Result<u64> {
        match a {
            ParameterValue::ULong(ul) => Ok(ul),
            other => {
                log_then_return!(ParameterValueConversionFailure(other.clone(), "u64"));
            }
        }
    }
}

impl SupportedParameterType<bool> for bool {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_hyperlight_type() -> ParameterType {
        ParameterType::Bool
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_hyperlight_value(&self) -> ParameterValue {
        ParameterValue::Bool(*self)
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn get_inner(a: ParameterValue) -> Result<bool> {
        match a {
            ParameterValue::Bool(i) => Ok(i),
            other => {
                log_then_return!(ParameterValueConversionFailure(other.clone(), "bool"));
            }
        }
    }
}

impl SupportedParameterType<Vec<u8>> for Vec<u8> {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_hyperlight_type() -> ParameterType {
        ParameterType::VecBytes
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_hyperlight_value(&self) -> ParameterValue {
        ParameterValue::VecBytes(self.clone())
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn get_inner(a: ParameterValue) -> Result<Vec<u8>> {
        match a {
            ParameterValue::VecBytes(i) => Ok(i),
            other => {
                log_then_return!(ParameterValueConversionFailure(other.clone(), "Vec<u8>"));
            }
        }
    }
}
