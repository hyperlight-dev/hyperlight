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
use tracing::{instrument, Span};

use crate::HyperlightError::ParameterValueConversionFailure;
use crate::{log_then_return, Result};

/// This is a marker trait that is used to indicate that a type is a
/// valid Hyperlight parameter type.
///
/// For each parameter type Hyperlight supports in host functions, we
/// provide an implementation for `SupportedParameterType`
pub trait SupportedParameterType: Sized {
    /// The underlying Hyperlight parameter type representing this `SupportedParameterType`
    const TYPE: ParameterType;

    /// Get the underling Hyperlight parameter value representing this
    /// `SupportedParameterType`
    fn into_value(self) -> ParameterValue;
    /// Get the actual inner value of this `SupportedParameterType`
    fn from_value(value: ParameterValue) -> Result<Self>;
}

// We can then implement these traits for each type that Hyperlight supports as a parameter or return type
macro_rules! for_each_param_type {
    ($macro:ident) => {
        $macro!(String, String);
        $macro!(i32, Int);
        $macro!(u32, UInt);
        $macro!(i64, Long);
        $macro!(u64, ULong);
        $macro!(bool, Bool);
        $macro!(Vec<u8>, VecBytes);
    };
}

macro_rules! impl_supported_param_type {
    ($type:ty, $enum:ident) => {
        impl SupportedParameterType for $type {
            const TYPE: ParameterType = ParameterType::$enum;

            #[instrument(skip_all, parent = Span::current(), level= "Trace")]
            fn into_value(self) -> ParameterValue {
                ParameterValue::$enum(self)
            }

            #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
            fn from_value(value: ParameterValue) -> Result<Self> {
                match value {
                    ParameterValue::$enum(i) => Ok(i),
                    other => {
                        log_then_return!(ParameterValueConversionFailure(
                            other.clone(),
                            stringify!($type)
                        ));
                    }
                }
            }
        }
    };
}

for_each_param_type!(impl_supported_param_type);
