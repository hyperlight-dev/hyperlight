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

use hyperlight_common::flatbuffer_wrappers::function_types::{ReturnType, ReturnValue};
use tracing::{instrument, Span};

use crate::HyperlightError::ReturnValueConversionFailure;
use crate::{log_then_return, Result};

/// This is a marker trait that is used to indicate that a type is a valid Hyperlight return type.
pub trait SupportedReturnType: Sized + Clone + Send + Sync + 'static {
    /// The return type of the supported return value
    const TYPE: ReturnType;

    /// Gets the value of the supported return value
    fn into_value(self) -> ReturnValue;

    /// Gets the inner value of the supported return type
    fn from_value(value: ReturnValue) -> Result<Self>;
}

/// A trait to handle either a SupportedReturnType or a Result<impl SupportedReturnType>
pub trait ResultType {
    /// The return type of the supported return value
    type ReturnType: SupportedReturnType;

    /// Convert the return type into a Result<impl SupportedReturnType>
    fn into_result(self) -> Result<Self::ReturnType>;
}

macro_rules! for_each_return_type {
    ($macro:ident) => {
        $macro!((), Void);
        $macro!(String, String);
        $macro!(i32, Int);
        $macro!(u32, UInt);
        $macro!(i64, Long);
        $macro!(u64, ULong);
        $macro!(bool, Bool);
        $macro!(Vec<u8>, VecBytes);
    };
}

macro_rules! impl_supported_return_type {
    ($type:ty, $enum:ident) => {
        impl SupportedReturnType for $type {
            const TYPE: ReturnType = ReturnType::$enum;

            #[instrument(skip_all, parent = Span::current(), level= "Trace")]
            fn into_value(self) -> ReturnValue {
                ReturnValue::$enum(self)
            }

            #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
            fn from_value(value: ReturnValue) -> Result<Self> {
                match value {
                    ReturnValue::$enum(i) => Ok(i),
                    other => {
                        log_then_return!(ReturnValueConversionFailure(
                            other.clone(),
                            stringify!($type)
                        ));
                    }
                }
            }
        }

        impl ResultType for $type {
            type ReturnType = $type;

            #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
            fn into_result(self) -> Result<Self::ReturnType> {
                Ok(self)
            }
        }

        impl ResultType for Result<$type> {
            type ReturnType = $type;

            #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
            fn into_result(self) -> Result<Self::ReturnType> {
                self
            }
        }
    };
}

for_each_return_type!(impl_supported_return_type);
