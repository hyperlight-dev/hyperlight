// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use alloc::string::String;
use alloc::vec::Vec;

use super::error::Error;
use crate::flatbuffer_wrappers::function_types::{ReturnType, ReturnValue};

/// This is a marker trait that is used to indicate that a type is a valid Hyperlight return type.
pub trait SupportedReturnType: Sized + Clone + Send + Sync + 'static {
    /// The return type of the supported return value
    const TYPE: ReturnType;

    /// Gets the value of the supported return value
    fn into_value(self) -> ReturnValue;

    /// Gets the inner value of the supported return type
    fn from_value(value: ReturnValue) -> Result<Self, Error>;
}

#[macro_export]
#[doc(hidden)]
macro_rules! for_each_return_type {
    ($macro:ident) => {
        $macro!((), Void);
        $macro!(String, String);
        $macro!(i32, Int);
        $macro!(u32, UInt);
        $macro!(i64, Long);
        $macro!(u64, ULong);
        $macro!(f32, Float);
        $macro!(f64, Double);
        $macro!(bool, Bool);
        $macro!(Vec<u8>, VecBytes);
    };
}

macro_rules! impl_supported_return_type {
    ($type:ty, $enum:ident) => {
        impl SupportedReturnType for $type {
            const TYPE: ReturnType = ReturnType::$enum;

            fn into_value(self) -> ReturnValue {
                ReturnValue::$enum(self)
            }

            fn from_value(value: ReturnValue) -> Result<Self, Error> {
                match value {
                    ReturnValue::$enum(i) => Ok(i),
                    other => Err(Error::ReturnValueConversionFailure(
                        other.clone(),
                        stringify!($type),
                    )),
                }
            }
        }
    };
}

/// A trait to handle either a [`SupportedReturnType`] or a [`Result<impl SupportedReturnType>`]
pub trait ResultType<E: core::fmt::Debug> {
    /// The return type of the supported return value
    type ReturnType: SupportedReturnType;

    /// Convert the return type into a `Result<impl SupportedReturnType>`
    fn into_result(self) -> Result<Self::ReturnType, E>;
}

impl<T, E> ResultType<E> for T
where
    T: SupportedReturnType,
    E: core::fmt::Debug,
{
    type ReturnType = T;

    fn into_result(self) -> Result<Self::ReturnType, E> {
        Ok(self)
    }
}

impl<T, E> ResultType<E> for Result<T, E>
where
    T: SupportedReturnType,
    E: core::fmt::Debug,
{
    type ReturnType = T;

    fn into_result(self) -> Result<Self::ReturnType, E> {
        self
    }
}

for_each_return_type!(impl_supported_return_type);
