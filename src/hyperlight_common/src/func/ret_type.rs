// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use alloc::string::String;
use alloc::vec::Vec;

use super::error::Error;
use crate::flatbuffer_wrappers::function_types::{ReturnType, ReturnValue};

/// This is a marker trait that is used to indicate that a type is a valid Hyperlight return type.
///
/// `Vec<u8>` and `Vec<Bytes>` both represent one logical byte sequence.
/// `Vec<u8>` stores it contiguously. `Vec<Bytes>` represents it as chunks and
/// may avoid flattening them into one allocation. Chunk boundaries are a
/// storage detail and may change during transport. They do not delimit messages
/// or values.
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
        $macro!(Vec<$crate::func::Bytes>, ByteChunks);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flatbuffer_wrappers::function_types::Bytes;

    #[test]
    fn byte_chunks_return_round_trips_without_copying() {
        let chunks = vec![Bytes::from_static(b"hello"), Bytes::from_static(b" world")];
        let first_chunk = chunks[0].as_ptr();
        let value = <Vec<Bytes> as SupportedReturnType>::into_value(chunks);
        let chunks = <Vec<Bytes> as SupportedReturnType>::from_value(value).unwrap();

        assert_eq!(chunks[0].as_ptr(), first_chunk);
        assert_eq!(
            chunks,
            [Bytes::from_static(b"hello"), Bytes::from_static(b" world")]
        );
    }
}
