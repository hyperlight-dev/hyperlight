// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::error::Error;
use super::utils::for_each_tuple;
use crate::flatbuffer_wrappers::function_types::{ReturnType, ReturnValue};
use crate::future::{FutureReader, FutureValue};

/// This is a marker trait that is used to indicate that a type is a valid Hyperlight return type.
///
/// `Vec<u8>` and `Vec<Bytes>` both represent one logical byte sequence.
/// `Vec<u8>` stores it contiguously. `Vec<Bytes>` represents it as chunks and
/// may avoid flattening them into one allocation. Chunk boundaries are a
/// storage detail and may change during transport. They do not delimit messages
/// or values.
pub trait SupportedReturnType: Sized + Send + Sync + 'static {
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
        $macro!($crate::stream::StreamReader<u8>, StreamReader);
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
                        other,
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

/// A future crosses as the reader of the stream that carries its value.
impl<T: FutureValue + 'static> SupportedReturnType for FutureReader<T> {
    const TYPE: ReturnType = ReturnType::StreamReader;

    fn into_value(self) -> ReturnValue {
        ReturnValue::StreamReader(self.into_stream())
    }

    fn from_value(value: ReturnValue) -> Result<Self, Error> {
        match value {
            ReturnValue::StreamReader(reader) => Ok(Self::from_stream(reader)),
            other => Err(Error::ReturnValueConversionFailure(other, "FutureReader")),
        }
    }
}

mod sealed {
    /// Restricts [`TupleElement`](super::TupleElement) to the types this crate lists.
    pub trait Sealed {}
}

/// An element of a returned tuple.
///
/// A tuple of 2 to 32 elements is a [`SupportedReturnType`], and its elements return in order,
/// as call parameters do. Every built-in return type except `()` and tuples is an element.
pub trait TupleElement: SupportedReturnType + sealed::Sealed {}

/// `()` returns no value, so it is not an element.
macro_rules! impl_tuple_element {
    ((), Void) => {};
    ($type:ty, $enum:ident) => {
        impl sealed::Sealed for $type {}
        impl TupleElement for $type {}
    };
}

for_each_return_type!(impl_tuple_element);

impl<T: FutureValue + 'static> sealed::Sealed for FutureReader<T> {}
impl<T: FutureValue + 'static> TupleElement for FutureReader<T> {}

/// A tuple of 2 or more elements returns as [`ReturnValue::Tuple`]. `()` is `Void`.
macro_rules! impl_return_tuple {
    ([$count:expr] ()) => {};
    ([$count:expr] ($name:ident: $ty:ident)) => {};
    ([$count:expr] ($($name:ident: $ty:ident),*)) => {
        impl<$($ty: TupleElement),*> SupportedReturnType for ($($ty,)*) {
            const TYPE: ReturnType = ReturnType::Tuple;

            fn into_value(self) -> ReturnValue {
                let ($($name,)*) = self;

                ReturnValue::Tuple(vec![$(<$ty as SupportedReturnType>::into_value($name)),*])
            }

            fn from_value(value: ReturnValue) -> Result<Self, Error> {
                let values = match value {
                    ReturnValue::Tuple(values) => values,
                    other => return Err(Error::ReturnValueConversionFailure(other, "tuple")),
                };

                match <[ReturnValue; $count]>::try_from(values) {
                    Ok([$($name),*]) => Ok(($(<$ty as SupportedReturnType>::from_value($name)?,)*)),
                    Err(values) => Err(Error::ReturnValueConversionFailure(
                        ReturnValue::Tuple(values),
                        "tuple",
                    )),
                }
            }
        }

        impl<$($ty: TupleElement),*> TryFrom<ReturnValue> for ($($ty,)*) {
            type Error = anyhow::Error;

            fn try_from(value: ReturnValue) -> Result<Self, anyhow::Error> {
                Ok(<Self as SupportedReturnType>::from_value(value)?)
            }
        }
    };
}

for_each_tuple!(impl_return_tuple);

#[cfg(all(test, not(loom)))]
mod tests {
    use alloc::sync::Arc;

    use super::*;
    use crate::flatbuffer_wrappers::function_types::Bytes;
    use crate::stream::{self, StreamReader};

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

    type Pair = (StreamReader<u8>, u64);

    #[test]
    fn tuple_moves_its_elements_in_order() {
        let (reader, _writer) = stream::new::<u8>();
        let pipe = Arc::clone(reader.pipe());

        let value = <Pair as SupportedReturnType>::into_value((reader, 7));

        assert!(matches!(
            &value,
            ReturnValue::Tuple(values) if matches!(
                &values[..],
                [ReturnValue::StreamReader(reader), ReturnValue::ULong(7)]
                    if Arc::ptr_eq(reader.pipe(), &pipe)
            )
        ));

        let (reader, number) = <Pair as SupportedReturnType>::from_value(value).unwrap();

        assert!(Arc::ptr_eq(reader.pipe(), &pipe));
        assert_eq!(number, 7);
    }

    #[test]
    fn tuple_rejects_a_wrong_count() {
        let (reader, _writer) = stream::new::<u8>();
        let value = ReturnValue::Tuple(vec![
            ReturnValue::StreamReader(reader),
            ReturnValue::ULong(7),
            ReturnValue::Bool(true),
        ]);

        let err = <Pair as SupportedReturnType>::from_value(value).unwrap_err();

        assert!(matches!(
            err,
            Error::ReturnValueConversionFailure(ReturnValue::Tuple(values), "tuple")
                if values.len() == 3
        ));
    }

    #[test]
    fn tuple_rejects_a_wrong_element() {
        let (reader, _writer) = stream::new::<u8>();
        let value = ReturnValue::Tuple(vec![
            ReturnValue::StreamReader(reader),
            ReturnValue::Bool(true),
        ]);

        let err = <Pair as SupportedReturnType>::from_value(value).unwrap_err();

        assert!(matches!(
            err,
            Error::ReturnValueConversionFailure(ReturnValue::Bool(true), "u64")
        ));
    }
}
