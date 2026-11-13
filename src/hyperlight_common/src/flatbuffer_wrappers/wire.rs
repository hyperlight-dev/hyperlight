// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Serde/postcard encoding of function calls and results.
//!
//! Control data is one postcard value. The message header records its length.
//! Byte values travel as external values and the control data carries only
//! their length.

use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use anyhow::{Result, anyhow, bail};
use postcard::ser_flavors::Size;
use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use smallvec::SmallVec;

use super::function_types::{ParameterValue, ReturnType, ReturnValue};
use super::util::byte_chunks_len;

/// One control value. Variant order is the wire tag.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(super) enum WireValue<'a> {
    Int(i32),
    UInt(u32),
    Long(i64),
    ULong(u64),
    Float(f32),
    Double(f64),
    String(&'a str),
    Bool(bool),
    Void,
    ExternalBytes { length: u64, chunked: bool },
}

impl<'a> WireValue<'a> {
    /// Byte lengths must have been checked by the caller.
    pub(super) fn from_parameter(value: &'a ParameterValue) -> Self {
        match value {
            ParameterValue::Int(v) => Self::Int(*v),
            ParameterValue::UInt(v) => Self::UInt(*v),
            ParameterValue::Long(v) => Self::Long(*v),
            ParameterValue::ULong(v) => Self::ULong(*v),
            ParameterValue::Float(v) => Self::Float(*v),
            ParameterValue::Double(v) => Self::Double(*v),
            ParameterValue::String(v) => Self::String(v),
            ParameterValue::Bool(v) => Self::Bool(*v),
            ParameterValue::VecBytes(v) => Self::ExternalBytes {
                length: v.len() as u64,
                chunked: false,
            },
            ParameterValue::ByteChunks(v) => Self::ExternalBytes {
                length: byte_chunks_len(v) as u64,
                chunked: true,
            },
        }
    }

    /// Byte lengths must have been checked by the caller.
    pub(super) fn from_return(value: &'a ReturnValue) -> Self {
        match value {
            ReturnValue::Int(v) => Self::Int(*v),
            ReturnValue::UInt(v) => Self::UInt(*v),
            ReturnValue::Long(v) => Self::Long(*v),
            ReturnValue::ULong(v) => Self::ULong(*v),
            ReturnValue::Float(v) => Self::Float(*v),
            ReturnValue::Double(v) => Self::Double(*v),
            ReturnValue::String(v) => Self::String(v),
            ReturnValue::Bool(v) => Self::Bool(*v),
            ReturnValue::Void(()) => Self::Void,
            ReturnValue::VecBytes(v) => Self::ExternalBytes {
                length: v.len() as u64,
                chunked: false,
            },
            ReturnValue::ByteChunks(v) => Self::ExternalBytes {
                length: byte_chunks_len(v) as u64,
                chunked: true,
            },
        }
    }
}

/// Serializes parameters as a sequence without collecting them first.
pub(super) struct ParamsOut<'a>(pub(super) &'a [ParameterValue]);

impl Serialize for ParamsOut<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for value in self.0 {
            seq.serialize_element(&WireValue::from_parameter(value))?;
        }
        seq.end()
    }
}

/// Inline capacity covers the common parameter counts without heap use.
pub(super) struct ParamsIn<'a>(pub(super) SmallVec<[WireValue<'a>; 8]>);

impl<'de: 'a, 'a> Deserialize<'de> for ParamsIn<'a> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        struct ParamsVisitor<'a>(PhantomData<&'a ()>);

        impl<'de: 'a, 'a> Visitor<'de> for ParamsVisitor<'a> {
            type Value = ParamsIn<'a>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a parameter sequence")
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> core::result::Result<Self::Value, A::Error> {
                // The length hint is untrusted, so growth follows decoded elements.
                let mut values = SmallVec::new();
                while let Some(value) = seq.next_element()? {
                    values.push(value);
                }
                Ok(ParamsIn(values))
            }
        }

        deserializer.deserialize_seq(ParamsVisitor(PhantomData))
    }
}

/// One function call. Senders use [`ParamsOut`] and receivers use
/// [`ParamsIn`].
#[derive(Serialize, Deserialize)]
pub(super) struct WireCall<'a, P> {
    pub(super) name: &'a str,
    pub(super) host: bool,
    pub(super) return_type: ReturnType,
    pub(super) params: P,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(super) enum WireResult<'a> {
    #[serde(borrow)]
    Ok(WireValue<'a>),
    Err {
        code: u64,
        message: &'a str,
    },
}

/// Write `value` as control data into `buffer`.
///
/// Measures the encoded size first so `buffer` grows at most once.
pub(super) fn encode_value<'b, T: Serialize>(
    value: &T,
    buffer: &'b mut Vec<u8>,
) -> Result<&'b [u8]> {
    let size = postcard::serialize_with_flavor::<T, Size, usize>(value, Size::default())
        .map_err(|e| anyhow!("Encode failed: {e}"))?;
    let mut out = core::mem::take(buffer);
    out.clear();
    out.try_reserve_exact(size)?;
    *buffer = postcard::to_extend(value, out).map_err(|e| anyhow!("Encode failed: {e}"))?;
    Ok(buffer.as_slice())
}

/// Read one postcard value and reject trailing bytes.
pub(super) fn decode_value<'a, T: Deserialize<'a>>(value: &'a [u8]) -> Result<T> {
    let (decoded, rest) =
        postcard::take_from_bytes(value).map_err(|e| anyhow!("Decode failed: {e}"))?;
    if !rest.is_empty() {
        bail!("Control data has {} trailing bytes", rest.len());
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoding_rejects_truncated_and_trailing_bytes() {
        let mut buffer = Vec::new();
        let encoded = encode_value(&WireValue::String("text"), &mut buffer)
            .unwrap()
            .to_vec();
        assert_eq!(
            decode_value::<WireValue>(&encoded).unwrap(),
            WireValue::String("text")
        );

        assert!(decode_value::<WireValue>(&encoded[..encoded.len() - 1]).is_err());

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_value::<WireValue>(&trailing).is_err());
    }
}
