// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Serde/postcard encoding of function calls and results.
//!
//! Control data is one postcard call or result. The message header records its
//! length. Byte values travel as external values, and control data carries their
//! length. A stream reader carries its stream ID and consumed position. A tuple
//! result carries its elements as a sequence, like call parameters.

use alloc::string::ToString;
use alloc::vec::Vec;

use anyhow::{Result, anyhow, bail};
use postcard::ser_flavors::Size;
use serde::ser::{Error as _, SerializeSeq};
use serde::{Deserialize, Serialize, Serializer};

use super::codec::ExternalValueSource;
use super::function_types::{
    ParameterValue, ReturnType, ReturnValue, decode_parameter_value, decode_return_value,
};
use super::guest_error::GuestError;
use super::util::byte_chunks_len;
use crate::stream::{MAX_TRANSFERS, Mux, ProtocolError, StreamReader, Transfer};

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
    StreamReader(Transfer),
}

impl<'a> WireValue<'a> {
    /// Encode `value` with the next prepared transfer for a reader.
    ///
    /// Byte lengths must have been checked by the caller.
    pub(super) fn from_parameter(
        value: &'a ParameterValue,
        xfers: &mut impl Iterator<Item = Transfer>,
    ) -> Result<Self> {
        Ok(match value {
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
            ParameterValue::StreamReader(_) => {
                Self::StreamReader(xfers.next().ok_or_else(|| anyhow!("Missing transfer"))?)
            }
        })
    }

    /// Encode `value` with the next prepared transfer for a reader.
    ///
    /// Byte lengths must have been checked by the caller. A tuple result encodes as
    /// [`WireResult::Tuple`], so a tuple here is nested and fails.
    pub(super) fn from_return(
        value: &'a ReturnValue,
        xfers: &mut impl Iterator<Item = Transfer>,
    ) -> Result<Self> {
        Ok(match value {
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
            ReturnValue::StreamReader(_) => {
                Self::StreamReader(xfers.next().ok_or_else(|| anyhow!("Missing transfer"))?)
            }
            ReturnValue::Tuple(_) => bail!("A tuple cannot hold a tuple"),
        })
    }
}

/// Serializes parameters as a sequence without collecting them first.
pub(super) struct ParamsOut<'a> {
    pub(super) values: &'a [ParameterValue],
    pub(super) xfers: &'a [Transfer],
}

impl Serialize for ParamsOut<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.values.len()))?;
        let mut xfers = self.xfers.iter().copied();

        for val in self.values {
            let val = WireValue::from_parameter(val, &mut xfers).map_err(S::Error::custom)?;
            seq.serialize_element(&val)?;
        }

        seq.end()
    }
}

/// Serializes tuple elements as a sequence without collecting them first.
pub(super) struct TupleOut<'a> {
    pub(super) values: &'a [ReturnValue],
    pub(super) xfers: &'a [Transfer],
}

impl Serialize for TupleOut<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.values.len()))?;
        let mut xfers = self.xfers.iter().copied();

        for val in self.values {
            if matches!(val, ReturnValue::Void(())) {
                return Err(S::Error::custom("Void is not a valid tuple element"));
            }

            let val = WireValue::from_return(val, &mut xfers).map_err(S::Error::custom)?;
            seq.serialize_element(&val)?;
        }

        seq.end()
    }
}

/// Function call fields before its parameters. Parameters follow as a
/// sequence so decoding can convert each one as it is read.
#[derive(Serialize, Deserialize)]
pub(super) struct CallHead<'a> {
    pub(super) name: &'a str,
    pub(super) host: bool,
    pub(super) return_type: ReturnType,
}

/// Decode a call and convert each parameter as it is read.
///
/// External byte values are taken from `externals` in parameter order. Readers receive their
/// transfers through `streams` in parameter order. A message moves at most [`MAX_TRANSFERS`]
/// readers, so the reader past it fails before its transfer is received.
pub(super) fn decode_call<'a, S>(
    value: &'a [u8],
    externals: &mut S,
    streams: &mut Mux,
) -> Result<(CallHead<'a>, Vec<ParameterValue>)>
where
    S: ExternalValueSource + ?Sized,
{
    let mut deserializer = postcard::Deserializer::from_bytes(value);
    let head = CallHead::deserialize(&mut deserializer)?;
    head.return_type.check_supported()?;
    let count = usize::deserialize(&mut deserializer)?;

    // Each value takes at least one byte.
    let mut params = Vec::with_capacity(count.min(value.len()));
    let mut reader_cnt = 0;

    for _ in 0..count {
        let value = WireValue::deserialize(&mut deserializer)?;

        if matches!(value, WireValue::StreamReader(_)) {
            if reader_cnt == MAX_TRANSFERS {
                return Err(ProtocolError::Transfer.into());
            }

            reader_cnt += 1;
        }

        params.push(decode_parameter_value(value, externals, streams)?);
    }

    let rest = deserializer.finalize()?;
    if !rest.is_empty() {
        bail!("Control data has {} trailing bytes", rest.len());
    }
    Ok((head, params))
}

/// A function call result. Variant order is the wire tag.
///
/// Encoding writes a tuple's elements through [`TupleOut`]. Decoding reads only a tuple's
/// element count as `usize`, and the elements follow it.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(super) enum WireResult<'a, T> {
    #[serde(borrow)]
    Ok(WireValue<'a>),
    Err {
        code: u64,
        message: &'a str,
    },
    Tuple(T),
}

/// A tuple element as read from control data, or the reader its transfer gave.
enum Element<'a> {
    Wire(WireValue<'a>),
    Reader(StreamReader<u8>),
}

/// Decode a result and convert its value.
pub(super) fn decode_result<S>(
    control: &[u8],
    externals: &mut S,
    streams: &mut Mux,
) -> Result<core::result::Result<ReturnValue, GuestError>>
where
    S: ExternalValueSource + ?Sized,
{
    let mut elems = Vec::new();
    let mut deserializer = postcard::Deserializer::from_bytes(control);
    let head = WireResult::<usize>::deserialize(&mut deserializer)?;

    if let WireResult::Tuple(count) = head {
        // Each element takes at least one byte.
        elems.reserve(count.min(control.len()));
        let mut reader_cnt = 0;

        for _ in 0..count {
            let value = WireValue::deserialize(&mut deserializer)?;

            match value {
                WireValue::Void => bail!("Void is not a valid tuple element"),
                WireValue::StreamReader(_) => reader_cnt += 1,
                _ => {}
            }

            if reader_cnt > MAX_TRANSFERS {
                return Err(ProtocolError::Transfer.into());
            }

            elems.push(Element::Wire(value));
        }
    }

    let rest = deserializer.finalize()?;

    if !rest.is_empty() {
        bail!("Control data has {} trailing bytes", rest.len());
    }

    Ok(match head {
        WireResult::Ok(value) => Ok(decode_return_value(value, externals, streams)?),
        WireResult::Err { code, message } => Err(GuestError::new(code.into(), message.to_string())),
        WireResult::Tuple(_) => {
            let values = decode_tuple(elems, externals, streams)?;
            Ok(ReturnValue::Tuple(values))
        }
    })
}

/// Convert a tuple's elements in order.
///
/// Every transfer is received before any external value is taken. A short external value then
/// leaves no transfer unreceived, and the failure closes every received reader.
fn decode_tuple<S>(
    mut elems: Vec<Element<'_>>,
    externals: &mut S,
    streams: &mut Mux,
) -> Result<Vec<ReturnValue>>
where
    S: ExternalValueSource + ?Sized,
{
    for element in &mut elems {
        if let Element::Wire(WireValue::StreamReader(xfer)) = *element {
            *element = Element::Reader(streams.recv_transfer(xfer)?);
        }
    }

    elems
        .into_iter()
        .map(|element| match element {
            Element::Wire(value) => decode_return_value(value, externals, streams),
            Element::Reader(reader) => Ok(ReturnValue::StreamReader(reader)),
        })
        .collect()
}

/// Write `value` as control data into `buffer`.
pub(super) fn encode_value<'b, T: Serialize>(
    value: &T,
    buffer: &'b mut Vec<u8>,
) -> Result<&'b [u8]> {
    encode_capped(value, buffer, usize::MAX)?;
    Ok(buffer.as_slice())
}

/// Write `value` as control data of at most `cap` bytes into `buffer`.
///
/// Measures the encoded size first so `buffer` grows at most once. A reused buffer keeps its
/// capacity, so it stops allocating once it fits its messages.
pub(super) fn encode_capped<T: Serialize>(
    value: &T,
    buffer: &mut Vec<u8>,
    cap: usize,
) -> Result<()> {
    let size = postcard::serialize_with_flavor::<T, Size, usize>(value, Size::default())
        .map_err(|e| anyhow!("Encode failed: {e}"))?;

    if size > cap {
        bail!("Encode failed: {size} bytes exceed the {cap} byte limit");
    }

    let mut out = core::mem::take(buffer);
    out.clear();
    out.try_reserve_exact(size)?;
    *buffer = postcard::to_extend(value, out).map_err(|e| anyhow!("Encode failed: {e}"))?;
    Ok(())
}

/// Read one postcard value and reject trailing bytes.
pub(super) fn decode_value<'a, T: Deserialize<'a>>(value: &'a [u8]) -> Result<T> {
    let (decoded, rest) = postcard::take_from_bytes(value)?;
    if !rest.is_empty() {
        bail!("Control data has {} trailing bytes", rest.len());
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

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

    #[test]
    fn encoding_stops_at_the_cap() {
        let mut buffer = vec![0xff; 8];
        let value = WireValue::String("text");

        encode_capped(&value, &mut buffer, 6).unwrap();
        assert_eq!(buffer, [6, 4, b't', b'e', b'x', b't']);
        assert!(encode_capped(&value, &mut buffer, 5).is_err());
    }
}
