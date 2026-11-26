// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use anyhow::{Result, anyhow};
#[cfg(feature = "tracing")]
use tracing::{Span, instrument};

use super::codec::{ExternalValueSink, ExternalValueSource, control_cap};
use super::function_types::{ParameterValue, ReturnType};
use super::util::try_byte_chunks_len;
use super::wire::{CallHead, ParamsOut, decode_call, encode_capped};
use crate::stream::{Mux, StreamReader, Transfer};

/// The type of function call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunctionCallType {
    /// The function call is to a guest function.
    Guest,
    /// The function call is to a host function.
    Host,
}

/// `Functioncall` represents a call to a function in the guest or host.
pub struct FunctionCall {
    /// The function name
    pub function_name: String,
    /// The parameters for the function call.
    pub parameters: Option<Vec<ParameterValue>>,
    function_call_type: FunctionCallType,
    /// The return type of the function call
    pub expected_return_type: ReturnType,
}

impl FunctionCall {
    #[cfg_attr(feature = "tracing", instrument(skip_all, parent = Span::current(), level= "Trace"))]
    pub fn new(
        function_name: String,
        parameters: Option<Vec<ParameterValue>>,
        function_call_type: FunctionCallType,
        expected_return_type: ReturnType,
    ) -> Self {
        Self {
            function_name,
            parameters,
            function_call_type,
            expected_return_type,
        }
    }

    /// The type of the function call.
    pub fn function_call_type(&self) -> FunctionCallType {
        self.function_call_type.clone()
    }

    /// Encode control data and supply borrowed byte parameters to `external_values`.
    ///
    /// `transfers` describes the reader parameters in their value order.
    pub(crate) fn encode<'a, 'b, S>(
        &'a self,
        buffer: &'b mut Vec<u8>,
        external_values: &mut S,
        transfers: &[Transfer],
    ) -> Result<&'b [u8]>
    where
        S: ExternalValueSink<'a> + ?Sized,
    {
        let parameters = self.parameters.as_deref().unwrap_or_default();
        let mut external_len = 0usize;

        for parameter in parameters {
            let length = match parameter {
                ParameterValue::VecBytes(value) => value.len(),
                ParameterValue::ByteChunks(value) => try_byte_chunks_len(value)
                    .ok_or_else(|| anyhow!("External ByteChunks parameter length overflow"))?,
                _ => continue,
            };

            external_len = external_len
                .checked_add(length)
                .ok_or_else(|| anyhow!("External parameters length overflow"))?;
        }

        let cap = control_cap(external_len)?;
        let head = CallHead {
            name: &self.function_name,
            host: self.function_call_type == FunctionCallType::Host,
            return_type: self.expected_return_type,
        };
        let params = ParamsOut {
            values: parameters,
            xfers: transfers,
        };
        encode_capped(&(head, params), buffer, cap)?;

        for parameter in parameters {
            match parameter {
                ParameterValue::VecBytes(value) => external_values.push_bytes(value)?,
                ParameterValue::ByteChunks(value) => external_values.push_chunks(value)?,
                _ => {}
            }
        }

        Ok(buffer.as_slice())
    }

    /// Decode control data and receive its readers through `streams`.
    ///
    /// Each parameter is built as it is parsed, taking byte values from `external_values` and
    /// receiving readers in order. A failure drops the parameters built so far, which closes
    /// their readers. It also fails `streams`, since later transfers stay unreceived.
    pub fn decode<S>(control: &[u8], external_values: &mut S, streams: &mut Mux) -> Result<Self>
    where
        S: ExternalValueSource + ?Sized,
    {
        let (head, params) = decode_call(control, external_values, streams)
            .and_then(|call| external_values.finish().map(|()| call))
            .inspect_err(|_| streams.fail())?;

        let function_call_type = if head.host {
            FunctionCallType::Host
        } else {
            FunctionCallType::Guest
        };
        let parameters = (!params.is_empty()).then_some(params);

        Ok(Self {
            function_name: head.name.to_string(),
            parameters,
            function_call_type,
            expected_return_type: head.return_type,
        })
    }

    /// Borrow reader parameters in their wire order.
    pub(crate) fn readers(&self) -> impl Iterator<Item = &StreamReader<u8>> {
        self.parameters
            .iter()
            .flatten()
            .filter_map(|value| match value {
                ParameterValue::StreamReader(reader) => Some(reader),
                _ => None,
            })
    }

    /// Take reader parameters to commit their transfers.
    pub(crate) fn into_readers(self) -> impl Iterator<Item = StreamReader<u8>> {
        self.parameters
            .into_iter()
            .flatten()
            .filter_map(|value| match value {
                ParameterValue::StreamReader(reader) => Some(reader),
                _ => None,
            })
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use alloc::collections::VecDeque;
    use alloc::vec;

    use super::*;
    use crate::flatbuffer_wrappers::function_types::{Bytes, ReturnType};
    use crate::flatbuffer_wrappers::wire::{WireValue, decode_value};
    use crate::stream::{DEFAULT_WINDOW, Side};
    use crate::transport::{EncodedMessage, ExternalValues, MsgKind};
    use crate::virtq::Segments;

    #[derive(Debug, Clone, PartialEq)]
    enum TestExternalValue {
        VecBytes(Vec<u8>),
        ByteChunks(Vec<Bytes>),
    }

    #[derive(Default)]
    struct TestExternalValues {
        values: VecDeque<TestExternalValue>,
    }

    impl TestExternalValues {
        fn from_values(values: impl IntoIterator<Item = TestExternalValue>) -> Self {
            Self {
                values: values.into_iter().collect(),
            }
        }
    }

    impl ExternalValueSource for TestExternalValues {
        fn take_bytes(&mut self, _length: usize) -> Result<Vec<u8>> {
            match self.values.pop_front() {
                Some(TestExternalValue::VecBytes(value)) => Ok(value),
                Some(TestExternalValue::ByteChunks(_)) => {
                    anyhow::bail!("Expected external VecBytes value")
                }
                None => anyhow::bail!("Missing external VecBytes value"),
            }
        }

        fn take_chunks(&mut self, _length: usize) -> Result<Vec<Bytes>> {
            match self.values.pop_front() {
                Some(TestExternalValue::ByteChunks(value)) => Ok(value),
                Some(TestExternalValue::VecBytes(_)) => {
                    anyhow::bail!("Expected external ByteChunks value")
                }
                None => anyhow::bail!("Missing external ByteChunks value"),
            }
        }

        fn finish(&mut self) -> Result<()> {
            if self.values.is_empty() {
                Ok(())
            } else {
                anyhow::bail!("Unused external values")
            }
        }
    }

    /// Encode a call without stream readers and copy its external bytes.
    fn encode(call: &FunctionCall) -> Result<(Vec<u8>, Segments)> {
        let mut buffer = Vec::new();
        let mut externals = ExternalValues::new();
        let control = call.encode(&mut buffer, &mut externals, &[])?;
        let message = EncodedMessage::new(MsgKind::Request, 1, control, externals).unwrap();

        Ok((
            message.control().to_vec(),
            Segments::new(message.external_chunks().map(Bytes::copy_from_slice)),
        ))
    }

    /// Decode a call from `control` and `external_values`.
    fn decode(
        control: &[u8],
        external_values: &mut impl ExternalValueSource,
    ) -> Result<FunctionCall> {
        let mut mux = Mux::new(Side::Guest, DEFAULT_WINDOW);
        FunctionCall::decode(control, external_values, &mut mux)
    }

    #[test]
    fn twelve_parameters_round_trip() -> Result<()> {
        let (control, mut external_values) = encode(&FunctionCall::new(
            "PrintTwelveArgs".to_string(),
            Some(vec![
                ParameterValue::String("1".to_string()),
                ParameterValue::Int(2),
                ParameterValue::Long(3),
                ParameterValue::String("4".to_string()),
                ParameterValue::String("5".to_string()),
                ParameterValue::Bool(true),
                ParameterValue::Bool(false),
                ParameterValue::UInt(8),
                ParameterValue::ULong(9),
                ParameterValue::Int(10),
                ParameterValue::Float(3.123),
                ParameterValue::Double(0.01),
            ]),
            FunctionCallType::Guest,
            ReturnType::Int,
        ))?;

        let function_call = decode(&control, &mut external_values)?;
        assert_eq!(function_call.function_name, "PrintTwelveArgs");
        assert!(function_call.parameters.is_some());
        let parameters = function_call.parameters.unwrap();
        assert_eq!(parameters.len(), 12);
        let expected_parameters = vec![
            ParameterValue::String("1".to_string()),
            ParameterValue::Int(2),
            ParameterValue::Long(3),
            ParameterValue::String("4".to_string()),
            ParameterValue::String("5".to_string()),
            ParameterValue::Bool(true),
            ParameterValue::Bool(false),
            ParameterValue::UInt(8),
            ParameterValue::ULong(9),
            ParameterValue::Int(10),
            ParameterValue::Float(3.123),
            ParameterValue::Double(0.01),
        ];
        assert!(expected_parameters == parameters);
        assert_eq!(function_call.function_call_type, FunctionCallType::Guest);

        Ok(())
    }

    #[test]
    fn byte_parameters_round_trip_in_external_value_order() {
        let call = FunctionCall::new(
            "external_bytes".to_string(),
            Some(vec![
                ParameterValue::Int(7),
                ParameterValue::UInt(8),
                ParameterValue::Long(-9),
                ParameterValue::ULong(10),
                ParameterValue::Float(1.25),
                ParameterValue::Double(2.5),
                ParameterValue::Bool(true),
                ParameterValue::VecBytes(vec![0xa5; 4096]),
                ParameterValue::String("middle".to_string()),
                ParameterValue::ByteChunks(vec![
                    Bytes::from_static(b"chunk one"),
                    Bytes::from_static(b" and two"),
                ]),
                ParameterValue::VecBytes(Vec::new()),
                ParameterValue::ByteChunks(Vec::new()),
            ]),
            FunctionCallType::Host,
            ReturnType::ByteChunks,
        );

        let (encoded, mut external_values) = encode(&call).unwrap();

        assert!(encoded.len() < 4096);
        assert_eq!(external_values.len(), 4096 + 17);

        let (_, params): (CallHead, Vec<WireValue>) = decode_value(&encoded).unwrap();

        for (index, length, chunked) in [
            (7, 4096, false),
            (9, 17, true),
            (10, 0, false),
            (11, 0, true),
        ] {
            assert_eq!(params[index], WireValue::ExternalBytes { length, chunked });
        }

        let decoded = decode(&encoded, &mut external_values).unwrap();
        assert_eq!(decoded.function_name, "external_bytes");
        assert_eq!(decoded.parameters, call.parameters);
        assert_eq!(decoded.function_call_type(), FunctionCallType::Host);
        assert_eq!(decoded.expected_return_type, ReturnType::ByteChunks);
        assert!(external_values.is_empty());
    }

    #[test]
    fn scalar_call_uses_no_external_values() {
        let call = FunctionCall::new(
            "scalars".to_string(),
            Some(vec![
                ParameterValue::Int(42),
                ParameterValue::String("value".to_string()),
            ]),
            FunctionCallType::Guest,
            ReturnType::Bool,
        );
        let (encoded, mut external_values) = encode(&call).unwrap();

        assert!(external_values.is_empty());
        let decoded = decode(&encoded, &mut external_values).unwrap();
        assert_eq!(decoded.function_name, "scalars");
    }

    #[test]
    fn external_parameter_decoder_rejects_invalid_value_sequences() {
        let call = FunctionCall::new(
            "external_bytes".to_string(),
            Some(vec![ParameterValue::VecBytes(vec![1, 2, 3])]),
            FunctionCallType::Guest,
            ReturnType::Void,
        );
        let (encoded, _) = encode(&call).unwrap();

        let mut missing = TestExternalValues::default();
        assert!(decode(&encoded, &mut missing).is_err());

        let mut wrong_type =
            TestExternalValues::from_values([TestExternalValue::ByteChunks(vec![
                Bytes::from_static(b"123"),
            ])]);
        assert!(decode(&encoded, &mut wrong_type).is_err());

        let mut wrong_length =
            TestExternalValues::from_values([TestExternalValue::VecBytes(vec![1, 2])]);
        assert!(decode(&encoded, &mut wrong_length).is_err());

        let mut extra = TestExternalValues::from_values([
            TestExternalValue::VecBytes(vec![1, 2, 3]),
            TestExternalValue::VecBytes(Vec::new()),
        ]);
        assert!(decode(&encoded, &mut extra).is_err());
    }
}
