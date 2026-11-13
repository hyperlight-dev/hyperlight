// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use anyhow::Result;
#[cfg(feature = "tracing")]
use tracing::{Span, instrument};

use super::codec::{ExternalValueSink, ExternalValueSource};
use super::function_types::{ParameterValue, ReturnType};
use super::util::try_byte_chunks_len;
use super::wire::{CallHead, ParamsOut, decode_call, encode_value};

/// The type of function call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunctionCallType {
    /// The function call is to a guest function.
    Guest,
    /// The function call is to a host function.
    Host,
}

/// `Functioncall` represents a call to a function in the guest or host.
#[derive(Clone)]
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

    /// Encode control data and collect byte parameters as external values.
    pub fn encode<'a, 'b, S>(
        &'a self,
        buffer: &'b mut Vec<u8>,
        external_values: &mut S,
    ) -> Result<&'b [u8]>
    where
        S: ExternalValueSink<'a> + ?Sized,
    {
        let parameters = self.parameters.as_deref().unwrap_or_default();
        for parameter in parameters {
            match parameter {
                ParameterValue::VecBytes(value) => {
                    u64::try_from(value.len()).map_err(|_| {
                        anyhow::anyhow!("External VecBytes parameter length does not fit in u64")
                    })?;
                    external_values.push_bytes(value)?;
                }
                ParameterValue::ByteChunks(value) => {
                    let length = try_byte_chunks_len(value).ok_or_else(|| {
                        anyhow::anyhow!("External ByteChunks parameter length overflow")
                    })?;
                    u64::try_from(length).map_err(|_| {
                        anyhow::anyhow!("External ByteChunks parameter length does not fit in u64")
                    })?;
                    external_values.push_chunks(value)?;
                }
                _ => {}
            }
        }

        let head = CallHead {
            name: &self.function_name,
            host: self.function_call_type == FunctionCallType::Host,
            return_type: self.expected_return_type,
        };
        encode_value(&(head, ParamsOut(parameters)), buffer)
    }

    /// Decode control data and consume external byte parameters.
    pub fn decode<S>(value: &[u8], external_values: &mut S) -> Result<Self>
    where
        S: ExternalValueSource + ?Sized,
    {
        let (head, params) = decode_call(value, external_values)?;
        let function_call_type = if head.host {
            FunctionCallType::Host
        } else {
            FunctionCallType::Guest
        };
        let parameters = (!params.is_empty()).then_some(params);

        external_values.finish()?;
        Ok(Self {
            function_name: head.name.to_string(),
            parameters,
            function_call_type,
            expected_return_type: head.return_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::VecDeque;
    use alloc::vec;

    use super::*;
    use crate::flatbuffer_wrappers::function_types::{Bytes, ReturnType};
    use crate::flatbuffer_wrappers::wire::{WireValue, decode_value};

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

    impl<'a> ExternalValueSink<'a> for TestExternalValues {
        fn push_bytes(&mut self, value: &'a [u8]) -> Result<()> {
            self.values
                .push_back(TestExternalValue::VecBytes(value.to_vec()));
            Ok(())
        }

        fn push_chunks(&mut self, value: &'a [Bytes]) -> Result<()> {
            self.values
                .push_back(TestExternalValue::ByteChunks(value.to_vec()));
            Ok(())
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

    #[test]
    fn twelve_parameters_round_trip() -> Result<()> {
        let mut buffer = Vec::new();
        let mut external_values = TestExternalValues::default();
        let test_data = FunctionCall::new(
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
        )
        .encode(&mut buffer, &mut external_values)?;

        let function_call = FunctionCall::decode(test_data, &mut external_values)?;
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
        let mut buffer = Vec::new();
        let expected_parameters = vec![
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
        ];
        let call = FunctionCall::new(
            "external_bytes".to_string(),
            Some(expected_parameters.clone()),
            FunctionCallType::Host,
            ReturnType::ByteChunks,
        );
        let mut external_values = TestExternalValues::default();
        let encoded = call.encode(&mut buffer, &mut external_values).unwrap();

        assert!(encoded.len() < 4096);
        assert_eq!(
            external_values.values,
            VecDeque::from([
                TestExternalValue::VecBytes(vec![0xa5; 4096]),
                TestExternalValue::ByteChunks(vec![
                    Bytes::from_static(b"chunk one"),
                    Bytes::from_static(b" and two"),
                ]),
                TestExternalValue::VecBytes(Vec::new()),
                TestExternalValue::ByteChunks(Vec::new()),
            ])
        );

        let (_, params): (CallHead, Vec<WireValue>) = decode_value(encoded).unwrap();
        for (index, length, chunked) in [
            (7, 4096, false),
            (9, 17, true),
            (10, 0, false),
            (11, 0, true),
        ] {
            assert_eq!(params[index], WireValue::ExternalBytes { length, chunked });
        }

        let decoded = FunctionCall::decode(encoded, &mut external_values).unwrap();
        assert_eq!(decoded.function_name, "external_bytes");
        assert_eq!(decoded.parameters, Some(expected_parameters));
        assert_eq!(decoded.function_call_type(), FunctionCallType::Host);
        assert_eq!(decoded.expected_return_type, ReturnType::ByteChunks);
        assert!(external_values.values.is_empty());
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
        let mut buffer = Vec::new();
        let mut external_values = TestExternalValues::default();
        let encoded = call.encode(&mut buffer, &mut external_values).unwrap();

        assert!(external_values.values.is_empty());
        let decoded = FunctionCall::decode(encoded, &mut external_values).unwrap();
        assert_eq!(decoded.function_name, "scalars");
    }

    #[test]
    fn external_parameter_decoder_rejects_invalid_value_sequences() {
        let mut buffer = Vec::new();
        let call = FunctionCall::new(
            "external_bytes".to_string(),
            Some(vec![ParameterValue::VecBytes(vec![1, 2, 3])]),
            FunctionCallType::Guest,
            ReturnType::Void,
        );
        let mut encoded_values = TestExternalValues::default();
        let encoded = call.encode(&mut buffer, &mut encoded_values).unwrap();

        let mut missing = TestExternalValues::default();
        assert!(FunctionCall::decode(encoded, &mut missing).is_err());

        let mut wrong_type =
            TestExternalValues::from_values([TestExternalValue::ByteChunks(vec![
                Bytes::from_static(b"123"),
            ])]);
        assert!(FunctionCall::decode(encoded, &mut wrong_type).is_err());

        let mut wrong_length =
            TestExternalValues::from_values([TestExternalValue::VecBytes(vec![1, 2])]);
        assert!(FunctionCall::decode(encoded, &mut wrong_length).is_err());

        let mut extra = TestExternalValues::from_values([
            TestExternalValue::VecBytes(vec![1, 2, 3]),
            TestExternalValue::VecBytes(Vec::new()),
        ]);
        assert!(FunctionCall::decode(encoded, &mut extra).is_err());
    }
}
