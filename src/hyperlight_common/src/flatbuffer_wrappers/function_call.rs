// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use anyhow::{Error, Result, bail};
use flatbuffers::{FlatBufferBuilder, WIPOffset, size_prefixed_root};
#[cfg(feature = "tracing")]
use tracing::{Span, instrument};

use super::codec::{ExternalValueSink, ExternalValueSource};
use super::function_types::{ParameterValue, ReturnType, decode_external_parameter_value};
use super::util::{byte_chunks_to_bytes, try_byte_chunks_len};
use crate::flatbuffers::hyperlight::generated::{
    FunctionCall as FbFunctionCall, FunctionCallArgs as FbFunctionCallArgs,
    FunctionCallType as FbFunctionCallType, Parameter, ParameterArgs,
    ParameterValue as FbParameterValue, hlbool, hlboolArgs, hlbytechunks, hlbytechunksArgs,
    hldouble, hldoubleArgs, hlexternalbytes, hlexternalbytesArgs, hlfloat, hlfloatArgs, hlint,
    hlintArgs, hllong, hllongArgs, hlstring, hlstringArgs, hluint, hluintArgs, hlulong,
    hlulongArgs, hlvecbytes, hlvecbytesArgs,
};

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

    /// Encodes self into the given builder and returns the encoded data.
    ///
    /// # Notes
    ///
    /// The builder should not be reused after a call to encode, since this function
    /// does not reset the state of the builder. If you want to reuse the builder,
    /// you'll need to reset it first.
    pub fn encode<'a>(&self, builder: &'a mut FlatBufferBuilder) -> &'a [u8] {
        let function_name = builder.create_string(&self.function_name);

        let function_call_type = match self.function_call_type {
            FunctionCallType::Guest => FbFunctionCallType::guest,
            FunctionCallType::Host => FbFunctionCallType::host,
        };

        let expected_return_type = self.expected_return_type.into();

        let parameters = match &self.parameters {
            Some(p) if !p.is_empty() => {
                let parameter_offsets: Vec<WIPOffset<Parameter>> = p
                    .iter()
                    .map(|param| match param {
                        ParameterValue::Int(i) => {
                            let hlint = hlint::create(builder, &hlintArgs { value: *i });
                            Parameter::create(
                                builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hlint,
                                    value: Some(hlint.as_union_value()),
                                },
                            )
                        }
                        ParameterValue::UInt(ui) => {
                            let hluint = hluint::create(builder, &hluintArgs { value: *ui });
                            Parameter::create(
                                builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hluint,
                                    value: Some(hluint.as_union_value()),
                                },
                            )
                        }
                        ParameterValue::Long(l) => {
                            let hllong = hllong::create(builder, &hllongArgs { value: *l });
                            Parameter::create(
                                builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hllong,
                                    value: Some(hllong.as_union_value()),
                                },
                            )
                        }
                        ParameterValue::ULong(ul) => {
                            let hlulong = hlulong::create(builder, &hlulongArgs { value: *ul });
                            Parameter::create(
                                builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hlulong,
                                    value: Some(hlulong.as_union_value()),
                                },
                            )
                        }
                        ParameterValue::Float(f) => {
                            let hlfloat = hlfloat::create(builder, &hlfloatArgs { value: *f });
                            Parameter::create(
                                builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hlfloat,
                                    value: Some(hlfloat.as_union_value()),
                                },
                            )
                        }
                        ParameterValue::Double(d) => {
                            let hldouble = hldouble::create(builder, &hldoubleArgs { value: *d });
                            Parameter::create(
                                builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hldouble,
                                    value: Some(hldouble.as_union_value()),
                                },
                            )
                        }
                        ParameterValue::Bool(b) => {
                            let hlbool = hlbool::create(builder, &hlboolArgs { value: *b });
                            Parameter::create(
                                builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hlbool,
                                    value: Some(hlbool.as_union_value()),
                                },
                            )
                        }
                        ParameterValue::String(s) => {
                            let val = builder.create_string(s.as_str());
                            let hlstring =
                                hlstring::create(builder, &hlstringArgs { value: Some(val) });
                            Parameter::create(
                                builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hlstring,
                                    value: Some(hlstring.as_union_value()),
                                },
                            )
                        }
                        ParameterValue::VecBytes(v) => {
                            let vec_bytes = builder.create_vector(v);
                            let hlvecbytes = hlvecbytes::create(
                                builder,
                                &hlvecbytesArgs {
                                    value: Some(vec_bytes),
                                },
                            );
                            Parameter::create(
                                builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hlvecbytes,
                                    value: Some(hlvecbytes.as_union_value()),
                                },
                            )
                        }
                        ParameterValue::ByteChunks(v) => {
                            let value = byte_chunks_to_bytes(v);
                            let vec_bytes = builder.create_vector(value.as_ref());
                            let hlbytechunks = hlbytechunks::create(
                                builder,
                                &hlbytechunksArgs {
                                    value: Some(vec_bytes),
                                },
                            );
                            Parameter::create(
                                builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hlbytechunks,
                                    value: Some(hlbytechunks.as_union_value()),
                                },
                            )
                        }
                    })
                    .collect();
                Some(builder.create_vector(&parameter_offsets))
            }
            _ => None,
        };

        let function_call = FbFunctionCall::create(
            builder,
            &FbFunctionCallArgs {
                function_name: Some(function_name),
                parameters,
                function_call_type,
                expected_return_type,
            },
        );
        builder.finish_size_prefixed(function_call, None);
        builder.finished_data()
    }

    /// Encodes byte parameters as external markers and sends their payloads to
    /// `external_values` in parameter order.
    pub fn encode_external<'a, 'b, S>(
        &'a self,
        builder: &'b mut FlatBufferBuilder,
        external_values: &mut S,
    ) -> Result<&'b [u8]>
    where
        S: ExternalValueSink<'a> + ?Sized,
    {
        let function_name = builder.create_string(&self.function_name);

        let function_call_type = match self.function_call_type {
            FunctionCallType::Guest => FbFunctionCallType::guest,
            FunctionCallType::Host => FbFunctionCallType::host,
        };

        let expected_return_type = self.expected_return_type.into();

        let parameters = match &self.parameters {
            Some(parameters) if !parameters.is_empty() => {
                let parameter_offsets: Vec<WIPOffset<Parameter>> = parameters
                    .iter()
                    .map(|parameter| -> Result<WIPOffset<Parameter>> {
                        let parameter = match parameter {
                            ParameterValue::Int(value) => {
                                let value = hlint::create(builder, &hlintArgs { value: *value });
                                Parameter::create(
                                    builder,
                                    &ParameterArgs {
                                        value_type: FbParameterValue::hlint,
                                        value: Some(value.as_union_value()),
                                    },
                                )
                            }
                            ParameterValue::UInt(value) => {
                                let value = hluint::create(builder, &hluintArgs { value: *value });
                                Parameter::create(
                                    builder,
                                    &ParameterArgs {
                                        value_type: FbParameterValue::hluint,
                                        value: Some(value.as_union_value()),
                                    },
                                )
                            }
                            ParameterValue::Long(value) => {
                                let value = hllong::create(builder, &hllongArgs { value: *value });
                                Parameter::create(
                                    builder,
                                    &ParameterArgs {
                                        value_type: FbParameterValue::hllong,
                                        value: Some(value.as_union_value()),
                                    },
                                )
                            }
                            ParameterValue::ULong(value) => {
                                let value =
                                    hlulong::create(builder, &hlulongArgs { value: *value });
                                Parameter::create(
                                    builder,
                                    &ParameterArgs {
                                        value_type: FbParameterValue::hlulong,
                                        value: Some(value.as_union_value()),
                                    },
                                )
                            }
                            ParameterValue::Float(value) => {
                                let value =
                                    hlfloat::create(builder, &hlfloatArgs { value: *value });
                                Parameter::create(
                                    builder,
                                    &ParameterArgs {
                                        value_type: FbParameterValue::hlfloat,
                                        value: Some(value.as_union_value()),
                                    },
                                )
                            }
                            ParameterValue::Double(value) => {
                                let value =
                                    hldouble::create(builder, &hldoubleArgs { value: *value });
                                Parameter::create(
                                    builder,
                                    &ParameterArgs {
                                        value_type: FbParameterValue::hldouble,
                                        value: Some(value.as_union_value()),
                                    },
                                )
                            }
                            ParameterValue::Bool(value) => {
                                let value = hlbool::create(builder, &hlboolArgs { value: *value });
                                Parameter::create(
                                    builder,
                                    &ParameterArgs {
                                        value_type: FbParameterValue::hlbool,
                                        value: Some(value.as_union_value()),
                                    },
                                )
                            }
                            ParameterValue::String(value) => {
                                let value = builder.create_string(value.as_str());
                                let value =
                                    hlstring::create(builder, &hlstringArgs { value: Some(value) });
                                Parameter::create(
                                    builder,
                                    &ParameterArgs {
                                        value_type: FbParameterValue::hlstring,
                                        value: Some(value.as_union_value()),
                                    },
                                )
                            }
                            ParameterValue::VecBytes(value) => {
                                let length = u64::try_from(value.len()).map_err(|_| {
                                    anyhow::anyhow!(
                                        "External VecBytes parameter length does not fit in u64"
                                    )
                                })?;
                                external_values.push_bytes(value)?;
                                let value = hlexternalbytes::create(
                                    builder,
                                    &hlexternalbytesArgs {
                                        length,
                                        chunked: false,
                                    },
                                );
                                Parameter::create(
                                    builder,
                                    &ParameterArgs {
                                        value_type: FbParameterValue::hlexternalbytes,
                                        value: Some(value.as_union_value()),
                                    },
                                )
                            }
                            ParameterValue::ByteChunks(value) => {
                                let length = try_byte_chunks_len(value).ok_or_else(|| {
                                    anyhow::anyhow!("External ByteChunks parameter length overflow")
                                })?;
                                let length = u64::try_from(length).map_err(|_| {
                                    anyhow::anyhow!(
                                        "External ByteChunks parameter length does not fit in u64"
                                    )
                                })?;
                                external_values.push_chunks(value)?;
                                let value = hlexternalbytes::create(
                                    builder,
                                    &hlexternalbytesArgs {
                                        length,
                                        chunked: true,
                                    },
                                );
                                Parameter::create(
                                    builder,
                                    &ParameterArgs {
                                        value_type: FbParameterValue::hlexternalbytes,
                                        value: Some(value.as_union_value()),
                                    },
                                )
                            }
                        };
                        Ok(parameter)
                    })
                    .collect::<Result<Vec<_>>>()?;
                Some(builder.create_vector(&parameter_offsets))
            }
            _ => None,
        };

        let function_call = FbFunctionCall::create(
            builder,
            &FbFunctionCallArgs {
                function_name: Some(function_name),
                parameters,
                function_call_type,
                expected_return_type,
            },
        );
        builder.finish_size_prefixed(function_call, None);
        Ok(builder.finished_data())
    }

    /// Decodes a function call using `external_values` for external byte
    /// markers.
    pub fn decode_external<S>(value: &[u8], external_values: &mut S) -> Result<Self>
    where
        S: ExternalValueSource + ?Sized,
    {
        let function_call_fb = size_prefixed_root::<FbFunctionCall>(value)
            .map_err(|e| anyhow::anyhow!("Error reading function call buffer: {:?}", e))?;
        let function_name = function_call_fb.function_name();
        let function_call_type = match function_call_fb.function_call_type() {
            FbFunctionCallType::guest => FunctionCallType::Guest,
            FbFunctionCallType::host => FunctionCallType::Host,
            other => {
                bail!("Invalid function call type: {:?}", other);
            }
        };
        let expected_return_type = function_call_fb.expected_return_type().try_into()?;

        let parameters = function_call_fb
            .parameters()
            .map(|parameters| {
                parameters
                    .iter()
                    .map(|parameter| decode_external_parameter_value(parameter, external_values))
                    .collect::<Result<Vec<ParameterValue>>>()
            })
            .transpose()?;

        external_values.finish()?;
        Ok(Self {
            function_name: function_name.to_string(),
            parameters,
            function_call_type,
            expected_return_type,
        })
    }
}

#[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
pub fn validate_guest_function_call_buffer(function_call_buffer: &[u8]) -> Result<()> {
    let guest_function_call_fb = size_prefixed_root::<FbFunctionCall>(function_call_buffer)
        .map_err(|e| anyhow::anyhow!("Error reading function call buffer: {:?}", e))?;
    match guest_function_call_fb.function_call_type() {
        FbFunctionCallType::guest => Ok(()),
        other => {
            bail!("Invalid function call type: {:?}", other);
        }
    }
}

#[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
pub fn validate_host_function_call_buffer(function_call_buffer: &[u8]) -> Result<()> {
    let host_function_call_fb = size_prefixed_root::<FbFunctionCall>(function_call_buffer)
        .map_err(|e| anyhow::anyhow!("Error reading function call buffer: {:?}", e))?;
    match host_function_call_fb.function_call_type() {
        FbFunctionCallType::host => Ok(()),
        other => {
            bail!("Invalid function call type: {:?}", other);
        }
    }
}

impl TryFrom<&[u8]> for FunctionCall {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: &[u8]) -> Result<Self> {
        let function_call_fb = size_prefixed_root::<FbFunctionCall>(value)
            .map_err(|e| anyhow::anyhow!("Error reading function call buffer: {:?}", e))?;
        let function_name = function_call_fb.function_name();
        let function_call_type = match function_call_fb.function_call_type() {
            FbFunctionCallType::guest => FunctionCallType::Guest,
            FbFunctionCallType::host => FunctionCallType::Host,
            other => {
                bail!("Invalid function call type: {:?}", other);
            }
        };
        let expected_return_type = function_call_fb.expected_return_type().try_into()?;

        let parameters = function_call_fb
            .parameters()
            .map(|v| {
                v.iter()
                    .map(|p| p.try_into())
                    .collect::<Result<Vec<ParameterValue>>>()
            })
            .transpose()?;

        Ok(Self {
            function_name: function_name.to_string(),
            parameters,
            function_call_type,
            expected_return_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::VecDeque;
    use alloc::vec;

    use super::*;
    use crate::flatbuffer_wrappers::function_types::{Bytes, ReturnType};

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
    fn read_from_flatbuffer() -> Result<()> {
        let mut builder = FlatBufferBuilder::new();
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
        .encode(&mut builder);

        let function_call = FunctionCall::try_from(test_data)?;
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
    fn embedded_byte_parameters_round_trip_as_distinct_logical_types() {
        let mut builder = FlatBufferBuilder::new();
        let parameters = vec![
            ParameterValue::VecBytes(vec![1, 2, 3]),
            ParameterValue::ByteChunks(vec![Bytes::from_static(&[4, 5]), Bytes::from_static(&[6])]),
        ];
        let encoded = FunctionCall::new(
            "bytes".to_string(),
            Some(parameters),
            FunctionCallType::Host,
            ReturnType::VecBytes,
        )
        .encode(&mut builder);

        let decoded = FunctionCall::try_from(encoded).unwrap();
        assert_eq!(
            decoded.parameters,
            Some(vec![
                ParameterValue::VecBytes(vec![1, 2, 3]),
                ParameterValue::ByteChunks(vec![Bytes::from_static(&[4, 5, 6])]),
            ])
        );
    }

    #[test]
    fn external_byte_parameters_round_trip_in_parameter_order() {
        let mut builder = FlatBufferBuilder::new();
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
        let encoded = call
            .encode_external(&mut builder, &mut external_values)
            .unwrap();

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

        let encoded_call = size_prefixed_root::<FbFunctionCall>(encoded).unwrap();
        let encoded_parameters = encoded_call.parameters().unwrap();
        for (index, length, chunked) in [
            (7, 4096, false),
            (9, 17, true),
            (10, 0, false),
            (11, 0, true),
        ] {
            let parameter = encoded_parameters.get(index);
            assert_eq!(parameter.value_type(), FbParameterValue::hlexternalbytes);
            let marker = parameter.value_as_hlexternalbytes().unwrap();
            assert_eq!(marker.length(), length);
            assert_eq!(marker.chunked(), chunked);
        }

        assert!(FunctionCall::try_from(encoded).is_err());
        let decoded = FunctionCall::decode_external(encoded, &mut external_values).unwrap();
        assert_eq!(decoded.function_name, "external_bytes");
        assert_eq!(decoded.parameters, Some(expected_parameters));
        assert_eq!(decoded.function_call_type(), FunctionCallType::Host);
        assert_eq!(decoded.expected_return_type, ReturnType::ByteChunks);
        assert!(external_values.values.is_empty());
    }

    #[test]
    fn external_encoding_matches_embedded_encoding_without_byte_parameters() {
        let call = FunctionCall::new(
            "scalars".to_string(),
            Some(vec![
                ParameterValue::Int(42),
                ParameterValue::String("value".to_string()),
            ]),
            FunctionCallType::Guest,
            ReturnType::Bool,
        );
        let mut embedded_builder = FlatBufferBuilder::new();
        let embedded = call.encode(&mut embedded_builder).to_vec();

        let mut external_builder = FlatBufferBuilder::new();
        let mut external_values = TestExternalValues::default();
        let external = call
            .encode_external(&mut external_builder, &mut external_values)
            .unwrap();

        assert_eq!(external, embedded);
        assert!(external_values.values.is_empty());
    }

    #[test]
    fn external_parameter_decoder_rejects_invalid_value_sequences() {
        let mut builder = FlatBufferBuilder::new();
        let call = FunctionCall::new(
            "external_bytes".to_string(),
            Some(vec![ParameterValue::VecBytes(vec![1, 2, 3])]),
            FunctionCallType::Guest,
            ReturnType::Void,
        );
        let mut encoded_values = TestExternalValues::default();
        let encoded = call
            .encode_external(&mut builder, &mut encoded_values)
            .unwrap();

        let mut missing = TestExternalValues::default();
        assert!(FunctionCall::decode_external(encoded, &mut missing).is_err());

        let mut wrong_type =
            TestExternalValues::from_values([TestExternalValue::ByteChunks(vec![
                Bytes::from_static(b"123"),
            ])]);
        assert!(FunctionCall::decode_external(encoded, &mut wrong_type).is_err());

        let mut wrong_length =
            TestExternalValues::from_values([TestExternalValue::VecBytes(vec![1, 2])]);
        assert!(FunctionCall::decode_external(encoded, &mut wrong_length).is_err());

        let mut extra = TestExternalValues::from_values([
            TestExternalValue::VecBytes(vec![1, 2, 3]),
            TestExternalValue::VecBytes(Vec::new()),
        ]);
        assert!(FunctionCall::decode_external(encoded, &mut extra).is_err());
    }
}
