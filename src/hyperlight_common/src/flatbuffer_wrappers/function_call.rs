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

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use anyhow::{bail, Error, Result};
use flatbuffers::{size_prefixed_root, WIPOffset};
#[cfg(feature = "tracing")]
use tracing::{instrument, Span};

use super::function_types::{ParameterValue, ReturnType};
use crate::flatbuffers::hyperlight::generated::{
    hlbool, hlboolArgs, hldouble, hldoubleArgs, hlfloat, hlfloatArgs, hlint, hlintArgs, hllong,
    hllongArgs, hlstring, hlstringArgs, hluint, hluintArgs, hlulong, hlulongArgs, hlvecbytes,
    hlvecbytesArgs, FunctionCall as FbFunctionCall, FunctionCallArgs as FbFunctionCallArgs,
    FunctionCallType as FbFunctionCallType, Parameter, ParameterArgs,
    ParameterValue as FbParameterValue,
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

impl TryFrom<FunctionCall> for Vec<u8> {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: FunctionCall) -> Result<Vec<u8>> {
        let mut builder = flatbuffers::FlatBufferBuilder::new();
        let function_name = builder.create_string(&value.function_name);

        let function_call_type = match value.function_call_type {
            FunctionCallType::Guest => FbFunctionCallType::guest,
            FunctionCallType::Host => FbFunctionCallType::host,
        };

        let expected_return_type = value.expected_return_type.into();

        let parameters = match &value.parameters {
            Some(p) => {
                let num_items = p.len();
                let mut parameters: Vec<WIPOffset<Parameter>> = Vec::with_capacity(num_items);

                for param in p {
                    match param {
                        ParameterValue::Int(i) => {
                            let hlint = hlint::create(&mut builder, &hlintArgs { value: *i });
                            let parameter = Parameter::create(
                                &mut builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hlint,
                                    value: Some(hlint.as_union_value()),
                                },
                            );
                            parameters.push(parameter);
                        }
                        ParameterValue::UInt(ui) => {
                            let hluint = hluint::create(&mut builder, &hluintArgs { value: *ui });
                            let parameter = Parameter::create(
                                &mut builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hluint,
                                    value: Some(hluint.as_union_value()),
                                },
                            );
                            parameters.push(parameter);
                        }
                        ParameterValue::Long(l) => {
                            let hllong = hllong::create(&mut builder, &hllongArgs { value: *l });
                            let parameter = Parameter::create(
                                &mut builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hllong,
                                    value: Some(hllong.as_union_value()),
                                },
                            );
                            parameters.push(parameter);
                        }
                        ParameterValue::ULong(ul) => {
                            let hlulong =
                                hlulong::create(&mut builder, &hlulongArgs { value: *ul });
                            let parameter = Parameter::create(
                                &mut builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hlulong,
                                    value: Some(hlulong.as_union_value()),
                                },
                            );
                            parameters.push(parameter);
                        }
                        ParameterValue::Float(f) => {
                            let hlfloat = hlfloat::create(&mut builder, &hlfloatArgs { value: *f });
                            let parameter = Parameter::create(
                                &mut builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hlfloat,
                                    value: Some(hlfloat.as_union_value()),
                                },
                            );
                            parameters.push(parameter);
                        }
                        ParameterValue::Double(d) => {
                            let hldouble =
                                hldouble::create(&mut builder, &hldoubleArgs { value: *d });
                            let parameter = Parameter::create(
                                &mut builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hldouble,
                                    value: Some(hldouble.as_union_value()),
                                },
                            );
                            parameters.push(parameter);
                        }
                        ParameterValue::Bool(b) => {
                            let hlbool: WIPOffset<hlbool<'_>> =
                                hlbool::create(&mut builder, &hlboolArgs { value: *b });
                            let parameter = Parameter::create(
                                &mut builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hlbool,
                                    value: Some(hlbool.as_union_value()),
                                },
                            );
                            parameters.push(parameter);
                        }
                        ParameterValue::String(s) => {
                            let hlstring = {
                                let val = builder.create_string(s.as_str());
                                hlstring::create(&mut builder, &hlstringArgs { value: Some(val) })
                            };
                            let parameter = Parameter::create(
                                &mut builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hlstring,
                                    value: Some(hlstring.as_union_value()),
                                },
                            );
                            parameters.push(parameter);
                        }
                        ParameterValue::VecBytes(v) => {
                            let vec_bytes = builder.create_vector(v);

                            let hlvecbytes = hlvecbytes::create(
                                &mut builder,
                                &hlvecbytesArgs {
                                    value: Some(vec_bytes),
                                },
                            );
                            let parameter = Parameter::create(
                                &mut builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hlvecbytes,
                                    value: Some(hlvecbytes.as_union_value()),
                                },
                            );
                            parameters.push(parameter);
                        }
                    }
                }
                parameters
            }
            None => Vec::new(),
        };

        let parameters = if !parameters.is_empty() {
            Some(builder.create_vector(&parameters))
        } else {
            None
        };

        let function_call = FbFunctionCall::create(
            &mut builder,
            &FbFunctionCallArgs {
                function_name: Some(function_name),
                parameters,
                function_call_type,
                expected_return_type,
            },
        );
        builder.finish_size_prefixed(function_call, None);
        let res = builder.finished_data().to_vec();

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::flatbuffer_wrappers::function_types::ReturnType;

    #[test]
    fn read_from_flatbuffer() -> Result<()> {
        let test_data: Vec<u8> = FunctionCall::new(
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
        .try_into()
        .unwrap();

        let function_call = FunctionCall::try_from(test_data.as_slice())?;
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
}
