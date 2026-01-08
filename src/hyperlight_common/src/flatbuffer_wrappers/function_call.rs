/*
Copyright 2025  The Hyperlight Authors.

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

use alloc::string::String;
use alloc::vec::Vec;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
#[cfg(feature = "tracing")]
use tracing::{Span, instrument};

use super::function_types::{ParameterValue, ReturnType};
use crate::flatbuffer_wrappers::util::decode;

/// The type of function call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FunctionCallType {
    /// The function call is to a guest function.
    Guest,
    /// The function call is to a host function.
    Host,
}

/// `Functioncall` represents a call to a function in the guest or host.
#[derive(Clone, Serialize, Deserialize)]
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
    let guest_function_call: FunctionCall =
        decode(function_call_buffer).context("Error reading function call buffer")?;
    match guest_function_call.function_call_type {
        FunctionCallType::Guest => Ok(()),
        other => {
            bail!("Invalid function call type: {:?}", other);
        }
    }
}

#[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
pub fn validate_host_function_call_buffer(function_call_buffer: &[u8]) -> Result<()> {
    let host_function_call: FunctionCall =
        decode(function_call_buffer).context("Error reading function call buffer")?;
    match host_function_call.function_call_type {
        FunctionCallType::Host => Ok(()),
        other => {
            bail!("Invalid function call type: {:?}", other);
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use super::*;
    use crate::flatbuffer_wrappers::function_types::ReturnType;
    use crate::flatbuffer_wrappers::util::encode;

    #[test]
    fn read_from_flatbuffer() -> Result<()> {
        let value = FunctionCall::new(
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
        );

        let test_data = encode(&value)?;

        let function_call: FunctionCall = decode(&test_data)?;
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
