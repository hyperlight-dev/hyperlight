/*
Copyright 2025 The Hyperlight Authors.

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

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
#[cfg(feature = "tracing")]
use tracing::{Span, instrument};

use super::function_types::{ParameterType, ReturnType};

/// The definition of a function exposed from the host to the guest
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostFunctionDefinition {
    /// The function name
    pub function_name: String,
    /// The type of the parameter values for the host function call.
    pub parameter_types: Option<Vec<ParameterType>>,
    /// The type of the return value from the host function call
    pub return_type: ReturnType,
}

impl HostFunctionDefinition {
    /// Create a new `HostFunctionDefinition`.
    #[cfg_attr(feature = "tracing", instrument(skip_all, parent = Span::current(), level= "Trace"))]
    pub fn new(
        function_name: String,
        parameter_types: Option<Vec<ParameterType>>,
        return_type: ReturnType,
    ) -> Self {
        Self {
            function_name,
            parameter_types,
            return_type,
        }
    }

    /// Verify that the function call has the correct parameter types.
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    pub fn verify_equal_parameter_types(
        &self,
        function_call_parameter_types: &[ParameterType],
    ) -> Result<()> {
        if let Some(parameter_types) = &self.parameter_types {
            for (i, parameter_type) in parameter_types.iter().enumerate() {
                if parameter_type != &function_call_parameter_types[i] {
                    return Err(anyhow!("Incorrect parameter type for parameter {}", i + 1));
                }
            }
        }
        Ok(())
    }
}
