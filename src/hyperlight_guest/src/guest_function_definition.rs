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

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterType, ReturnType};
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;

use crate::error::{HyperlightGuestError, Result};

/// The definition of a function exposed from the guest to the host
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestFunctionDefinition {
    /// The function name
    pub function_name: String,
    /// The type of the parameter values for the host function call.
    pub parameter_types: Vec<ParameterType>,
    /// The type of the return value from the host function call
    pub return_type: ReturnType,
    /// The function pointer to the guest function
    pub function_pointer: usize,
}

impl GuestFunctionDefinition {
    /// Create a new `GuestFunctionDefinition`.
    pub fn new(
        function_name: String,
        parameter_types: Vec<ParameterType>,
        return_type: ReturnType,
        function_pointer: usize,
    ) -> Self {
        Self {
            function_name,
            parameter_types,
            return_type,
            function_pointer,
        }
    }

    /// Verify that `self` has same signature as the provided `parameter_types`.
    pub fn verify_parameters(&self, parameter_types: &[ParameterType]) -> Result<()> {
        // Verify that the function does not have more than `MAX_PARAMETERS` parameters.
        const MAX_PARAMETERS: usize = 11;
        if parameter_types.len() > MAX_PARAMETERS {
            return Err(HyperlightGuestError::new(
                ErrorCode::GuestError,
                format!(
                    "Function {} has too many parameters: {} (max allowed is {}).",
                    self.function_name,
                    parameter_types.len(),
                    MAX_PARAMETERS
                ),
            ));
        }

        if self.parameter_types.len() != parameter_types.len() {
            return Err(HyperlightGuestError::new(
                ErrorCode::GuestFunctionIncorrecNoOfParameters,
                format!(
                    "Called function {} with {} parameters but it takes {}.",
                    self.function_name,
                    parameter_types.len(),
                    self.parameter_types.len()
                ),
            ));
        }

        for (i, parameter_type) in self.parameter_types.iter().enumerate() {
            if parameter_type != &parameter_types[i] {
                return Err(HyperlightGuestError::new(
                    ErrorCode::GuestFunctionParameterTypeMismatch,
                    format!(
                        "Expected parameter type {:?} for parameter index {} of function {} but got {:?}.",
                        parameter_type, i, self.function_name, parameter_types[i]
                    ),
                ));
            }
        }

        Ok(())
    }
}
