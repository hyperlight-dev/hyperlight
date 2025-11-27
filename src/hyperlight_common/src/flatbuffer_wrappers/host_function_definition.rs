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

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use anyhow::{Error, Result, anyhow};
use flatbuffers::{FlatBufferBuilder, WIPOffset};
use tracing::instrument;

use super::function_types::{ParameterType, ReturnType};
use crate::flatbuffers::hyperlight::generated::{
    HostFunctionDefinition as FbHostFunctionDefinition,
    HostFunctionDefinitionArgs as FbHostFunctionDefinitionArgs, ParameterType as FbParameterType,
};

/// The definition of a function exposed from the host to the guest
#[derive(Debug, Default, Clone, PartialEq, Eq)]
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
    #[instrument(skip_all, level = "Trace")]
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

    /// Convert this `HostFunctionDefinition` into a `WIPOffset<FbHostFunctionDefinition>`.
    #[instrument(err(Debug), skip_all, level = "Trace")]
    pub(crate) fn convert_to_flatbuffer_def<'a>(
        &self,
        builder: &mut FlatBufferBuilder<'a>,
    ) -> Result<WIPOffset<FbHostFunctionDefinition<'a>>> {
        let host_function_name = builder.create_string(&self.function_name);
        let return_value_type = self.return_type.into();
        let vec_parameters = match &self.parameter_types {
            Some(vec_pvt) => {
                let num_items = vec_pvt.len();
                let mut parameters: Vec<FbParameterType> = Vec::with_capacity(num_items);
                for pvt in vec_pvt {
                    let fb_pvt = pvt.clone().into();
                    parameters.push(fb_pvt);
                }
                Some(builder.create_vector(&parameters))
            }
            None => None,
        };

        let fb_host_function_definition: WIPOffset<FbHostFunctionDefinition> =
            FbHostFunctionDefinition::create(
                builder,
                &FbHostFunctionDefinitionArgs {
                    function_name: Some(host_function_name),
                    return_type: return_value_type,
                    parameters: vec_parameters,
                },
            );

        Ok(fb_host_function_definition)
    }

    /// Verify that the function call has the correct parameter types.
    #[instrument(err(Debug), skip_all, level = "Trace")]
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

impl TryFrom<&FbHostFunctionDefinition<'_>> for HostFunctionDefinition {
    type Error = Error;
    #[instrument(err(Debug), skip_all, level = "Trace")]
    fn try_from(value: &FbHostFunctionDefinition) -> Result<Self> {
        let function_name = value.function_name().to_string();
        let return_type = value.return_type().try_into().map_err(|_| {
            anyhow!(
                "Failed to convert return type for function {}",
                function_name
            )
        })?;
        let parameter_types = match value.parameters() {
            Some(pvt) => {
                let len = pvt.len();
                let mut pv: Vec<ParameterType> = Vec::with_capacity(len);
                for fb_pvt in pvt {
                    let pvt: ParameterType = fb_pvt.try_into().map_err(|_| {
                        anyhow!(
                            "Failed to convert parameter type for function {}",
                            function_name
                        )
                    })?;
                    pv.push(pvt);
                }
                Some(pv)
            }
            None => None,
        };

        Ok(Self::new(function_name, parameter_types, return_type))
    }
}

impl TryFrom<&[u8]> for HostFunctionDefinition {
    type Error = Error;
    #[instrument(err(Debug), skip_all, level = "Trace")]
    fn try_from(value: &[u8]) -> Result<Self> {
        let fb_host_function_definition = flatbuffers::root::<FbHostFunctionDefinition<'_>>(value)
            .map_err(|e| anyhow!("Error while reading HostFunctionDefinition: {:?}", e))?;
        Self::try_from(&fb_host_function_definition)
    }
}

impl TryFrom<&HostFunctionDefinition> for Vec<u8> {
    type Error = Error;
    #[instrument(err(Debug), skip_all, level = "Trace")]
    fn try_from(hfd: &HostFunctionDefinition) -> Result<Vec<u8>> {
        let mut builder = flatbuffers::FlatBufferBuilder::new();
        let host_function_definition = hfd.convert_to_flatbuffer_def(&mut builder)?;
        builder.finish_size_prefixed(host_function_definition, None);
        Ok(builder.finished_data().to_vec())
    }
}
