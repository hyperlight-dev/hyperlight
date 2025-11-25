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

use alloc::vec::Vec;

use anyhow::{Error, Result};
use flatbuffers::{WIPOffset, size_prefixed_root};
use tracing::{Span, instrument};

use super::host_function_definition::HostFunctionDefinition;
use crate::flatbuffers::hyperlight::generated::{
    HostFunctionDefinition as FbHostFunctionDefinition,
    HostFunctionDetails as FbHostFunctionDetails,
    HostFunctionDetailsArgs as FbHostFunctionDetailsArgs,
};

/// `HostFunctionDetails` represents the set of functions that the host exposes to the guest.
#[derive(Debug, Default, Clone)]
pub struct HostFunctionDetails {
    /// The host functions.
    pub host_functions: Option<Vec<HostFunctionDefinition>>,
}

impl TryFrom<&[u8]> for HostFunctionDetails {
    type Error = Error;
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn try_from(value: &[u8]) -> Result<Self> {
        let host_function_details_fb = size_prefixed_root::<FbHostFunctionDetails>(value)
            .map_err(|e| anyhow::anyhow!("Error while reading HostFunctionDetails: {:?}", e))?;

        let host_function_definitions = match host_function_details_fb.functions() {
            Some(hfd) => {
                let len = hfd.len();
                let mut vec_hfd: Vec<HostFunctionDefinition> = Vec::with_capacity(len);
                for i in 0..len {
                    let fb_host_function_definition = hfd.get(i);
                    let hfdef = HostFunctionDefinition::try_from(&fb_host_function_definition)?;
                    vec_hfd.push(hfdef);
                }

                Some(vec_hfd)
            }

            None => None,
        };

        Ok(Self {
            host_functions: host_function_definitions,
        })
    }
}

impl TryFrom<&HostFunctionDetails> for Vec<u8> {
    type Error = Error;
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn try_from(value: &HostFunctionDetails) -> Result<Vec<u8>> {
        let mut builder = flatbuffers::FlatBufferBuilder::new();
        let vec_host_function_definitions = match &value.host_functions {
            Some(vec_hfd) => {
                let num_items = vec_hfd.len();
                let mut host_function_definitions: Vec<WIPOffset<FbHostFunctionDefinition>> =
                    Vec::with_capacity(num_items);

                for hfd in vec_hfd {
                    let host_function_definition = hfd.convert_to_flatbuffer_def(&mut builder)?;
                    host_function_definitions.push(host_function_definition);
                }

                Some(host_function_definitions)
            }
            None => None,
        };

        let fb_host_function_definitions =
            vec_host_function_definitions.map(|v| builder.create_vector(&v));

        let host_function_details = FbHostFunctionDetails::create(
            &mut builder,
            &FbHostFunctionDetailsArgs {
                functions: fb_host_function_definitions,
            },
        );
        builder.finish_size_prefixed(host_function_details, None);
        let res = builder.finished_data().to_vec();

        Ok(res)
    }
}
