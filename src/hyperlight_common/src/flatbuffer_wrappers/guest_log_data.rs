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

use anyhow::{anyhow, Error, Result};
use flatbuffers::size_prefixed_root;
#[cfg(feature = "tracing")]
use tracing::{instrument, Span};

use super::guest_log_level::LogLevel;
use crate::flatbuffers::hyperlight::generated::{
    GuestLogData as FbGuestLogData, GuestLogDataArgs as FbGuestLogDataArgs, LogLevel as FbLogLevel,
};

/// The guest log data for a VM sandbox
#[derive(Eq, PartialEq, Debug, Clone)]
#[allow(missing_docs)]
pub struct GuestLogData {
    pub message: String,
    pub source: String,
    pub level: LogLevel,
    pub caller: String,
    pub source_file: String,
    pub line: u32,
}

impl GuestLogData {
    #[cfg_attr(feature = "tracing", instrument(skip_all, parent = Span::current(), level= "Trace"))]
    pub fn new(
        message: String,
        source: String,
        level: LogLevel,
        caller: String,
        source_file: String,
        line: u32,
    ) -> Self {
        Self {
            message,
            source,
            level,
            caller,
            source_file,
            line,
        }
    }
}

impl TryFrom<&[u8]> for GuestLogData {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(raw_bytes: &[u8]) -> Result<Self> {
        let gld_gen = size_prefixed_root::<FbGuestLogData>(raw_bytes)
            .map_err(|e| anyhow!("Error while reading GuestLogData: {:?}", e))?;
        let message = convert_generated_option("message", gld_gen.message())?;
        let source = convert_generated_option("source", gld_gen.source())?;
        let level = LogLevel::try_from(&gld_gen.level())?;
        let caller = convert_generated_option("caller", gld_gen.caller())?;
        let source_file = convert_generated_option("source file", gld_gen.source_file())?;
        let line = gld_gen.line();

        Ok(GuestLogData {
            message,
            source,
            level,
            caller,
            source_file,
            line,
        })
    }
}

impl TryFrom<&GuestLogData> for Vec<u8> {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: &GuestLogData) -> Result<Vec<u8>> {
        let mut builder = flatbuffers::FlatBufferBuilder::new();
        let message = builder.create_string(&value.message);
        let source = builder.create_string(&value.source);
        let caller = builder.create_string(&value.caller);
        let source_file = builder.create_string(&value.source_file);
        let level = FbLogLevel::from(&value.level);

        let guest_log_data_fb = FbGuestLogData::create(
            &mut builder,
            &FbGuestLogDataArgs {
                message: Some(message),
                source: Some(source),
                level,
                caller: Some(caller),
                source_file: Some(source_file),
                line: value.line,
            },
        );
        builder.finish_size_prefixed(guest_log_data_fb, None);
        let res = builder.finished_data().to_vec();

        Ok(res)
    }
}

impl TryFrom<GuestLogData> for Vec<u8> {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: GuestLogData) -> Result<Vec<u8>> {
        (&value).try_into()
    }
}

#[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
fn convert_generated_option(field_name: &str, opt: Option<&str>) -> Result<String> {
    opt.map(|s| s.to_string())
        .ok_or_else(|| anyhow!("Missing field: {}", field_name))
}
