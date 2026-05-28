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

use serde::{Deserialize, Serialize};
#[cfg(feature = "tracing")]
use tracing::{Span, instrument};

use super::guest_log_level::LogLevel;

/// The guest log data for a VM sandbox
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
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
