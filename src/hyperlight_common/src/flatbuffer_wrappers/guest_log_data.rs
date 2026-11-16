// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use alloc::string::String;
use alloc::vec::Vec;

use anyhow::{Error, Result};
use serde::{Deserialize, Serialize};
#[cfg(feature = "tracing")]
use tracing::{Span, instrument};

use super::guest_log_level::LogLevel;
use super::wire::{decode_value, encode_value};

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

impl TryFrom<&[u8]> for GuestLogData {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(raw_bytes: &[u8]) -> Result<Self> {
        decode_value(raw_bytes)
    }
}

impl TryFrom<&GuestLogData> for Vec<u8> {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: &GuestLogData) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        encode_value(value, &mut buffer)?;
        Ok(buffer)
    }
}

impl TryFrom<GuestLogData> for Vec<u8> {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: GuestLogData) -> Result<Vec<u8>> {
        (&value).try_into()
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn round_trips() {
        let log = GuestLogData::new(
            "message".to_string(),
            "source".to_string(),
            LogLevel::Warning,
            "caller".to_string(),
            "file.rs".to_string(),
            42,
        );
        let encoded: Vec<u8> = (&log).try_into().unwrap();
        assert_eq!(GuestLogData::try_from(encoded.as_slice()).unwrap(), log);
    }
}
