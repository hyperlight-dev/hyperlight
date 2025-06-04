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

use alloc::format;
use alloc::string::String;

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use {anyhow, serde_json};

pub type Result<T> = core::result::Result<T, HyperlightGuestError>;

#[derive(Debug)]
pub struct HyperlightGuestError {
    pub kind: ErrorCode,
    pub message: String,
}

impl HyperlightGuestError {
    pub fn new(kind: ErrorCode, message: String) -> Self {
        Self { kind, message }
    }
}

impl From<anyhow::Error> for HyperlightGuestError {
    fn from(error: anyhow::Error) -> Self {
        Self {
            kind: ErrorCode::GuestError,
            message: format!("Error: {:?}", error),
        }
    }
}

impl From<serde_json::Error> for HyperlightGuestError {
    fn from(error: serde_json::Error) -> Self {
        Self {
            kind: ErrorCode::GuestError,
            message: format!("Error: {:?}", error),
        }
    }
}
