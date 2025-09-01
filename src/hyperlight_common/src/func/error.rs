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

use thiserror::Error;

use crate::func::{ParameterValue, ReturnValue};

/// The error type for Hyperlight operations
#[derive(Error, Debug)]
pub enum Error {
    /// Failed to get value from parameter value
    #[error("Failed To Convert Parameter Value {0:?} to {1:?}")]
    ParameterValueConversionFailure(ParameterValue, &'static str),

    /// Failed to get value from return value
    #[error("Failed To Convert Return Value {0:?} to {1:?}")]
    ReturnValueConversionFailure(ReturnValue, &'static str),

    /// A function was called with an incorrect number of arguments
    #[error("The number of arguments to the function is wrong: got {0:?} expected {1:?}")]
    UnexpectedNoOfArguments(usize, usize),

    /// The parameter value type is unexpected
    #[error("The parameter value type is unexpected got {0:?} expected {1:?}")]
    UnexpectedParameterValueType(ParameterValue, String),

    /// The return value type is unexpected
    #[error("The return value type is unexpected got {0:?} expected {1:?}")]
    UnexpectedReturnValueType(ReturnValue, String),
}
