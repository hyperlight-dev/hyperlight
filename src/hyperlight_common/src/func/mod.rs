// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

/// Error types related to function support
pub(crate) mod error;
/// Definitions and functionality to enable guest-to-host function calling,
/// also called "host functions"
///
/// This module includes functionality to do the following
///
/// - Define several prototypes for what a host function must look like,
///   including the number of arguments (arity) they can have, supported argument
///   types, and supported return types
/// - Registering host functions to be callable by the guest
/// - Dynamically dispatching a call from the guest to the appropriate
///   host function
pub(crate) mod functions;
/// Definitions and functionality for supported parameter types
pub(crate) mod param_type;
/// Definitions and functionality for supported return types
pub(crate) mod ret_type;

pub use error::Error;
/// Re-export for `HostFunction` trait
pub use functions::Function;
pub use param_type::{ParameterTuple, SupportedParameterType};
pub use ret_type::{ResultType, SupportedReturnType};

/// Re-export for chunk-preserving byte values
pub use crate::flatbuffer_wrappers::function_types::Bytes;
/// Re-export for `ParameterValue` enum
pub use crate::flatbuffer_wrappers::function_types::ParameterValue;
/// Re-export for `ReturnType` enum
pub use crate::flatbuffer_wrappers::function_types::ReturnType;
/// Re-export for `ReturnType` enum
pub use crate::flatbuffer_wrappers::function_types::ReturnValue;

mod utils;
