// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

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
pub(crate) mod host_functions;

/// Re-export for `HostFunction` trait
pub use host_functions::{HostFunction, Registerable};
/// Re-export for `ParameterType` enum
pub use hyperlight_common::flatbuffer_wrappers::function_types::ParameterType;
/// Re-export for `ParameterValue` enum
pub use hyperlight_common::flatbuffer_wrappers::function_types::ParameterValue;
/// Re-export for `ReturnType` enum
pub use hyperlight_common::flatbuffer_wrappers::function_types::ReturnType;
/// Re-export for `ReturnValue` enum
pub use hyperlight_common::flatbuffer_wrappers::function_types::ReturnValue;
/// Re-export for `HostFunctionDefinition`
pub use hyperlight_common::flatbuffer_wrappers::host_function_definition::HostFunctionDefinition;
/// Re-export for `HostFunctionDetails`
pub use hyperlight_common::flatbuffer_wrappers::host_function_details::HostFunctionDetails;
pub use hyperlight_common::func::{
    ParameterTuple, ResultType, SupportedParameterType, SupportedReturnType,
};
