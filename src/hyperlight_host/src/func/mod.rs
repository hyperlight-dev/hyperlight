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

/// Context structures used to allow the user to call one or more guest
/// functions on the same Hyperlight sandbox instance, all from within the
/// same state and mutual exclusion context.
pub mod call_ctx;
/// Functionality to dispatch a call from the host to the guest
pub(crate) mod guest_dispatch;
/// Functionality to check for errors after a guest call
pub(crate) mod guest_err;
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
/// Definitions and functionality for supported parameter types
pub(crate) mod param_type;
/// Definitions and functionality for supported return types
pub(crate) mod ret_type;

/// Re-export for `HostFunction` trait
pub use host_functions::HostFunction;
/// Re-export for `ParameterValue` enum
pub use hyperlight_common::flatbuffer_wrappers::function_types::ParameterValue;
/// Re-export for `ReturnType` enum
pub use hyperlight_common::flatbuffer_wrappers::function_types::ReturnType;
/// Re-export for `ReturnType` enum
pub use hyperlight_common::flatbuffer_wrappers::function_types::ReturnValue;
pub use param_type::{ParameterTuple, SupportedParameterType};
pub use ret_type::{ResultType, SupportedReturnType};

mod utils;
