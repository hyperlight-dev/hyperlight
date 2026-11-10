// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use alloc::vec::Vec;

use super::host_function_definition::HostFunctionDefinition;

/// `HostFunctionDetails` represents the set of functions that the host exposes to the guest.
#[derive(Debug, Default, Clone)]
pub struct HostFunctionDetails {
    /// The host functions.
    pub host_functions: Option<Vec<HostFunctionDefinition>>,
}
