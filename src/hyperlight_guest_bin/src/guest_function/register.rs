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

use alloc::collections::BTreeMap;
use alloc::string::String;

use super::definition::GuestFunctionDefinition;
use crate::REGISTERED_GUEST_FUNCTIONS;

/// Represents the functions that the guest exposes to the host.
#[derive(Debug, Default, Clone)]
pub struct GuestFunctionRegister {
    /// Currently registered guest functions
    guest_functions: BTreeMap<String, GuestFunctionDefinition>,
}

impl GuestFunctionRegister {
    /// Create a new `GuestFunctionDetails`.
    pub const fn new() -> Self {
        Self {
            guest_functions: BTreeMap::new(),
        }
    }

    /// Register a new `GuestFunctionDefinition` into self.
    /// If a function with the same name already exists, it will be replaced.
    /// None is returned if the function name was not previously registered,
    /// otherwise the previous `GuestFunctionDefinition` is returned.
    pub fn register(
        &mut self,
        guest_function: GuestFunctionDefinition,
    ) -> Option<GuestFunctionDefinition> {
        self.guest_functions
            .insert(guest_function.function_name.clone(), guest_function)
    }

    /// Gets a `GuestFunctionDefinition` by its `name` field.
    pub fn get(&self, function_name: &str) -> Option<&GuestFunctionDefinition> {
        self.guest_functions.get(function_name)
    }
}

pub fn register_function(function_definition: GuestFunctionDefinition) {
    unsafe {
        // This is currently safe, because we are single threaded, but we
        // should find a better way to do this, see issue #808
        #[allow(static_mut_refs)]
        let gfd = &mut REGISTERED_GUEST_FUNCTIONS;
        gfd.register(function_definition);
    }
}
