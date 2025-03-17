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

use tracing::{Span, instrument};

/// Configuration options for setting up a new `UninitializedSandbox` and
/// subsequent initialized sandboxes, including `MultiUseSandbox`.
///
/// A `SandboxRunOptions` instance must be created with either in-process
/// or in-hypervisor execution mode, and then can optionally be augmented
/// with run-from-guest-binary mode if created with in-hypervisor mode.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub enum SandboxRunOptions {
    /// Run directly in a platform-appropriate hypervisor
    #[default]
    RunInHypervisor,
    /// Run in-process, without a hypervisor, optionally using the
    /// Windows LoadLibrary API to load the binary if the `bool` field is
    /// set to `true`. This should only be used for testing and debugging
    /// as it does not offer any security guarantees.
    RunInProcess(bool),
}

impl SandboxRunOptions {
    /// Returns true if the sandbox should be run in-process using the LoadLibrary API.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn use_loadlib(&self) -> bool {
        matches!(self, Self::RunInProcess(true))
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    /// Returns true if the sandbox should be run in-process
    pub(super) fn in_process(&self) -> bool {
        matches!(self, SandboxRunOptions::RunInProcess(_))
    }
}
