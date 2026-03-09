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

use tracing::{Span, instrument};

use crate::hypervisor::virtual_machine::CreateVmError;

/// Return `true` if the MSHV API is available
#[instrument(skip_all, parent = Span::current(), level = "Trace")]
pub(crate) fn is_hypervisor_present() -> bool {
    // TODO(aarch64): implement MSHV detection
    false
}

/// An MSHV implementation of a single-vcpu VM
#[derive(Debug)]
pub(crate) struct MshvVm {
    _placeholder: (),
}

impl MshvVm {
    pub(crate) fn new() -> std::result::Result<Self, CreateVmError> {
        unimplemented!("MshvVm::new")
    }
}
