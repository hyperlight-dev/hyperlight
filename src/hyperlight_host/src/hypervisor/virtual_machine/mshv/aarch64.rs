// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

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

#[allow(unused)]
impl MshvVm {
    #[allow(unused)]
    pub(crate) fn new() -> std::result::Result<Self, CreateVmError> {
        unimplemented!("MshvVm::new")
    }
}
