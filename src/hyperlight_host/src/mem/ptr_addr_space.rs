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

use tracing::{instrument, Span};

use super::layout::SandboxMemoryLayout;
use crate::Result;

/// A representation of a specific address space
pub trait AddressSpace: std::cmp::Eq {
    /// The base address for this address space
    fn base(&self) -> u64;
}

/// The address space for the guest executable
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct GuestAddressSpace(u64);
impl GuestAddressSpace {
    /// Create a new instance of a `GuestAddressSpace`
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn new() -> Result<Self> {
        let base_addr = u64::try_from(SandboxMemoryLayout::BASE_ADDRESS)?;
        Ok(Self(base_addr))
    }
}
impl AddressSpace for GuestAddressSpace {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn base(&self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{AddressSpace, GuestAddressSpace};
    use crate::mem::layout::SandboxMemoryLayout;

    #[test]
    fn guest_addr_space_base() {
        let space = GuestAddressSpace::new().unwrap();
        assert_eq!(SandboxMemoryLayout::BASE_ADDRESS as u64, space.base());
    }
}
