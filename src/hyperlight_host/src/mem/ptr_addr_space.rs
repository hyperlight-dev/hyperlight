// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use tracing::{Span, instrument};

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
