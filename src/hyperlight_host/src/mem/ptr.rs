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

use std::ops::Add;

use tracing::{instrument, Span};

use super::ptr_addr_space::{AddressSpace, GuestAddressSpace};
use super::ptr_offset::Offset;
use crate::error::HyperlightError::{self, CheckedAddOverflow, RawPointerLessThanBaseAddress};
use crate::Result;

/// A representation of a raw pointer inside a given address space.
///
/// Use this type to distinguish between an offset and a raw pointer
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RawPtr(u64);

impl From<u64> for RawPtr {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn from(val: u64) -> Self {
        Self(val)
    }
}

impl Add<Offset> for RawPtr {
    type Output = RawPtr;
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn add(self, rhs: Offset) -> RawPtr {
        let val = self.0 + u64::from(rhs);
        RawPtr(val)
    }
}

impl TryFrom<usize> for RawPtr {
    type Error = HyperlightError;
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn try_from(val: usize) -> Result<Self> {
        let val_u64 = u64::try_from(val)?;
        Ok(Self::from(val_u64))
    }
}

impl TryFrom<RawPtr> for usize {
    type Error = HyperlightError;
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn try_from(val: RawPtr) -> Result<usize> {
        Ok(usize::try_from(val.0)?)
    }
}

impl From<RawPtr> for u64 {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn from(val: RawPtr) -> u64 {
        val.0
    }
}

impl From<&RawPtr> for u64 {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn from(val: &RawPtr) -> u64 {
        val.0
    }
}

/// Convenience type for representing a pointer into the guest address space
pub(crate) type GuestPtr = Ptr<GuestAddressSpace>;

impl TryFrom<RawPtr> for GuestPtr {
    type Error = HyperlightError;
    /// Create a new `GuestPtr` from the given `guest_raw_ptr`, which must
    /// be a pointer in the guest's address space.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn try_from(raw: RawPtr) -> Result<Self> {
        GuestPtr::from_raw_ptr(GuestAddressSpace::new()?, raw)
    }
}

impl TryFrom<Offset> for GuestPtr {
    type Error = HyperlightError;
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn try_from(val: Offset) -> Result<Self> {
        let addr_space = GuestAddressSpace::new()?;
        Ok(Ptr::from_offset(addr_space, val))
    }
}

impl TryFrom<i64> for GuestPtr {
    type Error = HyperlightError;
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn try_from(val: i64) -> Result<Self> {
        let offset = Offset::try_from(val)?;
        GuestPtr::try_from(offset)
    }
}

impl TryFrom<GuestPtr> for i64 {
    type Error = HyperlightError;
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn try_from(val: GuestPtr) -> Result<Self> {
        let offset = val.offset();
        i64::try_from(offset)
    }
}

/// A pointer into a specific `AddressSpace` `T`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Ptr<T: AddressSpace> {
    addr_space: T,
    offset: Offset,
}

impl<T: AddressSpace> std::cmp::PartialEq for Ptr<T> {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn eq(&self, other: &Self) -> bool {
        other.addr_space == self.addr_space && other.offset == self.offset
    }
}

impl<T: AddressSpace> std::cmp::Eq for Ptr<T> {}
#[instrument(skip_all, parent = Span::current(), level= "Trace")]
fn cmp_helper<T: AddressSpace>(left: &Ptr<T>, right: &Ptr<T>) -> std::cmp::Ordering {
    // We know both left and right have the same address space, thus
    // they have the same base, so we can get away with just comparing
    // the offsets and assume we're in the same address space, practically
    // speaking.
    left.offset.cmp(&right.offset)
}

#[allow(clippy::non_canonical_partial_ord_impl)]
impl<T: AddressSpace> std::cmp::PartialOrd for Ptr<T> {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(cmp_helper(self, other))
    }
}

impl<T: AddressSpace> std::cmp::Ord for Ptr<T> {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        cmp_helper(self, other)
    }
}

impl<T: AddressSpace> Ptr<T> {
    /// Create a new pointer in the given `AddressSpace` `addr_space`
    /// from the given pointer `raw_ptr`. Returns `Ok` if subtracting
    /// the base address from `raw_ptr` succeeds (i.e. does not overflow)
    /// and a `Ptr<T>` can be successfully created
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn from_raw_ptr(addr_space: T, raw_ptr: RawPtr) -> Result<Ptr<T>> {
        let offset = raw_ptr
            .0
            .checked_sub(addr_space.base())
            .ok_or_else(|| RawPointerLessThanBaseAddress(raw_ptr, addr_space.base()))?;
        Ok(Self {
            addr_space,
            offset: Offset::from(offset),
        })
    }

    /// Create a new `Ptr` into the given `addr_space` from the given
    /// `offset`.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn from_offset(addr_space: T, offset: Offset) -> Ptr<T> {
        Self { addr_space, offset }
    }

    /// Get the base address for this pointer
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn base(&self) -> u64 {
        self.addr_space.base()
    }

    /// Get the offset into the pointer's address space
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn offset(&self) -> Offset {
        self.offset
    }

    /// Get the absolute value for the pointer represented by `self`.
    ///
    /// This function should rarely be used. Prefer to use offsets
    /// instead.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn absolute(&self) -> Result<u64> {
        let offset_u64: u64 = self.offset.into();
        self.base()
            .checked_add(offset_u64)
            .ok_or_else(|| CheckedAddOverflow(self.base(), offset_u64))
    }
}

impl<T: AddressSpace> Add<Offset> for Ptr<T> {
    type Output = Ptr<T>;
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn add(self, rhs: Offset) -> Self::Output {
        Self {
            addr_space: self.addr_space,
            offset: self.offset + rhs,
        }
    }
}

impl<T: AddressSpace> TryFrom<Ptr<T>> for usize {
    type Error = HyperlightError;
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn try_from(val: Ptr<T>) -> Result<usize> {
        let abs = val.absolute()?;
        Ok(usize::try_from(abs)?)
    }
}

#[cfg(test)]
mod tests {
    use super::{GuestPtr, RawPtr};
    use crate::mem::layout::SandboxMemoryLayout;
    const OFFSET: u64 = 1;

    #[test]
    fn ptr_basic_ops() {
        {
            let raw_guest_ptr = RawPtr(OFFSET + SandboxMemoryLayout::BASE_ADDRESS as u64);
            let guest_ptr = GuestPtr::try_from(raw_guest_ptr).unwrap();
            assert_eq!(
                OFFSET + SandboxMemoryLayout::BASE_ADDRESS as u64,
                guest_ptr.absolute().unwrap()
            );
        }
    }
}
