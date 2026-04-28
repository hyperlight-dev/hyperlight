/*
Copyright 2026  The Hyperlight Authors.

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

//! Host-side [`MemOps`] implementation for virtqueue access.
//!
//! Translates guest virtual addresses used in virtqueue descriptors
//! to offsets into the scratch [`HostSharedMemory`], reusing its
//! volatile access and locking patterns.

use core::sync::atomic::{AtomicU16, Ordering};

use hyperlight_common::virtq::MemOps;

use super::shared_mem::{HostSharedMemory, SharedMemory};

/// Error type for host memory operations.
#[derive(Debug, thiserror::Error)]
pub enum HostMemError {
    #[error("address {addr:#x} out of bounds scratch_size={scratch_size}")]
    OutOfBounds { addr: u64, scratch_size: usize },
    #[error("shared memory error: {0}")]
    SharedMem(String),
    #[error("as_slice/as_mut_slice not supported on host")]
    DirectSliceNotSupported,
}

/// Host-side memory accessor for virtqueue operations.
///
/// Owns a clone of the scratch [`HostSharedMemory`] and translates
/// guest virtual addresses (in the scratch region) to offsets for the
/// existing volatile read/write methods.
#[derive(Clone)]
pub(crate) struct HostMemOps {
    /// Cloned handle to the scratch shared memory
    scratch: HostSharedMemory,
    /// The guest virtual address that corresponds to scratch offset 0.
    scratch_base_gva: u64,
}

impl HostMemOps {
    /// Create a new `HostMemOps` backed by shared memory.
    pub(crate) fn new(scratch: &HostSharedMemory, scratch_base_gva: u64) -> Self {
        Self {
            scratch: scratch.clone(),
            scratch_base_gva,
        }
    }

    /// Translate a guest virtual address to a scratch offset.
    fn to_offset(&self, addr: u64) -> Result<usize, HostMemError> {
        addr.checked_sub(self.scratch_base_gva)
            .map(|o| o as usize)
            .ok_or(HostMemError::OutOfBounds {
                addr,
                scratch_size: self.scratch.mem_size(),
            })
    }

    /// Get a raw pointer into scratch memory at the given guest address.
    fn raw_ptr(&self, addr: u64, len: usize) -> Result<*mut u8, HostMemError> {
        let offset = self.to_offset(addr)?;
        let scratch_size = self.scratch.mem_size();

        if offset.checked_add(len).is_none_or(|end| end > scratch_size) {
            return Err(HostMemError::OutOfBounds { addr, scratch_size });
        }

        Ok(self.scratch.base_ptr().wrapping_add(offset))
    }
}

impl MemOps for HostMemOps {
    type Error = HostMemError;

    fn read(&self, addr: u64, dst: &mut [u8]) -> Result<usize, Self::Error> {
        let offset = self.to_offset(addr)?;
        self.scratch
            .copy_to_slice(dst, offset)
            .map_err(|e| HostMemError::SharedMem(e.to_string()))?;
        Ok(dst.len())
    }

    fn write(&self, addr: u64, src: &[u8]) -> Result<usize, Self::Error> {
        let offset = self.to_offset(addr)?;
        self.scratch
            .copy_from_slice(src, offset)
            .map_err(|e| HostMemError::SharedMem(e.to_string()))?;
        Ok(src.len())
    }

    fn load_acquire(&self, addr: u64) -> Result<u16, Self::Error> {
        let ptr = self.raw_ptr(addr, core::mem::size_of::<u16>())?;
        let atomic = unsafe { &*(ptr as *const AtomicU16) };
        Ok(atomic.load(Ordering::Acquire))
    }

    fn store_release(&self, addr: u64, val: u16) -> Result<(), Self::Error> {
        let ptr = self.raw_ptr(addr, core::mem::size_of::<u16>())?;
        let atomic = unsafe { &*(ptr as *const AtomicU16) };
        atomic.store(val, Ordering::Release);
        Ok(())
    }

    unsafe fn as_slice(&self, _addr: u64, _len: usize) -> Result<&[u8], Self::Error> {
        Err(HostMemError::DirectSliceNotSupported)
    }

    unsafe fn as_mut_slice(&self, _addr: u64, _len: usize) -> Result<&mut [u8], Self::Error> {
        Err(HostMemError::DirectSliceNotSupported)
    }
}
