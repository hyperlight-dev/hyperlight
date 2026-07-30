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

//! Guest-side [`MemOps`] implementation for virtqueue access.

use core::mem::{align_of, size_of};
use core::sync::atomic::{AtomicU16, Ordering};

use hyperlight_common::virtq::MemOps;

use crate::layout;

/// Guest-side memory accessor for GVA-valued virtqueue addresses.
#[derive(Clone, Copy, Debug)]
pub struct GuestMemOps {
    scratch_gva: u64,
    scratch_end: u64,
}

/// Invalid guest virtqueue memory access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestMemError;

impl GuestMemOps {
    pub(super) fn for_scratch() -> Self {
        let scratch_len = unsafe { layout::scratch_size_gva().read_volatile() };
        // SAFETY: Generic initialization keeps the scratch GVA range mapped.
        unsafe { Self::from_raw_parts(layout::scratch_base_gva(), scratch_len) }
    }

    /// Create an accessor for a scratch virtual address range.
    ///
    /// # Safety
    ///
    /// The range must remain mapped for this value's lifetime. Peer access must
    /// follow virtqueue descriptor ownership.
    pub unsafe fn from_raw_parts(scratch_gva: u64, scratch_len: u64) -> Self {
        let scratch_end = scratch_gva
            .checked_add(scratch_len)
            .expect("scratch end overflow");

        Self {
            scratch_gva,
            scratch_end,
        }
    }

    fn ptr(&self, addr: u64, len: usize) -> Result<*mut u8, GuestMemError> {
        let end = addr.checked_add(len as u64).ok_or(GuestMemError)?;
        if addr < self.scratch_gva || end > self.scratch_end {
            return Err(GuestMemError);
        }
        Ok(addr as *mut u8)
    }

    fn atomic(&self, addr: u64) -> Result<&AtomicU16, GuestMemError> {
        let ptr = self.ptr(addr, size_of::<AtomicU16>())?;
        if !(ptr as usize).is_multiple_of(align_of::<AtomicU16>()) {
            return Err(GuestMemError);
        }
        // SAFETY: `ptr` is inside the live scratch mapping and is aligned.
        Ok(unsafe { &*ptr.cast::<AtomicU16>() })
    }
}

// SAFETY: Every address is restricted to the scratch mapping. Payload
// references rely on descriptor ownership, and ring flags use aligned atomics.
unsafe impl MemOps for GuestMemOps {
    type Error = GuestMemError;

    fn read(&self, addr: u64, dst: &mut [u8]) -> Result<(), Self::Error> {
        let src = self.ptr(addr, dst.len())?;
        // SAFETY: `src` covers `dst.len()` initialized scratch bytes.
        unsafe { src.copy_to_nonoverlapping(dst.as_mut_ptr(), dst.len()) };
        Ok(())
    }

    fn write(&self, addr: u64, src: &[u8]) -> Result<(), Self::Error> {
        let dst = self.ptr(addr, src.len())?;
        // SAFETY: `dst` covers `src.len()` scratch bytes.
        unsafe { src.as_ptr().copy_to_nonoverlapping(dst, src.len()) };
        Ok(())
    }

    fn load_acquire(&self, addr: u64) -> Result<u16, Self::Error> {
        Ok(self.atomic(addr)?.load(Ordering::Acquire))
    }

    fn store_release(&self, addr: u64, val: u16) -> Result<(), Self::Error> {
        self.atomic(addr)?.store(val, Ordering::Release);
        Ok(())
    }

    unsafe fn as_slice(&self, addr: u64, len: usize) -> Result<&[u8], Self::Error> {
        let ptr = self.ptr(addr, len)?;
        // SAFETY: The caller upholds descriptor ownership for this range.
        Ok(unsafe { core::slice::from_raw_parts(ptr, len) })
    }

    #[allow(clippy::mut_from_ref)]
    unsafe fn as_mut_slice(&self, addr: u64, len: usize) -> Result<&mut [u8], Self::Error> {
        let ptr = self.ptr(addr, len)?;
        // SAFETY: The caller upholds exclusive descriptor ownership.
        Ok(unsafe { core::slice::from_raw_parts_mut(ptr, len) })
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use core::mem::size_of;

    use hyperlight_common::virtq::MemOps;

    use super::*;

    #[test]
    fn guest_mem_access_is_bounded_by_scratch() {
        const LEN: usize = 0x4000;
        let mut backing = vec![0u64; LEN / size_of::<u64>()];
        let base = backing.as_mut_ptr() as usize as u64;
        let mem = unsafe { GuestMemOps::from_raw_parts(base, LEN as u64) };

        mem.write(base, &[1, 2, 3, 4]).unwrap();
        let mut bytes = [0; 4];
        mem.read(base, &mut bytes).unwrap();
        assert_eq!(bytes, [1, 2, 3, 4]);

        mem.store_release(base, 0x1234).unwrap();
        assert_eq!(mem.load_acquire(base).unwrap(), 0x1234);

        assert!(mem.write(base + LEN as u64 - 1, &[1, 2]).is_err());
        assert!(mem.load_acquire(base + 1).is_err());
    }
}
