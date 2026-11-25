// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Host [`MemOps`] implementations for scratch and private ring images.
//!
//! Live scratch operations use [`HostSharedMemory`]'s checked API and acquire
//! its lifecycle read lock. This preserves exclusive-memory coordination but
//! makes descriptor traversal pay for one lock acquisition per field access.

use core::cell::RefCell;
use core::mem::{align_of, size_of};
use core::ops::Range;
use core::sync::atomic::{AtomicU16, Ordering};

use hyperlight_common::layout::scratch_base_gva;
use hyperlight_common::virtq::MemOps;

use crate::mem::shared_mem::{HostSharedMemory, SharedMemory};
use crate::{HyperlightError, Result, new_error};

/// Checked copies and atomics over the scratch GVA range.
///
/// Clones share the backing mapping and lifecycle lock.
#[derive(Clone)]
pub(crate) struct HostMemOps {
    /// Shared scratch mapping used for checked memory operations.
    scratch_mem: HostSharedMemory,
    /// Guest virtual address corresponding to offset zero in `scratch_mem`.
    scratch_base_gva: u64,
}

impl HostMemOps {
    pub(crate) fn new(scratch: &HostSharedMemory) -> Self {
        Self {
            scratch_mem: scratch.clone(),
            scratch_base_gva: scratch_base_gva(scratch.mem_size()),
        }
    }

    fn to_offset(&self, addr: u64) -> Result<usize> {
        let offset = addr.checked_sub(self.scratch_base_gva).ok_or_else(|| {
            new_error!(
                "address {addr:#x} is below scratch at {:#x}",
                self.scratch_base_gva
            )
        })?;
        Ok(usize::try_from(offset)?)
    }
}

// TODO: Hold one HostSharedMemory read guard across a virtq transaction.
// Descriptor metadata requires several reads and writes, so locking every
// operation scales with chain length and dominates the cached metadata path.

// SAFETY: GVA translation checks subtraction and conversion. HostSharedMemory
// keeps the mapping alive, bounds-checks each operation, and coordinates byte
// and atomic access with exclusive memory operations.
unsafe impl MemOps for HostMemOps {
    type Error = HyperlightError;

    fn read(&self, addr: u64, dst: &mut [u8]) -> Result<()> {
        let offset = self.to_offset(addr)?;
        Ok(self.scratch_mem.copy_to_slice(dst, offset)?)
    }

    fn write(&self, addr: u64, src: &[u8]) -> Result<()> {
        let offset = self.to_offset(addr)?;
        Ok(self.scratch_mem.copy_from_slice(src, offset)?)
    }

    fn load_acquire(&self, addr: u64) -> Result<u16> {
        let offset = self.to_offset(addr)?;
        Ok(self
            .scratch_mem
            .load_atomic::<AtomicU16>(offset, Ordering::Acquire)?)
    }

    fn store_release(&self, addr: u64, val: u16) -> Result<()> {
        let offset = self.to_offset(addr)?;
        Ok(self
            .scratch_mem
            .store_atomic::<AtomicU16>(offset, val, Ordering::Release)?)
    }

    unsafe fn as_slice(&self, _addr: u64, _len: usize) -> Result<&[u8]> {
        Err(new_error!("as_slice/as_mut_slice not supported on host"))
    }

    #[allow(clippy::mut_from_ref)]
    unsafe fn as_mut_slice(&self, _addr: u64, _len: usize) -> Result<&mut [u8]> {
        Err(new_error!("as_slice/as_mut_slice not supported on host"))
    }
}

/// Private ring image addressed by its guest virtual base.
pub(super) struct ImageMem<'a> {
    base: u64,
    bytes: RefCell<&'a mut [u8]>,
}

impl<'a> ImageMem<'a> {
    /// Bind an exclusively borrowed image for single-threaded initialization.
    pub(super) fn new(base: u64, bytes: &'a mut [u8]) -> Self {
        Self {
            base,
            bytes: RefCell::new(bytes),
        }
    }

    /// Translate a guest address into a checked image range.
    fn range(&self, addr: u64, len: usize) -> Result<Range<usize>> {
        let out_of_bounds = || new_error!("image memory access is out of bounds");
        let offset = addr.checked_sub(self.base).ok_or_else(out_of_bounds)?;
        let offset = usize::try_from(offset).map_err(|_| out_of_bounds())?;
        let end = offset.checked_add(len).ok_or_else(out_of_bounds)?;

        if end > self.bytes.borrow().len() {
            return Err(out_of_bounds());
        }

        Ok(offset..end)
    }
}

// SAFETY: Copies stay within exclusively borrowed host storage. RefCell excludes
// concurrent access, so aligned flag operations need no cross-thread ordering.
// Borrowed slices are unsupported.
unsafe impl MemOps for ImageMem<'_> {
    type Error = HyperlightError;

    fn read(&self, addr: u64, dst: &mut [u8]) -> Result<()> {
        let range = self.range(addr, dst.len())?;
        dst.copy_from_slice(&self.bytes.borrow()[range]);
        Ok(())
    }

    fn write(&self, addr: u64, src: &[u8]) -> Result<()> {
        let range = self.range(addr, src.len())?;
        self.bytes.borrow_mut()[range].copy_from_slice(src);
        Ok(())
    }

    fn load_acquire(&self, addr: u64) -> Result<u16> {
        if !addr.is_multiple_of(align_of::<AtomicU16>() as u64) {
            return Err(new_error!("image atomic access is unaligned"));
        }
        let mut bytes = [0; size_of::<u16>()];
        self.read(addr, &mut bytes)?;
        Ok(u16::from_ne_bytes(bytes))
    }

    fn store_release(&self, addr: u64, val: u16) -> Result<()> {
        if !addr.is_multiple_of(align_of::<AtomicU16>() as u64) {
            return Err(new_error!("image atomic access is unaligned"));
        }

        self.write(addr, &val.to_ne_bytes())
    }

    unsafe fn as_slice(&self, _addr: u64, _len: usize) -> Result<&[u8]> {
        Err(new_error!("borrowed image access is unsupported"))
    }

    #[allow(clippy::mut_from_ref)]
    unsafe fn as_mut_slice(&self, _addr: u64, _len: usize) -> Result<&mut [u8]> {
        Err(new_error!("borrowed image access is unsupported"))
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use hyperlight_common::virtq::MemOps;

    use super::*;
    use crate::mem::shared_mem::ExclusiveSharedMemory;

    const SCRATCH_SIZE: usize = 0x4000;

    fn host_mem_ops() -> HostMemOps {
        let scratch = ExclusiveSharedMemory::new(SCRATCH_SIZE).unwrap();
        let (scratch, _) = scratch.build();
        HostMemOps::new(&scratch)
    }

    #[test]
    fn accesses_only_mapped_scratch() {
        let mem = host_mem_ops();
        let base = mem.scratch_base_gva;
        let end = base + SCRATCH_SIZE as u64;

        mem.write(base, &[1, 2, 3, 4]).unwrap();
        let mut bytes = [0; 4];
        mem.read(base, &mut bytes).unwrap();
        assert_eq!(bytes, [1, 2, 3, 4]);

        mem.write(end - 1, &[0x5a]).unwrap();
        let mut last = [0];
        mem.read(end - 1, &mut last).unwrap();
        assert_eq!(last, [0x5a]);
        mem.read(end, &mut []).unwrap();
        assert!(mem.read(base - 1, &mut [0]).is_err());
        assert!(mem.write(end - 1, &[1, 2]).is_err());
        assert!(mem.read(end, &mut [0]).is_err());
        assert!(mem.read(u64::MAX, &mut [0]).is_err());
    }

    #[test]
    fn atomics_use_shared_memory_checks() {
        let mem = host_mem_ops();
        let base = mem.scratch_base_gva;

        mem.store_release(base, 0x1234).unwrap();
        assert_eq!(mem.load_acquire(base).unwrap(), 0x1234);
        assert!(mem.load_acquire(base + 1).is_err());
        assert!(mem.store_release(base + 1, 0).is_err());
        assert!(mem.load_acquire(base + SCRATCH_SIZE as u64).is_err());
        assert!(mem.store_release(base + SCRATCH_SIZE as u64, 0).is_err());
    }

    #[test]
    fn rejects_borrowed_slices() {
        let mem = host_mem_ops();
        let base = mem.scratch_base_gva;

        // SAFETY: The byte is initialized and no other thread accesses the mapping.
        assert!(unsafe { mem.as_slice(base, 1) }.is_err());
        // SAFETY: The byte is valid and no other references to it exist.
        assert!(unsafe { mem.as_mut_slice(base, 1) }.is_err());
    }

    #[test]
    fn image_access_is_bounded() {
        let mut bytes = [1, 2, 3, 4];
        let mem = ImageMem::new(0x1000, &mut bytes);
        let mut read = [0; 2];
        mem.read(0x1002, &mut read).unwrap();
        assert_eq!(read, [3, 4]);
        assert_eq!(
            mem.load_acquire(0x1000).unwrap(),
            u16::from_ne_bytes([1, 2])
        );
        assert_matches!(mem.load_acquire(0x1001), Err(_));
        assert_matches!(mem.read(0xfff, &mut read), Err(_));
        assert_matches!(mem.read(0x1003, &mut read), Err(_));
        assert_matches!(mem.read(u64::MAX, &mut read), Err(_));
        assert_matches!(mem.range(0x1001, usize::MAX), Err(_));

        mem.write(0x1002, &[5, 6]).unwrap();
        mem.read(0x1002, &mut read).unwrap();
        assert_eq!(read, [5, 6]);

        mem.store_release(0x1000, 0x1234).unwrap();
        assert_eq!(mem.load_acquire(0x1000).unwrap(), 0x1234);
        assert_matches!(mem.write(0x1003, &[5, 6]), Err(_));
        assert_matches!(mem.store_release(0x1001, 0), Err(_));
        assert_matches!(mem.store_release(0x1004, 0), Err(_));
    }
}
