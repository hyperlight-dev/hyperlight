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

//! Host [`MemOps`] implementations for live scratch and captured ring images.
//!
//! Live scratch operations use [`HostSharedMemory`]'s checked API and acquire
//! its lifecycle read lock. This preserves exclusive-memory coordination but
//! makes descriptor traversal pay for one lock acquisition per field access.

use core::mem::size_of;
use core::ops::Range;
use core::sync::atomic::{AtomicU16, Ordering};

use hyperlight_common::layout::scratch_base_gva;
use hyperlight_common::virtq::MemOps;

use super::shared_mem::{HostSharedMemory, SharedMemory};
use crate::{HyperlightError, Result, new_error};

/// Host virtqueue memory access confined to one scratch GVA range.
///
/// Accepted guest virtual addresses are translated relative to
/// `scratch_base_gva` and delegated to `scratch_mem`. Separate instances
/// confine ring metadata and payload pools independently. Clones share the
/// backing mapping and lifecycle lock while retaining the same range.
#[derive(Clone)]
pub(crate) struct HostMemOps {
    /// Shared scratch mapping used for checked memory operations.
    scratch_mem: HostSharedMemory,
    /// Guest virtual address corresponding to offset zero in `scratch_mem`.
    scratch_base_gva: u64,
    /// End-exclusive guest virtual address range accepted by this accessor.
    region: Range<u64>,
}

impl HostMemOps {
    /// Create a memory accessor for `region`.
    pub(crate) fn new(scratch: &HostSharedMemory, region: Range<u64>) -> Result<Self> {
        let scratch_size = scratch.mem_size();
        let scratch_base_gva = scratch_base_gva(scratch_size);

        let scratch_end = u64::try_from(scratch_size)
            .ok()
            .and_then(|size| scratch_base_gva.checked_add(size));

        if scratch_end.is_none_or(|end| region.end > end)
            || region.start >= region.end
            || region.start < scratch_base_gva
        {
            return Err(new_error!(
                "region [{:#x}, {:#x}) is outside scratch at {:#x} with size {}",
                region.start,
                region.end,
                scratch_base_gva,
                scratch_size
            ));
        }

        Ok(Self {
            scratch_mem: scratch.clone(),
            scratch_base_gva,
            region,
        })
    }

    fn to_offset(&self, addr: u64, len: usize) -> Result<usize> {
        let out_of_bounds = || {
            new_error!(
                "address {:#x} with length {} is outside region [{:#x}, {:#x})",
                addr,
                len,
                self.region.start,
                self.region.end
            )
        };

        let access_end = u64::try_from(len)
            .ok()
            .and_then(|len| addr.checked_add(len));

        if addr < self.region.start || access_end.is_none_or(|end| end > self.region.end) {
            return Err(out_of_bounds());
        }

        addr.checked_sub(self.scratch_base_gva)
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or_else(out_of_bounds)
    }
}

// TODO: Hold one HostSharedMemory read guard across a virtq transaction.
// Descriptor metadata requires several reads and writes, so locking every
// operation scales with chain length and dominates the cached metadata path.

// SAFETY: HostMemOps rejects accesses outside its assigned region. The backing
// HostSharedMemory keeps the mapping alive, bounds-checks each operation, and
// coordinates every byte and atomic access with exclusive memory operations.
unsafe impl MemOps for HostMemOps {
    type Error = HyperlightError;

    fn read(&self, addr: u64, dst: &mut [u8]) -> Result<()> {
        let offset = self.to_offset(addr, dst.len())?;
        self.scratch_mem.copy_to_slice(dst, offset)
    }

    fn write(&self, addr: u64, src: &[u8]) -> Result<()> {
        let offset = self.to_offset(addr, src.len())?;
        self.scratch_mem.copy_from_slice(src, offset)
    }

    fn load_acquire(&self, addr: u64) -> Result<u16> {
        let offset = self.to_offset(addr, size_of::<AtomicU16>())?;
        self.scratch_mem
            .load_atomic::<AtomicU16>(offset, Ordering::Acquire)
    }

    fn store_release(&self, addr: u64, val: u16) -> Result<()> {
        let offset = self.to_offset(addr, size_of::<AtomicU16>())?;
        self.scratch_mem
            .store_atomic::<AtomicU16>(offset, val, Ordering::Release)
    }

    unsafe fn as_slice(&self, _addr: u64, _len: usize) -> Result<&[u8]> {
        Err(new_error!("as_slice/as_mut_slice not supported on host"))
    }

    #[allow(clippy::mut_from_ref)]
    unsafe fn as_mut_slice(&self, _addr: u64, _len: usize) -> Result<&mut [u8]> {
        Err(new_error!("as_slice/as_mut_slice not supported on host"))
    }
}

/// Read-only [`MemOps`] view over a captured ring image.
///
/// Snapshot preflight must validate captured bytes before writing them into
/// restored scratch. This view maps the image to its captured ring GVA, letting
/// the same directional validators handle snapshots and live [`HostMemOps`].
pub(super) struct ImageMem<'a> {
    base: u64,
    bytes: &'a [u8],
}

impl<'a> ImageMem<'a> {
    pub(super) fn new(base: u64, bytes: &'a [u8]) -> Self {
        Self { base, bytes }
    }

    fn offset(&self, addr: u64, len: usize) -> Result<usize> {
        let out_of_bounds = || new_error!("image memory access is out of bounds");
        // VirtqLayout uses absolute GVAs, while the captured image starts at index zero.
        let offset = addr.checked_sub(self.base).ok_or_else(&out_of_bounds)?;
        let offset = usize::try_from(offset).map_err(|_| out_of_bounds())?;
        let end = offset.checked_add(len).ok_or_else(&out_of_bounds)?;

        (end <= self.bytes.len())
            .then_some(offset)
            .ok_or_else(out_of_bounds)
    }
}

// SAFETY: ImageMem provides immutable access only within `bytes`. Write
// operations fail, and the backing slice outlives every returned shared slice.
unsafe impl MemOps for ImageMem<'_> {
    type Error = HyperlightError;

    fn read(&self, addr: u64, dst: &mut [u8]) -> Result<()> {
        let offset = self.offset(addr, dst.len())?;
        dst.copy_from_slice(&self.bytes[offset..offset + dst.len()]);
        Ok(())
    }

    fn load_acquire(&self, addr: u64) -> Result<u16> {
        let mut bytes = [0; size_of::<u16>()];
        self.read(addr, &mut bytes)?;
        Ok(u16::from_ne_bytes(bytes))
    }

    unsafe fn as_slice(&self, addr: u64, len: usize) -> Result<&[u8]> {
        let offset = self.offset(addr, len)?;
        Ok(&self.bytes[offset..offset + len])
    }

    fn write(&self, _addr: u64, _src: &[u8]) -> Result<()> {
        Err(new_error!("image memory is read-only"))
    }

    fn store_release(&self, _addr: u64, _val: u16) -> Result<()> {
        Err(new_error!("image memory is read-only"))
    }

    #[allow(clippy::mut_from_ref)]
    unsafe fn as_mut_slice(&self, _addr: u64, _len: usize) -> Result<&mut [u8]> {
        Err(new_error!("image memory is read-only"))
    }
}

#[cfg(test)]
mod tests {
    use hyperlight_common::virtq::MemOps;

    use super::*;
    use crate::mem::shared_mem::ExclusiveSharedMemory;

    const SCRATCH_SIZE: usize = 0x4000;

    fn scratch_base() -> u64 {
        scratch_base_gva(SCRATCH_SIZE)
    }

    fn region() -> Range<u64> {
        let scratch_base = scratch_base();
        scratch_base + 0x1000..scratch_base + 0x2000
    }

    fn host_mem_ops() -> HostMemOps {
        let scratch = ExclusiveSharedMemory::new(SCRATCH_SIZE).unwrap();
        let (scratch, _) = scratch.build();
        HostMemOps::new(&scratch, region()).unwrap()
    }

    #[test]
    fn accesses_only_assigned_region() {
        let mem = host_mem_ops();
        let region = region();

        mem.write(region.start, &[1, 2, 3, 4]).unwrap();
        let mut bytes = [0; 4];
        mem.read(region.start, &mut bytes).unwrap();
        assert_eq!(bytes, [1, 2, 3, 4]);

        assert!(mem.read(region.start - 1, &mut [0]).is_err());
        assert!(mem.write(region.end - 1, &[1, 2]).is_err());
        assert!(mem.read(region.end, &mut [0]).is_err());
        assert!(mem.read(u64::MAX, &mut [0]).is_err());
    }

    #[test]
    fn atomics_use_shared_memory_checks() {
        let mem = host_mem_ops();
        let region = region();

        mem.store_release(region.start, 0x1234).unwrap();
        assert_eq!(mem.load_acquire(region.start).unwrap(), 0x1234);
        assert!(mem.load_acquire(region.start + 1).is_err());
        assert!(mem.load_acquire(region.end - 1).is_err());
    }

    #[test]
    fn rejects_regions_outside_scratch() {
        let scratch = ExclusiveSharedMemory::new(SCRATCH_SIZE).unwrap();
        let (scratch, _) = scratch.build();
        let scratch_base = scratch_base();
        let scratch_end = scratch_base + SCRATCH_SIZE as u64;

        assert!(HostMemOps::new(&scratch, scratch_base - 1..scratch_base).is_err());
        assert!(HostMemOps::new(&scratch, scratch_end - 1..scratch_end + 1).is_err());
    }
}
