// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Guest-side [`MemOps`] implementation for virtqueue access.

use core::mem::{ManuallyDrop, align_of, size_of};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU16, Ordering};

use hyperlight_common::virtq::{BufferLease, BufferMap, MemOps};

use crate::layout;

#[cfg(test)]
extern crate std;

/// Fixed-pool memory access within an initialized guest runtime.
///
/// Copies reject buffers that overlap the accessed scratch range.
#[derive(Clone, Copy, Debug)]
pub(crate) struct GuestMemOps {
    scratch_gva: u64,
    scratch_end: u64,
}

/// Invalid guest virtqueue memory access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestMemError;

impl GuestMemOps {
    /// # Safety
    ///
    /// Guest scratch metadata must be initialized. Execution must stay within
    /// the single-vCPU guest. Scratch must remain mapped while this accessor
    /// or any returned views exist.
    pub(super) unsafe fn for_scratch() -> Self {
        // SAFETY: The caller guarantees initialized guest scratch metadata.
        let scratch_len = unsafe { layout::scratch_size_gva().read_volatile() };
        // SAFETY: The caller supplies the guest execution and backing lifetime guarantees.
        unsafe { Self::from_raw_parts(layout::scratch_base_gva(), scratch_len) }
    }

    /// Create an accessor for a scratch virtual address range.
    ///
    /// # Safety
    ///
    /// The range must remain mapped while this accessor or its returned views
    /// exist. Peer access must follow descriptor ownership. Production callers
    /// must uphold the guest execution requirements of [`Self::for_scratch`].
    unsafe fn from_raw_parts(scratch_gva: u64, scratch_len: u64) -> Self {
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

impl BufferMap for GuestMemOps {
    type Mapping = GuestMapping;

    unsafe fn map_buffer(
        &self,
        lease: BufferLease,
        written: usize,
    ) -> Result<Self::Mapping, Self::Error> {
        // SAFETY: The caller owns the initialized prefix. The accessor's
        // constructor guarantees backing remains mapped while returned views exist.
        let data = NonNull::from(unsafe { self.as_slice(lease.allocation().addr, written)? });
        Ok(GuestMapping {
            data,
            lease: ManuallyDrop::new(lease),
            #[cfg(test)]
            creator: std::thread::current().id(),
        })
    }
}

/// An initialized scratch view held by its original allocation lease.
pub(crate) struct GuestMapping {
    data: NonNull<[u8]>,
    lease: ManuallyDrop<BufferLease>,
    #[cfg(test)]
    creator: std::thread::ThreadId,
}

// SAFETY: The view is immutable. Production construction requires serialized
// guest execution and guest-lifetime backing. Native tests check the creator
// thread before releasing the Rc-backed lease.
unsafe impl Send for GuestMapping {}

impl AsRef<[u8]> for GuestMapping {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: The lease protects the initialized view from reuse.
        unsafe { self.data.as_ref() }
    }
}

impl Drop for GuestMapping {
    fn drop(&mut self) {
        #[cfg(test)]
        assert_eq!(
            self.creator,
            std::thread::current().id(),
            "guest mapping dropped on another thread"
        );

        // SAFETY: The view is no longer exposed. Guest execution, or the native
        // creator-thread check, serializes release of the Rc-backed lease.
        unsafe { ManuallyDrop::drop(&mut self.lease) };
    }
}

// SAFETY: Every address is restricted to the scratch mapping. Payload
// references rely on descriptor ownership, and ring flags use aligned atomics.
unsafe impl MemOps for GuestMemOps {
    type Error = GuestMemError;

    fn read(&self, addr: u64, dst: &mut [u8]) -> Result<(), Self::Error> {
        let src = self.ptr(addr, dst.len())?;

        if dst.is_empty() {
            return Ok(());
        }

        if (src as usize).abs_diff(dst.as_ptr() as usize) < dst.len() {
            return Err(GuestMemError);
        }

        // SAFETY: The initialized scratch range is disjoint from `dst`.
        unsafe { src.copy_to_nonoverlapping(dst.as_mut_ptr(), dst.len()) };
        Ok(())
    }

    fn write(&self, addr: u64, src: &[u8]) -> Result<(), Self::Error> {
        let dst = self.ptr(addr, src.len())?;

        if src.is_empty() {
            return Ok(());
        }

        if (dst as usize).abs_diff(src.as_ptr() as usize) < src.len() {
            return Err(GuestMemError);
        }

        // SAFETY: The writable scratch range is disjoint from `src`.
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

    use hyperlight_common::flatbuffer_wrappers::function_types::Bytes;
    use hyperlight_common::virtq::{MemOps, SlotLayout, SlotPool};

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

    #[test]
    fn guest_mem_rejects_overlapping_reads() {
        let mut backing = [1u8, 2, 3, 4];
        let base = backing.as_mut_ptr() as u64;
        // SAFETY: Backing stays initialized and mapped. No peer accesses it.
        let mem = unsafe { GuestMemOps::from_raw_parts(base, 4) };

        assert_eq!(mem.read(base, &mut backing), Err(GuestMemError));
        assert_eq!(mem.read(base, &mut backing[1..]), Err(GuestMemError));
        assert_eq!(mem.read(base + 1, &mut backing[..3]), Err(GuestMemError));
        assert_eq!(backing, [1, 2, 3, 4]);
    }

    #[test]
    fn guest_mem_rejects_overlapping_writes() {
        let mut backing = [1u8, 2, 3, 4];
        let base = backing.as_mut_ptr() as u64;
        // SAFETY: Backing stays initialized and mapped. No peer accesses it.
        let mem = unsafe { GuestMemOps::from_raw_parts(base, 4) };

        assert_eq!(mem.write(base, &backing), Err(GuestMemError));
        assert_eq!(mem.write(base, &backing[1..]), Err(GuestMemError));
        assert_eq!(mem.write(base + 1, &backing[..3]), Err(GuestMemError));
        assert_eq!(backing, [1, 2, 3, 4]);
    }

    #[test]
    fn guest_mem_copies_disjoint_scratch_ranges() {
        let mut backing = [1u8, 2, 3, 4];
        let base = backing.as_mut_ptr() as u64;
        // SAFETY: Backing stays initialized and mapped. No peer accesses it.
        let mem = unsafe { GuestMemOps::from_raw_parts(base, 4) };

        // Expose each copy address after splitting to preserve pointer provenance.
        let (left, right) = backing.split_at_mut(2);

        mem.read(left.as_mut_ptr() as u64, right).unwrap();
        assert_eq!(right, [1, 2]);

        right.copy_from_slice(&[3, 4]);
        mem.read(right.as_mut_ptr() as u64, left).unwrap();
        assert_eq!(left, [3, 4]);

        right.copy_from_slice(&[5, 6]);
        mem.write(left.as_mut_ptr() as u64, right).unwrap();
        assert_eq!(left, [5, 6]);

        left.copy_from_slice(&[7, 8]);
        mem.write(right.as_mut_ptr() as u64, left).unwrap();
        assert_eq!(right, [7, 8]);
    }

    #[test]
    fn guest_mem_empty_copies_preserve_bounds() {
        let mut backing = [1u8, 2, 3, 4];
        let base = backing.as_mut_ptr() as u64;
        // SAFETY: Backing stays initialized and mapped. No peer accesses it.
        let mem = unsafe { GuestMemOps::from_raw_parts(base, 4) };

        mem.read(base, &mut backing[..0]).unwrap();
        mem.write(base, &backing[..0]).unwrap();
        mem.read(base + 4, &mut []).unwrap();
        mem.write(base + 4, &[]).unwrap();

        assert_eq!(mem.read(base + 5, &mut []), Err(GuestMemError));
        assert_eq!(mem.write(base + 5, &[]), Err(GuestMemError));
        assert_eq!(backing, [1, 2, 3, 4]);
    }

    #[test]
    fn mapped_bytes_keep_the_slot_until_the_last_view_drops() {
        let mut backing = [u64::from_ne_bytes(*b"dataTAIL")];
        let base = backing.as_mut_ptr() as u64;
        // SAFETY: Backing remains live until all mapped views are dropped.
        let mem = unsafe { GuestMemOps::from_raw_parts(base, 8) };
        let layout = SlotLayout::new(base, 8, 1).unwrap();
        let pool = SlotPool::new(layout).unwrap();
        let allocation = pool.alloc(8).unwrap();
        let lease = BufferLease::new(pool.clone(), allocation);

        // SAFETY: The allocation is initialized and exclusively leased.
        let bytes = Bytes::from_owner(unsafe { mem.map_buffer(lease, 4) }.unwrap());
        assert_eq!(bytes.as_ref(), b"data");
        assert_eq!(bytes.as_ptr() as u64, base);

        let retained = bytes.slice(1..3);
        drop(bytes);
        assert_eq!(pool.num_free(), 0);
        assert_eq!(retained.as_ref(), b"at");
        assert_eq!(retained.as_ptr() as u64, base + 1);

        drop(retained);
        assert_eq!(pool.num_free(), 1);
    }

    #[test]
    fn failed_mapping_releases_its_lease() {
        let mut backing = [0u64; 2];
        let base = backing.as_mut_ptr() as u64;
        // SAFETY: Backing remains mapped for the accessor's lifetime.
        let mem = unsafe { GuestMemOps::from_raw_parts(base, 8) };
        let layout = SlotLayout::new(base + 8, 8, 1).unwrap();
        let pool = SlotPool::new(layout).unwrap();
        let allocation = pool.alloc(8).unwrap();
        let lease = BufferLease::new(pool.clone(), allocation);

        // SAFETY: The allocation is initialized and leased, but outside this accessor.
        assert!(unsafe { mem.map_buffer(lease, 8) }.is_err());
        assert_eq!(pool.num_free(), 1);
    }
}
