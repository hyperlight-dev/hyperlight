// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::cell::{RefCell, UnsafeCell};
use std::mem::ManuallyDrop;
use std::ops::Range;
use std::ptr::NonNull;
use std::rc::Rc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::thread::{self, ThreadId};

use hyperlight_common::virtq::{Allocation, BufferLease, BufferMap, MemOps};

#[derive(Clone)]
pub struct FuzzMem(Rc<Backing>);

struct Backing {
    storage: Box<[UnsafeCell<u64>]>,
    base_addr: u64,
    len: usize,
    mappings: RefCell<Vec<Allocation>>,
}

impl FuzzMem {
    pub fn new(base_addr: u64, len: usize) -> Self {
        Self(Rc::new(Backing {
            storage: (0..len.div_ceil(8)).map(|_| UnsafeCell::new(0)).collect(),
            base_addr,
            len,
            mappings: RefCell::new(Vec::new()),
        }))
    }

    fn range(&self, addr: u64, len: usize) -> Result<Range<usize>, ()> {
        let offset =
            usize::try_from(addr.checked_sub(self.0.base_addr).ok_or(())?).map_err(|_| ())?;
        let end = offset.checked_add(len).ok_or(())?;
        if end > self.0.len {
            return Err(());
        }
        Ok(offset..end)
    }

    fn ptr(&self, range: &Range<usize>) -> *mut u8 {
        self.0
            .storage
            .as_ptr()
            .cast::<u8>()
            .cast_mut()
            .wrapping_add(range.start)
    }

    fn assert_unmapped(&self, range: &Range<usize>) {
        if range.is_empty() {
            return;
        }
        for allocation in self.0.mappings.borrow().iter() {
            let mapped = self
                .range(allocation.addr, allocation.len as usize)
                .unwrap();
            assert!(
                range.end <= mapped.start || mapped.end <= range.start,
                "access overlaps a leased buffer"
            );
        }
    }
}

// SAFETY: All ranges are checked against stable, initialized storage. Atomic
// accesses check alignment. Writes cannot overlap retained immutable views.
unsafe impl MemOps for FuzzMem {
    type Error = ();

    fn read(&self, addr: u64, dst: &mut [u8]) -> Result<(), Self::Error> {
        let range = self.range(addr, dst.len())?;
        // SAFETY: Both ranges are valid. Copy permits overlapping ranges.
        unsafe { std::ptr::copy(self.ptr(&range), dst.as_mut_ptr(), dst.len()) };
        Ok(())
    }

    fn write(&self, addr: u64, src: &[u8]) -> Result<(), Self::Error> {
        let range = self.range(addr, src.len())?;
        self.assert_unmapped(&range);
        // SAFETY: The checked destination lies in UnsafeCell storage without
        // retained views. The harness accesses the backing on one thread.
        unsafe { std::ptr::copy(src.as_ptr(), self.ptr(&range), src.len()) };
        Ok(())
    }

    fn load_acquire(&self, addr: u64) -> Result<u16, Self::Error> {
        let range = self.range(addr, 2)?;
        let ptr = self.ptr(&range).cast::<AtomicU16>();
        if !ptr.is_aligned() {
            return Err(());
        }
        // SAFETY: The checked range is aligned, initialized, and live.
        Ok(u16::from_le(unsafe { (*ptr).load(Ordering::Acquire) }))
    }

    fn store_release(&self, addr: u64, val: u16) -> Result<(), Self::Error> {
        let range = self.range(addr, 2)?;
        let ptr = self.ptr(&range).cast::<AtomicU16>();
        if !ptr.is_aligned() {
            return Err(());
        }
        self.assert_unmapped(&range);
        // SAFETY: The checked range is aligned and live, without retained views.
        unsafe { (*ptr).store(val.to_le(), Ordering::Release) };
        Ok(())
    }

    unsafe fn as_slice(&self, addr: u64, len: usize) -> Result<&[u8], Self::Error> {
        let range = self.range(addr, len)?;
        // SAFETY: The range is initialized and live. The caller excludes writes.
        Ok(unsafe { std::slice::from_raw_parts(self.ptr(&range), len) })
    }

    #[allow(clippy::mut_from_ref)]
    unsafe fn as_mut_slice(&self, addr: u64, len: usize) -> Result<&mut [u8], Self::Error> {
        let range = self.range(addr, len)?;
        self.assert_unmapped(&range);
        // SAFETY: The range is initialized and live. The caller owns it exclusively.
        Ok(unsafe { std::slice::from_raw_parts_mut(self.ptr(&range), len) })
    }
}

pub struct Mapping {
    creator: ThreadId,
    owner: ManuallyDrop<MappingOwner>,
}

struct MappingOwner {
    data: NonNull<[u8]>,
    mem: FuzzMem,
    lease: BufferLease,
}

// SAFETY: Only immutable bytes are accessible across threads. Drop checks the
// creator thread before touching either Rc-backed owner.
unsafe impl Send for Mapping {}

impl AsRef<[u8]> for Mapping {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: The owner retains the backing and lease for this immutable view.
        unsafe { self.owner.data.as_ref() }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        assert_eq!(self.creator, thread::current().id());
        // SAFETY: Only the creator thread destroys the Rc-backed owner.
        unsafe { ManuallyDrop::drop(&mut self.owner) };
    }
}

impl Drop for MappingOwner {
    fn drop(&mut self) {
        let mut mappings = self.mem.0.mappings.borrow_mut();
        let index = mappings
            .iter()
            .position(|allocation| allocation.addr == self.lease.allocation().addr)
            .unwrap();
        // The view expires before field drop returns the lease to the pool.
        mappings.swap_remove(index);
    }
}

impl BufferMap for FuzzMem {
    type Mapping = Mapping;

    unsafe fn map_buffer(
        &self,
        lease: BufferLease,
        written: usize,
    ) -> Result<Self::Mapping, Self::Error> {
        let allocation = lease.allocation();
        assert!(written <= allocation.len as usize);
        let range = self.range(allocation.addr, allocation.len as usize)?;
        self.assert_unmapped(&range);
        self.0.mappings.borrow_mut().push(allocation);
        let ptr = NonNull::new(self.ptr(&range)).unwrap();
        Ok(Mapping {
            creator: thread::current().id(),
            owner: ManuallyDrop::new(MappingOwner {
                data: NonNull::slice_from_raw_parts(ptr, written),
                mem: self.clone(),
                lease,
            }),
        })
    }
}
