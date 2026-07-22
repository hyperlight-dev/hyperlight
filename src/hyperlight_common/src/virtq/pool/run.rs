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
//! Variable-sized contiguous-run pool.
//!
//! [`RunPool`] partitions one backing region into lower and upper tiers with
//! compile-time slot sizes. The lower tier is carved from the first eighth of
//! the aligned usable region. Eligible requests try that tier first and fall
//! back to the upper tier only when no contiguous lower-tier run is available.
//!
//! Allocations are rounded to a tier's slot size and occupy contiguous runs, so
//! scatter/gather requests produce one allocation. Occupied-slot and run-start
//! bitmaps support reclaiming a complete run by its start address, while a
//! cached free run accelerates immediate reuse. This preserves contiguous
//! buffers but remains subject to fragmentation.

use alloc::rc::Rc;
use core::cell::RefCell;

use fixedbitset::FixedBitSet;
use smallvec::SmallVec;

use super::{AllocError, Allocation, BufferProvider, SendWrap, align_up};

#[derive(Debug, Clone)]
pub(super) struct Tier<const N: usize> {
    pub(super) base_addr: u64,
    pub(super) used_slots: FixedBitSet,
    pub(super) run_starts: FixedBitSet,
    pub(super) last_free_run: Option<Allocation>,
}

impl<const N: usize> Tier<N> {
    fn new(base_addr: u64, region_len: usize) -> Result<Self, AllocError> {
        let usable = region_len - (region_len % N);
        let num_slots = usable / N;
        let used_slots = FixedBitSet::with_capacity(num_slots);
        let run_starts = FixedBitSet::with_capacity(num_slots);

        if !base_addr.is_multiple_of(N as u64) {
            return Err(AllocError::InvalidAlign(base_addr));
        }
        if num_slots == 0 {
            return Err(AllocError::EmptyRegion);
        }

        Ok(Self {
            base_addr,
            used_slots,
            run_starts,
            last_free_run: None,
        })
    }

    fn addr_of(&self, slot_idx: usize) -> Option<u64> {
        self.base_addr
            .checked_add((slot_idx as u64).checked_mul(N as u64)?)
    }

    fn slot_of(&self, addr: u64) -> usize {
        let off = (addr - self.base_addr) as usize;
        off / N
    }

    fn checked_slot_of(&self, addr: u64, len: usize) -> Result<usize, AllocError> {
        if addr < self.base_addr {
            return Err(AllocError::InvalidFree(addr, len));
        }

        let off = (addr - self.base_addr) as usize;
        if !off.is_multiple_of(N) {
            return Err(AllocError::InvalidFree(addr, len));
        }

        let slot = off / N;
        if slot >= self.used_slots.len() {
            return Err(AllocError::InvalidFree(addr, len));
        }

        Ok(slot)
    }

    fn live_run_slots_at(&self, start: usize) -> Option<usize> {
        if start >= self.used_slots.len()
            || !self.used_slots.contains(start)
            || !self.run_starts.contains(start)
        {
            return None;
        }

        let mut end = start + 1;
        while end < self.used_slots.len()
            && self.used_slots.contains(end)
            && !self.run_starts.contains(end)
        {
            end += 1;
        }

        Some(end - start)
    }

    fn maybe_invalidate_last_run(&mut self, alloc: Allocation) {
        if let Some(run) = &self.last_free_run {
            let new_end = alloc.addr + alloc.len as u64;
            let run_end = run.addr + run.len as u64;

            if alloc.addr < run_end && run.addr < new_end {
                self.last_free_run = None;
            }
        }
    }

    fn find_slots(&mut self, slots_num: usize) -> Option<usize> {
        debug_assert!(slots_num > 0);

        if let Some(alloc) = self.last_free_run
            && alloc.len >= slots_num * N
        {
            let pos = self.slot_of(alloc.addr);
            let _ = self.last_free_run.take();
            return Some(pos);
        }

        let total = self.used_slots.len();
        self.used_slots.zeroes().find(|&next_free| {
            let end = next_free + slots_num;
            end <= total && self.used_slots.count_zeroes(next_free..end) == slots_num
        })
    }

    pub(super) fn alloc(&mut self, len: usize) -> Result<Allocation, AllocError> {
        if len == 0 {
            return Err(AllocError::InvalidArg);
        }

        let total = self.used_slots.len();
        let need_slots = len.div_ceil(N);
        if need_slots > total {
            return Err(AllocError::OutOfMemory);
        }

        let idx = self.find_slots(need_slots).ok_or(AllocError::NoSpace)?;
        self.used_slots.insert_range(idx..idx + need_slots);
        self.run_starts.insert(idx);
        let addr = self.addr_of(idx).ok_or(AllocError::Overflow)?;

        let alloc = Allocation {
            addr,
            len: need_slots * N,
        };

        self.maybe_invalidate_last_run(alloc);
        Ok(alloc)
    }

    fn dealloc_addr(&mut self, addr: u64) -> Result<(), AllocError> {
        let start = self.checked_slot_of(addr, 0)?;
        let run_slots = self
            .live_run_slots_at(start)
            .ok_or(AllocError::InvalidFree(addr, 0))?;
        self.dealloc_run(start, run_slots, addr)
    }

    fn dealloc_run(&mut self, start: usize, run_slots: usize, addr: u64) -> Result<(), AllocError> {
        let len = run_slots * N;
        self.used_slots.remove_range(start..start + run_slots);
        self.run_starts.set(start, false);
        self.last_free_run = Some(Allocation { addr, len });
        Ok(())
    }

    fn allocation_len(&self, addr: u64) -> Result<usize, AllocError> {
        let start = self.checked_slot_of(addr, 0)?;
        let run_slots = self
            .live_run_slots_at(start)
            .ok_or(AllocError::InvalidFree(addr, 0))?;
        Ok(run_slots * N)
    }

    pub(super) fn capacity(&self) -> usize {
        self.used_slots.len() * N
    }

    pub(super) fn range(&self) -> core::ops::Range<u64> {
        self.base_addr..self.base_addr + self.capacity() as u64
    }

    pub(super) fn contains(&self, addr: u64) -> bool {
        self.range().contains(&addr)
    }
}

#[cfg(test)]
impl<const N: usize> Tier<N> {
    pub(super) fn free_bytes(&self) -> usize {
        (self.used_slots.len() - self.used_slots.count_ones(..)) * N
    }
}

#[derive(Debug)]
pub(super) struct Inner<const L: usize, const U: usize> {
    pub(super) lower: Tier<L>,
    pub(super) upper: Tier<U>,
}

// SAFETY: only sound for single-threaded (guest-side) access; see the
// type-level invariant on `SendWrap`.
unsafe impl<const L: usize, const U: usize> Send for SendWrap<Rc<RefCell<Inner<L, U>>>> {}

/// Two-tier pool for variable-sized contiguous runs.
#[derive(Debug, Clone)]
pub struct RunPool<const L: usize = 256, const U: usize = 4096> {
    pub(super) inner: SendWrap<Rc<RefCell<Inner<L, U>>>>,
}

impl<const L: usize, const U: usize> RunPool<L, U> {
    /// Create a new run pool over a fixed region.
    pub fn new(base_addr: u64, region_len: usize) -> Result<Self, AllocError> {
        let inner = Inner::<L, U>::new(base_addr, region_len)?;
        Ok(Self {
            inner: SendWrap(Rc::new(RefCell::new(inner))),
        })
    }
}

impl RunPool {
    /// Upper tier slot size in bytes.
    pub const fn upper_slot_size() -> usize {
        4096
    }

    /// Lower tier slot size in bytes.
    pub const fn lower_slot_size() -> usize {
        256
    }
}

#[cfg(all(test, loom))]
#[derive(Debug, Clone)]
pub struct RunPoolSync<const L: usize = 256, const U: usize = 4096> {
    inner: std::sync::Arc<std::sync::Mutex<Inner<L, U>>>,
}

#[cfg(all(test, loom))]
impl<const L: usize, const U: usize> RunPoolSync<L, U> {
    /// Create a new synchronized run pool over a fixed region.
    pub fn new(base_addr: u64, region_len: usize) -> Result<Self, AllocError> {
        let inner = Inner::<L, U>::new(base_addr, region_len)?;
        Ok(Self {
            inner: std::sync::Arc::new(std::sync::Mutex::new(inner)),
        })
    }
}

impl<const L: usize, const U: usize> Inner<L, U> {
    /// Create new run-pool state over a fixed region.
    pub fn new(base_addr: u64, region_len: usize) -> Result<Self, AllocError> {
        const LOWER_FRACTION: usize = 8;

        let base = usize::try_from(base_addr).map_err(|_| AllocError::Overflow)?;
        let region_end = base.checked_add(region_len).ok_or(AllocError::Overflow)?;

        let lower_base = align_up(base, L)?;
        let usable = region_end
            .checked_sub(lower_base)
            .ok_or(AllocError::EmptyRegion)?;

        let lower_region = usable / LOWER_FRACTION;
        let lower = Tier::<L>::new(lower_base as u64, lower_region)?;

        let upper_base = lower_base
            .checked_add(lower.capacity())
            .ok_or(AllocError::Overflow)?;

        let upper_base = align_up(upper_base, U)?;
        let upper_region = region_end
            .checked_sub(upper_base)
            .ok_or(AllocError::EmptyRegion)?;

        let upper = Tier::<U>::new(upper_base as u64, upper_region)?;
        Ok(Self { lower, upper })
    }

    /// Allocate at least `len` bytes.
    pub fn alloc(&mut self, len: usize) -> Result<Allocation, AllocError> {
        if len <= L {
            match self.lower.alloc(len) {
                Ok(alloc) => return Ok(alloc),
                Err(AllocError::NoSpace) => {}
                Err(e) => return Err(e),
            }
        }

        // Fall back to the upper tier.
        self.upper.alloc(len)
    }

    /// Free a previously allocated block by its start address.
    pub fn dealloc_addr(&mut self, addr: u64) -> Result<(), AllocError> {
        if self.lower.contains(addr) {
            self.lower.dealloc_addr(addr)
        } else {
            self.upper.dealloc_addr(addr)
        }
    }

    /// Capacity of a live allocation by its start address.
    pub fn allocation_len(&self, addr: u64) -> Result<usize, AllocError> {
        if self.lower.contains(addr) {
            self.lower.allocation_len(addr)
        } else {
            self.upper.allocation_len(addr)
        }
    }
}

impl<const L: usize, const U: usize> BufferProvider for RunPool<L, U> {
    fn max_alloc_len(&self) -> usize {
        U
    }

    fn alloc(&self, len: usize) -> Result<Allocation, AllocError> {
        self.inner.borrow_mut().alloc(len)
    }

    fn alloc_sg(&self, total_len: usize) -> Result<SmallVec<[Allocation; 4]>, AllocError> {
        Ok(smallvec::smallvec![self.alloc(total_len)?])
    }

    fn dealloc(&self, addr: u64) -> Result<(), AllocError> {
        self.inner.borrow_mut().dealloc_addr(addr)
    }
}

impl<const L: usize, const U: usize> RunPool<L, U> {
    /// Free a previously allocated block by its start address.
    pub fn dealloc_addr(&self, addr: u64) -> Result<(), AllocError> {
        self.inner.borrow_mut().dealloc_addr(addr)
    }

    /// Capacity of a live allocation by its start address.
    pub fn allocation_len(&self, addr: u64) -> Result<usize, AllocError> {
        self.inner.borrow().allocation_len(addr)
    }
}

#[cfg(all(test, loom))]
impl<const L: usize, const U: usize> BufferProvider for RunPoolSync<L, U> {
    fn max_alloc_len(&self) -> usize {
        U
    }

    fn alloc(&self, len: usize) -> Result<Allocation, AllocError> {
        self.inner.lock().expect("poisoned mutex").alloc(len)
    }

    fn alloc_sg(&self, total_len: usize) -> Result<SmallVec<[Allocation; 4]>, AllocError> {
        Ok(smallvec::smallvec![self.alloc(total_len)?])
    }

    fn dealloc(&self, addr: u64) -> Result<(), AllocError> {
        self.inner
            .lock()
            .expect("poisoned mutex")
            .dealloc_addr(addr)
    }
}
