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
//! Buffer pool implementations for virtqueue buffer management.
//!
//! This module provides concrete buffer allocators:
//!
//! - [`BufferPool`] - a two-tier bitmap pool with small and large slabs,
//!   intended for G2H descriptors where allocation sizes vary.
//! - [`RecyclePool`] - a fixed-size free-list recycler for H2G prefill
//!   entries where all buffers are the same size.
//!
//! Both implement [`BufferProvider`] from the [`super::buffer`] module.
//!
//! # BufferPool design
//!
//! The core allocation strategy is a bitmap allocator that performs a linear
//! search over the bitmap, but implemented via `fixedbitset`'s SIMD iteration
//! over zero bits.
//!
//! # Two-tier layout
//!
//! [`BufferPool`] divides the underlying region into two slabs with different
//! slot sizes:
//!
//! - The lower tier (`Slab<L>`, default `L = 256`) is intended for
//!   *smaller allocations* - control messages, descriptor metadata, and other
//!   small structures. Small allocations first try this tier.
//! - The upper tier (`Slab<U>`, default `U = 4096`) uses page sized slots
//!   and is intended for larger data buffers.

use alloc::rc::Rc;
use core::cell::RefCell;
use core::cmp::Ordering;
use core::ops::Deref;

use fixedbitset::FixedBitSet;
use smallvec::SmallVec;

use super::buffer::{AllocError, Allocation, BufferProvider};

/// Wrapper asserting `Send + Sync` for single-threaded contexts.
///
/// # Safety
///
/// The wrapped value must only be accessed from a single thread.
#[derive(Debug)]
pub(super) struct SyncWrap<T>(pub(super) T);

// SAFETY: The wrapped value must only be accessed from a single thread.
unsafe impl<T> Send for SyncWrap<T> {}
// SAFETY: The wrapped value must only be accessed from a single thread.
unsafe impl<T> Sync for SyncWrap<T> {}

impl<T: Clone> Clone for SyncWrap<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Deref for SyncWrap<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct Slab<const N: usize> {
    /// Base address of the slab
    base_addr: u64,
    /// Flat bitmap to track allocated/free slots
    used_slots: FixedBitSet,
    /// Last free allocation cache
    last_free_run: Option<Allocation>,
}

impl<const N: usize> Slab<N> {
    /// Create a new slab allocator over a fixed region.
    /// Region is rounded down to a multiple of N.
    pub fn new(base_addr: u64, region_len: usize) -> Result<Self, AllocError> {
        let usable = region_len - (region_len % N);
        let num_slots = usable / N;
        let used_slots = FixedBitSet::with_capacity(num_slots);

        if base_addr % (N as u64) != 0 {
            return Err(AllocError::InvalidAlign(base_addr));
        }

        if num_slots == 0 {
            return Err(AllocError::EmptyRegion);
        }

        Ok(Self {
            base_addr,
            used_slots,
            last_free_run: None,
        })
    }

    /// Get the address of a slot by its index
    #[inline]
    fn addr_of(&self, slot_idx: usize) -> Option<u64> {
        self.base_addr
            .checked_add((slot_idx as u64).checked_mul(N as u64)?)
    }

    /// Get the slot index for a given address
    #[inline]
    fn slot_of(&self, addr: u64) -> usize {
        let off = (addr - self.base_addr) as usize;
        off / N
    }

    /// Invalidate last_free_run cache if it overlaps with the given allocation.
    fn maybe_invalidate_last_run(&mut self, alloc: Allocation) {
        if let Some(run) = &self.last_free_run {
            let new_end = alloc.addr + alloc.len as u64;
            let run_end = run.addr + run.len as u64;

            if alloc.addr < run_end && run.addr < new_end {
                self.last_free_run = None;
            }
        }
    }

    /// Find a run of slots to satisfy at least `len` bytes starting at `start`.
    pub fn find_slots(&mut self, slots_num: usize) -> Option<usize> {
        debug_assert!(slots_num > 0);

        // Check last free run optimization
        if let Some(alloc) = self.last_free_run
            && alloc.len >= slots_num * N
        {
            let pos = self.slot_of(alloc.addr);
            let _ = self.last_free_run.take();
            return Some(pos);
        }

        // Fallback to full search
        let total = self.used_slots.len();
        self.used_slots.zeroes().find(|&next_free| {
            let end = next_free + slots_num;
            end <= total && self.used_slots.count_zeroes(next_free..end) == slots_num
        })
    }

    /// Allocate at least `len` bytes by merging consecutive slots.
    pub fn alloc(&mut self, len: usize) -> Result<Allocation, AllocError> {
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
        let addr = self.addr_of(idx).ok_or(AllocError::Overflow)?;

        let alloc = Allocation {
            addr,
            len: need_slots * N,
        };

        self.maybe_invalidate_last_run(alloc);
        Ok(alloc)
    }

    /// Free a previously allocated slot or multiple slots.
    ///
    /// `len` must be a multiple of N and `addr` must be N-aligned to base.
    pub fn dealloc(&mut self, alloc: Allocation) -> Result<(), AllocError> {
        let Allocation { addr, len } = alloc;
        if len == 0 || len % N != 0 || addr < self.base_addr {
            return Err(AllocError::InvalidFree(addr, len));
        }
        let alloc_slots = len / N;
        let off = (addr - self.base_addr) as usize;
        if off % N != 0 {
            return Err(AllocError::InvalidFree(addr, len));
        }
        let start = off / N;
        let num_slots = self.used_slots.len();
        if start + alloc_slots > num_slots {
            return Err(AllocError::InvalidFree(addr, len));
        }

        // Ensure all bits are set (avoid double-free)
        if !self
            .used_slots
            .contains_all_in_range(start..start + alloc_slots)
        {
            return Err(AllocError::InvalidFree(addr, len));
        }

        // Mark as free
        self.used_slots.remove_range(start..start + alloc_slots);
        self.last_free_run = Some(alloc);

        Ok(())
    }

    /// Try to grow a block in place by reserving adjacent free slots to the right.
    ///
    /// Returns Ok(None) if in-place growth is not possible. Returns Err on invalid input.
    pub fn try_grow_inplace(
        &mut self,
        old_alloc: Allocation,
        new_len: usize,
    ) -> Result<Option<Allocation>, AllocError> {
        let Allocation {
            addr: old_addr,
            len: old_len,
        } = old_alloc;

        if new_len <= old_len || old_len == 0 || old_len % N != 0 {
            return Err(AllocError::InvalidFree(old_addr, old_len));
        }

        let old_slots = old_len / N;
        let need_slots = new_len.div_ceil(N);
        let off = (old_addr - self.base_addr) as usize;
        if off % N != 0 {
            return Err(AllocError::InvalidFree(old_addr, old_len));
        }

        let start = off / N;
        if start + need_slots > self.used_slots.len() {
            return Ok(None);
        }
        // Existing range must be allocated
        if !self
            .used_slots
            .contains_all_in_range(start..start + old_slots)
        {
            return Err(AllocError::InvalidFree(old_addr, old_len));
        }

        // Extension must be free
        if self
            .used_slots
            .count_ones(start + old_slots..start + need_slots)
            > 0
        {
            return Ok(None);
        }

        // Mark extension as allocated
        self.used_slots
            .insert_range(start + old_slots..start + need_slots);

        let alloc = Allocation {
            addr: old_addr,
            len: need_slots * N,
        };

        self.maybe_invalidate_last_run(alloc);
        Ok(Some(alloc))
    }

    /// Shrink a block in place by freeing excess slots to the right.
    pub fn shrink_inplace(
        &mut self,
        old_alloc: Allocation,
        new_len: usize,
    ) -> Result<Allocation, AllocError> {
        let Allocation {
            addr: old_addr,
            len: old_len,
        } = old_alloc;

        if new_len >= old_len || old_len == 0 || old_len % N != 0 {
            return Err(AllocError::InvalidFree(old_addr, old_len));
        }

        let old_slots = old_len / N;
        let need_slots = new_len.div_ceil(N);
        let off = (old_addr - self.base_addr) as usize;
        if off % N != 0 {
            return Err(AllocError::InvalidFree(old_addr, old_len));
        }

        let start = off / N;
        if start + old_slots > self.used_slots.len() {
            return Err(AllocError::InvalidFree(old_addr, old_len));
        }
        // Existing range must be allocated
        if !self
            .used_slots
            .contains_all_in_range(start..start + old_slots)
        {
            return Err(AllocError::InvalidFree(old_addr, old_len));
        }

        // Free the excess slots
        self.used_slots
            .remove_range(start + need_slots..start + old_slots);

        Ok(Allocation {
            addr: old_addr,
            len: need_slots * N,
        })
    }

    /// Reallocate by trying in-place grow; otherwise reserve a new run of slots and free old.
    /// Caller should copy the payload; this function only manages reservations.
    pub fn resize(
        &mut self,
        old_alloc: Allocation,
        new_len: usize,
    ) -> Result<Allocation, AllocError> {
        if new_len == 0 {
            return Err(AllocError::InvalidArg);
        }

        match new_len.cmp(&old_alloc.len) {
            Ordering::Greater => {
                match self.try_grow_inplace(old_alloc, new_len) {
                    // in-place growth succeeded
                    Ok(Some(new_alloc)) => Ok(new_alloc),
                    // in-place growth failed; allocate new and free old
                    Ok(None) => {
                        let new_alloc = self.alloc(new_len)?;
                        self.dealloc(old_alloc)?;
                        Ok(new_alloc)
                    }
                    // other errors are propagated
                    Err(err) => Err(err),
                }
            }
            Ordering::Less => self.shrink_inplace(old_alloc, new_len),
            Ordering::Equal => Ok(old_alloc),
        }
    }

    /// Usable size rounded up to slot multiple.
    pub fn usable_size(&self, _addr: usize, len: usize) -> usize {
        if len == 0 { 0 } else { len.div_ceil(N) * N }
    }

    /// Number of free bytes in the slab.
    pub fn free_bytes(&self) -> usize {
        (self.used_slots.len() - self.used_slots.count_ones(..)) * N
    }

    /// Total capacity of the slab in bytes.
    pub fn capacity(&self) -> usize {
        self.used_slots.len() * N
    }

    /// Get the address range covered by this slab.
    pub fn range(&self) -> core::ops::Range<u64> {
        let end = self.base_addr + self.capacity() as u64;
        self.base_addr..end
    }

    /// Check if an address is within this slab's range.
    pub fn contains(&self, addr: u64) -> bool {
        self.range().contains(&addr)
    }

    /// Get the slot size N.
    pub const fn slot_size() -> usize {
        N
    }

    /// Reset the slab to initial state which is all slots free.
    pub fn reset(&mut self) {
        self.used_slots.clear();
        self.last_free_run = None;
    }
}

#[inline]
fn align_up(val: usize, align: usize) -> usize {
    assert!(align > 0);
    if val == 0 {
        return 0;
    }
    val.div_ceil(align) * align
}

#[derive(Debug)]
struct Inner<const L: usize, const U: usize> {
    lower: Slab<L>,
    upper: Slab<U>,
}

/// Two tier buffer pool with small and large slabs.
#[derive(Debug, Clone)]
pub struct BufferPool<const L: usize = 256, const U: usize = 4096> {
    inner: SyncWrap<Rc<RefCell<Inner<L, U>>>>,
}

impl<const L: usize, const U: usize> BufferPool<L, U> {
    /// Create a new buffer pool over a fixed region.
    pub fn new(base_addr: u64, region_len: usize) -> Result<Self, AllocError> {
        let inner = Inner::<L, U>::new(base_addr, region_len)?;
        Ok(Self {
            inner: SyncWrap(Rc::new(RefCell::new(inner))),
        })
    }
}

impl BufferPool {
    /// Upper slab slot size in bytes.
    pub const fn upper_slot_size() -> usize {
        4096
    }

    /// Lower slab slot size in bytes.
    pub const fn lower_slot_size() -> usize {
        256
    }
}

#[cfg(all(test, loom))]
#[derive(Debug, Clone)]
pub struct BufferPoolSync<const L: usize = 256, const U: usize = 4096> {
    inner: std::sync::Arc<std::sync::Mutex<Inner<L, U>>>,
}

#[cfg(all(test, loom))]
impl<const L: usize, const U: usize> BufferPoolSync<L, U> {
    /// Create a new buffer pool over a fixed region.
    pub fn new(base_addr: u64, region_len: usize) -> Result<Self, AllocError> {
        let inner = Inner::<L, U>::new(base_addr, region_len)?;
        Ok(Self {
            inner: Arc::new(std::sync::Mutex::new(inner)),
        })
    }
}

impl<const L: usize, const U: usize> Inner<L, U> {
    /// Create a new buffer pool over a fixed region.
    pub fn new(base_addr: u64, region_len: usize) -> Result<Self, AllocError> {
        const LOWER_FRACTION: usize = 8;

        let lower_region = region_len / LOWER_FRACTION;
        let upper_region = region_len - lower_region;

        let mut aligned = base_addr;
        aligned = align_up(aligned as usize, L) as u64;
        let lower = Slab::<L>::new(aligned, lower_region)?;

        // advance and align upper base to N
        aligned = aligned
            .checked_add(lower.capacity() as u64)
            .ok_or(AllocError::Overflow)?;

        aligned = align_up(aligned as usize, U) as u64;
        let upper = Slab::<U>::new(aligned, upper_region)?;

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

        // fallback to upper slab
        self.upper.alloc(len)
    }

    /// Free a previously allocated block.
    pub fn dealloc(&mut self, alloc: Allocation) -> Result<(), AllocError> {
        if self.lower.contains(alloc.addr) {
            self.lower.dealloc(alloc)
        } else {
            self.upper.dealloc(alloc)
        }
    }

    /// Reallocate by trying in-place grow; otherwise reserve a new block and free old.
    pub fn resize(
        &mut self,
        old_alloc: Allocation,
        new_len: usize,
    ) -> Result<Allocation, AllocError> {
        if self.lower.contains(old_alloc.addr) {
            maybe_move(&mut self.lower, &mut self.upper, old_alloc, new_len)
        } else {
            maybe_move(&mut self.upper, &mut self.lower, old_alloc, new_len)
        }
    }
}

/// Try to realloc using slab that owns the old allocation; if that fails,
/// try to allocate in the other slab. The function prefers to move allocations
/// between slabs only when necessary based on size thresholds.
#[inline]
fn maybe_move<const A: usize, const B: usize>(
    slab: &mut Slab<A>,
    other: &mut Slab<B>,
    old_alloc: Allocation,
    new_len: usize,
) -> Result<Allocation, AllocError> {
    let needs_move = if A < B { new_len > A } else { new_len <= B };
    if !needs_move {
        return slab.resize(old_alloc, new_len);
    }

    let new_alloc = other.alloc(new_len)?;

    slab.dealloc(old_alloc)?;
    Ok(new_alloc)
}

impl<const L: usize, const U: usize> BufferProvider for BufferPool<L, U> {
    fn alloc(&self, len: usize) -> Result<Allocation, AllocError> {
        self.inner.borrow_mut().alloc(len)
    }

    fn dealloc(&self, alloc: Allocation) -> Result<(), AllocError> {
        self.inner.borrow_mut().dealloc(alloc)
    }

    fn resize(&self, old_alloc: Allocation, new_len: usize) -> Result<Allocation, AllocError> {
        self.inner.borrow_mut().resize(old_alloc, new_len)
    }

    fn reset(&self) {
        let mut inner = self.inner.borrow_mut();
        inner.lower.reset();
        inner.upper.reset();
    }
}

#[cfg(all(test, loom))]
impl<const L: usize, const U: usize> BufferProvider for BufferPoolSync<L, U> {
    fn alloc(&self, len: usize) -> Result<Allocation, AllocError> {
        self.inner.lock().expect("poisoned mutex").alloc(len)
    }

    fn dealloc(&self, alloc: Allocation) -> Result<(), AllocError> {
        self.inner.lock().expect("poisoned mutex").dealloc(alloc)
    }

    fn resize(&self, old_alloc: Allocation, new_len: usize) -> Result<Allocation, AllocError> {
        self.inner
            .lock()
            .expect("poisoned mutex")
            .resize(old_alloc, new_len)
    }
}

struct RecyclePoolInner {
    base_addr: u64,
    slot_size: usize,
    count: usize,
    free: SmallVec<[u64; 64]>,
}

/// A recycling buffer provider with fixed-size slots.
///
/// Unlike [`BufferPool`] which uses a bitmap allocator, this holds a
/// fixed set of same-sized buffer addresses in a free list. Alloc and
/// dealloc are O(1). Intended for H2G writable buffers that are
/// pre-allocated once and recycled after each use.
#[derive(Clone)]
pub struct RecyclePool {
    inner: SyncWrap<Rc<RefCell<RecyclePoolInner>>>,
}

impl RecyclePool {
    /// Create a new recycling pool by carving `base..base+region_len` into slots of `slot_size` bytes.
    pub fn new(base_addr: u64, region_len: usize, slot_size: usize) -> Result<Self, AllocError> {
        if slot_size == 0 {
            return Err(AllocError::InvalidArg);
        }

        let count = region_len / slot_size;
        if count == 0 {
            return Err(AllocError::EmptyRegion);
        }

        let mut free = SmallVec::with_capacity(count);
        for i in 0..count {
            free.push(base_addr + (i * slot_size) as u64);
        }

        let inner = RefCell::new(RecyclePoolInner {
            base_addr,
            slot_size,
            count,
            free,
        });

        Ok(Self {
            inner: SyncWrap(Rc::new(inner)),
        })
    }

    /// Rebuild pool state so that every address in `allocated` is removed
    /// from the free list, matching externally known inflight state.
    pub fn restore_allocated(&self, allocated: &[u64]) -> Result<(), AllocError> {
        self.reset();

        if allocated.is_empty() {
            return Ok(());
        }

        let mut inner = self.inner.borrow_mut();

        for &addr in allocated {
            let pos = inner
                .free
                .iter()
                .position(|&a| a == addr)
                .ok_or(AllocError::InvalidFree(addr, inner.slot_size))?;

            inner.free.swap_remove(pos);
        }

        Ok(())
    }

    /// Compute the address of slot `index`.
    ///
    /// Returns `None` if `index >= count`.
    pub fn slot_addr(&self, index: usize) -> Option<u64> {
        let inner = self.inner.borrow();
        if index < inner.count {
            Some(inner.base_addr + (index * inner.slot_size) as u64)
        } else {
            None
        }
    }

    /// Number of free slots.
    pub fn num_free(&self) -> usize {
        self.inner.borrow().free.len()
    }

    /// Base address of the pool region.
    pub fn base_addr(&self) -> u64 {
        self.inner.borrow().base_addr
    }

    /// Slot size in bytes.
    pub fn slot_size(&self) -> usize {
        self.inner.borrow().slot_size
    }

    /// Number of slots in the pool.
    pub fn count(&self) -> usize {
        self.inner.borrow().count
    }
}

impl BufferProvider for RecyclePool {
    fn alloc(&self, len: usize) -> Result<Allocation, AllocError> {
        let mut inner = self.inner.borrow_mut();
        if len > inner.slot_size {
            return Err(AllocError::OutOfMemory);
        }

        let addr = inner.free.pop().ok_or(AllocError::NoSpace)?;

        Ok(Allocation {
            addr,
            len: inner.slot_size,
        })
    }

    fn dealloc(&self, alloc: Allocation) -> Result<(), AllocError> {
        let mut inner = self.inner.borrow_mut();
        let end = inner.base_addr + (inner.count * inner.slot_size) as u64;

        if alloc.addr < inner.base_addr || alloc.addr >= end {
            return Err(AllocError::InvalidFree(alloc.addr, alloc.len));
        }

        if (alloc.addr - inner.base_addr) % inner.slot_size as u64 != 0 {
            return Err(AllocError::InvalidFree(alloc.addr, alloc.len));
        }

        if inner.free.contains(&alloc.addr) {
            return Err(AllocError::InvalidFree(alloc.addr, alloc.len));
        }

        inner.free.push(alloc.addr);
        Ok(())
    }

    fn resize(&self, old: Allocation, new_len: usize) -> Result<Allocation, AllocError> {
        let inner = self.inner.borrow();
        if new_len > inner.slot_size {
            return Err(AllocError::OutOfMemory);
        }
        Ok(old)
    }

    fn reset(&self) {
        let mut inner = self.inner.borrow_mut();
        let base = inner.base_addr;
        let slot = inner.slot_size;
        let count = inner.count;

        inner.free.clear();

        for i in 0..count {
            inner.free.push(base + (i * slot) as u64);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_slab<const N: usize>(size: usize) -> Slab<N> {
        let base = align_up(0x10000, N) as u64;
        Slab::<N>::new(base, size).unwrap()
    }

    fn make_pool<const L: usize, const U: usize>(size: usize) -> BufferPool<L, U> {
        let base = align_up(0x10000, L.max(U)) as u64;
        BufferPool::<L, U>::new(base, size).unwrap()
    }

    fn make_recycle_pool(slot_count: usize, slot_size: usize) -> RecyclePool {
        let base = 0x80000u64;
        RecyclePool::new(base, slot_count * slot_size, slot_size).unwrap()
    }

    #[test]
    fn test_slab_new_success() {
        let slab = Slab::<256>::new(0x10000, 1024).unwrap();
        assert_eq!(slab.capacity(), 1024);
        assert_eq!(slab.free_bytes(), 1024);
    }

    #[test]
    fn test_slab_new_misaligned() {
        let result = Slab::<256>::new(0x10001, 1024);
        assert!(matches!(result, Err(AllocError::InvalidAlign(0x10001))));
    }

    #[test]
    fn test_slab_new_empty_region() {
        let result = Slab::<256>::new(0x10000, 100);
        assert!(matches!(result, Err(AllocError::EmptyRegion)));
    }

    #[test]
    fn test_slab_alloc_single_slot() {
        let mut slab = make_slab::<256>(1024);
        let alloc = slab.alloc(128).unwrap();
        assert_eq!(alloc.len, 256);
        assert_eq!(slab.free_bytes(), 1024 - 256);
    }

    #[test]
    fn test_slab_alloc_multiple_slots() {
        let mut slab = make_slab::<256>(1024);
        let alloc = slab.alloc(600).unwrap();
        assert_eq!(alloc.len, 768); // 3 slots × 256 bytes
        assert_eq!(slab.free_bytes(), 1024 - 768);
    }

    #[test]
    fn test_slab_alloc_zero_length() {
        let mut slab = make_slab::<256>(1024);
        let result = slab.alloc(0);
        assert!(matches!(result, Err(AllocError::InvalidArg)));
    }

    #[test]
    fn test_slab_alloc_too_large() {
        let mut slab = make_slab::<256>(1024);
        let result = slab.alloc(2048);
        assert!(matches!(result, Err(AllocError::OutOfMemory)));
    }

    #[test]
    fn test_slab_alloc_until_full() {
        let mut slab = make_slab::<256>(1024);

        // Allocate all 4 slots
        let _a1 = slab.alloc(256).unwrap();
        let a2 = slab.alloc(256).unwrap();
        let _a3 = slab.alloc(256).unwrap();
        let _a4 = slab.alloc(256).unwrap();

        assert_eq!(slab.free_bytes(), 0);

        // Next allocation should fail
        let result = slab.alloc(256);
        assert!(matches!(result, Err(AllocError::NoSpace)));

        // Free one and retry
        slab.dealloc(a2).unwrap();
        let a5 = slab.alloc(256).unwrap();
        assert_eq!(a5.addr, a2.addr); // Should reuse same slot
    }

    #[test]
    fn test_slab_free_success() {
        let mut slab = make_slab::<256>(1024);
        let alloc = slab.alloc(256).unwrap();
        assert_eq!(slab.free_bytes(), 768);

        slab.dealloc(alloc).unwrap();
        assert_eq!(slab.free_bytes(), 1024);
    }

    #[test]
    fn test_slab_free_invalid_length() {
        let mut slab = make_slab::<256>(1024);
        let mut alloc = slab.alloc(256).unwrap();
        alloc.len = 100; // Invalid: not multiple of N

        let result = slab.dealloc(alloc);
        assert!(matches!(result, Err(AllocError::InvalidFree(_, 100))));
    }

    #[test]
    fn test_slab_free_double_free() {
        let mut slab = make_slab::<256>(1024);
        let alloc = slab.alloc(256).unwrap();

        slab.dealloc(alloc).unwrap();
        let result = slab.dealloc(alloc);
        assert!(matches!(result, Err(AllocError::InvalidFree(_, _))));
    }

    #[test]
    fn test_slab_multi_slot_alloc_near_end() {
        let mut slab = make_slab::<256>(1792); // 7 slots
        let a0 = slab.alloc(256).unwrap();
        let a1 = slab.alloc(256).unwrap();
        let _a2 = slab.alloc(256).unwrap();
        let _a3 = slab.alloc(256).unwrap();
        let _a4 = slab.alloc(256).unwrap();
        let _a5 = slab.alloc(256).unwrap();
        let _a6 = slab.alloc(256).unwrap();

        slab.dealloc(a0).unwrap();
        slab.dealloc(a1).unwrap();

        // 2-slot run fits at indices 0..2 but the search visits index 6
        // (a free zero) first if slots 0-1 are not found before it.
        // Actually slots 0-1 are free, so it should find them.
        let run = slab.alloc(300).unwrap(); // needs 2 slots
        assert_eq!(run.len, 512);
    }

    #[test]
    fn test_slab_multi_slot_alloc_no_room_at_end() {
        // Only the last slot is free but a 2-slot run is requested.
        // find_slots must not panic when checking beyond the bitset.
        let mut slab = make_slab::<256>(1792); // 7 slots
        let allocs: Vec<_> = (0..7).map(|_| slab.alloc(256).unwrap()).collect();
        // Free only the last slot (index 6)
        slab.dealloc(allocs[6]).unwrap();

        let result = slab.alloc(300); // needs 2 slots, only 1 free
        assert!(matches!(result, Err(AllocError::NoSpace)));
    }

    #[test]
    fn test_slab_free_invalid_address() {
        let mut slab = make_slab::<256>(1024);
        let alloc = Allocation {
            addr: 0x99999,
            len: 256,
        };

        let result = slab.dealloc(alloc);
        assert!(matches!(result, Err(AllocError::InvalidFree(0x99999, _))));
    }

    #[test]
    fn test_slab_cursor_optimization_lifo() {
        let mut slab = make_slab::<256>(1024);

        let a1 = slab.alloc(256).unwrap();
        let addr1 = a1.addr;

        slab.dealloc(a1).unwrap();

        // Next allocation should reuse same slot (cursor moved back)
        let a2 = slab.alloc(256).unwrap();
        assert_eq!(a2.addr, addr1);
    }

    #[test]
    fn test_slab_cursor_rewind_for_single_slot() {
        let mut slab = make_slab::<256>(1024);

        let _a1 = slab.alloc(256).unwrap();
        let a2 = slab.alloc(256).unwrap();
        let _a3 = slab.alloc(256).unwrap();

        // Free single-slot at position 1, before cursor at 3
        slab.dealloc(a2).unwrap();

        // Cursor should rewind to 1
        let a4 = slab.alloc(256).unwrap();
        // Should reuse slot 1
        assert_eq!(a4.addr, a2.addr);
    }

    #[test]
    fn test_slab_grow_inplace_success() {
        let mut slab = make_slab::<256>(1024);
        let alloc = slab.alloc(256).unwrap();

        // Grow from 256 to 512 (adjacent slot is free)
        let grown = slab.try_grow_inplace(alloc, 512).unwrap();
        assert!(grown.is_some());
        assert_eq!(grown.unwrap().len, 512);
        assert_eq!(grown.unwrap().addr, alloc.addr);
    }

    #[test]
    fn test_slab_grow_inplace_blocked() {
        let mut slab = make_slab::<256>(1024);
        let a1 = slab.alloc(256).unwrap();
        let _a2 = slab.alloc(256).unwrap(); // Blocks growth

        // Can't grow because next slot is allocated
        let result = slab.try_grow_inplace(a1, 512).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_slab_shrink_inplace() {
        let mut slab = make_slab::<256>(1024);
        let alloc = slab.alloc(512).unwrap(); // 2 slots

        let shrunk = slab.shrink_inplace(alloc, 256).unwrap();
        assert_eq!(shrunk.len, 256);
        assert_eq!(shrunk.addr, alloc.addr);
        assert_eq!(slab.free_bytes(), 1024 - 256);
    }

    #[test]
    fn test_slab_realloc_grow_inplace() {
        let mut slab = make_slab::<256>(1024);
        let alloc = slab.alloc(256).unwrap();

        let new_alloc = slab.resize(alloc, 512).unwrap();
        assert_eq!(new_alloc.addr, alloc.addr); // Same address (in-place)
        assert_eq!(new_alloc.len, 512);
    }

    #[test]
    fn test_slab_realloc_grow_relocate() {
        let mut slab = make_slab::<256>(1024);
        let a1 = slab.alloc(256).unwrap();
        let _a2 = slab.alloc(256).unwrap(); // Blocks growth

        let new_alloc = slab.resize(a1, 512).unwrap();
        assert_ne!(new_alloc.addr, a1.addr); // Different address (relocated)
        assert_eq!(new_alloc.len, 512);
    }

    #[test]
    fn test_slab_realloc_shrink() {
        let mut slab = make_slab::<256>(1024);
        let alloc = slab.alloc(512).unwrap();

        let new_alloc = slab.resize(alloc, 256).unwrap();
        assert_eq!(new_alloc.addr, alloc.addr);
        assert_eq!(new_alloc.len, 256);
    }

    #[test]
    fn test_slab_realloc_same_size() {
        let mut slab = make_slab::<256>(1024);
        let alloc = slab.alloc(256).unwrap();

        let new_alloc = slab.resize(alloc, 256).unwrap();
        assert_eq!(new_alloc.addr, alloc.addr);
        assert_eq!(new_alloc.len, alloc.len);
    }

    #[test]
    fn test_slab_fragmentation_handling() {
        let mut slab = make_slab::<256>(1024);

        // Create fragmentation: [U][F][U][F]
        let a1 = slab.alloc(256).unwrap();
        let a2 = slab.alloc(256).unwrap();
        let _a3 = slab.alloc(256).unwrap();
        let _a4 = slab.alloc(256).unwrap();

        slab.dealloc(a2).unwrap();
        slab.dealloc(a1).unwrap();

        // Should still be able to allocate 2-slot buffer
        let big = slab.alloc(512).unwrap();
        assert_eq!(big.len, 512);
    }

    #[test]
    fn test_pool_new_success() {
        let pool = BufferPool::<256, 4096>::new(0x10000, 1024 * 1024).unwrap();
        assert!(pool.inner.borrow().lower.capacity() > 0);
        assert!(pool.inner.borrow().upper.capacity() > 0);
    }

    #[test]
    fn test_pool_alloc_small_to_lower() {
        let pool = make_pool::<256, 4096>(1024 * 1024);
        let alloc = pool.alloc(128).unwrap();

        // Should come from lower slab
        assert!(pool.inner.borrow().lower.contains(alloc.addr));
        assert_eq!(alloc.len, 256);
    }

    #[test]
    fn test_pool_alloc_large_to_upper() {
        let pool = make_pool::<256, 4096>(1024 * 1024);
        let alloc = pool.alloc(1500).unwrap();

        // Should come from upper slab
        assert!(pool.inner.borrow().upper.contains(alloc.addr));
        assert_eq!(alloc.len, 4096);
    }

    #[test]
    fn test_pool_alloc_fallback_to_upper() {
        let pool = make_pool::<256, 4096>(1024 * 1024);

        // Fill lower slab completely
        let mut allocations = Vec::new();
        while pool.inner.borrow().lower.free_bytes() > 0 {
            allocations.push(pool.inner.borrow_mut().lower.alloc(256).unwrap());
        }

        // Small allocation should fallback to upper slab
        let alloc = pool.alloc(128).unwrap();
        assert!(pool.inner.borrow().upper.contains(alloc.addr));
    }

    #[test]
    fn test_pool_free_from_lower() {
        let pool = make_pool::<256, 4096>(1024 * 1024);
        let alloc = pool.alloc(128).unwrap();

        let free_before = pool.inner.borrow().lower.free_bytes();
        pool.dealloc(alloc).unwrap();
        assert_eq!(
            pool.inner.borrow().lower.free_bytes(),
            free_before + alloc.len
        );
    }

    #[test]
    fn test_pool_free_from_upper() {
        let pool = make_pool::<256, 4096>(1024 * 1024);
        let alloc = pool.alloc(1500).unwrap();

        let free_before = pool.inner.borrow().upper.free_bytes();
        pool.dealloc(alloc).unwrap();
        assert_eq!(
            pool.inner.borrow().upper.free_bytes(),
            free_before + alloc.len
        );
    }

    #[test]
    fn test_pool_realloc_within_same_tier() {
        let pool = make_pool::<256, 4096>(1024 * 1024);
        let alloc = pool.alloc(128).unwrap();

        // Realloc within lower tier (128 -> 200, both fit in 256 slots)
        let new_alloc = pool.resize(alloc, 200).unwrap();
        assert!(pool.inner.borrow().lower.contains(new_alloc.addr));
    }

    #[test]
    fn test_pool_realloc_move_to_different_tier() {
        let pool = make_pool::<256, 4096>(1024 * 1024);
        let alloc = pool.alloc(128).unwrap();
        assert!(pool.inner.borrow().lower.contains(alloc.addr));

        // Realloc to size that needs upper tier
        let new_alloc = pool.resize(alloc, 1500).unwrap();
        assert!(pool.inner.borrow().upper.contains(new_alloc.addr));
    }

    #[test]
    fn test_pool_realloc_shrink_stays_in_tier() {
        let pool = make_pool::<256, 4096>(1024 * 1024);
        let alloc = pool.alloc(1500).unwrap();
        assert!(pool.inner.borrow().upper.contains(alloc.addr));

        // Shrink but stay in upper tier
        let new_alloc = pool.resize(alloc, 1000).unwrap();
        assert!(pool.inner.borrow().upper.contains(new_alloc.addr));
    }

    #[test]
    fn test_pool_stress_many_allocations() {
        let pool = make_pool::<256, 4096>(4 * 1024 * 1024);
        let mut allocations = Vec::new();

        // Allocate many buffers
        for i in 0..100 {
            let size = if i % 2 == 0 { 128 } else { 1500 };
            allocations.push(pool.alloc(size).unwrap());
        }

        // Free half of them
        for i in (0..100).step_by(2) {
            pool.dealloc(allocations[i]).unwrap();
        }

        // Should be able to allocate again
        for i in 0..50 {
            let size = if i % 2 == 0 { 128 } else { 1500 };
            let _alloc = pool.alloc(size).unwrap();
        }
    }

    #[test]
    fn test_pool_mixed_workload() {
        let pool = make_pool::<256, 4096>(2 * 1024 * 1024);

        // Simulate virtio-net workload
        let desc_buf = pool.alloc(64).unwrap(); // Control message
        let rx_buf1 = pool.alloc(1500).unwrap(); // MTU packet
        let rx_buf2 = pool.alloc(1500).unwrap(); // MTU packet
        let tx_buf = pool.alloc(4096).unwrap(); // Large buffer

        // Free and reallocate
        pool.dealloc(rx_buf1).unwrap();
        let rx_buf3 = pool.alloc(1500).unwrap();

        // Should reuse freed buffer (LIFO)
        assert_eq!(rx_buf3.addr, rx_buf1.addr);

        pool.dealloc(desc_buf).unwrap();
        pool.dealloc(rx_buf2).unwrap();
        pool.dealloc(rx_buf3).unwrap();
        pool.dealloc(tx_buf).unwrap();
    }

    #[test]
    fn test_pool_zero_allocation_error() {
        let pool = make_pool::<256, 4096>(1024 * 1024);
        let result = pool.alloc(0);
        assert!(matches!(result, Err(AllocError::InvalidArg)));
    }

    #[test]
    fn test_pool_too_large_allocation() {
        let pool = make_pool::<256, 4096>(1024 * 1024);
        let result = pool.alloc(2 * 1024 * 1024); // Larger than pool
        assert!(matches!(result, Err(AllocError::OutOfMemory)));
    }

    #[test]
    fn test_align_up_helper() {
        assert_eq!(align_up(0, 256), 0);
        assert_eq!(align_up(1, 256), 256);
        assert_eq!(align_up(256, 256), 256);
        assert_eq!(align_up(257, 256), 512);
        assert_eq!(align_up(511, 256), 512);
        assert_eq!(align_up(512, 256), 512);
    }

    #[test]
    fn test_slab_usable_size() {
        let slab = make_slab::<256>(1024);
        assert_eq!(slab.usable_size(0, 0), 0);
        assert_eq!(slab.usable_size(0, 1), 256);
        assert_eq!(slab.usable_size(0, 256), 256);
        assert_eq!(slab.usable_size(0, 257), 512);
    }

    #[test]
    fn test_slab_contains() {
        let slab = make_slab::<256>(1024);
        let range = slab.range();

        assert!(slab.contains(range.start));
        assert!(!slab.contains(range.end)); // Exclusive end
        assert!(!slab.contains(0));
    }

    // Edge case: allocation exactly at boundary
    #[test]
    fn test_pool_boundary_allocation() {
        let pool = make_pool::<256, 4096>(1024 * 1024);

        // Allocate exactly at boundary
        let alloc = pool.alloc(256).unwrap();
        assert!(pool.inner.borrow().lower.contains(alloc.addr));

        // Allocate just over boundary
        let alloc2 = pool.alloc(257).unwrap();
        assert!(pool.inner.borrow().upper.contains(alloc2.addr));
    }

    // Test overflow protection
    #[test]
    fn test_addr_of_overflow_protection() {
        let slab = make_slab::<4096>(8192);

        // This should not panic due to overflow checks
        let addr = slab.addr_of(usize::MAX);
        assert!(addr.is_none());
    }

    #[test]
    fn test_no_overlapping_allocations() {
        let mut slab = make_slab::<4096>(32768); // 8 slots

        // Allocate slot 0-1
        let a1 = slab.alloc(8000).unwrap();
        assert_eq!(a1.len, 8192);

        // Shrink to slot 0 only
        let a2 = slab.shrink_inplace(a1, 4000).unwrap();
        assert_eq!(a2.len, 4096);

        // Allocate at slot 1-2
        let a3 = slab.alloc(8000).unwrap();
        assert_eq!(a3.len, 8192);
        let slot1_addr = a2.addr + 4096;
        assert_eq!(a3.addr, slot1_addr);

        // Free slot 0
        slab.dealloc(a2).unwrap();

        // Try to allocate 2 slots - should NOT get slot 0-1 because slot 1 is occupied!
        let a4 = slab.alloc(8000).unwrap();
        assert_ne!(a4.addr, a2.addr); // Should be at a different location

        slab.dealloc(a3).unwrap();
        slab.dealloc(a4).unwrap();
    }

    #[test]
    fn test_slab_reset_returns_to_initial_state() {
        let mut slab = make_slab::<256>(4096);
        let initial_free = slab.free_bytes();
        let initial_cap = slab.capacity();

        // Allocate some slots
        let _a1 = slab.alloc(256).unwrap();
        let _a2 = slab.alloc(512).unwrap();
        assert!(slab.free_bytes() < initial_free);

        slab.reset();

        assert_eq!(slab.free_bytes(), initial_free);
        assert_eq!(slab.capacity(), initial_cap);
        assert!(slab.last_free_run.is_none());
        assert_eq!(slab.used_slots.count_ones(..), 0);

        // Should be able to allocate the full capacity again
        let a = slab.alloc(initial_cap).unwrap();
        assert_eq!(a.len, initial_cap);
    }

    #[test]
    fn test_slab_reset_matches_new() {
        let base = align_up(0x10000, 256) as u64;
        let region = 4096;

        let fresh = Slab::<256>::new(base, region).unwrap();

        let mut used = Slab::<256>::new(base, region).unwrap();
        let _a = used.alloc(256).unwrap();
        let _b = used.alloc(1024).unwrap();
        used.reset();

        assert_eq!(used.free_bytes(), fresh.free_bytes());
        assert_eq!(used.capacity(), fresh.capacity());
        assert_eq!(
            used.used_slots.count_ones(..),
            fresh.used_slots.count_ones(..)
        );
        assert!(used.last_free_run.is_none());
        assert!(fresh.last_free_run.is_none());
    }

    #[test]
    fn test_buffer_pool_reset_returns_to_initial_state() {
        let pool = make_pool::<256, 4096>(0x20000);

        // Allocate from both tiers
        let a1 = pool.inner.borrow_mut().alloc(128).unwrap();
        let a2 = pool.inner.borrow_mut().alloc(8192).unwrap();
        assert!(a1.len > 0);
        assert!(a2.len > 0);

        pool.reset();

        let inner = pool.inner.borrow();
        assert_eq!(inner.lower.used_slots.count_ones(..), 0);
        assert_eq!(inner.upper.used_slots.count_ones(..), 0);
        assert!(inner.lower.last_free_run.is_none());
        assert!(inner.upper.last_free_run.is_none());
    }

    #[test]
    fn test_buffer_pool_reset_allows_reallocation() {
        let pool = make_pool::<256, 4096>(0x20000);

        // Fill up some allocations
        let mut allocs = Vec::new();
        for _ in 0..5 {
            allocs.push(pool.inner.borrow_mut().alloc(256).unwrap());
        }

        pool.reset();

        // Should be able to allocate as if fresh
        let a = pool.inner.borrow_mut().alloc(256).unwrap();
        assert!(a.len > 0);
    }

    #[test]
    fn test_recycle_pool_restore_allocated_removes_from_free_list() {
        let pool = make_recycle_pool(4, 4096);
        assert_eq!(pool.num_free(), 4);

        let addrs = [0x80000, 0x81000]; // slots 0 and 1
        pool.restore_allocated(&addrs).unwrap();
        assert_eq!(pool.num_free(), 2);

        // Allocating should only return the two remaining slots
        let a1 = pool.alloc(4096).unwrap();
        let a2 = pool.alloc(4096).unwrap();
        assert!(pool.alloc(4096).is_err());

        // The allocated addresses should be the non-restored ones
        let mut got = [a1.addr, a2.addr];
        got.sort();
        assert_eq!(got, [0x82000, 0x83000]);
    }

    #[test]
    fn test_recycle_pool_restore_allocated_invalid_addr_returns_error() {
        let pool = make_recycle_pool(4, 4096);
        let result = pool.restore_allocated(&[0xDEAD]);
        assert!(result.is_err());
    }

    #[test]
    fn test_recycle_pool_restore_allocated_then_dealloc_roundtrip() {
        let pool = make_recycle_pool(4, 4096);
        let addr = 0x81000u64;

        pool.restore_allocated(&[addr]).unwrap();
        assert_eq!(pool.num_free(), 3);

        // Dealloc the restored address
        pool.dealloc(Allocation { addr, len: 4096 }).unwrap();
        assert_eq!(pool.num_free(), 4);
    }

    #[test]
    fn test_recycle_pool_restore_allocated_all_slots() {
        let pool = make_recycle_pool(4, 4096);
        let addrs: Vec<u64> = (0..4).map(|i| 0x80000 + i * 4096).collect();

        pool.restore_allocated(&addrs).unwrap();
        assert_eq!(pool.num_free(), 0);
        assert!(pool.alloc(4096).is_err());
    }

    #[test]
    fn test_recycle_pool_restore_allocated_empty_list_is_noop() {
        let pool = make_recycle_pool(4, 4096);
        pool.restore_allocated(&[]).unwrap();
        assert_eq!(pool.num_free(), 4);
    }

    #[test]
    fn test_recycle_pool_restore_allocated_resets_first() {
        let pool = make_recycle_pool(4, 4096);

        // Allocate some slots
        let _ = pool.alloc(4096).unwrap();
        let _ = pool.alloc(4096).unwrap();
        assert_eq!(pool.num_free(), 2);

        // restore_allocated resets then removes - so 4 - 1 = 3
        pool.restore_allocated(&[0x80000]).unwrap();
        assert_eq!(pool.num_free(), 3);
    }

    #[test]
    fn test_recycle_pool_dealloc_out_of_range() {
        let pool = make_recycle_pool(4, 4096);
        let _ = pool.alloc(4096).unwrap();

        let bogus = Allocation {
            addr: 0xDEAD,
            len: 4096,
        };
        assert!(matches!(
            pool.dealloc(bogus),
            Err(AllocError::InvalidFree(0xDEAD, 4096))
        ));
    }

    #[test]
    fn test_recycle_pool_dealloc_misaligned() {
        let pool = make_recycle_pool(4, 4096);
        let _ = pool.alloc(4096).unwrap();

        let misaligned = Allocation {
            addr: 0x80001,
            len: 4096,
        };
        assert!(matches!(
            pool.dealloc(misaligned),
            Err(AllocError::InvalidFree(0x80001, 4096))
        ));
    }

    #[test]
    fn test_recycle_pool_dealloc_double_free() {
        let pool = make_recycle_pool(4, 4096);
        let a = pool.alloc(4096).unwrap();
        pool.dealloc(a).unwrap();

        // Second dealloc should fail - address is already in the free list
        assert!(matches!(
            pool.dealloc(a),
            Err(AllocError::InvalidFree(_, _))
        ));
    }

    #[test]
    fn test_recycle_pool_random_order_dealloc() {
        let pool = make_recycle_pool(8, 4096);

        let mut allocs: Vec<Allocation> = (0..8).map(|_| pool.alloc(4096).unwrap()).collect();
        assert_eq!(pool.num_free(), 0);

        // Dealloc in reverse order
        allocs.reverse();
        for a in &allocs {
            pool.dealloc(*a).unwrap();
        }
        assert_eq!(pool.num_free(), 8);

        // All slots should be re-allocatable
        let reallocs: Vec<Allocation> = (0..8).map(|_| pool.alloc(4096).unwrap()).collect();
        assert_eq!(pool.num_free(), 0);

        // Verify all addresses are distinct
        let mut addrs: Vec<u64> = reallocs.iter().map(|a| a.addr).collect();
        addrs.sort();
        addrs.dedup();
        assert_eq!(addrs.len(), 8);
    }

    #[test]
    fn test_recycle_pool_interleaved_alloc_dealloc_order() {
        let pool = make_recycle_pool(4, 4096);

        let a0 = pool.alloc(4096).unwrap();
        let a1 = pool.alloc(4096).unwrap();
        let a2 = pool.alloc(4096).unwrap();
        let a3 = pool.alloc(4096).unwrap();
        assert_eq!(pool.num_free(), 0);

        // Free middle slots first (out of allocation order)
        pool.dealloc(a2).unwrap();
        pool.dealloc(a0).unwrap();
        assert_eq!(pool.num_free(), 2);

        // Re-alloc gets the out-of-order slots back (LIFO)
        let b0 = pool.alloc(4096).unwrap();
        assert_eq!(b0.addr, a0.addr);
        let b1 = pool.alloc(4096).unwrap();
        assert_eq!(b1.addr, a2.addr);

        // Free everything in yet another order
        pool.dealloc(a1).unwrap();
        pool.dealloc(b0).unwrap();
        pool.dealloc(b1).unwrap();
        pool.dealloc(a3).unwrap();
        assert_eq!(pool.num_free(), 4);

        // All 4 original addresses should be available
        let mut final_addrs: Vec<u64> = (0..4).map(|_| pool.alloc(4096).unwrap().addr).collect();
        final_addrs.sort();
        let expected: Vec<u64> = (0..4).map(|i| 0x80000 + i * 4096).collect();
        assert_eq!(final_addrs, expected);
    }

    #[test]
    fn test_recycle_pool_dealloc_order_independent_of_alloc_order() {
        let pool = make_recycle_pool(6, 256);

        // Allocate all
        let allocs: Vec<Allocation> = (0..6).map(|_| pool.alloc(256).unwrap()).collect();

        // Dealloc in scattered order: 4, 1, 5, 0, 3, 2
        let order = [4, 1, 5, 0, 3, 2];
        for &i in &order {
            pool.dealloc(allocs[i]).unwrap();
        }
        assert_eq!(pool.num_free(), 6);

        // Re-allocate all and verify we get back the full set
        let mut realloc_addrs: Vec<u64> = (0..6).map(|_| pool.alloc(256).unwrap().addr).collect();
        realloc_addrs.sort();

        let mut orig_addrs: Vec<u64> = allocs.iter().map(|a| a.addr).collect();
        orig_addrs.sort();

        assert_eq!(realloc_addrs, orig_addrs);
    }
}

#[cfg(test)]
mod fuzz {
    use quickcheck::{Arbitrary, Gen, QuickCheck};

    use super::*;

    const MAX_OPS: usize = 10;
    const MAX_ALLOC_SIZE: usize = 8192;

    #[derive(Clone, Debug)]
    enum Op {
        Alloc(usize),
        Dealloc(usize),
        Resize(usize, usize),
    }

    impl Arbitrary for Op {
        fn arbitrary(g: &mut Gen) -> Self {
            match u8::arbitrary(g) % 3 {
                0 => Op::Alloc(usize::arbitrary(g) % MAX_ALLOC_SIZE + 1),
                1 => Op::Dealloc(usize::arbitrary(g)),
                2 => Op::Resize(
                    usize::arbitrary(g),
                    usize::arbitrary(g) % MAX_ALLOC_SIZE + 1,
                ),
                _ => unreachable!(),
            }
        }
    }

    #[derive(Clone, Debug)]
    struct Scenario {
        pool_size: usize,
        ops: Vec<Op>,
    }

    impl Arbitrary for Scenario {
        fn arbitrary(g: &mut Gen) -> Self {
            let pool_size = (usize::arbitrary(g) % (4 * 1024 * 1024)) + (1024 * 1024);
            let num_ops = usize::arbitrary(g) % MAX_OPS + 1;
            let ops = (0..num_ops).map(|_| Op::arbitrary(g)).collect();

            Scenario { pool_size, ops }
        }
    }

    fn run_scenario(s: Scenario) -> bool {
        let base = align_up(0x10000, 4096) as u64;
        let pool = match BufferPool::<256, 4096>::new(base, s.pool_size) {
            Ok(p) => p,
            Err(_) => return true,
        };

        let mut allocations: Vec<Allocation> = Vec::new();

        for op in &s.ops {
            match op {
                Op::Alloc(size) => match pool.alloc(*size) {
                    Ok(alloc) => {
                        assert!(alloc.len >= *size);
                        allocations.push(alloc);
                    }
                    Err(AllocError::NoSpace | AllocError::OutOfMemory) => {}
                    Err(_) => {
                        return false;
                    }
                },
                Op::Dealloc(idx) => {
                    if allocations.is_empty() {
                        continue;
                    }

                    let idx = idx % allocations.len();
                    let alloc = allocations.swap_remove(idx);

                    match pool.dealloc(alloc) {
                        Ok(_) => {}
                        Err(_) => return false,
                    }
                }
                Op::Resize(idx, new_size) => {
                    if allocations.is_empty() {
                        continue;
                    }

                    let idx = idx % allocations.len();
                    let old_alloc = allocations[idx];

                    match pool.resize(old_alloc, *new_size) {
                        Ok(new_alloc) => {
                            assert!(new_alloc.len >= *new_size);
                            allocations[idx] = new_alloc;
                        }
                        Err(AllocError::NoSpace | AllocError::OutOfMemory) => {}
                        Err(_) => return false,
                    }
                }
            }

            if check_pool_invariants(&pool, &allocations).is_err() {
                return false;
            }
        }

        // Cleanup
        for alloc in &allocations {
            if pool.dealloc(*alloc).is_err() {
                return false;
            }
        }

        check_pool_invariants(&pool, &allocations).is_ok()
    }

    fn check_slab_invariants<const N: usize>(slab: &Slab<N>) -> Result<(), &'static str> {
        // Check that number of used + free slots equals total
        let used = slab.used_slots.count_ones(..);
        let free = slab.used_slots.count_zeroes(..);
        if used + free != slab.used_slots.len() {
            return Err("used + free != total slots");
        }

        let expected_free = free * N;
        if slab.free_bytes() != expected_free {
            return Err("free_bytes doesn't match bitmap");
        }

        if let Some(alloc) = slab.last_free_run {
            if alloc.len == 0 || alloc.len % N != 0 {
                return Err("last_free_run has invalid length");
            }
            if !slab.contains(alloc.addr) {
                return Err("last_free_run addr outside range");
            }
        }

        Ok(())
    }

    fn check_pool_invariants<const L: usize, const U: usize>(
        pool: &BufferPool<L, U>,
        allocations: &[Allocation],
    ) -> Result<(), &'static str> {
        check_slab_invariants(&pool.inner.borrow().lower)?;
        check_slab_invariants(&pool.inner.borrow().upper)?;

        if pool.inner.borrow().lower.range().end > pool.inner.borrow().upper.range().start {
            return Err("lower and upper ranges overlap");
        }

        let mut seen = std::collections::HashSet::new();

        for alloc in allocations {
            if !pool.inner.borrow().lower.contains(alloc.addr)
                && !pool.inner.borrow().upper.contains(alloc.addr)
            {
                return Err("allocation address outside pool ranges");
            }

            if alloc.len % L != 0 && alloc.len % U != 0 {
                return Err("allocation length not aligned to any tier");
            }

            if !seen.insert(alloc.addr) {
                return Err("duplicate allocation address in tracking");
            }
        }

        Ok(())
    }

    #[test]
    fn prop_allocator_invariants() {
        #[cfg(miri)]
        let tests = 10;
        #[cfg(not(miri))]
        let tests = 1000;

        QuickCheck::new()
            .tests(tests)
            .quickcheck(run_scenario as fn(Scenario) -> bool);
    }
}
