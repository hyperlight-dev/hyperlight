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
//! - [`BufferPool`] - a two-tier run allocator for variable-sized allocations.
//! - [`RecyclePool`] - a single-tier fixed-slot free-list recycler for bounded
//!   descriptor segments.
//!
//! All implement [`BufferProvider`] from the [`super::buffer`] module.
//!
//! # BufferPool design
//!
//! `BufferPool` is a variable-sized run allocator.
//!
//! # Two-tier layout
//!
//! [`BufferPool`] divides the underlying region into two slabs with different
//! slot sizes:
//!
//! - The lower tier (default `L = 256`) is intended for *smaller allocations* -
//!   control messages, descriptor metadata, and other small structures. Small
//!   allocations first try this tier.
//! - The upper tier (default `U = 4096`) uses page sized slots and is intended
//!   for larger contiguous buffers.

use alloc::rc::Rc;
use core::cell::RefCell;
use core::ops::Deref;

use fixedbitset::FixedBitSet;
use smallvec::SmallVec;

use super::buffer::{AllocError, Allocation, BufferProvider};

/// Wrapper asserting `Send + Sync` for an inner value that is only ever
/// accessed from a single thread.
///
/// [`BufferPool`] and [`RecyclePool`] hold their state in an `Rc<RefCell<..>>`,
/// which is neither `Send` nor `Sync`. Their allocations are exposed as
/// zero-copy reply payloads through
/// [`Bytes::from_owner`](bytes::Bytes::from_owner), whose owner bound is
/// `Send + Sync + 'static`; this wrapper exists solely so the pools can satisfy
/// that bound.
///
/// # Safety
///
/// The `Send`/`Sync` assertions are only sound while the wrapped value - and
/// every `Bytes` handed out from it - stays on a single thread. Hyperlight
/// guests are single-threaded, so this holds for guest-side use. It is unsound
/// to move a pool (or a reply `Bytes`) to another thread, e.g. by using these
/// pools with a producer/consumer on the multi-threaded host.
#[derive(Debug)]
pub(super) struct SyncWrap<T>(pub(super) T);

// SAFETY: only sound for single-threaded (guest-side) access; see the
// type-level invariant on `SyncWrap`.
unsafe impl<T> Send for SyncWrap<T> {}
// SAFETY: only sound for single-threaded (guest-side) access; see the
// type-level invariant on `SyncWrap`.
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
struct Slab<const N: usize> {
    base_addr: u64,
    used_slots: FixedBitSet,
    run_starts: FixedBitSet,
    last_free_run: Option<Allocation>,
}

impl<const N: usize> Slab<N> {
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

    fn alloc(&mut self, len: usize) -> Result<Allocation, AllocError> {
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

    fn capacity(&self) -> usize {
        self.used_slots.len() * N
    }

    fn range(&self) -> core::ops::Range<u64> {
        self.base_addr..self.base_addr + self.capacity() as u64
    }

    fn contains(&self, addr: u64) -> bool {
        self.range().contains(&addr)
    }

    fn reset(&mut self) {
        self.used_slots.clear();
        self.run_starts.clear();
        self.last_free_run = None;
    }
}

#[cfg(test)]
impl<const N: usize> Slab<N> {
    fn free_bytes(&self) -> usize {
        (self.used_slots.len() - self.used_slots.count_ones(..)) * N
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
            inner: std::sync::Arc::new(std::sync::Mutex::new(inner)),
        })
    }
}

impl<const L: usize, const U: usize> Inner<L, U> {
    /// Create a new buffer pool over a fixed region.
    pub fn new(base_addr: u64, region_len: usize) -> Result<Self, AllocError> {
        const LOWER_FRACTION: usize = 8;

        let region_end = (base_addr as usize)
            .checked_add(region_len)
            .ok_or(AllocError::Overflow)? as u64;

        let lower_base = align_up(base_addr as usize, L) as u64;
        let usable = region_end
            .checked_sub(lower_base)
            .ok_or(AllocError::EmptyRegion)? as usize;

        let lower_region = usable / LOWER_FRACTION;
        let lower = Slab::<L>::new(lower_base, lower_region)?;

        let upper_base = lower_base
            .checked_add(lower.capacity() as u64)
            .ok_or(AllocError::Overflow)?;

        let upper_base = align_up(upper_base as usize, U) as u64;
        let upper_region = region_end
            .checked_sub(upper_base)
            .ok_or(AllocError::EmptyRegion)? as usize;

        let upper = Slab::<U>::new(upper_base, upper_region)?;
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

impl<const L: usize, const U: usize> BufferProvider for BufferPool<L, U> {
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

    fn reset(&self) {
        let mut inner = self.inner.borrow_mut();
        inner.lower.reset();
        inner.upper.reset();
    }
}

impl<const L: usize, const U: usize> BufferPool<L, U> {
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
impl<const L: usize, const U: usize> BufferProvider for BufferPoolSync<L, U> {
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

/// Single-tier fixed-slot free list.
///
/// Tracks a fixed set of equal-sized buffer slots. Allocation pops a free slot
/// and deallocation returns it, both O(1). A [`FixedBitSet`] records which slots
/// are currently allocated, so double frees and frees of unknown addresses are
/// rejected without scanning the free list.
struct RecycleList {
    base_addr: u64,
    slot_size: usize,
    count: usize,
    /// Free slot addresses, popped/pushed LIFO.
    free: SmallVec<[u64; 64]>,
    /// One bit per slot index; set means the slot is currently handed out.
    allocated: FixedBitSet,
}

impl RecycleList {
    fn new(base_addr: u64, region_len: usize, slot_size: usize) -> Result<Self, AllocError> {
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

        Ok(Self {
            base_addr,
            slot_size,
            count,
            free,
            allocated: FixedBitSet::with_capacity(count),
        })
    }

    fn end(&self) -> u64 {
        self.base_addr + (self.count * self.slot_size) as u64
    }

    fn contains(&self, addr: u64) -> bool {
        (self.base_addr..self.end()).contains(&addr)
    }

    /// Validate that `addr` names a slot start within the region.
    fn slot_of(&self, addr: u64) -> Result<usize, AllocError> {
        if !self.contains(addr) {
            return Err(AllocError::InvalidFree(addr, 0));
        }

        let off = addr - self.base_addr;
        if !off.is_multiple_of(self.slot_size as u64) {
            return Err(AllocError::InvalidFree(addr, 0));
        }

        Ok((off / self.slot_size as u64) as usize)
    }

    /// Validate that `addr` is a live (currently allocated) slot start.
    fn live_slot_of(&self, addr: u64) -> Result<usize, AllocError> {
        let slot = self.slot_of(addr)?;
        if !self.allocated.contains(slot) {
            return Err(AllocError::InvalidFree(addr, 0));
        }
        Ok(slot)
    }

    fn alloc(&mut self, len: usize) -> Result<Allocation, AllocError> {
        if len == 0 {
            return Err(AllocError::InvalidArg);
        }
        if len > self.slot_size {
            return Err(AllocError::OutOfMemory);
        }

        let addr = self.free.pop().ok_or(AllocError::NoSpace)?;
        // Safety of the index: `addr` came from `free`, which only ever holds
        // valid slot starts.
        self.allocated
            .insert(((addr - self.base_addr) / self.slot_size as u64) as usize);

        Ok(Allocation {
            addr,
            len: self.slot_size,
        })
    }

    fn dealloc_addr(&mut self, addr: u64) -> Result<(), AllocError> {
        let slot = self.live_slot_of(addr)?;
        self.allocated.set(slot, false);
        self.free.push(addr);
        Ok(())
    }

    fn allocation_len(&self, addr: u64) -> Result<usize, AllocError> {
        self.live_slot_of(addr)?;
        Ok(self.slot_size)
    }

    /// Rebuild state so that exactly the addresses in `allocated` are marked
    /// live and every other slot is free.
    ///
    /// On error the pool is left in an indeterminate state and should be
    /// [`reset`](Self::reset) before reuse.
    fn restore_allocated(&mut self, allocated: &[u64]) -> Result<(), AllocError> {
        self.allocated.clear();
        for &addr in allocated {
            let slot = self.slot_of(addr)?;
            if self.allocated.contains(slot) {
                return Err(AllocError::InvalidFree(addr, self.slot_size));
            }
            self.allocated.insert(slot);
        }
        self.rebuild_free();
        Ok(())
    }

    fn reset(&mut self) {
        self.allocated.clear();
        self.rebuild_free();
    }

    /// Repopulate the free list with every slot whose allocated bit is clear.
    fn rebuild_free(&mut self) {
        self.free.clear();
        for i in 0..self.count {
            if !self.allocated.contains(i) {
                self.free.push(self.base_addr + (i * self.slot_size) as u64);
            }
        }
    }

    fn slot_addr(&self, index: usize) -> Option<u64> {
        (index < self.count).then(|| self.base_addr + (index * self.slot_size) as u64)
    }

    fn num_free(&self) -> usize {
        self.free.len()
    }
}

/// A recycling buffer provider with fixed-size slots.
///
/// Holds a fixed set of equal-sized buffer addresses in a free list. Alloc and
/// dealloc are O(1). It is intended for bounded scatter/gather descriptor
/// segments that are pre-allocated and recycled after use:
/// [`alloc_sg`](BufferProvider::alloc_sg) splits a logical payload into
/// `ceil(total_len / slot_size)` fixed-size segments.
#[derive(Clone)]
pub struct RecyclePool {
    inner: SyncWrap<Rc<RefCell<RecycleList>>>,
}

impl RecyclePool {
    /// Create a recycling pool of `slot_size`-byte slots over a fixed region.
    ///
    /// The base address is aligned up to `slot_size`; the slot count is
    /// `region_len / slot_size`.
    pub fn new(base_addr: u64, region_len: usize, slot_size: usize) -> Result<Self, AllocError> {
        if slot_size == 0 {
            return Err(AllocError::InvalidArg);
        }

        let aligned = align_up(base_addr as usize, slot_size) as u64;
        let list = RecycleList::new(aligned, region_len, slot_size)?;

        Ok(Self {
            inner: SyncWrap(Rc::new(RefCell::new(list))),
        })
    }

    /// Rebuild pool state so that every address in `allocated` is removed from
    /// the free list, matching externally known inflight state.
    pub fn restore_allocated(&self, allocated: &[u64]) -> Result<(), AllocError> {
        self.inner.borrow_mut().restore_allocated(allocated)
    }

    /// Compute the address of slot `index`.
    ///
    /// Returns `None` if `index >= count`.
    pub fn slot_addr(&self, index: usize) -> Option<u64> {
        self.inner.borrow().slot_addr(index)
    }

    /// Number of free slots.
    pub fn num_free(&self) -> usize {
        self.inner.borrow().num_free()
    }

    /// Free a previously allocated slot by address.
    pub fn dealloc_addr(&self, addr: u64) -> Result<(), AllocError> {
        self.inner.borrow_mut().dealloc_addr(addr)
    }

    /// Capacity of a live allocation by its start address.
    pub fn allocation_len(&self, addr: u64) -> Result<usize, AllocError> {
        self.inner.borrow().allocation_len(addr)
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
    fn max_alloc_len(&self) -> usize {
        self.inner.borrow().slot_size
    }

    fn alloc(&self, len: usize) -> Result<Allocation, AllocError> {
        self.inner.borrow_mut().alloc(len)
    }

    fn dealloc(&self, addr: u64) -> Result<(), AllocError> {
        self.inner.borrow_mut().dealloc_addr(addr)
    }

    fn reset(&self) {
        self.inner.borrow_mut().reset()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pool<const L: usize, const U: usize>(size: usize) -> BufferPool<L, U> {
        let base = align_up(0x10000, L.max(U)) as u64;
        BufferPool::<L, U>::new(base, size).unwrap()
    }

    fn make_recycle_pool(slot_count: usize, slot_size: usize) -> RecyclePool {
        let base = 0x80000u64;
        RecyclePool::new(base, slot_count * slot_size, slot_size).unwrap()
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
        pool.dealloc(alloc.addr).unwrap();
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
        pool.dealloc(alloc.addr).unwrap();
        assert_eq!(
            pool.inner.borrow().upper.free_bytes(),
            free_before + alloc.len
        );
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
            pool.dealloc(allocations[i].addr).unwrap();
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
        pool.dealloc(rx_buf1.addr).unwrap();
        let rx_buf3 = pool.alloc(1500).unwrap();

        // Should reuse freed buffer (LIFO)
        assert_eq!(rx_buf3.addr, rx_buf1.addr);

        pool.dealloc(desc_buf.addr).unwrap();
        pool.dealloc(rx_buf2.addr).unwrap();
        pool.dealloc(rx_buf3.addr).unwrap();
        pool.dealloc(tx_buf.addr).unwrap();
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

    #[test]
    fn test_buffer_pool_reset_returns_to_initial_state() {
        let pool = make_pool::<256, 4096>(0x20000);

        // Allocate from both tiers
        let a1 = pool.inner.borrow_mut().alloc(128).unwrap();
        let a2 = pool.inner.borrow_mut().alloc(4096).unwrap();
        assert!(a1.len > 0);
        assert!(a2.len > 0);

        pool.reset();

        let inner = pool.inner.borrow();
        assert_eq!(inner.lower.free_bytes(), inner.lower.capacity());
        assert_eq!(inner.upper.free_bytes(), inner.upper.capacity());
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
    fn test_pool_dealloc_addr_routes_to_correct_tier() {
        let pool = make_pool::<256, 4096>(0x20000);
        let lower = pool.alloc(128).unwrap();
        let upper = pool.alloc(1024).unwrap();

        assert_eq!(pool.allocation_len(lower.addr).unwrap(), 256);
        assert_eq!(pool.allocation_len(upper.addr).unwrap(), 4096);

        pool.dealloc_addr(lower.addr).unwrap();
        pool.dealloc_addr(upper.addr).unwrap();
    }

    #[test]
    fn test_buffer_pool_alloc_sg_uses_one_contiguous_run() {
        let pool = make_pool::<256, 4096>(0x20000);
        let sgs = pool.alloc_sg(4096 * 2 + 1).unwrap();

        assert_eq!(sgs.len(), 1);
        assert_eq!(sgs[0].len, 4096 * 3);

        for sg in sgs {
            pool.dealloc(sg.addr).unwrap();
        }
    }

    #[test]
    fn test_buffer_pool_alloc_sg_large_run() {
        let pool = make_pool::<256, 4096>(0x20000);
        let sgs = pool.alloc_sg(8192).unwrap();

        assert_eq!(sgs.len(), 1);
        assert_eq!(sgs[0].len, 8192);

        for sg in sgs {
            pool.dealloc(sg.addr).unwrap();
        }
    }

    #[test]
    fn test_recycle_pool_alloc_sg_splits() {
        let pool = make_recycle_pool(8, 4096);
        let sgs = pool.alloc_sg(4096 * 2 + 1).unwrap();

        assert_eq!(sgs.len(), 3);
        assert_eq!(sgs[0].len, 4096);
        assert_eq!(sgs[1].len, 4096);
        assert_eq!(sgs[2].len, 4096);

        for sg in sgs {
            pool.dealloc(sg.addr).unwrap();
        }
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
        pool.dealloc(addr).unwrap();
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

        assert!(matches!(
            pool.dealloc(0xDEAD),
            Err(AllocError::InvalidFree(0xDEAD, 0))
        ));
    }

    #[test]
    fn test_recycle_pool_dealloc_misaligned() {
        let pool = make_recycle_pool(4, 4096);
        let _ = pool.alloc(4096).unwrap();

        assert!(matches!(
            pool.dealloc(0x80001),
            Err(AllocError::InvalidFree(0x80001, 0))
        ));
    }

    #[test]
    fn test_recycle_pool_dealloc_double_free() {
        let pool = make_recycle_pool(4, 4096);
        let a = pool.alloc(4096).unwrap();
        pool.dealloc(a.addr).unwrap();

        // Second dealloc should fail - address is already in the free list
        assert!(matches!(
            pool.dealloc(a.addr),
            Err(AllocError::InvalidFree(_, _))
        ));
    }

    #[test]
    fn test_recycle_pool_alloc_sg_rolls_back_on_failure() {
        let pool = make_recycle_pool(2, 4096);

        assert!(matches!(pool.alloc_sg(4096 * 3), Err(AllocError::NoSpace)));
        assert_eq!(pool.num_free(), 2);

        let alloc = pool.alloc(4096).unwrap();
        assert_eq!(pool.num_free(), 1);
        pool.dealloc(alloc.addr).unwrap();
    }

    #[test]
    fn test_recycle_pool_dealloc_addr_and_allocation_len() {
        let pool = make_recycle_pool(4, 4096);
        let alloc = pool.alloc(4096).unwrap();

        assert_eq!(pool.allocation_len(alloc.addr).unwrap(), 4096);
        pool.dealloc_addr(alloc.addr).unwrap();
        assert!(matches!(
            pool.allocation_len(alloc.addr),
            Err(AllocError::InvalidFree(_, 0))
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
            pool.dealloc(a.addr).unwrap();
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
        pool.dealloc(a2.addr).unwrap();
        pool.dealloc(a0.addr).unwrap();
        assert_eq!(pool.num_free(), 2);

        // Re-alloc gets the out-of-order slots back (LIFO)
        let b0 = pool.alloc(4096).unwrap();
        assert_eq!(b0.addr, a0.addr);
        let b1 = pool.alloc(4096).unwrap();
        assert_eq!(b1.addr, a2.addr);

        // Free everything in yet another order
        pool.dealloc(a1.addr).unwrap();
        pool.dealloc(b0.addr).unwrap();
        pool.dealloc(b1.addr).unwrap();
        pool.dealloc(a3.addr).unwrap();
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
            pool.dealloc(allocs[i].addr).unwrap();
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
        AllocSg(usize),
        Dealloc(usize),
    }

    impl Arbitrary for Op {
        fn arbitrary(g: &mut Gen) -> Self {
            match u8::arbitrary(g) % 3 {
                0 => Op::Alloc(usize::arbitrary(g) % MAX_ALLOC_SIZE + 1),
                1 => Op::AllocSg(usize::arbitrary(g) % MAX_ALLOC_SIZE + 1),
                2 => Op::Dealloc(usize::arbitrary(g)),
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
                Op::AllocSg(size) => match pool.alloc_sg(*size) {
                    Ok(sgs) => {
                        let total: usize = sgs.iter().map(|sg| sg.len).sum();
                        assert!(total >= *size);
                        allocations.extend(sgs);
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

                    match pool.dealloc(alloc.addr) {
                        Ok(_) => {}
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
            if pool.dealloc(alloc.addr).is_err() {
                return false;
            }
        }

        check_pool_invariants(&pool, &allocations).is_ok()
    }

    fn check_slab_invariants<const N: usize>(slab: &Slab<N>) -> Result<(), &'static str> {
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
