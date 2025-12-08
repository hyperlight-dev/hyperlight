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
//! Simple bitmap-based allocator for virtio buffer management.
//!
//! This module provides two layers:
//!
//! - [`Slab`] - a fixed-size region allocator with a power-of-two slot size `N`,
//!   backed by a flat bitmap (`FixedBitSet`).
//! - [`BufferPool`] - a two-tier pool that composes two slabs: one with small
//!   slots (e.g. 256 bytes) for control messages / small descriptors, and one
//!   with page-sized slots (e.g. 4 KiB) for data buffers.
//!
//! # Design and algorithm
//!
//! The core allocation strategy is a bitmap allocator that performs a linear
//! search over the bitmap, but implemented via `fixedbitset`'s SIMD iteration
//! over zero bits. This is conceptually simpler than tree-based allocators
//! (e.g. linked lists or bitmaps representing a tree as in
//! <https://arxiv.org/pdf/2110.10357>), yet for "moderate" region sizes it can
//! be faster in practice:
//!
//! - `FixedBitSet::zeroes()` and related methods use word/SIMD operations to
//!   skip over runs of set bits, so the linear search is over words rather than
//!   individual bits.
//! - We scan for a contiguous run of free bits corresponding to the required
//!   number of slots; no auxiliary tree structure is maintained.
//!
//! The tree-based approach (bitmap encoding a tree and doing a binary search
//! in O(log(n)) time) is a natural next step if larger regions or stricter worst
//! case bounds are required; switching to such a representation should be
//! relatively straightforward since all allocation paths go through a single
//! `find_slots` function.
//!
//! # Locality characteristics
//!
//! The allocator tends to preserve spatial locality:
//!
//! - It searches from low indices upward, returning the first run of free
//!   slots large enough for the request. Slots are merged if necessary.
//! - Freed runs are cached in `last_free_run` and reused eagerly, which
//!   introduces a mild LIFO behavior for recently freed blocks.
//! - As a result, consecutive allocations are likely to end up in nearby slots,
//!   which keeps virtqueue descriptors, control buffers, and data buffers
//!   clustered in memory and helps cache performance.
//!
//! # Two-tier buffer pool
//!
//! [`BufferPool`] divides the underlying region into two slabs with different
//! slot sizes:
//!
//! - The lower tier (`Slab<L>`, default `L = 256`) is intended for
//!   *smaller allocations* - control messages, descriptor metadata, and other
//!   small structures. Small allocations first try this tier.
//! - The upper tier (`Slab<U>`, default `U = 4096`) uses page sized slots
//!   and is intended for larger data buffers.
//!
//! The split of the region is currently fixed at a constant fraction
//! (`LOWER_FRACTION`) for the lower slab and the remainder for the upper slab.
//!
//! Allocation policy:
//!
//! - Requests `<= L` bytes are first attempted in the lower slab; on
//!   `OutOfMemory` they fall back to the upper slab.
//! - Larger requests go directly to the upper slab.
//! - [`BufferPool::resize`] will try to grow or shrink in place within the
//!   owning slab (`Slab::resize`) but will never move allocations between
//!   slabs.

use alloc::sync::Arc;
use core::cmp::Ordering;

use atomic_refcell::AtomicRefCell;
use fixedbitset::FixedBitSet;
use thiserror::Error;

use super::access::MemOps;

#[derive(Debug, Error, Copy, Clone)]
pub enum AllocError {
    #[error("Invalid region addr {0}")]
    InvalidAlign(u64),
    #[error("Invalid free addr {0} and size {1}")]
    InvalidFree(u64, usize),
    #[error("Invalid argument")]
    InvalidArg,
    #[error("Empty region")]
    EmptyRegion,
    #[error("Out of memory")]
    OutOfMemory,
    #[error("Overflow")]
    Overflow,
}

/// Allocation result
#[derive(Debug, Clone, Copy)]
pub struct Allocation {
    /// Starting address of the allocation
    pub addr: u64,
    /// Length of the allocation in bytes rounded up to slab size
    pub len: usize,
}

/// Trait for buffer providers.
pub trait BufferProvider {
    /// Allocate at least `len` bytes.
    fn alloc(&self, len: usize) -> Result<Allocation, AllocError>;

    /// Free a previously allocated block.
    fn dealloc(&self, alloc: Allocation) -> Result<(), AllocError>;

    /// Resize by trying in-place grow; otherwise reserve a new block and free old.
    fn resize(&self, old_alloc: Allocation, new_len: usize) -> Result<Allocation, AllocError>;
}

/// The owner of mapped buffer, ensuring its lifetime.
#[derive(Debug, Clone)]
pub struct BufferOwner<P: BufferProvider, M: MemOps> {
    pub pool: Arc<P>,
    pub mem: Arc<M>,
    pub alloc: Allocation,
    pub written: usize,
}

impl<P: BufferProvider, M: MemOps> Drop for BufferOwner<P, M> {
    fn drop(&mut self) {
        let _ = self.pool.dealloc(self.alloc);
    }
}

impl<P: BufferProvider, M: MemOps> AsRef<[u8]> for BufferOwner<P, M> {
    fn as_ref(&self) -> &[u8] {
        todo!()
    }
}

/// A guard that runs a cleanup function when dropped, unless dismissed.
pub struct AllocGuard<F: FnOnce(Allocation)>(Option<(Allocation, F)>);

impl<F: FnOnce(Allocation)> AllocGuard<F> {
    pub fn new(alloc: Allocation, cleanup: F) -> Self {
        Self(Some((alloc, cleanup)))
    }

    pub fn dismiss(mut self) -> Allocation {
        self.0.take().unwrap().0
    }
}

impl<F: FnOnce(Allocation)> core::ops::Deref for AllocGuard<F> {
    type Target = Allocation;

    fn deref(&self) -> &Allocation {
        &self.0.as_ref().unwrap().0
    }
}

impl<F: FnOnce(Allocation)> Drop for AllocGuard<F> {
    fn drop(&mut self) {
        if let Some((alloc, cleanup)) = self.0.take() {
            cleanup(alloc)
        }
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
        self.used_slots.zeroes().find(|&next_free| {
            self.used_slots
                .count_zeroes(next_free..next_free + slots_num)
                == slots_num
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

        let idx = self.find_slots(need_slots).ok_or(AllocError::OutOfMemory)?;
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
#[derive(Debug)]
pub struct BufferPool<const L: usize = 256, const U: usize = 4096> {
    inner: AtomicRefCell<Inner<L, U>>,
}

impl<const L: usize, const U: usize> BufferPool<L, U> {
    /// Create a new buffer pool over a fixed region.
    pub fn new(base_addr: u64, region_len: usize) -> Result<Self, AllocError> {
        let inner = Inner::<L, U>::new(base_addr, region_len)?;
        Ok(Self {
            inner: inner.into(),
        })
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
                Err(AllocError::OutOfMemory) => {}
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
        assert!(matches!(result, Err(AllocError::OutOfMemory)));

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
                    Err(AllocError::OutOfMemory) => {}
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
                        Err(AllocError::OutOfMemory) => {}
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
