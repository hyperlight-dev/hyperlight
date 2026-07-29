// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Fixed-slot pool with optional lower and required upper tiers.
//!
//! [`SlotPool`] manages one or two non-overlapping [`SlotLayout`]s. Each tier
//! contains independent, equal-sized slots tracked by a free list and an
//! allocation bitmap. Eligible requests try the lower tier first and fall back
//! to the upper tier only when the lower tier has no free slot.
//!
//! Slots need not be contiguous, so scatter/gather allocation splits a logical
//! buffer at the upper-tier slot size and may place an eligible final segment
//! in the lower tier. [`SlotPool::live_addrs`] reports ownership in deterministic
//! lower-then-upper index order without mutating pool state.

use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use fixedbitset::FixedBitSet;
use smallvec::SmallVec;

use super::{AllocError, Allocation, BufferProvider, SendWrap};

/// Exact memory layout for one [`SlotPool`] tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotLayout {
    /// Start of the first slot.
    pub base_addr: u64,
    /// Capacity of each slot.
    pub slot_size: usize,
    /// Number of slots.
    pub slot_count: usize,
}

impl SlotLayout {
    /// Describe exact fixed-slot placement.
    pub const fn new(base_addr: u64, slot_size: usize, slot_count: usize) -> Self {
        Self {
            base_addr,
            slot_size,
            slot_count,
        }
    }

    /// Total bytes occupied by the slots.
    pub fn byte_len(self) -> Result<usize, AllocError> {
        self.slot_size
            .checked_mul(self.slot_count)
            .ok_or(AllocError::Overflow)
    }

    /// Exclusive end address.
    pub fn end_addr(self) -> Result<u64, AllocError> {
        self.base_addr
            .checked_add(u64::try_from(self.byte_len()?).map_err(|_| AllocError::Overflow)?)
            .ok_or(AllocError::Overflow)
    }
}

/// Single-tier fixed-slot free list.
///
/// Tracks a fixed set of equal-sized buffer slots. Allocation pops a free slot
/// and deallocation returns it, both O(1). A [`FixedBitSet`] records which slots
/// are currently allocated, so double frees and frees of unknown addresses are
/// rejected without scanning the free list.
struct Tier {
    /// Start of this tier's backing memory.
    base_addr: u64,
    /// Capacity of this slot.
    slot_size: usize,
    /// Number of slots in this tier.
    count: usize,
    /// Free slot addresses, popped/pushed LIFO.
    free: SmallVec<[u64; 64]>,
    /// One bit per slot index; set means the slot is currently handed out.
    allocated: FixedBitSet,
}

// SAFETY: only sound for single-threaded (guest-side) access; see the
// type-level invariant on `SendWrap`.
unsafe impl Send for SendWrap<Rc<RefCell<Inner>>> {}

impl Tier {
    fn from_layout(layout: SlotLayout) -> Result<Self, AllocError> {
        if layout.slot_size == 0 {
            return Err(AllocError::InvalidArg);
        }

        if layout.slot_count == 0 {
            return Err(AllocError::EmptyRegion);
        }

        layout.end_addr()?;

        let mut free = SmallVec::with_capacity(layout.slot_count);
        for i in 0..layout.slot_count {
            free.push(layout.base_addr + (i * layout.slot_size) as u64);
        }

        Ok(Self {
            base_addr: layout.base_addr,
            slot_size: layout.slot_size,
            count: layout.slot_count,
            free,
            allocated: FixedBitSet::with_capacity(layout.slot_count),
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

    fn slot_addr(&self, index: usize) -> Option<u64> {
        (index < self.count).then(|| self.base_addr + (index * self.slot_size) as u64)
    }

    fn num_free(&self) -> usize {
        self.free.len()
    }

    fn append_live_addrs(&self, addrs: &mut Vec<u64>) {
        addrs.extend(
            self.allocated
                .ones()
                .map(|slot| self.base_addr + (slot * self.slot_size) as u64),
        );
    }

    fn layout(&self) -> SlotLayout {
        SlotLayout::new(self.base_addr, self.slot_size, self.count)
    }
}

struct Inner {
    lower: Option<Tier>,
    upper: Tier,
}

impl Inner {
    fn new(lower: Option<SlotLayout>, upper: SlotLayout) -> Result<Self, AllocError> {
        let lower = lower.map(Tier::from_layout).transpose()?;
        let upper = Tier::from_layout(upper)?;

        let Some(lower) = lower else {
            return Ok(Self { lower: None, upper });
        };

        if lower.slot_size > upper.slot_size || lower.end() > upper.base_addr {
            return Err(AllocError::InvalidArg);
        }

        if lower.slot_size == upper.slot_size {
            if lower.end() != upper.base_addr {
                return Err(AllocError::InvalidArg);
            }

            let count = lower
                .count
                .checked_add(upper.count)
                .ok_or(AllocError::Overflow)?;
            let layout = SlotLayout::new(lower.base_addr, lower.slot_size, count);
            return Ok(Self {
                lower: None,
                upper: Tier::from_layout(layout)?,
            });
        }

        Ok(Self {
            lower: Some(lower),
            upper,
        })
    }

    fn max_alloc_len(&self) -> usize {
        self.upper.slot_size
    }

    fn alloc(&mut self, len: usize) -> Result<Allocation, AllocError> {
        if let Some(lower) = &mut self.lower
            && len <= lower.slot_size
        {
            match lower.alloc(len) {
                Ok(alloc) => return Ok(alloc),
                Err(AllocError::NoSpace) => {}
                Err(err) => return Err(err),
            }
        }

        self.upper.alloc(len)
    }

    fn dealloc_addr(&mut self, addr: u64) -> Result<(), AllocError> {
        if let Some(lower) = &mut self.lower
            && lower.contains(addr)
        {
            return lower.dealloc_addr(addr);
        }
        self.upper.dealloc_addr(addr)
    }

    fn allocation_len(&self, addr: u64) -> Result<usize, AllocError> {
        if let Some(lower) = &self.lower
            && lower.contains(addr)
        {
            return lower.allocation_len(addr);
        }
        self.upper.allocation_len(addr)
    }

    fn slot_addr(&self, index: usize) -> Option<u64> {
        if let Some(lower) = &self.lower {
            if index < lower.count {
                return lower.slot_addr(index);
            }
            return self.upper.slot_addr(index - lower.count);
        }
        self.upper.slot_addr(index)
    }

    fn live_addrs(&self) -> Vec<u64> {
        let mut addrs = Vec::with_capacity(self.count() - self.num_free());
        if let Some(lower) = &self.lower {
            lower.append_live_addrs(&mut addrs);
        }
        self.upper.append_live_addrs(&mut addrs);
        addrs
    }

    fn base_addr(&self) -> u64 {
        self.lower
            .as_ref()
            .map_or(self.upper.base_addr, |lower| lower.base_addr)
    }

    fn count(&self) -> usize {
        self.lower.as_ref().map_or(0, |lower| lower.count) + self.upper.count
    }

    fn num_free(&self) -> usize {
        self.lower.as_ref().map_or(0, Tier::num_free) + self.upper.num_free()
    }

    fn layouts(&self) -> (Option<SlotLayout>, SlotLayout) {
        (self.lower.as_ref().map(Tier::layout), self.upper.layout())
    }
}

/// A buffer pool with one or two fixed-slot tiers.
///
/// Allocation and deallocation are O(1) per slot. Eligible allocations first
/// try the optional lower tier and fall back to the required upper tier when
/// the lower tier is full. [`alloc_sg`](BufferProvider::alloc_sg) splits logical
/// payloads into bounded descriptor segments.
#[derive(Clone)]
pub struct SlotPool {
    inner: SendWrap<Rc<RefCell<Inner>>>,
}

impl SlotPool {
    /// Create a single-tier recycling pool from exact slot placement.
    pub fn new(layout: SlotLayout) -> Result<Self, AllocError> {
        Self::from_layouts(None, layout)
    }

    /// Create a two-tier recycling pool from exact lower and upper layouts.
    ///
    /// The lower layout must precede the upper layout without overlap, and its
    /// slot size must not exceed the upper slot size. Adjacent equal-sized
    /// layouts form one tier.
    pub fn new_tiered(lower: SlotLayout, upper: SlotLayout) -> Result<Self, AllocError> {
        Self::from_layouts(Some(lower), upper)
    }

    fn from_layouts(lower: Option<SlotLayout>, upper: SlotLayout) -> Result<Self, AllocError> {
        let inner = Inner::new(lower, upper)?;
        Ok(Self {
            inner: SendWrap(Rc::new(RefCell::new(inner))),
        })
    }

    /// Return every live slot address in deterministic tier and index order.
    pub fn live_addrs(&self) -> Vec<u64> {
        self.inner.borrow().live_addrs()
    }

    /// Return the lower and upper tier layouts.
    pub fn layouts(&self) -> (Option<SlotLayout>, SlotLayout) {
        self.inner.borrow().layouts()
    }

    /// Compute the address of slot `index`, with lower-tier slots first.
    ///
    /// Returns `None` if `index >= count`.
    pub fn slot_addr(&self, index: usize) -> Option<u64> {
        self.inner.borrow().slot_addr(index)
    }

    /// Total number of free slots across all tiers.
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

    /// Base address of the first managed tier.
    pub fn base_addr(&self) -> u64 {
        self.inner.borrow().base_addr()
    }

    /// Maximum slot size in bytes.
    pub fn slot_size(&self) -> usize {
        self.inner.borrow().max_alloc_len()
    }

    /// Total number of slots across all tiers.
    pub fn count(&self) -> usize {
        self.inner.borrow().count()
    }
}

impl BufferProvider for SlotPool {
    fn max_alloc_len(&self) -> usize {
        self.inner.borrow().max_alloc_len()
    }

    fn alloc(&self, len: usize) -> Result<Allocation, AllocError> {
        self.inner.borrow_mut().alloc(len)
    }

    fn dealloc(&self, addr: u64) -> Result<(), AllocError> {
        self.inner.borrow_mut().dealloc_addr(addr)
    }
}
