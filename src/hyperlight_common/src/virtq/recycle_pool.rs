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

//! A simple fixed-size buffer recycler for H2G prefill entries.
//!
//! Unlike [`super::BufferPool`] which uses a bitmap allocator, this
//! holds a fixed set of same-sized buffer addresses in a free list.
//! Alloc and dealloc are O(1). Intended for H2G writable buffers
//! that are pre-allocated once and recycled after each use.

use alloc::sync::Arc;

use atomic_refcell::AtomicRefCell;
use smallvec::SmallVec;

use super::{AllocError, Allocation, BufferProvider};

/// A recycling buffer provider with fixed-size slots.
#[derive(Clone)]
pub struct RecyclePool {
    inner: Arc<AtomicRefCell<RecyclePoolInner>>,
}

struct RecyclePoolInner {
    base_addr: u64,
    slot_size: usize,
    count: usize,
    free: SmallVec<[u64; 64]>,
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

        let inner = AtomicRefCell::new(RecyclePoolInner {
            base_addr,
            slot_size,
            count,
            free,
        });

        Ok(Self {
            inner: inner.into(),
        })
    }

    /// Number of free slots.
    pub fn num_free(&self) -> usize {
        self.inner.borrow().free.len()
    }
}

impl BufferProvider for RecyclePool {
    fn alloc(&self, len: usize) -> Result<Allocation, AllocError> {
        let mut inner = self.inner.borrow_mut();
        if len > inner.slot_size {
            return Err(AllocError::OutOfMemory);
        }

        let addr = inner.free.pop().ok_or(AllocError::OutOfMemory)?;

        Ok(Allocation {
            addr,
            len: inner.slot_size,
        })
    }

    fn dealloc(&self, alloc: Allocation) -> Result<(), AllocError> {
        let mut inner = self.inner.borrow_mut();
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
