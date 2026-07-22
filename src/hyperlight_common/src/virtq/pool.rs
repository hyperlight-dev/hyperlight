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
//! Buffer pool APIs and implementations for virtqueue payloads.
//!
//! - [`RunPool`] allocates variable-sized contiguous runs from two tiers.
//! - [`SlotPool`] recycles one or two tiers of fixed-size slots.

use alloc::rc::Rc;
use alloc::sync::Arc;
use core::ops::Deref;

use smallvec::SmallVec;
use thiserror::Error;

mod run;
mod slot;

pub use run::RunPool;
#[cfg(all(test, loom))]
pub use run::RunPoolSync;
pub use slot::{SlotLayout, SlotPool};

/// Buffer allocation failure.
#[derive(Debug, Error, Copy, Clone)]
pub enum AllocError {
    /// A region does not meet its required alignment.
    #[error("Invalid region addr {0}")]
    InvalidAlign(u64),
    /// An address does not identify a live allocation.
    #[error("Invalid free addr {0} and size {1}")]
    InvalidFree(u64, usize),
    /// An argument is zero or otherwise invalid.
    #[error("Invalid argument")]
    InvalidArg,
    /// A region cannot hold any allocation.
    #[error("Empty region")]
    EmptyRegion,
    /// No currently free allocation can satisfy the request.
    #[error("No space available")]
    NoSpace,
    /// The request exceeds the pool's allocation capacity.
    #[error("Requested size exceeds pool capacity")]
    OutOfMemory,
    /// Address or size arithmetic overflowed.
    #[error("Overflow")]
    Overflow,
}

/// One allocation returned by a [`BufferProvider`].
#[derive(Debug, Clone, Copy)]
pub struct Allocation {
    /// Starting address of the allocation.
    pub addr: u64,
    /// Capacity in bytes, rounded up according to the provider's policy.
    pub len: usize,
}

/// Allocates and reclaims virtqueue payload buffers.
pub trait BufferProvider {
    /// Preferred maximum size of one allocation segment.
    fn max_alloc_len(&self) -> usize {
        usize::MAX
    }

    /// Allocate one buffer that can hold at least `len` bytes.
    fn alloc(&self, len: usize) -> Result<Allocation, AllocError>;

    /// Free a previously allocated segment by start address.
    fn dealloc(&self, addr: u64) -> Result<(), AllocError>;

    /// Allocate scatter/gather segments for a logical payload of `total_len` bytes.
    fn alloc_sg(&self, total_len: usize) -> Result<SmallVec<[Allocation; 4]>, AllocError> {
        if total_len == 0 {
            return Err(AllocError::InvalidArg);
        }

        let seg_cap = self.max_alloc_len();
        if seg_cap == 0 {
            return Err(AllocError::InvalidArg);
        }

        let mut rem = total_len;
        let mut sgs = SmallVec::<[Allocation; 4]>::new();

        while rem > 0 {
            let len = rem.min(seg_cap);
            match self.alloc(len) {
                Ok(alloc) => {
                    sgs.push(alloc);
                    rem -= len;
                }
                Err(err) => {
                    for sg in sgs {
                        let result = self.dealloc(sg.addr);
                        debug_assert!(result.is_ok(), "dealloc failed: {result:?}");
                    }
                    return Err(err);
                }
            }
        }

        Ok(sgs)
    }
}

impl<T: BufferProvider> BufferProvider for Rc<T> {
    fn max_alloc_len(&self) -> usize {
        (**self).max_alloc_len()
    }

    fn alloc(&self, len: usize) -> Result<Allocation, AllocError> {
        (**self).alloc(len)
    }

    fn dealloc(&self, addr: u64) -> Result<(), AllocError> {
        (**self).dealloc(addr)
    }

    fn alloc_sg(&self, total_len: usize) -> Result<SmallVec<[Allocation; 4]>, AllocError> {
        (**self).alloc_sg(total_len)
    }
}

impl<T: BufferProvider> BufferProvider for Arc<T> {
    fn max_alloc_len(&self) -> usize {
        (**self).max_alloc_len()
    }

    fn alloc(&self, len: usize) -> Result<Allocation, AllocError> {
        (**self).alloc(len)
    }

    fn dealloc(&self, addr: u64) -> Result<(), AllocError> {
        (**self).dealloc(addr)
    }

    fn alloc_sg(&self, total_len: usize) -> Result<SmallVec<[Allocation; 4]>, AllocError> {
        (**self).alloc_sg(total_len)
    }
}

/// Wrapper asserting `Send` for an inner value that is only ever accessed from
/// a single thread.
///
/// [`RunPool`] and [`SlotPool`] hold their state in an `Rc<RefCell<..>>`, which
/// is neither `Send` nor `Sync`. Their allocations are exposed as zero-copy
/// reply payloads through [`Bytes::from_owner`](bytes::Bytes::from_owner),
/// whose owner bound is `Send + 'static`; this wrapper exists solely so the
/// pools can satisfy that bound.
///
/// # Safety
///
/// The `Send` assertion is only sound while the wrapped value and every
/// `Bytes` handed out from it stay on a single thread. Hyperlight guests are
/// single-threaded, so this holds for guest-side use. It is unsound to move a
/// pool or reply `Bytes` to another thread.
#[derive(Debug)]
struct SendWrap<T>(T);

impl<T: Clone> Clone for SendWrap<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Deref for SendWrap<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

#[inline]
fn align_up(val: usize, align: usize) -> Result<usize, AllocError> {
    if align == 0 {
        return Err(AllocError::InvalidArg);
    }

    val.checked_next_multiple_of(align)
        .ok_or(AllocError::Overflow)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod fuzz;
