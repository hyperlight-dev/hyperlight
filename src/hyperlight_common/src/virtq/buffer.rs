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

//! Buffer allocation traits and shared types for virtqueue buffer management.

use alloc::rc::Rc;
use alloc::sync::Arc;

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

    /// Reset the pool to initial state.
    fn reset(&self) {}
}

impl<T: BufferProvider> BufferProvider for Rc<T> {
    fn alloc(&self, len: usize) -> Result<Allocation, AllocError> {
        (**self).alloc(len)
    }
    fn dealloc(&self, alloc: Allocation) -> Result<(), AllocError> {
        (**self).dealloc(alloc)
    }
    fn resize(&self, old_alloc: Allocation, new_len: usize) -> Result<Allocation, AllocError> {
        (**self).resize(old_alloc, new_len)
    }
    fn reset(&self) {
        (**self).reset()
    }
}

impl<T: BufferProvider> BufferProvider for Arc<T> {
    fn alloc(&self, len: usize) -> Result<Allocation, AllocError> {
        (**self).alloc(len)
    }
    fn dealloc(&self, alloc: Allocation) -> Result<(), AllocError> {
        (**self).dealloc(alloc)
    }
    fn resize(&self, old_alloc: Allocation, new_len: usize) -> Result<Allocation, AllocError> {
        (**self).resize(old_alloc, new_len)
    }
    fn reset(&self) {
        (**self).reset()
    }
}

/// The owner of a mapped buffer, ensuring its lifetime.
///
/// Holds a pool allocation and provides direct access to the underlying
/// shared memory via [`MemOps::as_slice`]. Implements `AsRef<[u8]>` so it
/// can be used with [`Bytes::from_owner`](bytes::Bytes::from_owner) for
/// zero-copy `Bytes` backed by shared memory.
///
/// When dropped, the allocation is returned to the pool.
#[derive(Debug, Clone)]
pub struct BufferOwner<P: BufferProvider, M: MemOps> {
    pub(crate) pool: P,
    pub(crate) mem: M,
    pub(crate) alloc: Allocation,
    pub(crate) written: usize,
}

impl<P: BufferProvider, M: MemOps> Drop for BufferOwner<P, M> {
    fn drop(&mut self) {
        let _ = self.pool.dealloc(self.alloc);
    }
}

impl<P: BufferProvider, M: MemOps> AsRef<[u8]> for BufferOwner<P, M> {
    fn as_ref(&self) -> &[u8] {
        let len = self.written.min(self.alloc.len);
        // Safety: BufferOwner keeps both the pool allocation and the M
        // alive, so the memory region is valid. Protocol-level descriptor
        // ownership transfer guarantees no concurrent writes.
        match unsafe { self.mem.as_slice(self.alloc.addr, len) } {
            Ok(slice) => slice,
            Err(_) => &[],
        }
    }
}

/// A guard that runs a cleanup function when dropped, unless dismissed.
pub struct AllocGuard<F: FnOnce(Allocation)>(Option<(Allocation, F)>);

impl<F: FnOnce(Allocation)> AllocGuard<F> {
    pub fn new(alloc: Allocation, cleanup: F) -> Self {
        Self(Some((alloc, cleanup)))
    }

    pub fn release(mut self) -> Allocation {
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
