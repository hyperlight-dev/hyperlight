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
    #[error("No space available")]
    NoSpace,
    #[error("Requested size exceeds pool capacity")]
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
/// Holds a [`PoolAlloc`] and provides direct access to the underlying
/// shared memory via [`MemOps::as_slice`]. Implements `AsRef<[u8]>` so it
/// can be used with [`Bytes::from_owner`](bytes::Bytes::from_owner) for
/// zero-copy `Bytes` backed by shared memory.
///
/// When dropped, the allocation is returned to the pool.
#[derive(Debug)]
pub struct BufferOwner<P: BufferProvider, M: MemOps> {
    pub(crate) alloc: PoolAlloc<P>,
    pub(crate) mem: M,
    pub(crate) written: usize,
}

impl<P: BufferProvider, M: MemOps> AsRef<[u8]> for BufferOwner<P, M> {
    fn as_ref(&self) -> &[u8] {
        let alloc = self.alloc.allocation();
        let len = self.written.min(alloc.len);
        // Safety: BufferOwner keeps both the pool allocation and the M alive,
        // so the memory region is valid.
        match unsafe { self.mem.as_slice(alloc.addr, len) } {
            Ok(slice) => slice,
            Err(_) => {
                debug_assert!(false, "BufferOwner direct slice failed");
                &[]
            }
        }
    }
}

/// Pool-owned allocation that is returned to the pool on drop.
///
/// Use [`into_raw`](Self::into_raw) to transfer ownership to a descriptor
/// state that will deallocate the raw [`Allocation`] through another path.
#[derive(Debug)]
pub struct PoolAlloc<P: BufferProvider> {
    inner: Option<PoolAllocInner<P>>,
}

#[derive(Debug)]
struct PoolAllocInner<P: BufferProvider> {
    pool: P,
    alloc: Allocation,
}

impl<P: BufferProvider> PoolAlloc<P> {
    /// Wrap an existing allocation with its owning pool.
    pub fn new(pool: P, alloc: Allocation) -> Self {
        Self {
            inner: Some(PoolAllocInner { pool, alloc }),
        }
    }

    /// Allocate from `pool` and return an owning guard.
    pub fn allocate(pool: P, len: usize) -> Result<Self, AllocError> {
        let alloc = pool.alloc(len)?;
        Ok(Self::new(pool, alloc))
    }

    /// The raw allocation currently owned by this guard.
    pub fn allocation(&self) -> Allocation {
        self.inner
            .as_ref()
            .map(|inner| inner.alloc)
            .unwrap_or_else(|| {
                unreachable!("PoolAlloc::allocation called after ownership transfer")
            })
    }

    /// Release ownership and return the raw allocation.
    pub fn into_raw(mut self) -> Allocation {
        self.inner
            .take()
            .map(|inner| inner.alloc)
            .unwrap_or_else(|| unreachable!("PoolAlloc::into_raw called after ownership transfer"))
    }

    pub(crate) fn into_buffer_owner<M: MemOps>(
        self,
        mem: M,
        written: usize,
    ) -> Result<BufferOwner<P, M>, M::Error> {
        let alloc = self.allocation();
        let len = written.min(alloc.len);
        let _ = unsafe { mem.as_slice(alloc.addr, len) }?;

        Ok(BufferOwner {
            alloc: self,
            mem,
            written,
        })
    }
}

impl<P: BufferProvider> Drop for PoolAlloc<P> {
    fn drop(&mut self) {
        if let Some(PoolAllocInner { pool, alloc }) = self.inner.take() {
            let _ = pool.dealloc(alloc);
        }
    }
}
