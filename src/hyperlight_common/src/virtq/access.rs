// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Memory Access Traits for Virtqueue Operations
//!
//! This module defines the [`MemOps`] trait that abstracts memory access patterns
//! required by the virtqueue implementation. This allows the virtqueue code to
//! work with different memory backends e.g. Host vs Guest.

use alloc::sync::Arc;

use bytemuck::Pod;

use super::BufferLease;

/// Backend-provided memory access for virtqueue.
///
/// # Safety
///
/// Implementations must ensure that:
/// - Addresses accepted by these methods are translated according to the
///   backend's memory model.
/// - Invalid or inaccessible addresses are reported with `Self::Error` rather
///   than causing undefined behavior.
/// - Memory ordering guarantees are upheld as documented.
/// - Typed reads/writes and atomic operations honor alignment and initialized
///   memory requirements for the translated addresses.
///
/// [`RingProducer`]: super::RingProducer
/// [`RingConsumer`]: super::RingConsumer
pub unsafe trait MemOps {
    type Error;

    /// Read bytes at a backend address.
    ///
    /// Used for reading buffer contents pointed to by descriptors.
    ///
    /// # Arguments
    ///
    /// * `addr` - Address in the backend's memory model
    /// * `dst` - Destination buffer to fill
    ///
    /// Implementations must return an error if `addr` cannot be read for
    /// at least `dst.len()` bytes.
    fn read(&self, addr: u64, dst: &mut [u8]) -> Result<(), Self::Error>;

    /// Write bytes at a backend address.
    ///
    /// # Arguments
    ///
    /// * `addr` - address to write to
    /// * `src` - Source data to write
    ///
    /// Implementations must return an error if `addr` cannot be written for
    /// at least `src.len()` bytes.
    fn write(&self, addr: u64, src: &[u8]) -> Result<(), Self::Error>;

    /// Load a u16 with acquire semantics.
    ///
    /// Implementations must return an error if `addr` does not translate to a
    /// valid, aligned `AtomicU16` in shared memory.
    fn load_acquire(&self, addr: u64) -> Result<u16, Self::Error>;

    /// Store a u16 with release semantics.
    ///
    /// Implementations must return an error if `addr` does not translate to a
    /// valid, aligned `AtomicU16` in shared memory.
    fn store_release(&self, addr: u64, val: u16) -> Result<(), Self::Error>;

    /// Get a direct read-only slice into shared memory.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - `addr` is valid and points to at least `len` bytes.
    /// - The memory region is not concurrently modified for the lifetime of
    ///   the returned slice. Caller must uphold this via protocol-level
    ///   synchronisation, e.g. descriptor ownership transfer.
    unsafe fn as_slice(&self, addr: u64, len: usize) -> Result<&[u8], Self::Error>;

    /// Get a direct mutable slice into shared memory.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - `addr` is valid and points to at least `len` bytes.
    /// - No other references (shared or mutable) to this memory region exist
    ///   for the lifetime of the returned slice.
    /// - Protocol-level synchronisation (e.g. descriptor ownership) guarantees
    ///   exclusive access.
    #[allow(clippy::mut_from_ref)]
    unsafe fn as_mut_slice(&self, addr: u64, len: usize) -> Result<&mut [u8], Self::Error>;

    /// Read a Pod type at the given pointer.
    ///
    /// Implementations must return an error if `addr` is not valid, aligned,
    /// and initialized for `T`.
    fn read_val<T: Pod>(&self, addr: u64) -> Result<T, Self::Error> {
        let mut val = T::zeroed();
        let bytes = bytemuck::bytes_of_mut(&mut val);

        self.read(addr, bytes)?;
        Ok(val)
    }

    /// Write a Pod type at the given pointer.
    ///
    /// Implementations must return an error if `addr` is not valid and aligned
    /// for `T`.
    fn write_val<T: Pod>(&self, addr: u64, val: T) -> Result<(), Self::Error> {
        let bytes = bytemuck::bytes_of(&val);
        self.write(addr, bytes)?;
        Ok(())
    }
}

/// Owned immutable views of completed queue buffers.
pub trait BufferMap: MemOps {
    /// A complete owner exposing exactly the initialized prefix.
    ///
    /// Its bytes must stay valid at the same address until the mapping drops,
    /// including when the mapping is moved. A borrowed view must retain its
    /// lease and release the view before returning the slot.
    type Mapping: AsRef<[u8]> + Send + 'static;

    /// Retain a view of the first `written` bytes of an allocation.
    ///
    /// Implementations must release the lease on error.
    ///
    /// # Safety
    ///
    /// The first `written` bytes of the leased allocation are initialized,
    /// and `written` does not exceed its capacity. No peer may write or reuse
    /// the allocation while the lease survives.
    unsafe fn map_buffer(
        &self,
        lease: BufferLease,
        written: usize,
    ) -> Result<Self::Mapping, Self::Error>;
}

// SAFETY: Arc delegates all memory operations to the wrapped backend, preserving
// that backend's MemOps contract.
unsafe impl<T: MemOps> MemOps for Arc<T> {
    type Error = T::Error;

    fn read(&self, addr: u64, dst: &mut [u8]) -> Result<(), Self::Error> {
        (**self).read(addr, dst)
    }

    fn write(&self, addr: u64, src: &[u8]) -> Result<(), Self::Error> {
        (**self).write(addr, src)
    }

    fn load_acquire(&self, addr: u64) -> Result<u16, Self::Error> {
        (**self).load_acquire(addr)
    }

    fn store_release(&self, addr: u64, val: u16) -> Result<(), Self::Error> {
        (**self).store_release(addr, val)
    }

    unsafe fn as_slice(&self, addr: u64, len: usize) -> Result<&[u8], Self::Error> {
        // SAFETY: The caller supplies the wrapped backend's slice preconditions.
        unsafe { (**self).as_slice(addr, len) }
    }

    #[allow(clippy::mut_from_ref)]
    unsafe fn as_mut_slice(&self, addr: u64, len: usize) -> Result<&mut [u8], Self::Error> {
        // SAFETY: The caller supplies the wrapped backend's exclusive-access preconditions.
        unsafe { (**self).as_mut_slice(addr, len) }
    }
}
