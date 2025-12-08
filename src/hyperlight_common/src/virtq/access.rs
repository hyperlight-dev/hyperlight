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

//! Memory Access Traits for Virtqueue Operations
//!
//! This module defines the [`MemOps`] trait that abstracts memory access patterns
//! required by the virtqueue implementation. This allows the virtqueue code to
//! work with different memory backends e.g. Host vs Guest.

use bytemuck::Pod;

/// Backend-provided memory access for virtqueue.
///
/// # Safety
///
/// Implementations must ensure that:
/// - Pointers passed to methods are valid for the duration of the call
/// - Memory ordering guarantees are upheld as documented
/// - Reads and writes don't cause undefined behavior (alignment, validity)
///
/// [`RingProducer`]: super::RingProducer
/// [`RingConsumer`]: super::RingConsumer
pub trait MemOps {
    type Error;

    /// Read bytes from physical memory.
    ///
    /// Used for reading buffer contents pointed to by descriptors.
    ///
    /// # Arguments
    ///
    /// * `addr` - Guest physical address to read from
    /// * `dst` - Destination buffer to fill
    ///
    /// # Returns
    ///
    /// Number of bytes actually read (should equal `dst.len()` on success).
    ///
    /// # Safety
    ///
    /// The caller must ensure `paddr` is valid and points to at least `dst.len()` bytes.
    fn read(&self, addr: u64, dst: &mut [u8]) -> Result<usize, Self::Error>;

    /// Write bytes to physical memory.
    ///
    /// # Arguments
    ///
    /// * `addr` - address to write to
    /// * `src` - Source data to write
    ///
    /// # Returns
    ///
    /// Number of bytes actually written (should equal `src.len()` on success).
    ///
    /// # Safety
    ///
    /// The caller must ensure `paddr` is valid and points to at least `src.len()` bytes.
    fn write(&self, addr: u64, src: &[u8]) -> Result<usize, Self::Error>;

    /// Load a u16 with acquire semantics.
    ///
    /// # Safety
    ///
    /// `addr` must translate to a valid, aligned `AtomicU16` in shared memory.
    fn load_acquire(&self, addr: u64) -> Result<u16, Self::Error>;

    /// Store a u16 with release semantics.
    ///
    /// # Safety
    ///
    /// `addr` must translate to a valid `AtomicU16` in shared memory.
    fn store_release(&self, addr: u64, val: u16) -> Result<(), Self::Error>;

    /// Read a Pod type at the given pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure `addr` is valid, aligned, and translates to initialized memory.
    fn read_val<T: Pod>(&self, addr: u64) -> Result<T, Self::Error> {
        let mut val = T::zeroed();
        let bytes = bytemuck::bytes_of_mut(&mut val);

        self.read(addr, bytes)?;
        Ok(val)
    }

    /// Write a Pod type at the given pointer.
    ///
    /// # Safety
    ///
    /// The caller ensures that `ptr` is valid.
    fn write_val<T: Pod>(&self, addr: u64, val: T) -> Result<(), Self::Error> {
        let bytes = bytemuck::bytes_of(&val);
        self.write(addr, bytes)?;
        Ok(())
    }
}
