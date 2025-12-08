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

//! Virtqueue Descriptor Types
//!
//! This module defines the descriptor format for packed virtqueues as specified
//! in VIRTIO 1.1+. Each descriptor represents a memory buffer in a scatter-gather
//! list that the device will read from or write to.

use bitflags::bitflags;
use bytemuck::{Pod, Zeroable};

use super::MemOps;

bitflags! {
    /// Descriptor flags as defined by VIRTIO specification.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct DescFlags: u16 {
        /// This marks a buffer as continuing via the next field.
        const NEXT     = 1 << 0;
        /// This marks a buffer as device write-only (otherwise device read-only).
        const WRITE    = 1 << 1;
        /// This means the buffer contains a list of buffer descriptors (unsupported here).
        const INDIRECT = 1 << 2;
        /// Available flag for packed virtqueue wrap counter.
        const AVAIL    = 1 << 7;
        /// Used flag for packed virtqueue wrap counter.
        const USED     = 1 << 15;
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable, PartialEq, Eq, Hash)]
pub struct Descriptor {
    /// Physical address of the buffer.
    pub addr: u64,
    /// Length of the buffer in bytes.
    /// For used descriptors, this contains bytes written by device.
    pub len: u32,
    /// Buffer ID - used to correlate completions with submissions.
    /// All descriptors in a chain share the same ID.
    pub id: u16,
    /// Flags (NEXT, WRITE, INDIRECT, AVAIL, USED).
    pub flags: u16,
}

const _: () = assert!(core::mem::size_of::<Descriptor>() == 16);
const _: () = assert!(Descriptor::ADDR_OFFSET == 0);
const _: () = assert!(Descriptor::LEN_OFFSET == 8);
const _: () = assert!(Descriptor::ID_OFFSET == 12);
const _: () = assert!(Descriptor::FLAGS_OFFSET == 14);

impl Descriptor {
    pub const SIZE: usize = core::mem::size_of::<Self>();
    pub const ALIGN: usize = core::mem::align_of::<Self>();

    pub const ADDR_OFFSET: usize = core::mem::offset_of!(Self, addr);
    pub const LEN_OFFSET: usize = core::mem::offset_of!(Self, len);
    pub const ID_OFFSET: usize = core::mem::offset_of!(Self, id);
    pub const FLAGS_OFFSET: usize = core::mem::offset_of!(Self, flags);

    pub fn new(addr: u64, len: u32, id: u16, flags: DescFlags) -> Self {
        Self {
            addr,
            len,
            id,
            flags: flags.bits(),
        }
    }

    /// Get flags as a [`DescFlags`] bitfield.
    #[inline]
    pub fn flags(&self) -> DescFlags {
        DescFlags::from_bits_truncate(self.flags)
    }

    /// Did the guest mark this descriptor in the current guest round?
    #[inline]
    pub fn is_avail(&self, wrap: bool) -> bool {
        let f = self.flags();
        let avail = f.contains(DescFlags::AVAIL);
        let used = f.contains(DescFlags::USED);
        avail == wrap && used != wrap
    }

    /// Did the host mark this descriptor used in the current host round?
    #[inline]
    pub fn is_used(&self, wrap: bool) -> bool {
        let f = self.flags();
        let avail = f.contains(DescFlags::AVAIL);
        let used = f.contains(DescFlags::USED);
        avail == wrap && used == wrap
    }

    /// Is this descriptor writeable by the device?
    #[inline]
    pub fn is_writeable(&self) -> bool {
        self.flags().contains(DescFlags::WRITE)
    }

    /// Does this descriptor point to a next descriptor in the chain?
    #[inline]
    pub fn is_next(&self) -> bool {
        self.flags().contains(DescFlags::NEXT)
    }

    /// Mark descriptor as available according to the driver's wrap bit.
    /// As per the packed-virtqueue description:
    /// - set AVAIL bit to `driver_wrap`
    /// - set USED bit to `!driver_wrap` (inverse)
    #[inline]
    pub fn mark_avail(&mut self, wrap: bool) {
        if wrap {
            self.flags |= DescFlags::AVAIL.bits();
            self.flags &= !DescFlags::USED.bits();
        } else {
            self.flags &= !DescFlags::AVAIL.bits();
            self.flags |= DescFlags::USED.bits();
        }
    }

    /// Mark descriptor as used according to the device's wrap bit.
    /// As per spec: set both USED and AVAIL bits to match device_wrap
    #[inline]
    pub fn mark_used(&mut self, wrap: bool) {
        if wrap {
            self.flags |= DescFlags::USED.bits();
            self.flags |= DescFlags::AVAIL.bits();
        } else {
            self.flags &= !DescFlags::USED.bits();
            self.flags &= !DescFlags::AVAIL.bits();
        }
    }

    /// Read a descriptor from memory with acquire semantics for flags
    /// This is the primary synchronization point for consuming descriptors.
    ///
    /// # Invariant
    ///
    /// The caller must ensure that `base` is valid for reads of Descriptor
    pub fn read_acquire<M: MemOps>(mem: &M, addr: u64) -> Result<Self, M::Error> {
        let flags = mem.load_acquire(addr + Self::FLAGS_OFFSET as u64)?;
        let addr_val: u64 = mem.read_val(addr + Self::ADDR_OFFSET as u64)?;
        let len: u32 = mem.read_val(addr + Self::LEN_OFFSET as u64)?;
        let id: u16 = mem.read_val(addr + Self::ID_OFFSET as u64)?;

        Ok(Self {
            addr: addr_val,
            len,
            id,
            flags,
        })
    }

    /// Write a descriptor to memory with release semantics for flags at the given base pointer
    ///
    /// This is the primary synchronization point for publishing descriptors.
    ///
    /// # Invariant
    ///
    /// The caller must ensure that `base` is valid for writes of Descriptor
    pub fn write_release<M: MemOps>(&self, mem: &M, addr: u64) -> Result<(), M::Error> {
        mem.write_val(addr + Self::ADDR_OFFSET as u64, self.addr)?;
        mem.write_val(addr + Self::LEN_OFFSET as u64, self.len)?;
        mem.write_val(addr + Self::ID_OFFSET as u64, self.id)?;
        // Flags written last with release semantics
        mem.store_release(addr + Self::FLAGS_OFFSET as u64, self.flags)?;
        Ok(())
    }
}

/// A table of descriptors stored in shared memory.
#[derive(Debug, Clone, Copy)]
pub struct DescTable {
    base_addr: u64,
    size: usize,
}

impl DescTable {
    pub const DEFAULT_LEN: usize = 256;

    /// Create a descriptor table from shared memory.
    ///
    /// # Safety
    ///
    /// - `base` must be valid for reads and writes of `size` descriptors
    /// - `base` must be properly aligned for `Descriptor`
    /// - `size` must not exceed `u16::MAX`
    /// - memory must remain valid for the lifetime of this table
    pub unsafe fn from_raw_parts(base_addr: u64, size: usize) -> Self {
        assert!(base_addr.is_multiple_of(Descriptor::ALIGN as u64));
        assert!(size <= u16::MAX as usize);

        Self { base_addr, size }
    }

    /// Get view into descriptor at index or None if idx is out of bounds
    pub fn desc_addr(&self, idx: u16) -> Option<u64> {
        if idx >= self.size as u16 {
            return None;
        }

        Some(self.base_addr + (idx as u64 * Descriptor::SIZE as u64))
    }

    /// Get number of descriptors in table
    pub fn len(&self) -> usize {
        self.size
    }

    /// Is the descriptor table empty?
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub const fn default_len() -> usize {
        Self::DEFAULT_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_avail_sets_bits_correctly_wrap_true() {
        let mut d = Descriptor::zeroed();
        d.flags = DescFlags::WRITE.bits() | DescFlags::NEXT.bits();
        d.mark_avail(true);
        let f = d.flags();
        assert!(f.contains(DescFlags::AVAIL));
        assert!(!f.contains(DescFlags::USED));
        assert!(f.contains(DescFlags::WRITE));
        assert!(f.contains(DescFlags::NEXT));
    }

    #[test]
    fn mark_avail_sets_bits_correctly_wrap_false() {
        let mut d = Descriptor::zeroed();
        d.mark_avail(false);
        let f = d.flags();
        assert!(!f.contains(DescFlags::AVAIL));
        assert!(f.contains(DescFlags::USED));
    }

    #[test]
    fn mark_used_sets_both_bits_match_wrap_true() {
        let mut d = Descriptor::zeroed();
        d.mark_used(true);
        let f = d.flags();
        assert!(f.contains(DescFlags::AVAIL));
        assert!(f.contains(DescFlags::USED));
    }

    #[test]
    fn mark_used_sets_both_bits_match_wrap_false() {
        let mut d = Descriptor::zeroed();
        d.mark_used(false);
        let f = d.flags();
        assert!(!f.contains(DescFlags::AVAIL));
        assert!(!f.contains(DescFlags::USED));
    }

    #[test]
    fn is_avail_and_is_used() {
        let mut d = Descriptor::zeroed();
        d.mark_avail(true);
        assert!(d.is_avail(true));
        assert!(!d.is_used(true));
        d.mark_used(true);
        assert!(d.is_used(true));
        assert!(!d.is_avail(true));
        d.mark_avail(false);
        assert!(d.is_avail(false));
        assert!(!d.is_used(false));
        d.mark_used(false);
        assert!(d.is_used(false));
        assert!(!d.is_avail(false));
    }

    #[test]
    fn writeable_and_next_helpers() {
        let mut d = Descriptor::zeroed();
        d.flags = (DescFlags::WRITE | DescFlags::NEXT).bits();
        assert!(d.is_writeable());
        assert!(d.is_next());
        d.flags = 0;
        assert!(!d.is_writeable());
        assert!(!d.is_next());
    }

    #[test]
    fn avail_then_used_wrap_flip_sequence() {
        let mut d = Descriptor::zeroed();
        d.mark_avail(true);
        assert!(d.is_avail(true));
        d.mark_used(false);
        assert!(d.is_used(false));
        assert!(!d.is_avail(false));
        d.mark_avail(true);
        assert!(d.is_avail(true));
    }

    #[test]
    fn desc_table_get_out_of_bounds() {
        let mut vec = vec![Descriptor::zeroed(); 4];
        let ptr = vec.as_mut_ptr();
        let table = unsafe { DescTable::from_raw_parts(ptr.addr() as u64, 4) };
        assert!(table.desc_addr(3).is_some());
        assert!(table.desc_addr(4).is_none());
    }
}
