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

//! Event Suppression for Virtqueue Notifications
//!
//! This module implements the event suppression mechanism from VIRTIO 1.1+
//! that allows fine-grained control over when notifications are sent between
//! driver and device.

use bitflags::bitflags;
use bytemuck::{Pod, Zeroable};

use super::MemOps;

bitflags! {
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct EventFlags: u16 {
        /// Enable notifications (always notify).
        const ENABLE = 0x0;
        /// Disable notifications (never notify).
        const DISABLE = 0x1;
        /// Notify only at specific descriptor (EVENT_IDX mode).
        const DESC = 0x2;
    }
}

/// Event suppression structure for controlling notifications.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable, PartialEq, Eq, Hash)]
pub struct EventSuppression {
    // bits 0-14: offset, bit 15: wrap
    pub off_wrap: u16,
    // bits 0-1: flags, bits 2-15: reserved
    pub flags: u16,
}

const _: () = assert!(core::mem::size_of::<EventSuppression>() == 4);
const _: () = assert!(EventSuppression::WRAP_OFFSET == 0);
const _: () = assert!(EventSuppression::FLAGS_OFFSET == 2);

impl EventSuppression {
    pub const SIZE: usize = core::mem::size_of::<Self>();
    pub const ALIGN: usize = core::mem::align_of::<Self>();
    pub const WRAP_OFFSET: usize = core::mem::offset_of!(Self, off_wrap);
    pub const FLAGS_OFFSET: usize = core::mem::offset_of!(Self, flags);

    /// Create a new event suppression with the given offset/wrap and flags.
    pub fn new(off_wrap: u16, flags: EventFlags) -> Self {
        Self {
            off_wrap,
            flags: flags.bits(),
        }
    }

    /// Get the event flags.
    pub fn flags(&self) -> EventFlags {
        EventFlags::from_bits_truncate(self.flags & 0x3)
    }

    /// Set the event flags.
    pub fn set_flags(&mut self, flags: EventFlags) {
        self.flags = (self.flags & !0x3) | (flags.bits() & 0x3);
    }

    /// Get the descriptor event offset (bits 0-14).
    pub fn desc_event_off(&self) -> u16 {
        self.off_wrap & 0x7FFF
    }

    /// Check if the descriptor event wrap bit (bit 15) is set.
    pub fn desc_event_wrap(&self) -> bool {
        (self.off_wrap & 0x8000) != 0
    }

    /// Set the descriptor event offset and wrap bit.
    pub fn set_desc_event(&mut self, off: u16, wrap: bool) {
        self.off_wrap = (off & 0x7FFF) | if wrap { 0x8000 } else { 0 };
    }

    /// Create an `EventSuppression` from a raw pointer with acquire semantics.
    ///
    /// # Invariant
    ///
    /// The caller must ensure that `base` is a valid pointer to an EventSuppression.
    pub fn read_acquire<M: MemOps>(mem: &M, addr: u64) -> Result<Self, M::Error> {
        // Atomic Acquire load of flags (publish point)
        let flags = mem.load_acquire(addr + Self::FLAGS_OFFSET as u64)?;
        let off_wrap: u16 = mem.read_val(addr + Self::WRAP_OFFSET as u64)?;
        Ok(Self { off_wrap, flags })
    }

    /// Write an `EventSuppression` to a raw pointer with release semantics.
    ///
    /// # Invariant
    ///
    /// The caller must ensure that `base` is a valid pointer to an EventSuppression.
    pub fn write_release<M: MemOps>(&self, mem: &M, addr: u64) -> Result<(), M::Error> {
        mem.write_val(addr + Self::WRAP_OFFSET as u64, self.off_wrap)?;
        // Atomic Release store of flags (publish point)
        mem.store_release(addr + Self::FLAGS_OFFSET as u64, self.flags)?;
        Ok(())
    }
}
