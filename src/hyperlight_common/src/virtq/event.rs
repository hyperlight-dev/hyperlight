#[cfg(not(all(test, loom)))]
use core::sync::atomic::{AtomicU16, Ordering};

use bitflags::bitflags;
use bytemuck::{Pod, Zeroable};
#[cfg(all(test, loom))]
use loom::sync::atomic::{AtomicU16, Ordering};

use super::access::MmioAccess;

bitflags! {
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct EventFlags: u16 {
        const ENABLE = 0x0;
        const DISABLE = 0x1;
        const DESC = 0x2;
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable, PartialEq, Eq, Hash)]
pub struct EventSuppression {
    // bits 0-14: offset, bit 15: wrap
    off_wrap: u16,
    // bits 0-1: flags, bits 2-15: reserved
    flags: u16,
}

const _: () = assert!(core::mem::size_of::<EventSuppression>() == 4);
const _: () = assert!(EventSuppression::WRAP_OFFSET == 0);
const _: () = assert!(EventSuppression::FLAGS_OFFSET == 2);

impl EventSuppression {
    pub const ALIGN: usize = core::mem::align_of::<Self>();
    pub const WRAP_OFFSET: usize = core::mem::offset_of!(Self, off_wrap);
    pub const FLAGS_OFFSET: usize = core::mem::offset_of!(Self, flags);

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
}

impl MmioAccess for EventSuppression {
    unsafe fn read_acquire(base: core::ptr::NonNull<Self>) -> Self {
        let base_ptr = base.as_ptr().cast::<u8>();

        // Atomic Acquire load of flags (publish point)
        let flags_ptr = base_ptr
            .wrapping_add(EventSuppression::FLAGS_OFFSET)
            .cast::<AtomicU16>();

        // SAFETY: flags pointer is valid
        let flags = unsafe { (*flags_ptr).load(Ordering::Acquire) };

        let off_wrap_ptr = base_ptr
            .wrapping_add(EventSuppression::WRAP_OFFSET)
            .cast::<u16>();

        let off_wrap = unsafe { core::ptr::read_volatile(off_wrap_ptr) };
        EventSuppression { off_wrap, flags }
    }

    unsafe fn write_release(base: core::ptr::NonNull<Self>, evt: Self) {
        let base_ptr = base.as_ptr().cast::<u8>();

        let off_wrap_ptr = base_ptr
            .wrapping_add(EventSuppression::WRAP_OFFSET)
            .cast::<u16>();

        // SAFETY: off_wrap pointer is valid
        unsafe { core::ptr::write_volatile(off_wrap_ptr, evt.off_wrap) };

        // Atomic Release store of flags (publish point)
        let flags_ptr = base_ptr
            .wrapping_add(EventSuppression::FLAGS_OFFSET)
            .cast::<AtomicU16>();

        unsafe { (*flags_ptr).store(evt.flags, Ordering::Release) };
    }
}
