use core::marker::PhantomData;
use core::ptr::{self, NonNull};
#[cfg(not(all(test, loom)))]
use core::sync::atomic::{AtomicU16, Ordering};

use bitflags::bitflags;
use bytemuck::{Pod, Zeroable};
#[cfg(all(test, loom))]
use loom::sync::atomic::{AtomicU16, Ordering};

use super::{MmioAccess, MmioView, MmioViewMut};

bitflags! {
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct DescFlags: u16 {
        const NEXT     = 1 << 0;
        const WRITE    = 1 << 1;
        const INDIRECT = 1 << 2;
        const AVAIL    = 1 << 7;
        const USED     = 1 << 15;
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable, PartialEq, Eq, Hash)]
pub struct Descriptor {
    pub addr: u64,
    pub len: u32,
    pub id: u16,
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

    /// Interpret flags as DescFlags
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
}

impl MmioAccess for Descriptor {
    unsafe fn read_acquire(base: NonNull<Self>) -> Self {
        let base_ptr = base.as_ptr().cast::<u8>();

        // Atomic Acquire load of flags (publish point)
        // SAFETY: flags pointer is valid
        let flags_ptr = base_ptr
            .wrapping_add(Descriptor::FLAGS_OFFSET)
            .cast::<AtomicU16>();

        let flags = unsafe { (*flags_ptr).load(Ordering::Acquire) };

        let addr_ptr = base_ptr.wrapping_add(Descriptor::ADDR_OFFSET).cast::<u64>();
        let addr = unsafe { ptr::read_volatile(addr_ptr) };

        let len_ptr = base_ptr.wrapping_add(Descriptor::LEN_OFFSET).cast::<u32>();
        let len = unsafe { ptr::read_volatile(len_ptr) };

        let id_ptr = base_ptr.wrapping_add(Descriptor::ID_OFFSET).cast::<u16>();
        let id = unsafe { ptr::read_volatile(id_ptr) };

        Descriptor {
            addr,
            len,
            id,
            flags,
        }
    }

    unsafe fn write_release(base: NonNull<Self>, desc: Self) {
        let base_ptr = base.as_ptr().cast::<u8>();

        let addr_ptr = base_ptr.wrapping_add(Descriptor::ADDR_OFFSET).cast::<u64>();
        unsafe { ptr::write_volatile(addr_ptr, desc.addr) };

        let len_ptr = base_ptr.wrapping_add(Descriptor::LEN_OFFSET).cast::<u32>();
        unsafe { ptr::write_volatile(len_ptr, desc.len) };

        let id_ptr = base_ptr.wrapping_add(Descriptor::ID_OFFSET).cast::<u16>();
        unsafe { ptr::write_volatile(id_ptr, desc.id) };

        let flags_ptr = base_ptr
            .wrapping_add(Descriptor::FLAGS_OFFSET)
            .cast::<AtomicU16>();

        // Atomic Release store of flags (publish)
        // SAFETY: flags pointer is valid
        unsafe { (*flags_ptr).store(desc.flags, Ordering::Release) };
    }
}

/// A table of descriptors stored in shared memory.
#[derive(Debug, Clone, Copy)]
pub struct DescTable<'t> {
    base: NonNull<Descriptor>,
    size: usize,
    owner: PhantomData<&'t [Descriptor]>,
}

impl<'t> DescTable<'t> {
    pub const DEFAULT_LEN: usize = 256;

    /// Create and initialize a descriptor table in shared memory.
    ///
    /// # Safety
    ///
    /// `base` must be valid for reads/writes for size descriptors
    pub unsafe fn init_mem(base: NonNull<Descriptor>, size: usize) -> Self {
        let mut table = unsafe { Self::from_mem(base, size) };

        // Zero out all descriptors
        for i in 0..size as u16 {
            table.set(i, &Descriptor::zeroed());
        }

        table
    }

    /// Create a descriptor table from shared memory.
    ///
    /// # Safety
    ///
    /// `base` must be valid for reads/writes for size descriptors
    pub unsafe fn from_mem(base: NonNull<Descriptor>, size: usize) -> Self {
        assert!((base.as_ptr() as usize) % Descriptor::ALIGN == 0);
        assert!(size <= u16::MAX as usize);

        Self {
            base,
            size,
            owner: PhantomData,
        }
    }

    /// Get view into descriptor at index or None if idx is out of bounds
    pub fn get(&self, idx: u16) -> Option<MmioView<'_, Descriptor>> {
        if idx >= self.size as u16 {
            return None;
        }

        let base = self.base.as_ptr().cast::<Descriptor>();
        // SAFETY: ptr is within table because idx < size
        let raw = unsafe { NonNull::new_unchecked(base.add(idx as usize)) };
        // SAFETY: raw is valid
        Some(unsafe { MmioView::new(raw) })
    }

    /// Get view into descriptor at index or None if idx is out of bounds
    pub fn get_mut(&mut self, idx: u16) -> Option<MmioViewMut<'_, Descriptor>> {
        if idx >= self.size as u16 {
            return None;
        }

        let base = self.base.as_ptr().cast::<Descriptor>();
        // SAFETY: ptr is within table because idx < size
        let raw = unsafe { NonNull::new_unchecked(base.add(idx as usize)) };
        // SAFETY: raw is valid
        Some(unsafe { MmioViewMut::new(raw) })
    }

    /// Set descriptor at index
    ///
    /// # Panics
    ///
    /// Panics if idx is out of bounds
    pub fn set(&mut self, idx: u16, desc: &Descriptor) {
        let Some(mut view) = self.get_mut(idx) else {
            panic!("Index out of bounds in DescTable::set");
        };

        view.write_release(*desc);
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
        let ptr = NonNull::new(vec.as_mut_ptr()).unwrap();
        let table = unsafe { DescTable::from_mem(ptr, 4) };
        assert!(table.get(3).is_some());
        assert!(table.get(4).is_none());
    }
}
