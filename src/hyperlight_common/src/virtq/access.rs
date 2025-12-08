use core::marker::PhantomData;
use core::ptr::NonNull;

use bytemuck::Pod;

pub trait MmioAccess: Pod {
    /// Acquire-ordered read from base pointer
    ///
    /// # Safety
    ///
    /// `base` must point to a valid Self in MMIO.
    unsafe fn read_acquire(base: core::ptr::NonNull<Self>) -> Self;

    /// Plain volatile read from base pointer (no ordering)
    ///
    /// # Safety
    ///
    /// `base` must point to a valid Self in MMIO.
    unsafe fn read_volatile(base: core::ptr::NonNull<Self>) -> Self {
        unsafe { core::ptr::read_volatile(base.as_ptr()) }
    }

    /// Release-ordered write to base pointer
    ///
    /// # Safety
    ///
    /// `base` must point to a valid Self in MMIO.
    unsafe fn write_release(base: core::ptr::NonNull<Self>, val: Self);

    /// Plain volatile write to base pointer (no ordering)
    ///
    /// # Safety
    ///
    /// `base` must point to a valid Self in MMIO.
    unsafe fn write_volatile(base: core::ptr::NonNull<Self>, val: Self) {
        unsafe { core::ptr::write_volatile(base.as_ptr(), val) }
    }
}

/// Access to the memory underlying virtqueue buffer addresses.
pub unsafe trait PhysMem: Send + Sync + 'static {
    type Error;

    /// Copy bytes out of guest memory at physical address `paddr` into `dst`.
    fn read_into(&self, paddr: u64, len: usize, dst: &mut [u8]) -> Result<usize, Self::Error>;

    /// Copy bytes into guest memory.
    fn write(&self, paddr: u64, data: &[u8]) -> Result<usize, Self::Error>;
}

/// A view into a `T` stored in shared memory.
#[derive(Debug)]
pub struct MmioView<'a, T: MmioAccess> {
    base: NonNull<T>,
    owner: PhantomData<&'a T>,
}

impl<'a, T: MmioAccess> MmioView<'a, T> {
    /// # Safety
    ///
    /// `base` must be valid for 'a and point to a valid T in MMIO.
    pub unsafe fn new(base: NonNull<T>) -> Self {
        Self {
            base,
            owner: PhantomData,
        }
    }

    #[inline(always)]
    pub fn read_acquire(&self) -> T {
        unsafe { T::read_acquire(self.base) }
    }

    #[inline(always)]
    pub fn read_volatile(&self) -> T {
        unsafe { T::read_volatile(self.base) }
    }
}

/// A mutable view into a `T` stored in shared memory.
#[derive(Debug)]
pub struct MmioViewMut<'a, T: MmioAccess> {
    base: NonNull<T>,
    owner: PhantomData<&'a mut T>,
}

impl<'a, T: MmioAccess> MmioViewMut<'a, T> {
    /// # Safety
    ///
    /// `base` must be valid for 'a and point to a valid T in MMIO.
    pub unsafe fn new(base: NonNull<T>) -> Self {
        Self {
            base,
            owner: PhantomData,
        }
    }

    #[inline(always)]
    pub fn read_acquire(&self) -> T {
        unsafe { T::read_acquire(self.base) }
    }

    #[inline(always)]
    pub fn read_volatile(&self) -> T {
        unsafe { T::read_volatile(self.base) }
    }

    #[inline(always)]
    pub fn write_release(&mut self, val: T) {
        unsafe { T::write_release(self.base, val) }
    }

    #[inline(always)]
    pub fn write_volatile(&mut self, val: T) {
        unsafe { T::write_volatile(self.base, val) }
    }

    #[inline(always)]
    pub fn as_view(&self) -> MmioView<'_, T> {
        unsafe { MmioView::new(self.base) }
    }
}
