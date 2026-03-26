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

//! Guest-side [`MemOps`] implementation for virtqueue access.

use core::convert::Infallible;
use core::sync::atomic::{AtomicU16, Ordering};
use core::{ptr, slice};

use hyperlight_common::virtq::MemOps;

/// Guest-side memory accessor for virtqueue operations. Treats virtq
/// addresses as guest virtual addresses that map directly to memory.
#[derive(Clone, Copy, Debug)]
pub struct GuestMemOps;

impl MemOps for GuestMemOps {
    type Error = Infallible;

    fn read(&self, addr: u64, dst: &mut [u8]) -> Result<usize, Self::Error> {
        unsafe { ptr::copy_nonoverlapping(addr as *const u8, dst.as_mut_ptr(), dst.len()) };
        Ok(dst.len())
    }

    fn write(&self, addr: u64, src: &[u8]) -> Result<usize, Self::Error> {
        unsafe { ptr::copy_nonoverlapping(src.as_ptr(), addr as *mut u8, src.len()) };
        Ok(src.len())
    }

    fn load_acquire(&self, addr: u64) -> Result<u16, Self::Error> {
        Ok(unsafe { (*(addr as *const AtomicU16)).load(Ordering::Acquire) })
    }

    fn store_release(&self, addr: u64, val: u16) -> Result<(), Self::Error> {
        unsafe { (*(addr as *const AtomicU16)).store(val, Ordering::Release) };
        Ok(())
    }

    unsafe fn as_slice(&self, addr: u64, len: usize) -> Result<&[u8], Self::Error> {
        Ok(unsafe { slice::from_raw_parts(addr as *const u8, len) })
    }

    unsafe fn as_mut_slice(&self, addr: u64, len: usize) -> Result<&mut [u8], Self::Error> {
        Ok(unsafe { slice::from_raw_parts_mut(addr as *mut u8, len) })
    }
}
