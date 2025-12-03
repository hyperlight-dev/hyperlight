/*
Copyright 2025  The Hyperlight Authors.

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
#![no_std]

// === Dependencies ===
extern crate alloc;

use core::fmt::Write;

use buddy_system_allocator::LockedHeap;
use guest_function::call::dispatch_function;
use guest_function::register::GuestFunctionRegister;
use guest_logger::init_logger;
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::mem::HyperlightPEB;
#[cfg(feature = "mem_profile")]
use hyperlight_common::outb::OutBAction;
use hyperlight_guest::exit::{halt, write_abort};
use hyperlight_guest::guest_handle::handle::GuestHandle;
use hyperlight_guest_tracing::{trace, trace_function};
use log::LevelFilter;

// === Modules ===
#[cfg_attr(target_arch = "x86_64", path = "arch/amd64/mod.rs")]
pub mod arch;
pub mod guest_err;
pub mod guest_function {
    pub(super) mod call;
    pub mod definition;
    pub mod register;
}

pub mod guest_logger;
pub mod host_comm;
pub mod memory;
pub mod paging;

// Globals
#[cfg(feature = "mem_profile")]
struct ProfiledLockedHeap<const ORDER: usize>(LockedHeap<ORDER>);
#[cfg(feature = "mem_profile")]
unsafe impl<const ORDER: usize> alloc::alloc::GlobalAlloc for ProfiledLockedHeap<ORDER> {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let addr = unsafe { self.0.alloc(layout) };
        unsafe {
            core::arch::asm!("out dx, al",
                in("dx") OutBAction::TraceMemoryAlloc as u16,
                in("rax") layout.size() as u64,
                in("rcx") addr as u64);
        }
        addr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        unsafe {
            core::arch::asm!("out dx, al",
                in("dx") OutBAction::TraceMemoryFree as u16,
                in("rax") layout.size() as u64,
                in("rcx") ptr as u64);
            self.0.dealloc(ptr, layout)
        }
    }
    unsafe fn alloc_zeroed(&self, layout: core::alloc::Layout) -> *mut u8 {
        let addr = unsafe { self.0.alloc_zeroed(layout) };
        unsafe {
            core::arch::asm!("out dx, al",
                in("dx") OutBAction::TraceMemoryAlloc as u16,
                in("rax") layout.size() as u64,
                in("rcx") addr as u64);
        }
        addr
    }
    unsafe fn realloc(
        &self,
        ptr: *mut u8,
        layout: core::alloc::Layout,
        new_size: usize,
    ) -> *mut u8 {
        let new_ptr = unsafe { self.0.realloc(ptr, layout, new_size) };
        unsafe {
            core::arch::asm!("out dx, al",
                in("dx") OutBAction::TraceMemoryFree as u16,
                in("rax") layout.size() as u64,
                in("rcx") ptr);
            core::arch::asm!("out dx, al",
                in("dx") OutBAction::TraceMemoryAlloc as u16,
                in("rax") new_size as u64,
                in("rcx") new_ptr);
        }
        new_ptr
    }
}

// === Globals ===
#[cfg(not(feature = "mem_profile"))]
#[global_allocator]
pub(crate) static HEAP_ALLOCATOR: LockedHeap<32> = LockedHeap::<32>::empty();
#[cfg(feature = "mem_profile")]
#[global_allocator]
pub(crate) static HEAP_ALLOCATOR: ProfiledLockedHeap<32> =
    ProfiledLockedHeap(LockedHeap::<32>::empty());

pub(crate) static mut GUEST_HANDLE: GuestHandle = GuestHandle::new();
pub(crate) static mut REGISTERED_GUEST_FUNCTIONS: GuestFunctionRegister =
    GuestFunctionRegister::new();

/// The size of one page in the host OS, which may have some impacts
/// on how buffers for host consumption should be aligned. Code only
/// working with the guest page tables should use
/// [`hyperlight_common::vm::PAGE_SIZE`] instead.
pub static mut OS_PAGE_SIZE: u32 = 0;

// === Panic Handler ===
// It looks like rust-analyzer doesn't correctly manage no_std crates,
// and so it displays an error about a duplicate panic_handler.
// See more here: https://github.com/rust-lang/rust-analyzer/issues/4490
// The cfg_attr attribute is used to avoid clippy failures as test pulls in std which pulls in a panic handler
#[cfg_attr(not(test), panic_handler)]
#[allow(clippy::panic)]
// to satisfy the clippy when cfg == test
#[allow(dead_code)]
fn panic(info: &core::panic::PanicInfo) -> ! {
    _panic_handler(info)
}

/// A writer that sends all output to the hyperlight host
/// using output ports. This allows us to not impose a
/// buffering limit on error message size on the guest end,
/// though one exists for the host.
struct HyperlightAbortWriter;
impl core::fmt::Write for HyperlightAbortWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        write_abort(s.as_bytes());
        Ok(())
    }
}

#[inline(always)]
fn _panic_handler(info: &core::panic::PanicInfo) -> ! {
    let mut w = HyperlightAbortWriter;

    // begin abort sequence by writing the error code
    write_abort(&[ErrorCode::UnknownError as u8]);

    let write_res = write!(w, "{}", info);
    if write_res.is_err() {
        write_abort("panic: message format failed".as_bytes());
    }

    // write abort terminator to finish the abort
    // and signal to the host that the message can now be read
    write_abort(&[0xFF]);
    unreachable!();
}

// === Entrypoint ===

unsafe extern "C" {
    fn hyperlight_main();
    fn srand(seed: u32);
}

/// Architecture-nonspecific initialisation: set up the heap,
/// coordinate some addresses and configuration with the host, and run
/// user initialisation
pub(crate) extern "C" fn generic_init(
    peb_address: u64,
    seed: u64,
    ops: u64,
    max_log_level: u64,
) -> u64 {
    unsafe {
        GUEST_HANDLE = GuestHandle::init(peb_address as *mut HyperlightPEB);
        #[allow(static_mut_refs)]
        let peb_ptr = GUEST_HANDLE.peb().unwrap();

        let heap_start = (*peb_ptr).guest_heap.ptr as usize;
        let heap_size = (*peb_ptr).guest_heap.size as usize;
        #[cfg(not(feature = "mem_profile"))]
        let heap_allocator = &HEAP_ALLOCATOR;
        #[cfg(feature = "mem_profile")]
        let heap_allocator = &HEAP_ALLOCATOR.0;
        heap_allocator
            .try_lock()
            .expect("Failed to access HEAP_ALLOCATOR")
            .init(heap_start, heap_size);

        let srand_seed = (((peb_address << 8) ^ (seed >> 4)) >> 32) as u32;
        // Set the seed for the random number generator for C code using rand;
        srand(srand_seed);

        OS_PAGE_SIZE = ops as u32;
    }

    // set up the logger
    let max_log_level = LevelFilter::iter()
        .nth(max_log_level as usize)
        .expect("Invalid log level");
    init_logger(max_log_level);

    unsafe {
        trace!("hyperlight_main",
            hyperlight_main();
        );
    }
    dispatch_function as usize as u64
}
