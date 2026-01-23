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
#[cfg(target_arch = "x86_64")]
use exceptions::{gdt::load_gdt, idtr::load_idt};
use guest_function::call::dispatch_function;
use guest_function::register::GuestFunctionRegister;
use guest_logger::init_logger;
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::mem::HyperlightPEB;
#[cfg(feature = "mem_profile")]
use hyperlight_common::outb::OutBAction;
use hyperlight_guest::exit::{halt, write_abort};
use hyperlight_guest::guest_handle::handle::GuestHandle;
use log::LevelFilter;
use spin::Once;

// === Modules ===
#[cfg(target_arch = "x86_64")]
pub mod exceptions {
    pub(super) mod gdt;
    pub mod handler;
    mod idt;
    pub(super) mod idtr;
    mod interrupt_entry;
}
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

pub static mut GUEST_HANDLE: GuestHandle = GuestHandle::new();
pub(crate) static mut REGISTERED_GUEST_FUNCTIONS: GuestFunctionRegister =
    GuestFunctionRegister::new();

pub static mut MIN_STACK_ADDRESS: u64 = 0;

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

static INIT: Once = Once::new();

#[unsafe(no_mangle)]
pub extern "C" fn entrypoint(peb_address: u64, seed: u64, ops: u64, max_log_level: u64) {
    // Save the guest start TSC for tracing
    #[cfg(feature = "trace_guest")]
    let guest_start_tsc = hyperlight_guest_tracing::invariant_tsc::read_tsc();

    if peb_address == 0 {
        panic!("PEB address is null");
    }

    INIT.call_once(|| {
        unsafe {
            GUEST_HANDLE = GuestHandle::init(peb_address as *mut HyperlightPEB);
            #[allow(static_mut_refs)]
            let peb_ptr = GUEST_HANDLE.peb().unwrap();

            let srand_seed = (((peb_address << 8) ^ (seed >> 4)) >> 32) as u32;

            // Set the seed for the random number generator for C code using rand;
            srand(srand_seed);

            // This static is to make it easier to implement the __chkstk function in assembly.
            // It also means that should we change the layout of the struct in the future, we
            // don't have to change the assembly code.
            MIN_STACK_ADDRESS = (*peb_ptr).guest_stack.min_user_stack_address;

            #[cfg(target_arch = "x86_64")]
            {
                // Setup GDT and IDT
                load_gdt();
                load_idt();
            }

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

            OS_PAGE_SIZE = ops as u32;

            (*peb_ptr).guest_function_dispatch_ptr = dispatch_function as usize as u64;

            // set up the logger
            let max_log_level = LevelFilter::iter()
                .nth(max_log_level as usize)
                .expect("Invalid log level");
            init_logger(max_log_level);

            // It is important that all the tracing events are produced after the tracing is initialized.
            #[cfg(feature = "trace_guest")]
            if max_log_level != LevelFilter::Off {
                hyperlight_guest_tracing::init_guest_tracing(guest_start_tsc, max_log_level);
            }

            #[cfg(feature = "macros")]
            for registration in __private::GUEST_FUNCTION_INIT {
                registration();
            }

            hyperlight_main();
        }
    });

    halt();
}

#[cfg(feature = "macros")]
#[doc(hidden)]
pub mod __private {
    pub use hyperlight_common::func::ResultType;
    pub use hyperlight_guest::error::HyperlightGuestError;
    pub use linkme;

    #[linkme::distributed_slice]
    pub static GUEST_FUNCTION_INIT: [fn()];

    pub trait FromResult {
        type Output;
        fn from_result(res: Result<Self::Output, HyperlightGuestError>) -> Self;
    }

    use alloc::string::String;
    use alloc::vec::Vec;

    use hyperlight_common::for_each_return_type;

    macro_rules! impl_maybe_unwrap {
        ($ty:ty, $enum:ident) => {
            impl FromResult for $ty {
                type Output = Self;
                fn from_result(res: Result<Self::Output, HyperlightGuestError>) -> Self {
                    // Unwrapping here is fine as this would only run in a guest
                    // and not in the host.
                    res.unwrap()
                }
            }

            impl FromResult for Result<$ty, HyperlightGuestError> {
                type Output = $ty;
                fn from_result(res: Result<Self::Output, HyperlightGuestError>) -> Self {
                    res
                }
            }
        };
    }

    for_each_return_type!(impl_maybe_unwrap);
}

#[cfg(feature = "macros")]
pub use hyperlight_guest_macro::{guest_function, host_function};
