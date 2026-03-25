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

use arch::dispatch::dispatch_function;
use buddy_system_allocator::LockedHeap;
use guest_function::register::GuestFunctionRegister;
use guest_logger::init_logger;
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::log_level::GuestLogFilter;
use hyperlight_common::mem::HyperlightPEB;
#[cfg(feature = "mem_profile")]
use hyperlight_common::outb::OutBAction;
use hyperlight_guest::exit::write_abort;
use hyperlight_guest::guest_handle::handle::GuestHandle;

// === Modules ===
#[cfg_attr(target_arch = "x86_64", path = "arch/amd64/mod.rs")]
#[cfg_attr(target_arch = "aarch64", path = "arch/aarch64/mod.rs")]
mod arch;
// temporarily expose the architecture-specific exception interface;
// this should be replaced with something a bit more abstract in the
// near future.
#[cfg(target_arch = "x86_64")]
pub mod exception;
pub mod guest_function {
    pub(super) mod call;
    pub mod definition;
    pub mod register;
}

pub mod error;
pub mod guest_logger;
pub mod host_comm;
pub mod memory;
#[cfg(target_arch = "x86_64")]
pub mod paging;
mod virtq_init;

/// Bridge between picolibc's POSIX expectations and the Hyperlight host.
#[cfg(feature = "libc")]
mod libc;

// Globals
#[cfg(all(feature = "mem_profile", target_arch = "x86_64"))]
struct ProfiledLockedHeap<const ORDER: usize>(LockedHeap<ORDER>);
#[cfg(all(feature = "mem_profile", target_arch = "x86_64"))]
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
#[cfg(not(all(feature = "mem_profile", target_arch = "x86_64")))]
#[global_allocator]
pub(crate) static HEAP_ALLOCATOR: LockedHeap<32> = LockedHeap::<32>::empty();
#[cfg(all(feature = "mem_profile", target_arch = "x86_64"))]
#[global_allocator]
pub(crate) static HEAP_ALLOCATOR: ProfiledLockedHeap<32> =
    ProfiledLockedHeap(LockedHeap::<32>::empty());

pub static mut GUEST_HANDLE: GuestHandle = GuestHandle::new();
pub(crate) static mut REGISTERED_GUEST_FUNCTIONS: GuestFunctionRegister<GuestFunc> =
    GuestFunctionRegister::new();

const VERSION_STR: &str = env!("CARGO_PKG_VERSION");

// Embed the hyperlight-guest-bin crate version as a proper ELF note so the
// host can verify ABI compatibility at load time.
#[used]
#[unsafe(link_section = ".note.hyperlight-version")]
static HYPERLIGHT_VERSION_NOTE: hyperlight_common::version_note::ElfNote<
    {
        hyperlight_common::version_note::padded_name_size(
            hyperlight_common::version_note::HYPERLIGHT_NOTE_NAME.len() + 1,
        )
    },
    { hyperlight_common::version_note::padded_desc_size(VERSION_STR.len() + 1) },
> = hyperlight_common::version_note::ElfNote::new(
    hyperlight_common::version_note::HYPERLIGHT_NOTE_NAME,
    VERSION_STR,
    hyperlight_common::version_note::HYPERLIGHT_NOTE_TYPE,
);

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

#[tracing::instrument(skip_all, parent = tracing::Span::current(), level= "Trace")]
extern "C" fn hyperlight_main_default() {
    // no-op
}

core::arch::global_asm!(
    ".weak hyperlight_main",
    ".set hyperlight_main, {}",
    sym hyperlight_main_default,
);

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
        #[cfg(not(all(feature = "mem_profile", target_arch = "x86_64")))]
        let heap_allocator = &HEAP_ALLOCATOR;
        #[cfg(all(feature = "mem_profile", target_arch = "x86_64"))]
        let heap_allocator = &HEAP_ALLOCATOR.0;
        heap_allocator
            .try_lock()
            .expect("Failed to access HEAP_ALLOCATOR")
            .init(heap_start, heap_size);
        peb_ptr
    };

    // Save the guest start TSC for tracing
    #[cfg(feature = "trace_guest")]
    let guest_start_tsc = hyperlight_guest_tracing::invariant_tsc::read_tsc();

    unsafe {
        let srand_seed = (((peb_address << 8) ^ (seed >> 4)) >> 32) as u32;
        // Set the seed for the random number generator for C code using rand;
        srand(srand_seed);

        OS_PAGE_SIZE = ops as u32;
    }

    // Initialize virtqueues
    virtq_init::init_virtqueues();

    // set up the logger
    let guest_log_level_filter =
        GuestLogFilter::try_from(max_log_level).expect("Invalid log level");
    init_logger(guest_log_level_filter.into());

    // It is important that all the tracing events are produced after the tracing is initialized.
    #[cfg(feature = "trace_guest")]
    if guest_log_level_filter != GuestLogFilter::Off {
        hyperlight_guest_tracing::init_guest_tracing(
            guest_start_tsc,
            guest_log_level_filter.into(),
        );
    }

    // Open a span to partly capture the initialization of the guest.
    // This is done here because the tracing subscriber is initialized and the guest is in a
    // well-known state
    #[cfg(all(feature = "trace_guest", target_arch = "x86_64"))]
    let _entered = tracing::span!(tracing::Level::INFO, "generic_init").entered();

    #[cfg(feature = "macros")]
    for registration in __private::GUEST_FUNCTION_INIT {
        registration();
    }

    unsafe {
        hyperlight_main();
    }

    // All this tracing logic shall be done right before the call to `hlt` which is done after this
    // function returns
    #[cfg(all(feature = "trace_guest", target_arch = "x86_64"))]
    {
        // NOTE: This is necessary to avoid closing the span twice. Flush closes all the open
        // spans, when preparing to close a guest function call context.
        // It is not mandatory, though, but avoids a warning on the host that alerts a spans
        // that has not been opened but is being closed.
        _entered.exit();

        // Ensure that any tracing output from the initialisation phase is
        // flushed to the host, if necessary.
        hyperlight_guest_tracing::flush();
    }

    dispatch_function as usize as u64
}

#[cfg(feature = "macros")]
#[doc(hidden)]
pub mod __private {
    pub use alloc::vec::Vec;

    pub use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
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
pub use hyperlight_guest_macro::{dispatch, guest_function, host_function, main};

pub use crate::guest_function::definition::GuestFunc;
