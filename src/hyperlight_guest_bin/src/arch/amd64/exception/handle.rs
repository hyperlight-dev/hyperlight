/*
Copyright 2025 The Hyperlight Authors.

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

use core::fmt::Write;

use hyperlight_common::outb::Exception;
use hyperlight_common::vmem::{
    BasicMapping, CowMapping, MappingKind, PAGE_SIZE, PhysAddr, VirtAddr,
};
use hyperlight_guest::exit::write_abort;
use hyperlight_guest::layout::{MAIN_STACK_LIMIT_GVA, MAIN_STACK_TOP_GVA};

use super::super::context::Context;
use super::super::machine::ExceptionInfo;
use crate::{ErrorCode, HyperlightAbortWriter};

/// Array of installed exception handlers for vectors 0-30.
///
/// TODO: This will eventually need to be part of a per-thread context when threading is implemented.
pub static HANDLERS: [core::sync::atomic::AtomicU64; 31] =
    [const { core::sync::atomic::AtomicU64::new(0) }; 31];

/// Exception handler function type.
///
/// Handlers receive mutable pointers to the exception information and CPU context,
/// allowing direct access and modification of exception state.
///
/// # Parameters
/// * `exception_number` - Exception vector number (0-30)
/// * `exception_info` - Mutable pointer to exception information (instruction pointer, error code, etc.)
/// * `context` - Mutable pointer to saved CPU context (registers, FPU state, etc.)
/// * `page_fault_address` - Page fault address (only valid for page fault exceptions)
///
/// # Returns
/// * `true` - Suppress the default abort behavior and continue execution
/// * `false` - Allow the default abort to occur
///
/// # Safety
/// This function type uses raw mutable pointers. Handlers must ensure:
/// - Pointers are valid for the duration of the handler
/// - Any modifications to exception state maintain system integrity
/// - Modified values are valid for CPU state (e.g., valid instruction pointers, aligned stack pointers)
pub type ExceptionHandler = fn(
    exception_number: u64,
    exception_info: *mut ExceptionInfo,
    context: *mut Context,
    page_fault_address: u64,
) -> bool;

fn handle_stack_pagefault(gva: u64) {
    // TODO: perhaps we should have a sanity check that the
    // stack grows only one page at a time, which should be
    // ensured by our stack probing discipline?
    unsafe {
        let new_page = hyperlight_guest::prim_alloc::alloc_phys_pages(1);
        crate::paging::map_region(
            new_page,
            (gva & !0xfff) as *mut u8,
            PAGE_SIZE as u64,
            MappingKind::Basic(BasicMapping {
                readable: true,
                writable: true,
                executable: false,
            }),
        );
    }
}

fn handle_cow_pagefault(_phys: PhysAddr, virt: VirtAddr, perms: CowMapping) {
    unsafe {
        let new_page = hyperlight_guest::prim_alloc::alloc_phys_pages(1);
        let target_virt = virt as *mut u8;
        core::ptr::copy(
            target_virt,
            crate::paging::phys_to_virt(new_page).unwrap(),
            PAGE_SIZE,
        );
        // todo(multithreading): when we have multiple threads, we
        // will likely need to (at least in some situations) do a
        // break-before-make sequence here to avoid any possible
        // issues with incoherent TLBs.
        crate::paging::map_region(
            new_page,
            target_virt,
            PAGE_SIZE as u64,
            MappingKind::Basic(BasicMapping {
                // Inherit R bit from the original mapping (always 1 at the moment)
                readable: perms.readable,
                // If we got here, the original marking was marked
                // CoW, so the copied mapping should always be
                // writable
                writable: true,
                executable: perms.executable,
            }),
        );
        core::arch::asm!("invlpg [{}]", in(reg) target_virt, options(readonly, nostack, preserves_flags));
    }
}

fn try_handle_internal_pagefault(
    exn_info: *mut ExceptionInfo,
    _ctx: *mut Context,
    gva: u64,
) -> bool {
    let error_code = unsafe { (&raw const (*exn_info).error_code).read_volatile() };
    let present = (error_code & (1 << 0)) != 0; // bit 0 is P
    if !present {
        // If the fault was caused by a not-present page, check if we
        // should populate it with a stack page
        if (MAIN_STACK_LIMIT_GVA..MAIN_STACK_TOP_GVA).contains(&gva) {
            handle_stack_pagefault(gva);
            return true;
        }
        return false;
    }
    let mut orig_mappings = crate::paging::virt_to_phys(gva);

    let fault_was_rsvd_entry = (error_code & (1 << 3)) != 0;
    if fault_was_rsvd_entry {
        // We don't expect this to ever happen
        return false;
    }
    let access_was_write = (error_code & (1 << 1)) != 0;
    let access_was_user = (error_code & (1 << 2)) != 0;
    let access_was_insn = (error_code & (1 << 4)) != 0;
    if access_was_write && !access_was_user && !access_was_insn {
        // The fault was probably caused by a lack of write
        // permission. Check if that's because the page needs to be
        // CoW'd
        if let Some(mapping) = orig_mappings.next()
            && let None = orig_mappings.next()
            && let MappingKind::Cow(cm) = mapping.kind
        {
            handle_cow_pagefault(mapping.phys_base, mapping.virt_base, cm);
            return true;
        }

        return false;
    };
    false
}

/// Internal exception handler invoked by the low-level exception entry code.
///
/// This function is called from assembly when an exception occurs. It checks for
/// registered user handlers and either invokes them or aborts with an error message.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn hl_exception_handler(
    stack_pointer: u64,
    exception_number: u64,
    page_fault_address: u64,
) {
    let ctx = stack_pointer as *mut Context;
    let exn_info = (stack_pointer + size_of::<Context>() as u64) as *mut ExceptionInfo;

    let exception = Exception::try_from(exception_number as u8).expect("Invalid exception number");

    // Check if it is a page fault that needs to be handled for normal Hyperlight operation
    if exception_number == 14 && try_handle_internal_pagefault(exn_info, ctx, page_fault_address) {
        return;
    }

    // Check for registered user handlers (only for architecture-defined vectors 0-30)
    if exception_number < 31 {
        let handler =
            HANDLERS[exception_number as usize].load(core::sync::atomic::Ordering::Acquire);
        if handler != 0 {
            unsafe {
                let handler = core::mem::transmute::<u64, ExceptionHandler>(handler);
                if handler(exception_number, exn_info, ctx, page_fault_address) {
                    return;
                }
                // Handler returned false, fall through to abort
            };
        }
    }

    // Otherwise, abort due to unexpected exception
    let saved_rip = unsafe { (&raw const (*exn_info).rip).read_volatile() };
    let error_code = unsafe { (&raw const (*exn_info).error_code).read_volatile() };
    let bytes_at_rip = unsafe { (saved_rip as *const [u8; 8]).read_volatile() };

    // begin abort sequence by writing the error code
    let mut w = HyperlightAbortWriter;
    write_abort(&[ErrorCode::GuestError as u8, exception as u8]);
    let write_res = write!(
        w,
        "Exception vector: {}\n\
         Faulting Instruction: {:#x}\n\
         Bytes At Faulting Instruction: {:?}\n\
         Page Fault Address: {:#x}\n\
         Error code: {:#x}\n\
         Stack Pointer: {:#x}",
        exception_number, saved_rip, bytes_at_rip, page_fault_address, error_code, stack_pointer
    );
    if write_res.is_err() {
        write_abort("exception message format failed".as_bytes());
    }

    write_abort(&[0xFF]);
    // At this point, write_abort with the 0xFF terminator is expected to terminate guest execution,
    // so control should never reach beyond this call.
    unreachable!();
}
