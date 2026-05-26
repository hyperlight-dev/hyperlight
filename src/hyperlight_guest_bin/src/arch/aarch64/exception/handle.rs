/*
Copyright 2026 The Hyperlight Authors.

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

use hyperlight_common::vmem::{
    BasicMapping, CowMapping, MappingKind, PAGE_SIZE, PhysAddr, VirtAddr,
};
use hyperlight_guest::error::ErrorCode;
use hyperlight_guest::exit::write_abort;
use hyperlight_guest::layout::{MAIN_STACK_LIMIT_GVA, MAIN_STACK_TOP_GVA};

use super::super::mrs;
use super::types::*;
use crate::HyperlightAbortWriter;

/// Utility function to extract an (inclusive on both ends) bit range
/// from a quadword.
#[inline(always)]
fn bits<const HIGH_BIT: u8, const LOW_BIT: u8>(x: u64) -> u64 {
    (x & ((1 << (HIGH_BIT + 1)) - 1)) >> LOW_BIT
}

const ESR_EC_DATA_ABORT_LOWER_EL: u64 = 0b100100;
const ESR_EC_DATA_ABORT_SAME_EL: u64 = 0b100101;

// some of the data in these is not used presently, but is logically
// part of the code being decoded & should be accounted for
#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
enum DataFault {
    TranslationFault(i64),
    PermissionFault(i64),
    Other(u64),
}
fn decode_data_fault(dfsc: u64) -> DataFault {
    if bits::<5, 2>(dfsc) == 0b0011 {
        DataFault::PermissionFault(bits::<1, 0>(dfsc) as i64)
    } else if bits::<5, 2>(dfsc) == 0b0001 {
        DataFault::TranslationFault(bits::<1, 0>(dfsc) as i64)
    } else if bits::<5, 2>(dfsc) == 0b1010 {
        if bits::<1, 0>(dfsc) >= 2 {
            DataFault::TranslationFault(bits::<1, 0>(dfsc) as i64 - 4)
        } else {
            DataFault::Other(dfsc)
        }
    } else {
        DataFault::Other(dfsc)
    }
}

// some of the data in these is not used presently, but is logically
// part of the code being decoded & should be accounted for
#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
enum Exception {
    /// lower el?, faulting address, status code
    DataFault(bool, u64, DataFault),
    Other(u64),
}
fn decode_syndrome(esr: u64) -> Exception {
    let ec = bits::<31, 26>(esr);
    match ec {
        ESR_EC_DATA_ABORT_LOWER_EL => Exception::DataFault(
            true,
            unsafe { mrs!(FAR_EL1) },
            decode_data_fault(bits::<5, 0>(esr)),
        ),
        ESR_EC_DATA_ABORT_SAME_EL => Exception::DataFault(
            false,
            unsafe { mrs!(FAR_EL1) },
            decode_data_fault(bits::<5, 0>(esr)),
        ),
        _ => Exception::Other(esr),
    }
}

fn handle_stack_fault(far: u64) {
    // TODO: perhaps we should have a sanity check that the
    // stack grows only one page at a time, which should be
    // ensured by our stack probing discipline?
    unsafe {
        let new_page = hyperlight_guest::prim_alloc::alloc_phys_pages(1);
        crate::paging::map_region(
            new_page,
            (far & !((PAGE_SIZE - 1) as u64)) as *mut u8,
            PAGE_SIZE as u64,
            MappingKind::Basic(BasicMapping {
                readable: true,
                writable: true,
                executable: false,
            }),
        );
        // We don't use crate::barrier::first_valid_same_ctx, because
        // we don't (presently) use FEAT_ExS and consequently don't
        // need the `isb`.
        core::arch::asm!("dsb sy");
    }
}

fn handle_cow_fault(_orig_phys: PhysAddr, virt: VirtAddr, perms: CowMapping) {
    unsafe {
        let new_page = hyperlight_guest::prim_alloc::alloc_phys_pages(1);
        let target_virt = virt as *mut u8;
        let Some(scratch_mapping_access) = crate::paging::phys_to_virt(new_page) else {
            write_abort(&[ErrorCode::GuestError as u8, 0xfeu8]);
            write_abort("impossible: phys_to_virt failed on alloc_phys_pages return".as_bytes());
            write_abort(&[0xFF]);
            // At this point, write_abort with the 0xFF terminator is
            // expected to terminate guest execution, so control
            // should never reach beyond this call.
            unreachable!();
        };
        core::ptr::copy(target_virt, scratch_mapping_access, PAGE_SIZE);
        // todo(multithreading): this will definitely require a
        // break-before-make sequence
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
        // This is updating an entry that was already valid, changing
        // its OA, so we need to actually invalidate the TLB for it.
        core::arch::asm!("
            dsb ish
            tlbi vae1is, {}
            dsb ish
            isb
        ",
            in(reg) (virt >> 12),
            options(readonly, nostack, preserves_flags)
        );
    }
}

#[unsafe(no_mangle)]
pub extern "Rust" fn _debug_print(x: &str) {
    hyperlight_guest::exit::debug_print(x);
}

fn handle_internal_fault(exn: Exception) -> bool {
    match exn {
        Exception::DataFault(false, far, DataFault::TranslationFault(_)) => {
            if (MAIN_STACK_LIMIT_GVA..MAIN_STACK_TOP_GVA).contains(&far) {
                handle_stack_fault(far);
                true
            } else {
                false
            }
        }
        Exception::DataFault(false, far, DataFault::PermissionFault(_)) => {
            let mut orig_mappings = crate::paging::virt_to_phys(far);
            if let Some(mapping) = orig_mappings.next()
                && let None = orig_mappings.next()
                && let MappingKind::Cow(cm) = mapping.kind
            {
                handle_cow_fault(mapping.phys_base, mapping.virt_base, cm);
                true
            } else {
                false
            }
        }
        _ => false,
    }
}

pub(super) extern "C" fn handle_exception(
    typ: ExceptionType,
    from: ExceptionFrom,
    _regs: *mut ExceptionContext,
) {
    let esr = unsafe { mrs!(ESR_EL1) };

    if typ == ExceptionType::Synchronous && from == ExceptionFrom::CurrentSP0 {
        let exn = decode_syndrome(esr);
        if handle_internal_fault(exn) {
            return;
        }
    }

    // Die with some diagnostic information
    let elr = unsafe { mrs!(ELR_EL1) };
    let far = unsafe { mrs!(FAR_EL1) };
    let insn_bytes = unsafe { (elr as *const [u8; 8]).read_volatile() };
    // amd64 provides the exception vector as the first byte of the
    // abort sequence after the guest error identifier code, but the
    // host doesn't use it for anything except printing an error
    // message, so it's not really useful to try to find an analogue
    // (e.g. we could use ESR_EL1.EC---but it's only used for
    // debugging and we'll include the whole syndrome in the message
    // anyway). So, use 0xfe which is invalid as an exception on x86,
    // to let the host know not to try to print anything extra.
    let mut w = HyperlightAbortWriter;
    write_abort(&[ErrorCode::GuestError as u8, 0xfeu8]);
    let write_res = write!(
        w,
        "Exception vector: {:?} {:?}\n\
         Faulting Instruction: {:#x}\n\
         Bytes At Faulting Instruction: {:?}\n\
         Faulting Address: {:#x}\n\
         Exception Syndrome: {:#x}",
        from, typ, elr, insn_bytes, far, esr
    );
    if write_res.is_err() {
        write_abort("exception message format failed".as_bytes());
    }

    write_abort(&[0xFF]);
    // At this point, write_abort with the 0xFF terminator is expected to terminate guest execution,
    // so control should never reach beyond this call.
    unreachable!();
}
