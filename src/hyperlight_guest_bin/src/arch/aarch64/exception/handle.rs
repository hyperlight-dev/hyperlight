// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.
use core::fmt::Write;
use core::sync::atomic::Ordering;

use hyperlight_common::arch::exn::{
    DataFault, DataFaultKind, Exception, InsnFault, InsnFaultKind, decode_syndrome,
};
use hyperlight_common::vmem::{BasicMapping, Mapping, MappingKind, PAGE_SIZE, PhysAddr, VirtAddr};
use hyperlight_guest::error::ErrorCode;
use hyperlight_guest::exit::write_abort;
use hyperlight_guest::layout::{MAIN_STACK_LIMIT_GVA, MAIN_STACK_TOP_GVA};

use super::super::{mrs, msr};
use super::types::*;
use crate::HyperlightAbortWriter;

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

fn handle_cow_fault(orig_phys: Option<PhysAddr>, virt: VirtAddr, perms: BasicMapping) {
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
        // Only copy if there is an original page from which to copy
        if orig_phys.is_some() {
            core::ptr::copy(target_virt, scratch_mapping_access, PAGE_SIZE);
        }
        // todo(multithreading): this will definitely require a
        // break-before-make sequence
        crate::paging::map_region(
            new_page,
            target_virt,
            PAGE_SIZE as u64,
            MappingKind::Basic(perms),
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

fn handle_internal_fault(exn: Exception, far: u64, orig_mapping: Option<Mapping>) -> bool {
    match exn {
        Exception::DataFault(DataFault {
            from_lower_el: false,
            kind: DataFaultKind::TranslationFault(_),
            ..
        }) => {
            if (MAIN_STACK_LIMIT_GVA..MAIN_STACK_TOP_GVA).contains(&far) {
                handle_stack_fault(far);
                true
            } else if let Some(
                m @ Mapping {
                    kind: MappingKind::ZeroInit(bm),
                    ..
                },
            ) = orig_mapping
            {
                handle_cow_fault(None, m.virt_base, bm);
                true
            } else {
                false
            }
        }
        Exception::DataFault(DataFault {
            from_lower_el: false,
            is_write: true,
            kind: DataFaultKind::PermissionFault(_),
            ..
        }) => {
            if let Some(
                m @ Mapping {
                    kind: MappingKind::Cow(cm),
                    ..
                },
            ) = orig_mapping
            {
                let bm = BasicMapping {
                    // Inherit R bit from the original mapping (always 1 at the moment)
                    readable: cm.readable,
                    // If we got here, the original marking was marked
                    // CoW, so the copied mapping should always be
                    // writable
                    writable: true,
                    executable: cm.executable,
                };
                handle_cow_fault(Some(m.phys_base), m.virt_base, bm);
                true
            } else {
                false
            }
        }
        _ => false,
    }
}

unsafe fn setup_user_exn_handler(regs: *mut ExceptionContext, handler: usize, params: &[u64]) {
    unsafe {
        // common params to all exn handler types
        let pc = mrs!(ELR_EL1);
        let fp = (&raw mut (*regs).x[29]).read_volatile();
        (&raw mut (*regs).x[0]).write_volatile(pc);
        (&raw mut (*regs).x[1]).write_volatile(fp);

        // extra params
        for (i, val) in params.iter().enumerate() {
            (&raw mut (*regs).x[2 + i]).write_volatile(*val);
        }

        // make sure the stack pointer is aligned
        let sp = mrs!(SP_EL0);
        let sp = sp - (sp % 16);
        msr!(SP_EL0, sp);

        // pc
        msr!(ELR_EL1, handler as u64);
    }
}

fn handle_user_fault(exn: Exception, far: u64, regs: *mut ExceptionContext) -> bool {
    match exn {
        Exception::DataFault(DataFault {
            from_lower_el: false,
            kind: DataFaultKind::TranslationFault(_) | DataFaultKind::PermissionFault(_),
            ..
        })
        | Exception::InsnFault(InsnFault {
            from_lower_el: false,
            kind: InsnFaultKind::TranslationFault(_) | InsnFaultKind::PermissionFault(_),
            ..
        }) => {
            let handler = crate::exception::PAGE_FAULT_HANDLER.load(Ordering::Relaxed);
            if handler != 0 {
                unsafe {
                    setup_user_exn_handler(regs, handler, &[far]);
                }
                true
            } else {
                false
            }
        }
        Exception::Unknown => {
            let handler = crate::exception::UNDEFINED_INSTRUCTION_HANDLER.load(Ordering::Relaxed);
            if handler != 0 {
                unsafe {
                    setup_user_exn_handler(regs, handler, &[]);
                }
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
    regs: *mut ExceptionContext,
) {
    let esr = unsafe { mrs!(ESR_EL1) };
    let far = unsafe { mrs!(FAR_EL1) };

    if typ == ExceptionType::Synchronous && from == ExceptionFrom::CurrentSP0 {
        let exn = decode_syndrome(esr);
        let mut orig_mappings = crate::paging::virt_to_phys(far);
        let orig_mapping = orig_mappings.next();
        if handle_internal_fault(exn, far, orig_mapping) {
            return;
        }
        if handle_user_fault(exn, far, regs) {
            return;
        }
    }

    // Die with some diagnostic information
    let elr = unsafe { mrs!(ELR_EL1) };
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
