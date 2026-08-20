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

// TODO(aarch64): implement aarch64 guest runtime

const IO_PAGE_GVA: u64 = hyperlight_common::layout::io_page().unwrap().1;
const HLT_ADDR: u64 = IO_PAGE_GVA
    + (core::mem::size_of::<u64>() as u64 * hyperlight_common::outb::VmAction::Halt as u64);

pub mod dispatch {
    unsafe extern "C" {
        /// See comments in amd64/dispatch.rs for why this
        /// architecture-dependent stub exists
        ///
        /// # ABI
        ///
        /// If a TLB flush is required, the host should start executing
        /// one instruction (4 bytes) after the base address of the
        /// dispatch function.
        pub(crate) unsafe fn dispatch_function();
    }
    core::arch::global_asm!("
        .global dispatch_function
        dispatch_function:
        .cfi_startproc\n
        .cfi_undefined x30\n
        b 0f\n
        tlbi vmalle1\n
        dsb ish\n
        isb\n
        0:\n
        bl {internal_dispatch_function}\n
        ldr x1, ={hlt_addr}\n
        str x0, [x1]\n
        .cfi_endproc\n
    ",
        internal_dispatch_function = sym crate::guest_function::call::internal_dispatch_function,
        hlt_addr = const super::HLT_ADDR,
    );
}

mod exception;

macro_rules! msr {
    ($sysreg:ident, $expr:expr) => {
        core::arch::asm!(concat!("msr ", core::stringify!($sysreg), ", {}"), in(reg) $expr);
    }
}
pub(crate) use msr;
macro_rules! mrs {
    ($sysreg:ident) => {
        {
            let x: u64;
            core::arch::asm!(concat!("mrs {}, ", core::stringify!($sysreg)), out(reg) x);
            x
        }
    }
}
pub(crate) use mrs;

unsafe fn init_vbar() {
    unsafe {
        core::arch::asm!("
            adrp {tmp}, vbar\n
            add {tmp}, {tmp}, :lo12:vbar\n
            msr VBAR_EL1, {tmp}\n
        ", tmp = out(reg) _);
    }
}

/// Machine-specific initialisation; calls [`crate::generic_init`]
/// once VBAR and the main stack have been set up
#[unsafe(no_mangle)]
pub extern "C" fn entrypoint(peb_address: u64, seed: u64, ops: u64, max_log_level: u64) -> ! {
    unsafe {
        init_vbar();
        let stack_top = crate::init::init_stack();
        pivot_stack(peb_address, seed, ops, max_log_level, stack_top);
    }
}

unsafe extern "C" {
    unsafe fn pivot_stack(
        peb_address: u64,
        seed: u64,
        ops: u64,
        max_log_level: u64,
        stack_top: u64,
    ) -> !;
}

core::arch::global_asm!("
    .global pivot_stack\n
    pivot_stack:\n
    .cfi_startproc\n
    .cfi_undefined x30\n
    ldr x5, ={exn_stack}\n
    msr SPSel, #1\n
    mov sp, x5\n
    msr SPSel, #0\n
    mov sp, x4\n
    bl {generic_init}\n
    ldr x1, ={hlt_addr}\n
    str x0, [x1]\n
    .cfi_endproc\n
",
    exn_stack = const (hyperlight_common::layout::SCRATCH_TOP_GVA as u64
        - hyperlight_common::layout::SCRATCH_TOP_EXN_STACK_OFFSET
        + 1),
    generic_init = sym crate::generic_init,
    hlt_addr = const HLT_ADDR,
);
