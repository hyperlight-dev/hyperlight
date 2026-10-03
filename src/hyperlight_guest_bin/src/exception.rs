// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(target_arch = "x86_64")]
#[deprecated(since = "0.18.0", note = "Use architecture-independent interface")]
pub mod arch {
    pub use crate::arch::context::Context;
    pub use crate::arch::exception::handle::HANDLERS;
    pub use crate::arch::machine::ExceptionInfo;
}

/// A handler for a page fault, given the faulting instruction, the
/// most recent frame pointer, and the faulting address. This function
/// must either panic or longjmp away; it must not return.
pub type PageFaultHandler = extern "C" fn(u64, u64, u64) -> !;
pub(crate) static PAGE_FAULT_HANDLER: AtomicUsize = AtomicUsize::new(0);
pub fn register_page_fault_handler(h: PageFaultHandler) {
    PAGE_FAULT_HANDLER.store(h as usize, Ordering::Relaxed);
}
/// A handler for undefined instruction exceptions, given the faulting
/// instruction and the most recent frame pointer. This function
/// must either panic or longjmp away; it must not return.
pub type UndefinedInstructionHandler = extern "C" fn(u64, u64) -> !;
pub(crate) static UNDEFINED_INSTRUCTION_HANDLER: AtomicUsize = AtomicUsize::new(0);
pub fn register_undefined_instruction_handler(h: UndefinedInstructionHandler) {
    UNDEFINED_INSTRUCTION_HANDLER.store(h as usize, Ordering::Relaxed);
}
