// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use core::mem::{offset_of, size_of};

#[derive(Debug, PartialEq)]
#[repr(u64)]
pub(super) enum ExceptionType {
    Synchronous,
    Irq,
    Fiq,
    SError,
}

#[derive(Debug, PartialEq)]
#[repr(u64)]
pub(super) enum ExceptionFrom {
    CurrentSP0,
    CurrentSPx,
    LowerAArch64,
    LowerAArch32,
}

#[repr(C)]
pub(super) struct ExceptionContext {
    pub(super) x: [u64; 31],
    pub(super) fpcr: u64,
    pub(super) fpsr: u64,
    // No need to store main context SP: it's in SP_EL0
    pub(super) q: [u128; 32],
}
const _: () = assert!(size_of::<ExceptionContext>().is_multiple_of(16));
const _: () = assert!(offset_of!(ExceptionContext, fpsr) == offset_of!(ExceptionContext, fpcr) + 8);
