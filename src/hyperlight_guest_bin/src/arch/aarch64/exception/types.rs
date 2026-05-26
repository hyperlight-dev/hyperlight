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

use core::mem::{offset_of, size_of};

#[derive(Debug, PartialEq)]
#[repr(u64)]
pub(super) enum ExceptionType {
    Synchronous,
    IRQ,
    FIQ,
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
