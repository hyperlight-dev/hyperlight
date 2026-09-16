// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use core::arch::asm;

/// OUT function for sending a 32-bit value to the host on the given port.
/// A pure I/O function that issues a single OUT instruction, safe to call
/// from an exception context.
pub(crate) unsafe fn out32(port: u16, val: u32) {
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") val, options(preserves_flags, nostack));
    }
}
