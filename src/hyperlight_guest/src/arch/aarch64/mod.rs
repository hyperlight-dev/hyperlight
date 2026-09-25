// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

/// Write an AArch64 system register.
///
/// # Safety
/// The register must be writable at the current exception level.
/// The value must preserve valid guest execution and live memory mappings.
#[macro_export]
macro_rules! msr {
    ($sysreg:ident, $expr:expr) => {
        core::arch::asm!(concat!("msr ", core::stringify!($sysreg), ", {}"), in(reg) $expr);
    }
}

/// Read an AArch64 system register.
///
/// # Safety
/// The register must be readable at the current exception level.
#[macro_export]
macro_rules! mrs {
    ($sysreg:ident) => {
        {
            let x: u64;
            core::arch::asm!(concat!("mrs {}, ", core::stringify!($sysreg)), out(reg) x);
            x
        }
    }
}
