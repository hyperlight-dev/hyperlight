// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

// This binary is used solely as an address-space host for WHvMapGpaRange2.
// It is created with CREATE_SUSPENDED and never executes user code.
//
// We use #![no_std] to avoid linking dbghelp.dll and VCRUNTIME140.dll,
// which add ~200ms to CreateProcess on ARM64 Windows. The process never
// runs, so the Rust stdlib is pure dead weight here.

#![no_std]
#![no_main]

#[link(name = "kernel32")]
unsafe extern "system" {
    fn Sleep(dwMilliseconds: u32);
}

/// Entry point — sleeps forever. In practice this code is never reached
/// because the process is created suspended, but Windows requires a valid
/// entry point in the PE.
///
/// # Safety
///
/// This is the raw PE entry point called by the OS loader.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mainCRTStartup() -> ! {
    // INFINITE = 0xFFFFFFFF
    Sleep(0xFFFF_FFFF);
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
