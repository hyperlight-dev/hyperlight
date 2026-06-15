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
