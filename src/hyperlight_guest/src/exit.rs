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

use core::arch::asm;
use core::ffi::{CStr, c_char};

use hyperlight_common::outb::OutBAction;
use tracing::instrument;

/// Halt the execution of the guest and returns control to the host.
/// Halt is generally called for a successful completion of the guest's work,
/// this means we can instrument it as a trace point because the trace state
/// shall not be locked at this point (we are not in an exception context).
#[inline(never)]
#[instrument(skip_all, level = "Trace")]
pub fn halt() {
    #[cfg(feature = "trace_guest")]
    {
        // Send data before halting
        // If there is no data, this doesn't do anything
        // The reason we do this here instead of in `hlt` asm function
        // is to avoid allocating before halting, which leaks memory
        // because the guest is not expected to resume execution after halting.
        hyperlight_guest_tracing::flush();
    }

    unsafe { asm!("hlt", options(nostack)) };
}

/// Exits the VM with an Abort OUT action and code 0.
#[unsafe(no_mangle)]
pub extern "C" fn abort() -> ! {
    abort_with_code(&[0, 0xFF])
}

/// Exits the VM with an Abort OUT action and a specific code.
pub fn abort_with_code(code: &[u8]) -> ! {
    // End any ongoing trace before aborting
    #[cfg(feature = "trace_guest")]
    hyperlight_guest_tracing::end_trace();
    outb(OutBAction::Abort as u16, code);
    outb(OutBAction::Abort as u16, &[0xFF]); // send abort terminator (if not included in code)
    unreachable!()
}

/// Aborts the program with a code and a message.
///
/// # Safety
/// This function is unsafe because it dereferences a raw pointer.
pub unsafe fn abort_with_code_and_message(code: &[u8], message_ptr: *const c_char) -> ! {
    // End any ongoing trace before aborting
    #[cfg(feature = "trace_guest")]
    hyperlight_guest_tracing::end_trace();
    unsafe {
        // Step 1: Send abort code (typically 1 byte, but `code` allows flexibility)
        outb(OutBAction::Abort as u16, code);

        // Step 2: Convert the C string to bytes
        let message_bytes = CStr::from_ptr(message_ptr).to_bytes(); // excludes null terminator

        // Step 3: Send the message itself in chunks
        outb(OutBAction::Abort as u16, message_bytes);

        // Step 4: Send abort terminator to signal completion (e.g., 0xFF)
        outb(OutBAction::Abort as u16, &[0xFF]);

        // This function never returns
        unreachable!()
    }
}

/// This function exists to give the guest more manual control
/// over the abort sequence. For example, in `hyperlight_guest_bin`'s panic handler,
/// we have a message of unknown length that we want to stream
/// to the host, which requires sending the message in chunks
pub fn write_abort(code: &[u8]) {
    outb(OutBAction::Abort as u16, code);
}

/// OUT bytes to the host through multiple exits.
pub(crate) fn outb(port: u16, data: &[u8]) {
    // Ensure all tracing data is flushed before sending OUT bytes
    unsafe {
        let mut i = 0;
        while i < data.len() {
            let remaining = data.len() - i;
            let chunk_len = remaining.min(3);
            let mut chunk = [0u8; 4];
            chunk[0] = chunk_len as u8;
            chunk[1..1 + chunk_len].copy_from_slice(&data[i..i + chunk_len]);
            let val = u32::from_le_bytes(chunk);
            out32(port, val);
            i += chunk_len;
        }
    }
}

/// OUT function for sending a 32-bit value to the host.
/// `out32` can be called from an exception context, so we must be careful
/// with the tracing state that might be locked at that time.
/// The tracing state calls `try_lock` internally to avoid deadlocks.
/// Furthermore, the instrument macro is not used here to avoid creating spans
/// in exception contexts. Because if the trace state is already locked, trying to create a span
/// would cause a panic, which is undesirable in exception handling.
pub(crate) unsafe fn out32(port: u16, val: u32) {
    #[cfg(feature = "trace_guest")]
    {
        if let Some((ptr, len)) = hyperlight_guest_tracing::serialized_data() {
            // If tracing is enabled and there is data to send, send it along with the OUT action
            unsafe {
                asm!("out dx, eax",
                    in("dx") port,
                    in("eax") val,
                    in("r8") OutBAction::TraceBatch as u64,
                    in("r9") ptr,
                    in("r10") len,
                    options(preserves_flags, nomem, nostack)
                )
            };

            // Reset the trace state after sending the batch
            // This clears all existing spans/events ensuring a clean state for the next operations
            // The trace state is expected to be flushed before this call
            hyperlight_guest_tracing::reset();
        } else {
            // If tracing is not enabled, just send the value
            unsafe {
                asm!("out dx, eax", in("dx") port, in("eax") val, options(preserves_flags, nomem, nostack))
            };
        }
    }
    #[cfg(not(feature = "trace_guest"))]
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") val, options(preserves_flags, nomem, nostack));
    }
}

/// Prints a message using `OutBAction::DebugPrint`. It transmits bytes of a message
/// through several VMExists and, with such, it is slower than
/// `print_output_with_host_print`.
///
/// This function should be used in debug mode only. This function does not
/// require memory to be setup to be used.
pub fn debug_print(msg: &str) {
    for byte in msg.bytes() {
        unsafe {
            out32(OutBAction::DebugPrint as u16, byte as u32);
        }
    }
}
