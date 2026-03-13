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

#[cfg(feature = "trace_guest")]
use hyperlight_common::outb::OutBAction;

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
