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
#![no_std]

// === Dependencies ===
extern crate alloc;

use core::mem::MaybeUninit;

use hyperlight_common::outb::OutBAction;
use spin::Mutex;

/// Global trace buffer for storing trace records.
static TRACE_BUFFER: Mutex<TraceBuffer> = Mutex::new(TraceBuffer::new());

/// Maximum number of entries in the trace buffer.
const MAX_NO_OF_ENTRIES: usize = 64;

/// Maximum length of a trace message in bytes.
pub const MAX_TRACE_MSG_LEN: usize = 64;

#[derive(Debug, Copy, Clone)]
/// Represents a trace record of a guest with a number of cycles and a message.
pub struct TraceRecord {
    /// The number of CPU cycles returned by the invariant TSC.
    pub cycles: u64,
    /// The length of the message in bytes.
    pub msg_len: usize,
    /// The message associated with the trace record.
    pub msg: [u8; MAX_TRACE_MSG_LEN],
}

/// A buffer for storing trace records.
struct TraceBuffer {
    /// The entries in the trace buffer.
    entries: [TraceRecord; MAX_NO_OF_ENTRIES],
    /// The index where the next entry will be written.
    write_index: usize,
}

impl TraceBuffer {
    /// Creates a new `TraceBuffer` with uninitialized entries.
    const fn new() -> Self {
        Self {
            entries: unsafe { [MaybeUninit::zeroed().assume_init(); MAX_NO_OF_ENTRIES] },
            write_index: 0,
        }
    }

    /// Push a new trace record into the buffer.
    /// If the buffer is full, it sends the records to the host.
    fn push(&mut self, entry: TraceRecord) {
        let mut write_index = self.write_index;

        self.entries[write_index] = entry;
        write_index = (write_index + 1) % MAX_NO_OF_ENTRIES;

        self.write_index = write_index;

        if write_index == 0 {
            // If buffer is full send to host
            self.send_to_host(MAX_NO_OF_ENTRIES);
        }
    }

    /// Flush the trace buffer, sending any remaining records to the host.
    fn flush(&mut self) {
        if self.write_index > 0 {
            self.send_to_host(self.write_index);
            self.write_index = 0; // Reset write index after flushing
        }
    }

    /// Send the trace records to the host.
    fn send_to_host(&self, count: usize) {
        unsafe {
            core::arch::asm!("out dx, al",
                in("dx") OutBAction::TraceRecord as u16,
                in("rax") count as u64,
                in("rcx") &self.entries as * const _ as u64);
        }
    }
}

/// Module for checking invariant TSC support and reading the timestamp counter
pub mod invariant_tsc {
    use core::arch::x86_64::{__cpuid, _rdtsc};

    /// Check if the processor supports invariant TSC
    ///
    /// Returns true if CPUID.80000007H:EDX[8] is set, indicating invariant TSC support
    pub fn has_invariant_tsc() -> bool {
        // Check if extended CPUID functions are available
        let max_extended = unsafe { __cpuid(0x80000000) };
        if max_extended.eax < 0x80000007 {
            return false;
        }

        // Query CPUID.80000007H for invariant TSC support
        let cpuid_result = unsafe { __cpuid(0x80000007) };

        // Check bit 8 of EDX register for invariant TSC support
        (cpuid_result.edx & (1 << 8)) != 0
    }

    /// Read the timestamp counter
    ///
    /// This function provides a high-performance timestamp by reading the TSC.
    /// Should only be used when invariant TSC is supported for reliable timing.
    ///
    /// # Safety
    /// This function uses unsafe assembly instructions but is safe to call.
    /// However, the resulting timestamp is only meaningful if invariant TSC is supported.
    pub fn read_tsc() -> u64 {
        unsafe { _rdtsc() }
    }
}

/// Create a trace record with the given message.
///
/// Note: The message must not exceed `MAX_TRACE_MSG_LEN` bytes.
/// If the message is too long, it will be skipped.
pub fn create_trace_record(msg: &str) {
    if msg.len() > MAX_TRACE_MSG_LEN {
        return; // Message too long, skip tracing
    }

    let cycles = invariant_tsc::read_tsc();

    let entry = TraceRecord {
        cycles,
        msg: {
            let mut arr = [0u8; MAX_TRACE_MSG_LEN];
            arr[..msg.len()].copy_from_slice(msg.as_bytes());
            arr
        },
        msg_len: msg.len(),
    };

    let mut buffer = TRACE_BUFFER.lock();
    buffer.push(entry);
}

/// Flush the trace buffer to send any remaining trace records to the host.
pub fn flush_trace_buffer() {
    let mut buffer = TRACE_BUFFER.lock();
    buffer.flush();
}
