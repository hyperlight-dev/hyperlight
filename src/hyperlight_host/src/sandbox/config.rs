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

use std::cmp::max;
use std::time::Duration;

#[cfg(target_os = "linux")]
use libc::c_int;
use tracing::{Span, instrument};

/// Used for passing debug configuration to a sandbox
#[cfg(gdb)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DebugInfo {
    /// Guest debug port
    pub port: u16,
}

/// The complete set of configuration needed to create a Sandbox
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct SandboxConfiguration {
    /// Guest core dump output directory
    /// This field is by default set to true which means the value core dumps will be placed in:
    /// - HYPERLIGHT_CORE_DUMP_DIR environment variable if it is set
    /// - default value of the temporary directory
    ///
    /// The core dump files generation can be disabled by setting this field to false.
    #[cfg(crashdump)]
    guest_core_dump: bool,
    /// Guest gdb debug port
    #[cfg(gdb)]
    guest_debug_info: Option<DebugInfo>,
    /// The size of the memory buffer that is made available for input to the
    /// Guest Binary
    input_data_size: usize,
    /// The size of the memory buffer that is made available for input to the
    /// Guest Binary
    output_data_size: usize,
    /// The heap size to use in the guest sandbox. If set to 0, the heap
    /// size will be determined from the PE file header
    ///
    /// Note: this is a C-compatible struct, so even though this optional
    /// field should be represented as an `Option`, that type is not
    /// FFI-safe, so it cannot be.
    heap_size_override: u64,
    /// Delay between interrupt retries. This duration specifies how long to wait
    /// between attempts to send signals to the thread running the sandbox's VCPU.
    /// Multiple retries may be necessary because signals only interrupt the VCPU
    /// thread when the vcpu thread is in kernel space. There's a narrow window during which a
    /// signal can be delivered to the thread, but the thread may not yet
    /// have entered kernel space.
    interrupt_retry_delay: Duration,
    /// Offset from `SIGRTMIN` used to determine the signal number for interrupting
    /// the VCPU thread. The actual signal sent is `SIGRTMIN + interrupt_vcpu_sigrtmin_offset`.
    ///
    /// This signal must fall within the valid real-time signal range supported by the host.
    ///
    /// Note: Since real-time signals can vary across platforms, ensure that the offset
    /// results in a signal number that is not already in use by other components of the system.
    interrupt_vcpu_sigrtmin_offset: u8,
    /// How much writable memory to offer the guest
    scratch_size: usize,
    /// Number of descriptors for the G2H (guest-to-host) virtqueue. Must be a power of 2.
    /// Default: 64 sized to 2x H2G depth for deadlock prevention.
    g2h_queue_depth: usize,
    /// Number of descriptors for the host-to-guest virtqueue. Must be a power of 2.
    /// Default: 32
    h2g_queue_depth: usize,
    /// Number of physical pages for the G2H (guest-to-host) buffer pool.
    /// If not set, derived from `input_data_size` for backward compatibility.
    /// Default: 8 pages (32KB).
    g2h_pool_pages: Option<usize>,
    /// Number of physical pages for the H2G (host-to-guest) buffer pool.
    /// If not set, derived from `output_data_size` for backward compatibility.
    /// Default: 4 page (16KB).
    h2g_pool_pages: Option<usize>,
}

impl SandboxConfiguration {
    /// The default size of input data
    pub const DEFAULT_INPUT_SIZE: usize = 0x4000;
    /// The minimum size of input data
    pub const MIN_INPUT_SIZE: usize = 0x2000;
    /// The default size of output data
    pub const DEFAULT_OUTPUT_SIZE: usize = 0x4000;
    /// The minimum size of output data
    pub const MIN_OUTPUT_SIZE: usize = 0x2000;
    /// The default interrupt retry delay
    pub const DEFAULT_INTERRUPT_RETRY_DELAY: Duration = Duration::from_micros(500);
    /// The default signal offset from `SIGRTMIN` used to determine the signal number for interrupting
    pub const INTERRUPT_VCPU_SIGRTMIN_OFFSET: u8 = 0;
    /// The default heap size of a hyperlight sandbox
    pub const DEFAULT_HEAP_SIZE: u64 = 131072;
    /// The default size of the scratch region
    pub const DEFAULT_SCRATCH_SIZE: usize = 0x48000;
    /// The default G2H virtqueue depth (number of descriptors, must be power of 2)
    pub const DEFAULT_G2H_QUEUE_DEPTH: usize = 64;
    /// The default H2G virtqueue depth (number of descriptors, must be power of 2)
    pub const DEFAULT_H2G_QUEUE_DEPTH: usize = 32;
    /// The default number of G2H buffer pool pages
    pub const DEFAULT_G2H_POOL_PAGES: usize = 8;
    /// The default number of H2G buffer pool pages
    pub const DEFAULT_H2G_POOL_PAGES: usize = 4;

    #[allow(clippy::too_many_arguments)]
    /// Create a new configuration for a sandbox with the given sizes.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn new(
        input_data_size: usize,
        output_data_size: usize,
        heap_size_override: Option<u64>,
        scratch_size: usize,
        interrupt_retry_delay: Duration,
        interrupt_vcpu_sigrtmin_offset: u8,
        #[cfg(gdb)] guest_debug_info: Option<DebugInfo>,
        #[cfg(crashdump)] guest_core_dump: bool,
    ) -> Self {
        Self {
            input_data_size: max(input_data_size, Self::MIN_INPUT_SIZE),
            output_data_size: max(output_data_size, Self::MIN_OUTPUT_SIZE),
            heap_size_override: heap_size_override.unwrap_or(0),
            scratch_size,
            interrupt_retry_delay,
            interrupt_vcpu_sigrtmin_offset,
            g2h_queue_depth: Self::DEFAULT_G2H_QUEUE_DEPTH,
            h2g_queue_depth: Self::DEFAULT_H2G_QUEUE_DEPTH,
            g2h_pool_pages: None,
            h2g_pool_pages: None,
            #[cfg(gdb)]
            guest_debug_info,
            #[cfg(crashdump)]
            guest_core_dump,
        }
    }

    /// Set the size of the legacy input data buffer (host-to-guest).
    ///
    /// Deprecated: use [`set_h2g_pool_pages`](Self::set_h2g_pool_pages) instead.
    /// When `h2g_pool_pages` is not set, the H2G pool size is derived
    /// from this value for backward compatibility.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_input_data_size(&mut self, input_data_size: usize) {
        self.input_data_size = max(input_data_size, Self::MIN_INPUT_SIZE);
    }

    /// Set the size of the legacy output data buffer (guest-to-host).
    ///
    /// Deprecated: use [`set_g2h_pool_pages`](Self::set_g2h_pool_pages) instead.
    /// When `g2h_pool_pages` is not set, the G2H pool size is derived
    /// from this value for backward compatibility.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_output_data_size(&mut self, output_data_size: usize) {
        self.output_data_size = max(output_data_size, Self::MIN_OUTPUT_SIZE);
    }

    /// Set the heap size to use in the guest sandbox. If set to 0, the heap size will be determined from the PE file header
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_heap_size(&mut self, heap_size: u64) {
        self.heap_size_override = heap_size;
    }

    /// Sets the interrupt retry delay
    #[cfg(target_os = "linux")]
    pub fn set_interrupt_retry_delay(&mut self, delay: Duration) {
        self.interrupt_retry_delay = delay;
    }

    /// Get the delay between retries for interrupts
    #[cfg(target_os = "linux")]
    pub fn get_interrupt_retry_delay(&self) -> Duration {
        self.interrupt_retry_delay
    }

    /// Get the signal offset from `SIGRTMIN` used to determine the signal number for interrupting the VCPU thread
    #[cfg(target_os = "linux")]
    pub fn get_interrupt_vcpu_sigrtmin_offset(&self) -> u8 {
        self.interrupt_vcpu_sigrtmin_offset
    }

    /// Sets the offset from `SIGRTMIN` to determine the real-time signal used for
    /// interrupting the VCPU thread.
    ///
    /// The final signal number is computed as `SIGRTMIN + offset`, and it must fall within
    /// the valid range of real-time signals supported by the host system.
    ///
    /// Returns Ok(()) if the offset is valid, or an error if it exceeds the maximum real-time signal number.
    #[cfg(target_os = "linux")]
    pub fn set_interrupt_vcpu_sigrtmin_offset(&mut self, offset: u8) -> crate::Result<()> {
        if libc::SIGRTMIN() + offset as c_int > libc::SIGRTMAX() {
            return Err(crate::new_error!(
                "Invalid SIGRTMIN offset: {}. It exceeds the maximum real-time signal number.",
                offset
            ));
        }
        self.interrupt_vcpu_sigrtmin_offset = offset;
        Ok(())
    }

    /// Toggles the guest core dump generation for a sandbox
    /// Setting this to false disables the core dump generation
    /// This is only used when the `crashdump` feature is enabled
    #[cfg(crashdump)]
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_guest_core_dump(&mut self, enable: bool) {
        self.guest_core_dump = enable;
    }

    /// Sets the configuration for the guest debug
    #[cfg(gdb)]
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_guest_debug_info(&mut self, debug_info: DebugInfo) {
        self.guest_debug_info = Some(debug_info);
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_input_data_size(&self) -> usize {
        self.input_data_size
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_output_data_size(&self) -> usize {
        self.output_data_size
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_scratch_size(&self) -> usize {
        self.scratch_size
    }

    /// Get the G2H virtqueue depth (number of descriptors).
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn get_g2h_queue_depth(&self) -> usize {
        self.g2h_queue_depth
    }

    /// Get the H2G virtqueue depth (number of descriptors).
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn get_h2g_queue_depth(&self) -> usize {
        self.h2g_queue_depth
    }

    /// Set the G2H virtqueue depth (number of descriptors, must be power of 2).
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_g2h_queue_depth(&mut self, depth: usize) {
        self.g2h_queue_depth = depth;
    }

    /// Set the H2G virtqueue depth (number of descriptors, must be power of 2).
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_h2g_queue_depth(&mut self, depth: usize) {
        self.h2g_queue_depth = depth;
    }

    /// Get the number of G2H buffer pool pages.
    /// Falls back to deriving from `output_data_size` if not explicitly set
    /// (output = guest-to-host direction).
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn get_g2h_pool_pages(&self) -> usize {
        self.g2h_pool_pages.unwrap_or_else(|| {
            let pages = self
                .output_data_size
                .div_ceil(hyperlight_common::mem::PAGE_SIZE_USIZE);
            pages.max(Self::DEFAULT_G2H_POOL_PAGES)
        })
    }

    /// Get the number of H2G buffer pool pages.
    /// Falls back to deriving from `input_data_size` if not explicitly set
    /// (input = host-to-guest direction).
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn get_h2g_pool_pages(&self) -> usize {
        self.h2g_pool_pages.unwrap_or_else(|| {
            let pages = self
                .input_data_size
                .div_ceil(hyperlight_common::mem::PAGE_SIZE_USIZE);
            pages.max(Self::DEFAULT_H2G_POOL_PAGES)
        })
    }

    /// Set the number of G2H buffer pool pages.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_g2h_pool_pages(&mut self, pages: usize) {
        self.g2h_pool_pages = Some(pages);
    }

    /// Set the number of H2G buffer pool pages.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_h2g_pool_pages(&mut self, pages: usize) {
        self.h2g_pool_pages = Some(pages);
    }

    /// Set the size of the scratch regiong
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_scratch_size(&mut self, scratch_size: usize) {
        self.scratch_size = scratch_size;
    }

    #[cfg(crashdump)]
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_guest_core_dump(&self) -> bool {
        self.guest_core_dump
    }

    #[cfg(gdb)]
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_guest_debug_info(&self) -> Option<DebugInfo> {
        self.guest_debug_info
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn heap_size_override_opt(&self) -> Option<u64> {
        (self.heap_size_override > 0).then_some(self.heap_size_override)
    }

    /// If self.heap_size_override is non-zero, return it. Otherwise,
    /// return exe_info.heap_reserve()
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_heap_size(&self) -> u64 {
        self.heap_size_override_opt()
            .unwrap_or(Self::DEFAULT_HEAP_SIZE)
    }
}

impl Default for SandboxConfiguration {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn default() -> Self {
        Self::new(
            Self::DEFAULT_INPUT_SIZE,
            Self::DEFAULT_OUTPUT_SIZE,
            None,
            Self::DEFAULT_SCRATCH_SIZE,
            Self::DEFAULT_INTERRUPT_RETRY_DELAY,
            Self::INTERRUPT_VCPU_SIGRTMIN_OFFSET,
            #[cfg(gdb)]
            None,
            #[cfg(crashdump)]
            true,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::SandboxConfiguration;

    #[test]
    fn overrides() {
        const HEAP_SIZE_OVERRIDE: u64 = 0x50000;
        const INPUT_DATA_SIZE_OVERRIDE: usize = 0x4000;
        const OUTPUT_DATA_SIZE_OVERRIDE: usize = 0x4001;
        const SCRATCH_SIZE_OVERRIDE: usize = 0x60000;
        let mut cfg = SandboxConfiguration::new(
            INPUT_DATA_SIZE_OVERRIDE,
            OUTPUT_DATA_SIZE_OVERRIDE,
            Some(HEAP_SIZE_OVERRIDE),
            SCRATCH_SIZE_OVERRIDE,
            SandboxConfiguration::DEFAULT_INTERRUPT_RETRY_DELAY,
            SandboxConfiguration::INTERRUPT_VCPU_SIGRTMIN_OFFSET,
            #[cfg(gdb)]
            None,
            #[cfg(crashdump)]
            true,
        );

        let heap_size = cfg.get_heap_size();
        let scratch_size = cfg.get_scratch_size();
        assert_eq!(HEAP_SIZE_OVERRIDE, heap_size);
        assert_eq!(SCRATCH_SIZE_OVERRIDE, scratch_size);

        cfg.heap_size_override = 2048;
        cfg.scratch_size = 0x40000;
        assert_eq!(2048, cfg.heap_size_override);
        assert_eq!(0x40000, cfg.scratch_size);
        assert_eq!(INPUT_DATA_SIZE_OVERRIDE, cfg.input_data_size);
        assert_eq!(OUTPUT_DATA_SIZE_OVERRIDE, cfg.output_data_size);
    }

    #[test]
    fn min_sizes() {
        let mut cfg = SandboxConfiguration::new(
            SandboxConfiguration::MIN_INPUT_SIZE - 1,
            SandboxConfiguration::MIN_OUTPUT_SIZE - 1,
            None,
            SandboxConfiguration::DEFAULT_SCRATCH_SIZE,
            SandboxConfiguration::DEFAULT_INTERRUPT_RETRY_DELAY,
            SandboxConfiguration::INTERRUPT_VCPU_SIGRTMIN_OFFSET,
            #[cfg(gdb)]
            None,
            #[cfg(crashdump)]
            true,
        );
        assert_eq!(SandboxConfiguration::MIN_INPUT_SIZE, cfg.input_data_size);
        assert_eq!(SandboxConfiguration::MIN_OUTPUT_SIZE, cfg.output_data_size);
        assert_eq!(0, cfg.heap_size_override);

        cfg.set_input_data_size(SandboxConfiguration::MIN_INPUT_SIZE - 1);
        cfg.set_output_data_size(SandboxConfiguration::MIN_OUTPUT_SIZE - 1);

        assert_eq!(SandboxConfiguration::MIN_INPUT_SIZE, cfg.input_data_size);
        assert_eq!(SandboxConfiguration::MIN_OUTPUT_SIZE, cfg.output_data_size);
    }

    mod proptests {
        use proptest::prelude::*;

        use super::SandboxConfiguration;
        #[cfg(gdb)]
        use crate::sandbox::config::DebugInfo;

        proptest! {
            #[test]
            fn input_data_size(size in SandboxConfiguration::MIN_INPUT_SIZE..=SandboxConfiguration::MIN_INPUT_SIZE * 10) {
                let mut cfg = SandboxConfiguration::default();
                cfg.set_input_data_size(size);
                prop_assert_eq!(size, cfg.get_input_data_size());
            }

            #[test]
            fn output_data_size(size in SandboxConfiguration::MIN_OUTPUT_SIZE..=SandboxConfiguration::MIN_OUTPUT_SIZE * 10) {
                let mut cfg = SandboxConfiguration::default();
                cfg.set_output_data_size(size);
                prop_assert_eq!(size, cfg.get_output_data_size());
            }


            #[test]
            fn heap_size_override(size in 0x1000..=0x10000u64) {
                let mut cfg = SandboxConfiguration::default();
                cfg.set_heap_size(size);
                prop_assert_eq!(size, cfg.heap_size_override);
            }

            #[test]
            #[cfg(gdb)]
            fn guest_debug_info(port in 9000..=u16::MAX) {
                let mut cfg = SandboxConfiguration::default();
                let debug_info = DebugInfo { port };
                cfg.set_guest_debug_info(debug_info);
                prop_assert_eq!(debug_info, *cfg.get_guest_debug_info().as_ref().unwrap());
            }
        }
    }
}
