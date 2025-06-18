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

use crate::mem::exe::ExeInfo;

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
    /// The size of the memory buffer that is made available for Guest Function
    /// Definitions
    host_function_definition_size: usize,
    /// The size of the memory buffer that is made available for input to the
    /// Guest Binary
    input_data_size: usize,
    /// The size of the memory buffer that is made available for input to the
    /// Guest Binary
    output_data_size: usize,
    /// The stack size to use in the guest sandbox. If set to 0, the stack
    /// size will be determined from the PE file header.
    ///
    /// Note: this is a C-compatible struct, so even though this optional
    /// field should be represented as an `Option`, that type is not
    /// FFI-safe, so it cannot be.
    stack_size_override: u64,
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
    /// The default size of host function definitionsSET
    /// Host function definitions has its own page in memory, in order to be READ-ONLY
    /// from a guest's perspective.
    pub const DEFAULT_HOST_FUNCTION_DEFINITION_SIZE: usize = 0x1000;
    /// The minimum size of host function definitions
    pub const MIN_HOST_FUNCTION_DEFINITION_SIZE: usize = 0x1000;
    /// The default interrupt retry delay
    pub const DEFAULT_INTERRUPT_RETRY_DELAY: Duration = Duration::from_micros(500);
    /// The default signal offset from `SIGRTMIN` used to determine the signal number for interrupting
    pub const INTERRUPT_VCPU_SIGRTMIN_OFFSET: u8 = 0;

    #[allow(clippy::too_many_arguments)]
    /// Create a new configuration for a sandbox with the given sizes.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn new(
        input_data_size: usize,
        output_data_size: usize,
        function_definition_size: usize,
        stack_size_override: Option<u64>,
        heap_size_override: Option<u64>,
        interrupt_retry_delay: Duration,
        interrupt_vcpu_sigrtmin_offset: u8,
        #[cfg(gdb)] guest_debug_info: Option<DebugInfo>,
        #[cfg(crashdump)] guest_core_dump: bool,
    ) -> Self {
        Self {
            input_data_size: max(input_data_size, Self::MIN_INPUT_SIZE),
            output_data_size: max(output_data_size, Self::MIN_OUTPUT_SIZE),
            host_function_definition_size: max(
                function_definition_size,
                Self::MIN_HOST_FUNCTION_DEFINITION_SIZE,
            ),
            stack_size_override: stack_size_override.unwrap_or(0),
            heap_size_override: heap_size_override.unwrap_or(0),
            interrupt_retry_delay,
            interrupt_vcpu_sigrtmin_offset,
            #[cfg(gdb)]
            guest_debug_info,
            #[cfg(crashdump)]
            guest_core_dump,
        }
    }

    /// Set the size of the memory buffer that is made available for serialising host function definitions
    /// the minimum value is MIN_HOST_FUNCTION_DEFINITION_SIZE
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_host_function_definition_size(&mut self, host_function_definition_size: usize) {
        self.host_function_definition_size = max(
            host_function_definition_size,
            Self::MIN_HOST_FUNCTION_DEFINITION_SIZE,
        );
    }

    /// Set the size of the memory buffer that is made available for input to the guest
    /// the minimum value is MIN_INPUT_SIZE
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_input_data_size(&mut self, input_data_size: usize) {
        self.input_data_size = max(input_data_size, Self::MIN_INPUT_SIZE);
    }

    /// Set the size of the memory buffer that is made available for output from the guest
    /// the minimum value is MIN_OUTPUT_SIZE
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_output_data_size(&mut self, output_data_size: usize) {
        self.output_data_size = max(output_data_size, Self::MIN_OUTPUT_SIZE);
    }

    /// Set the stack size to use in the guest sandbox. If set to 0, the stack size will be determined from the PE file header
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_stack_size(&mut self, stack_size: u64) {
        self.stack_size_override = stack_size;
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
    pub(crate) fn get_host_function_definition_size(&self) -> usize {
        self.host_function_definition_size
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_input_data_size(&self) -> usize {
        self.input_data_size
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_output_data_size(&self) -> usize {
        self.output_data_size
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
    fn stack_size_override_opt(&self) -> Option<u64> {
        (self.stack_size_override > 0).then_some(self.stack_size_override)
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn heap_size_override_opt(&self) -> Option<u64> {
        (self.heap_size_override > 0).then_some(self.heap_size_override)
    }

    /// If self.stack_size is non-zero, return it. Otherwise,
    /// return exe_info.stack_reserve()
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_stack_size(&self, exe_info: &ExeInfo) -> u64 {
        self.stack_size_override_opt()
            .unwrap_or_else(|| exe_info.stack_reserve())
    }

    /// If self.heap_size_override is non-zero, return it. Otherwise,
    /// return exe_info.heap_reserve()
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_heap_size(&self, exe_info: &ExeInfo) -> u64 {
        self.heap_size_override_opt()
            .unwrap_or_else(|| exe_info.heap_reserve())
    }
}

impl Default for SandboxConfiguration {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn default() -> Self {
        Self::new(
            Self::DEFAULT_INPUT_SIZE,
            Self::DEFAULT_OUTPUT_SIZE,
            Self::DEFAULT_HOST_FUNCTION_DEFINITION_SIZE,
            None,
            None,
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
    use crate::testing::simple_guest_exe_info;

    #[test]
    fn overrides() {
        const STACK_SIZE_OVERRIDE: u64 = 0x10000;
        const HEAP_SIZE_OVERRIDE: u64 = 0x50000;
        const INPUT_DATA_SIZE_OVERRIDE: usize = 0x4000;
        const OUTPUT_DATA_SIZE_OVERRIDE: usize = 0x4001;
        const HOST_FUNCTION_DEFINITION_SIZE_OVERRIDE: usize = 0x4002;
        let mut cfg = SandboxConfiguration::new(
            INPUT_DATA_SIZE_OVERRIDE,
            OUTPUT_DATA_SIZE_OVERRIDE,
            HOST_FUNCTION_DEFINITION_SIZE_OVERRIDE,
            Some(STACK_SIZE_OVERRIDE),
            Some(HEAP_SIZE_OVERRIDE),
            SandboxConfiguration::DEFAULT_INTERRUPT_RETRY_DELAY,
            SandboxConfiguration::INTERRUPT_VCPU_SIGRTMIN_OFFSET,
            #[cfg(gdb)]
            None,
            #[cfg(crashdump)]
            true,
        );
        let exe_info = simple_guest_exe_info().unwrap();

        let stack_size = cfg.get_stack_size(&exe_info);
        let heap_size = cfg.get_heap_size(&exe_info);
        assert_eq!(STACK_SIZE_OVERRIDE, stack_size);
        assert_eq!(HEAP_SIZE_OVERRIDE, heap_size);

        cfg.stack_size_override = 1024;
        cfg.heap_size_override = 2048;
        assert_eq!(1024, cfg.stack_size_override);
        assert_eq!(2048, cfg.heap_size_override);
        assert_eq!(INPUT_DATA_SIZE_OVERRIDE, cfg.input_data_size);
        assert_eq!(OUTPUT_DATA_SIZE_OVERRIDE, cfg.output_data_size);
        assert_eq!(
            HOST_FUNCTION_DEFINITION_SIZE_OVERRIDE,
            cfg.host_function_definition_size
        );
    }

    #[test]
    fn min_sizes() {
        let mut cfg = SandboxConfiguration::new(
            SandboxConfiguration::MIN_INPUT_SIZE - 1,
            SandboxConfiguration::MIN_OUTPUT_SIZE - 1,
            SandboxConfiguration::MIN_HOST_FUNCTION_DEFINITION_SIZE - 1,
            None,
            None,
            SandboxConfiguration::DEFAULT_INTERRUPT_RETRY_DELAY,
            SandboxConfiguration::INTERRUPT_VCPU_SIGRTMIN_OFFSET,
            #[cfg(gdb)]
            None,
            #[cfg(crashdump)]
            true,
        );
        assert_eq!(SandboxConfiguration::MIN_INPUT_SIZE, cfg.input_data_size);
        assert_eq!(SandboxConfiguration::MIN_OUTPUT_SIZE, cfg.output_data_size);
        assert_eq!(
            SandboxConfiguration::MIN_HOST_FUNCTION_DEFINITION_SIZE,
            cfg.host_function_definition_size
        );
        assert_eq!(0, cfg.stack_size_override);
        assert_eq!(0, cfg.heap_size_override);

        cfg.set_input_data_size(SandboxConfiguration::MIN_INPUT_SIZE - 1);
        cfg.set_output_data_size(SandboxConfiguration::MIN_OUTPUT_SIZE - 1);
        cfg.set_host_function_definition_size(
            SandboxConfiguration::MIN_HOST_FUNCTION_DEFINITION_SIZE - 1,
        );

        assert_eq!(SandboxConfiguration::MIN_INPUT_SIZE, cfg.input_data_size);
        assert_eq!(SandboxConfiguration::MIN_OUTPUT_SIZE, cfg.output_data_size);
        assert_eq!(
            SandboxConfiguration::MIN_HOST_FUNCTION_DEFINITION_SIZE,
            cfg.host_function_definition_size
        );
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
            fn host_function_definition_size(size in SandboxConfiguration::MIN_HOST_FUNCTION_DEFINITION_SIZE..=SandboxConfiguration::MIN_HOST_FUNCTION_DEFINITION_SIZE * 10) {
                let mut cfg = SandboxConfiguration::default();
                cfg.set_host_function_definition_size(size);
                prop_assert_eq!(size, cfg.get_host_function_definition_size());
            }

            #[test]
            fn stack_size_override(size in 0x1000..=0x10000u64) {
                let mut cfg = SandboxConfiguration::default();
                cfg.set_stack_size(size);
                prop_assert_eq!(size, cfg.stack_size_override);
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
