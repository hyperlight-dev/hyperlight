/*
Copyright 2024 The Hyperlight Authors.

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

use std::cmp::{max, min};
use std::time::Duration;

use tracing::{instrument, Span};

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
pub(crate) struct SandboxConfiguration {
    // The size of custom guest memory, which includes everything the guest might want to make
    // addressable (e.g., heap, etc.).
    custom_guest_memory_size: u64,

    /// The `max_execution_time` of a guest execution in milliseconds.
    ///
    /// Note: this is a C-compatible struct, so even though this optional
    /// field should be represented as an `Option`, that type is not
    /// FFI-safe, so it cannot be.
    max_execution_time: u16,
    /// The `max_wait_for_cancellation` represents the maximum time the host should wait for a guest
    /// execution to be cancelled.
    ///
    /// Note: this is a C-compatible struct, so even though this optional
    /// field should be represented as an `Option`, that type is not
    /// FFI-safe, so it cannot be.
    max_wait_for_cancellation: u8,
    // The `max_initialization_time` represents the maximum time the host should wait for a guest to
    // initialize.
    //
    // Note: this is a C-compatible struct, so even though this optional
    // field should be represented as an `Option`, that type is not
    // FFI-safe, so it cannot be.
    max_initialization_time: u16,

    /// Guest gdb debug port
    #[cfg(gdb)]
    guest_debug_info: Option<DebugInfo>,
}

impl SandboxConfiguration {
    /// The default value for custom memory region (200MB)
    // TODO: arbitrary value, maybe change
    pub const DEFAULT_CUSTOM_GUEST_MEMORY_SIZE: u64 = 200 * 1024 * 1024;
    /// The default value for max initialization time (in milliseconds)
    pub const DEFAULT_MAX_INITIALIZATION_TIME: u16 = 2000;
    /// The minimum value for max initialization time (in milliseconds)
    pub const MIN_MAX_INITIALIZATION_TIME: u16 = 1;
    /// The maximum value for max initialization time (in milliseconds)
    pub const MAX_MAX_INITIALIZATION_TIME: u16 = u16::MAX;
    /// The default and minimum values for max execution time (in milliseconds)
    pub const DEFAULT_MAX_EXECUTION_TIME: u16 = 1000;
    /// The minimum value for max execution time (in milliseconds)
    pub const MIN_MAX_EXECUTION_TIME: u16 = 1;
    /// The maximum value for max execution time (in milliseconds)
    pub const MAX_MAX_EXECUTION_TIME: u16 = u16::MAX;
    /// The default and minimum values for max wait for cancellation (in milliseconds)
    pub const DEFAULT_MAX_WAIT_FOR_CANCELLATION: u8 = 100;
    /// The minimum value for max wait for cancellation (in milliseconds)
    pub const MIN_MAX_WAIT_FOR_CANCELLATION: u8 = 10;
    /// The maximum value for max wait for cancellation (in milliseconds)
    pub const MAX_MAX_WAIT_FOR_CANCELLATION: u8 = u8::MAX;

    /// Create a new configuration for a sandbox
    fn new(
        custom_guest_memory_size: u64,
        max_initialization_time: Option<Duration>,
        max_execution_time: Option<Duration>,
        max_wait_for_cancellation: Option<Duration>,
        #[cfg(gdb)] guest_debug_info: Option<DebugInfo>,
    ) -> Self {
        Self {
            custom_guest_memory_size,
            max_initialization_time: {
                match max_initialization_time {
                    Some(max_initialization_time) => match max_initialization_time.as_millis() {
                        0 => Self::DEFAULT_MAX_INITIALIZATION_TIME,
                        // TODO: it's pretty confusing that if someone sets the
                        // max initialization time to 0 that we change it to
                        // DEFAULT_MAX_INITIALIZATION_TIME, we should improve this API.
                        1.. => min(
                            Self::MAX_MAX_INITIALIZATION_TIME.into(),
                            max(
                                max_initialization_time.as_millis(),
                                Self::MIN_MAX_INITIALIZATION_TIME.into(),
                            ),
                        ) as u16,
                    },
                    None => Self::DEFAULT_MAX_INITIALIZATION_TIME,
                }
            },
            max_execution_time: {
                match max_execution_time {
                    Some(max_execution_time) => match max_execution_time.as_millis() {
                        0 => Self::DEFAULT_MAX_EXECUTION_TIME,
                        // TODO: it's pretty confusing that if someone sets the
                        // max execution time to 0 that we change it to
                        // DEFAULT_MAX_EXECUTION_TIME, we should improve this API.
                        1.. => min(
                            Self::MAX_MAX_EXECUTION_TIME.into(),
                            max(
                                max_execution_time.as_millis(),
                                Self::MIN_MAX_EXECUTION_TIME.into(),
                            ),
                        ) as u16,
                    },
                    None => Self::DEFAULT_MAX_EXECUTION_TIME,
                }
            },
            max_wait_for_cancellation: {
                match max_wait_for_cancellation {
                    Some(max_wait_for_cancellation) => {
                        match max_wait_for_cancellation.as_millis() {
                            0 => Self::DEFAULT_MAX_WAIT_FOR_CANCELLATION,
                            // TODO: it's pretty confusing that if someone sets the
                            // max wait for cancellation time to 0 that we change it to
                            // DEFAULT_MAX_WAIT_FOR_CANCELLATION, we should improve this API.
                            1.. => min(
                                Self::MAX_MAX_WAIT_FOR_CANCELLATION.into(),
                                max(
                                    max_wait_for_cancellation.as_millis(),
                                    Self::MIN_MAX_WAIT_FOR_CANCELLATION.into(),
                                ),
                            ) as u8,
                        }
                    }
                    None => Self::DEFAULT_MAX_WAIT_FOR_CANCELLATION,
                }
            },
            #[cfg(gdb)]
            guest_debug_info,
        }
    }

    /// Set the maximum time to wait for guest initialization. If set to 0, the maximum initialization
    /// time will be set to the default value of `DEFAULT_MAX_INITIALIZATION_TIME`. If the guest
    /// initialization does not complete within the time specified then an error will be returned,
    /// the minimum value is `MIN_MAX_INITIALIZATION_TIME`
    pub fn set_max_initialization_time(&mut self, max_initialization_time: Duration) {
        match max_initialization_time.as_millis() {
            0 => self.max_initialization_time = Self::DEFAULT_MAX_INITIALIZATION_TIME,
            1.. => {
                self.max_initialization_time = min(
                    Self::MAX_MAX_INITIALIZATION_TIME.into(),
                    max(
                        max_initialization_time.as_millis(),
                        Self::MIN_MAX_INITIALIZATION_TIME.into(),
                    ),
                ) as u16
            }
        }
    }

    /// Get the maximum time to wait for guest initialization
    pub(crate) fn get_max_initialization_time(&self) -> u16 {
        self.max_initialization_time
    }

    /// Set the maximum execution time of a guest function execution. If set to 0, the
    /// `max_execution_time`  will be set to the default value of `DEFAULT_MAX_EXECUTION_TIME`.
    /// If the guest execution does not complete within the time specified then the execution
    /// will be cancelled, the minimum value is `MIN_MAX_EXECUTION_TIME`.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_max_execution_time(&mut self, max_execution_time: Duration) {
        match max_execution_time.as_millis() {
            0 => self.max_execution_time = Self::DEFAULT_MAX_EXECUTION_TIME,
            1.. => {
                self.max_execution_time = min(
                    Self::MAX_MAX_EXECUTION_TIME.into(),
                    max(
                        max_execution_time.as_millis(),
                        Self::MIN_MAX_EXECUTION_TIME.into(),
                    ),
                ) as u16
            }
        }
    }

    /// Get the maximum execution time of a guest function.
    pub(crate) fn get_max_execution_time(&self) -> u16 {
        self.max_execution_time
    }

    /// Set the maximum time to wait for guest execution calculation. If set to 0, the maximum
    /// cancellation time will be set to the default value of `DEFAULT_MAX_WAIT_FOR_CANCELLATION`.
    /// If the guest execution cancellation does not complete within the time specified
    /// then an error will be returned, the minimum value is `MIN_MAX_WAIT_FOR_CANCELLATION`
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_max_execution_cancel_wait_time(&mut self, max_wait_for_cancellation: Duration) {
        match max_wait_for_cancellation.as_millis() {
            0 => self.max_wait_for_cancellation = Self::DEFAULT_MAX_WAIT_FOR_CANCELLATION,
            1.. => {
                self.max_wait_for_cancellation = min(
                    Self::MAX_MAX_WAIT_FOR_CANCELLATION.into(),
                    max(
                        max_wait_for_cancellation.as_millis(),
                        Self::MIN_MAX_WAIT_FOR_CANCELLATION.into(),
                    ),
                ) as u8
            }
        }
    }

    /// Get the maximum time to wait for guest execution cancellation.
    pub(crate) fn get_max_wait_for_cancellation(&self) -> u8 {
        self.max_wait_for_cancellation
    }

    /// Sets the configuration for the guest debug
    #[cfg(gdb)]
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_guest_debug_info(&mut self, debug_info: DebugInfo) {
        self.guest_debug_info = Some(debug_info);
    }
}

impl Default for SandboxConfiguration {
    fn default() -> Self {
        Self::new(
            Self::DEFAULT_CUSTOM_GUEST_MEMORY_SIZE,
            Some(Duration::from_millis(
                Self::DEFAULT_MAX_INITIALIZATION_TIME as u64,
            )),
            Some(Duration::from_millis(
                Self::DEFAULT_MAX_EXECUTION_TIME as u64,
            )),
            Some(Duration::from_millis(
                Self::DEFAULT_MAX_WAIT_FOR_CANCELLATION as u64,
            )),
            #[cfg(gdb)]
            None,
        )
    }
}
