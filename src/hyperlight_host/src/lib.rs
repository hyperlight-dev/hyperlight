// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.
#![warn(dead_code, missing_docs, unused_mut)]
//! Hyperlight host runtime for executing guest code in lightweight virtual machines.
//!
//! This crate provides the host-side runtime for Hyperlight, enabling safe execution
//! of untrusted guest code within micro virtual machines with minimal overhead.
//! The runtime manages sandbox creation, guest function calls, memory isolation,
//! and host-guest communication.
//!
//! The primary entry point is [`SandboxBuilder`], which produces a
//! [`Sandbox`] for executing guest functions.
//!
//! ## Guest Requirements
//!
//! Hyperlight requires specially compiled guest binaries and cannot run regular
//! container images or executables. Guests must be built using either the Rust
//! API ([`hyperlight_guest`] with optional use of [`hyperlight_guest_bin`]),
//! or with the C API (`hyperlight_guest_capi`).
//!
//! [`hyperlight_guest`]: https://docs.rs/hyperlight_guest
//! [`hyperlight_guest_bin`]: https://docs.rs/hyperlight_guest_bin
//!

#![cfg_attr(not(any(test, debug_assertions)), warn(clippy::panic))]
#![cfg_attr(not(any(test, debug_assertions)), warn(clippy::expect_used))]
#![cfg_attr(not(any(test, debug_assertions)), warn(clippy::unwrap_used))]

/// Dealing with errors, including errors across VM boundaries
pub mod error;
/// Wrappers for host and guest functions.
pub mod func;
/// Wrappers for hypervisor implementations
pub mod hypervisor;
/// Functionality to establish and manage an individual sandbox's
/// memory.
///
/// - Virtual Address
///
/// 0x0000    PML4
/// 0x1000    PDPT
/// 0x2000    PD
/// 0x3000    The guest PE code (When the code has been loaded using LoadLibrary to debug the guest this will not be
/// present and code length will be zero;
///
/// - The pointer passed to the Entrypoint in the Guest application is the size of page table + size of code,
///   at this address structs below are laid out in this order
pub mod mem;
/// Metric definitions and helpers
pub mod metrics;
/// The main sandbox implementations. Do not use this module directly in code
/// outside this file. Types from this module needed for public consumption are
/// re-exported below.
pub mod sandbox;
/// Signal handling for Linux
#[cfg(target_os = "linux")]
pub(crate) mod signal_handlers;
/// Utilities for testing including interacting with `simpleguest` testing guest binary
#[cfg(test)]
pub(crate) mod testing;

/// The re-export for the `HyperlightError` type
pub use error::HyperlightError;
/// The re-export for the `is_hypervisor_present` type
pub use hypervisor::virtual_machine::is_hypervisor_present;
/// Deprecated name for [`Sandbox`].
#[allow(deprecated)]
pub use sandbox::MultiUseSandbox;
/// A sandbox that can call be used to make multiple calls to guest functions,
/// and otherwise reused multiple times
pub use sandbox::Sandbox;
/// The lifecycle state of a [`Sandbox`].
pub use sandbox::SandboxStatus;
/// The re-export for the `UninitializedSandbox` type
pub use sandbox::UninitializedSandbox;
/// The re-export for the `SandboxBuilder` type
pub use sandbox::builder::SandboxBuilder;
/// A collection of host functions that can be supplied to a sandbox
/// constructor (e.g. [`Sandbox::from_snapshot`]).
pub use sandbox::host_funcs::HostFunctions;
/// The re-export for the `GuestBinary` type
pub use sandbox::uninitialized::GuestBinary;

/// Unstable, internal API surface exposed solely for Hyperlight's own
/// integration tests. Not part of the public API: anything here may
/// change or disappear without notice. Do not depend on it.
#[doc(hidden)]
pub mod __private {
    /// Short golden-tag token for the host CPU vendor, or `None` if the
    /// goldens do not cover it. See the snapshot golden tests.
    pub fn host_cpu_vendor_golden_tag() -> Option<&'static str> {
        crate::sandbox::snapshot::host_cpu_vendor_golden_tag()
    }
}

/// The universal `Result` type used throughout the Hyperlight codebase.
pub type Result<T> = core::result::Result<T, error::HyperlightError>;

/// Logs an error then returns with it, more or less equivalent to the bail! macro in anyhow
/// but for HyperlightError instead of anyhow::Error
#[macro_export]
macro_rules! log_then_return {
    ($msg:literal $(,)?) => {{
        let __args = std::format_args!($msg);
        let __err_msg = match __args.as_str() {
            Some(msg) => String::from(msg),
            None => std::format!($msg),
        };
        let __err = $crate::HyperlightError::Error(__err_msg);
        tracing::error!("{}", __err);
        return Err(__err);
    }};
    ($err:expr $(,)?) => {
        tracing::error!("{}", $err);
        return Err($err);
    };
    ($err:stmt $(,)?) => {
        tracing::error!("{}", $err);
        return Err($err);
    };
    ($fmtstr:expr, $($arg:tt)*) => {
           let __err_msg = std::format!($fmtstr, $($arg)*);
           let __err = $crate::error::HyperlightError::Error(__err_msg);
           tracing::error!("{}", __err);
           return Err(__err);
    };
}
