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
#![deny(dead_code, missing_docs, unused_mut)]
//! This crate contains an SDK that is used to execute specially-
// compiled binaries within a very lightweight hypervisor environment.

#![cfg_attr(not(any(test, debug_assertions)), warn(clippy::panic))]
#![cfg_attr(not(any(test, debug_assertions)), warn(clippy::expect_used))]
#![cfg_attr(not(any(test, debug_assertions)), warn(clippy::unwrap_used))]
#![cfg_attr(any(test, debug_assertions), allow(clippy::disallowed_macros))]

#[cfg(feature = "build-metadata")]
use std::sync::Once;

#[cfg(feature = "build-metadata")]
/// The `built` crate is used to generate a `built.rs` file that contains
/// information about the build environment. This information is used to
/// populate the `built_info` module, which is re-exported here.
pub(crate) mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}
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
///     at this address structs below are laid out in this order
pub mod mem;
/// Metric definitions and helpers
pub mod metrics;
/// The main sandbox implementations. Do not use this module directly in code
/// outside this file. Types from this module needed for public consumption are
/// re-exported below.
pub mod sandbox;
/// `trait`s and other functionality for dealing with defining sandbox
/// states and moving between them
pub mod sandbox_state;
#[cfg(all(feature = "seccomp", target_os = "linux"))]
pub(crate) mod seccomp;
/// Signal handling for Linux
#[cfg(target_os = "linux")]
pub(crate) mod signal_handlers;
/// Utilities for testing including interacting with `simpleguest.exe`
/// and `callbackguest.exe`, our two most basic guest binaries for testing
#[cfg(test)]
pub(crate) mod testing;

/// The re-export for the `HyperlightError` type
pub use error::HyperlightError;
/// The re-export for the `is_hypervisor_present` type
pub use sandbox::is_hypervisor_present;
/// The re-export for the `GuestBinary` type
pub use sandbox::uninitialized::GuestBinary;
/// Re-export for `HypervisorWrapper` trait
/// Re-export for `MemMgrWrapper` type
/// A sandbox that can call be used to make multiple calls to guest functions,
/// and otherwise reused multiple times
pub use sandbox::MultiUseSandbox;
/// The re-export for the `UninitializedSandbox` type
pub use sandbox::UninitializedSandbox;

/// The re-export for the `MultiUseGuestCallContext` type`
pub use crate::func::call_ctx::MultiUseGuestCallContext;

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
        log::error!("{}", __err);
        return Err(__err);
    }};
    ($err:expr $(,)?) => {
        log::error!("{}", $err);
        return Err($err);
    };
    ($err:stmt $(,)?) => {
        log::error!("{}", $err);
        return Err($err);
    };
    ($fmtstr:expr, $($arg:tt)*) => {
           let __err_msg = std::format!($fmtstr, $($arg)*);
           let __err = $crate::error::HyperlightError::Error(__err_msg);
           log::error!("{}", __err);
           return Err(__err);
    };
}

/// Same as log::debug!, but will additionally print to stdout if the print_debug feature is enabled
#[macro_export]
macro_rules! debug {
    ($($arg:tt)+) =>
    {
        #[cfg(print_debug)]
        println!($($arg)+);
        log::debug!($($arg)+);
    }
}

// LOG_ONCE is used to log information about the crate version once
#[cfg(feature = "build-metadata")]
static LOG_ONCE: Once = Once::new();

#[cfg(feature = "build-metadata")]
pub(crate) fn log_build_details() {
    use log::info;
    LOG_ONCE.call_once(|| {
        info!("Package name: {}", built_info::PKG_NAME);
        info!("Package version: {}", built_info::PKG_VERSION);
        info!("Package features: {:?}", built_info::FEATURES);
        info!("Target triple: {}", built_info::TARGET);
        info!("Optimization level: {}", built_info::OPT_LEVEL);
        info!("Profile: {}", built_info::PROFILE);
        info!("Debug: {}", built_info::DEBUG);
        info!("Rustc: {}", built_info::RUSTC);
        info!("Built at: {}", built_info::BUILT_TIME_UTC);
        match built_info::CI_PLATFORM.unwrap_or("") {
            "" => info!("Not built on  a CI platform"),
            other => info!("Built on : {}", other),
        }
        match built_info::GIT_COMMIT_HASH.unwrap_or("") {
            "" => info!("No git commit hash found"),
            other => info!("Git commit hash: {}", other),
        }

        let git = match built_info::GIT_HEAD_REF.unwrap_or("") {
            "" => {
                info!("No git head ref found");
                false
            }
            other => {
                info!("Git head ref: {}", other);
                true
            }
        };
        match built_info::GIT_VERSION.unwrap_or("") {
            "" => info!("No git version found"),
            other => info!("Git version: {}", other),
        }
        match built_info::GIT_DIRTY.unwrap_or(false) {
            true => info!("Repo had uncommitted changes"),
            false => {
                if git {
                    info!("Repo had no uncommitted changes")
                } else {
                    info!("No git repo found")
                }
            }
        }
    });
}
