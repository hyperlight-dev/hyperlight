// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

#![no_std]
#[cfg(all(feature = "trace_guest", not(target_arch = "x86_64")))]
compile_error!("trace_guest feature is only supported on x86_64 architecture");

extern crate alloc;

// Modules
#[cfg(target_arch = "aarch64")]
#[path = "arch/aarch64/mod.rs"]
mod arch;

pub mod error;
pub mod exit;
pub mod layout;
pub mod paging;
pub mod prim_alloc;
pub mod transport;
pub mod types;

pub enum PendingHostCall {
    Unpolled,
    Polled(core::task::Waker),
    Completed(Result<hyperlight_common::flatbuffer_wrappers::function_types::FunctionCallResult, error::HyperlightGuestError>),
}
pub static mut PENDING_HOST_CALLS: alloc::collections::BTreeMap<hyperlight_common::virtq::Token, (u32, PendingHostCall)> = alloc::collections::BTreeMap::new();
