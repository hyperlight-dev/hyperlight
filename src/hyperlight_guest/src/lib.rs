// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

#![no_std]
#[cfg(all(feature = "trace_guest", not(target_arch = "x86_64")))]
compile_error!("trace_guest feature is only supported on x86_64 architecture");

extern crate alloc;

// Modules
pub mod error;
pub mod exit;
pub mod layout;
pub mod prim_alloc;
pub mod types;

pub mod guest_handle {
    pub mod handle;
    pub mod host_comm;
    pub mod io;
}
