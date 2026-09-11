// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

#![cfg_attr(not(any(test, debug_assertions)), warn(clippy::panic))]
#![cfg_attr(not(any(test, debug_assertions)), warn(clippy::expect_used))]
#![cfg_attr(not(any(test, debug_assertions)), warn(clippy::unwrap_used))]
// We use Arbitrary during fuzzing, which requires std
#![cfg_attr(not(any(feature = "fuzzing", test, miri)), no_std)]

extern crate alloc;

/// cbindgen:ignore
/// Support types for the bindings that `{host,guest}_bindgen!` generates
pub mod component;

pub mod flatbuffer_wrappers;
/// cbindgen:ignore
/// FlatBuffers-related utilities and (mostly) generated code
#[allow(clippy::all, warnings)]
mod flatbuffers;
// cbindgen:ignore
pub mod layout;

// cbindgen:ignore
pub mod log_level;

/// cbindgen:ignore
pub mod mem;

/// cbindgen:ignore
pub mod outb;

/// cbindgen:ignore
pub mod resource;

/// Shared guest and host transport protocol.
// cbindgen:ignore
pub mod transport;

/// cbindgen:ignore
pub mod func;

// cbindgen:ignore
pub mod vmem;

/// ELF note types for embedding hyperlight version metadata in guest binaries.
pub mod version_note;

/// cbindgen:ignore
pub mod virtq;

/// cbindgen:ignore
pub mod arch {
    #[cfg(target_arch = "aarch64")]
    #[path = "aarch64/exn.rs"]
    pub mod exn;
}
