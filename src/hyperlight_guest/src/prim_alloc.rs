// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

#[cfg_attr(target_arch = "x86_64", path = "arch/amd64/prim_alloc.rs")]
#[cfg_attr(target_arch = "aarch64", path = "arch/aarch64/prim_alloc.rs")]
mod arch;

/// Allocate n contiguous physical pages and return the physical
/// addresses of the pages in question.
/// # Safety
/// Since this reads and writes specific allocator state addresses, it
/// is only safe when the allocator has been set up properly. It may
/// become less safe in the future.
///
/// # Panics
/// This function will panic if memory allocation fails
///
/// This is defined in an arch-specific module because it reads and
/// writes the actual allocator state with inline assembly in order to
/// access it atomically according to the architecture memory model
/// rather than the Rust memory model: the stronger constraints of the
/// latter cannot be perfectly satisfied due to the lack of per-byte
/// atomic memcpy in the host.
pub use arch::alloc_phys_pages;
