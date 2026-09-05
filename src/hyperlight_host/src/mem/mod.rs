// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

/// A simple ELF loader
pub(crate) mod elf;
/// A generic wrapper for executable files (PE, ELF, etc)
pub(crate) mod exe;
/// Functionality to establish a sandbox's memory layout.
pub mod layout;
/// memory regions to be mapped inside a vm
pub mod memory_region;
/// Functionality that wraps a `SandboxMemoryLayout` and a
/// `SandboxMemoryConfig` to mutate a sandbox's memory as necessary.
pub mod mgr;
/// Structures to represent pointers into guest and host memory
pub mod ptr;
/// Structures to represent memory address spaces into which pointers
/// point.
pub(super) mod ptr_addr_space;
/// Structures to represent an offset into a memory space
pub mod ptr_offset;
/// A wrapper around unsafe functionality to create and initialize
/// a memory region for a guest running in a sandbox.
pub mod shared_mem;
/// Utilities for writing shared memory tests
#[cfg(all(test, not(miri)))] // uses proptest which isn't miri-compatible
pub(crate) mod shared_mem_tests;
/// Host virtqueue attachment and validation.
pub(crate) mod virtq;
