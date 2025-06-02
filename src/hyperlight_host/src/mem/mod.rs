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
/// A wrapper around a `SharedMemory` and a snapshot in time
/// of the memory therein
pub mod shared_mem_snapshot;
/// Utilities for writing shared memory tests
#[cfg(test)]
pub(crate) mod shared_mem_tests;
