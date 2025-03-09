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

#![no_std]

pub const PAGE_SIZE: usize = 0x1_000; // 4KB

extern crate alloc;

pub mod flatbuffer_wrappers;
/// cbindgen:ignore
/// FlatBuffers-related utilities and (mostly) generated code
#[allow(
    dead_code,
    unused_imports,
    clippy::all,
    unsafe_op_in_unsafe_fn,
    non_camel_case_types
)]
mod flatbuffers;

/// Hyperlight operates with a host-guest execution model.
///
/// The host is who creates the hypervisor partition, and the guest is whatever runs
/// inside said hypervisor partition (i.e., in between a `VMENTER` and `VMEXIT`).
///
/// The guest and host communicate through a shared memory region. In particular, the
/// input and output data sections. A guest can pop data from the input section, and
/// push data to the output section. On the other hand, the host can push data to the
/// input section and pop data from the output section.
pub mod input_output;
