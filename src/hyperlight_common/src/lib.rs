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

#![cfg_attr(not(any(test, debug_assertions)), warn(clippy::panic))]
#![cfg_attr(not(any(test, debug_assertions)), warn(clippy::expect_used))]
#![cfg_attr(not(any(test, debug_assertions)), warn(clippy::unwrap_used))]
// We use Arbitrary during fuzzing, which requires std
#![cfg_attr(not(feature = "fuzzing"), no_std)]

extern crate alloc;

pub mod flatbuffer_wrappers;
/// cbindgen:ignore
/// FlatBuffers-related utilities and (mostly) generated code
#[allow(
    dead_code,
    unused_imports,
    clippy::all,
    clippy::unwrap_used,
    unsafe_op_in_unsafe_fn,
    non_camel_case_types
)]
mod flatbuffers;
/// cbindgen:ignore
pub mod mem;

/// cbindgen:ignore
pub mod outb;
