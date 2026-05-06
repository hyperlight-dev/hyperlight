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

//! Hyperlight libc crate
//!
//! This crate provides the picolibc library for Hyperlight guests.
//! It builds picolibc from source and generates Rust bindings to the
//! C library types and functions.

#![no_std]
#![allow(clippy::approx_constant)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::useless_transmute)]
#![allow(dead_code)]
#![allow(improper_ctypes)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unpredictable_function_pointer_comparisons)]

// Include the generated bindings
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub use core::ffi::*;

mod stubs;
