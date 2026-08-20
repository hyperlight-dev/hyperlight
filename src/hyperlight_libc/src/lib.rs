// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

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
