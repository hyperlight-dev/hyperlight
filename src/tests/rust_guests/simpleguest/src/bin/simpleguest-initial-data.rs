// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;

use hyperlight_common::flatbuffer_wrappers::function_types::Bytes;
use hyperlight_guest::error::Result;
use hyperlight_guest_bin::{guest_function, host_function, main};

static mut INITIAL_DATA: Vec<Bytes> = Vec::new();

/// Fetch application data during guest startup.
#[host_function("InitialData")]
fn initial_data() -> Result<Vec<Bytes>>;

/// Keep the transport-backed reply for later calls and snapshots.
#[main]
fn main() {
    let data = initial_data().expect("initial data host call failed");

    // SAFETY: The guest is single threaded.
    unsafe { INITIAL_DATA = data };
}

/// Read startup data without releasing its transport owners.
#[guest_function("ReadInitialData")]
fn read_initial_data() -> Vec<Bytes> {
    // SAFETY: The guest is single threaded.
    #[allow(static_mut_refs)]
    unsafe {
        INITIAL_DATA.clone()
    }
}

/// Release the retained transport owners.
#[guest_function("ClearInitialData")]
fn clear_initial_data() {
    // SAFETY: The guest is single threaded.
    #[allow(static_mut_refs)]
    unsafe {
        INITIAL_DATA.clear();
    }
}
