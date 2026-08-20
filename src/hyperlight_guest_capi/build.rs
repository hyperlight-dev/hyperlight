// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR should be set");

    cbindgen::generate(&crate_dir)
        .expect("Could not generate hyperlight_guest.h")
        .write_to_file("include/hyperlight_guest.h");
}
