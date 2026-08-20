// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        panic!("hyperlight_surrogate can only be built for Windows targets");
    }

    let target_env = std::env::var("CARGO_CFG_TARGET_ENV")
        .expect("CARGO_CFG_TARGET_ENV should be set for Windows targets");
    // The surrogate is a #![no_std] binary with a custom entry point.
    if target_env == "gnu" {
        // useful for `just clippyw` (targeting x86_64-pc-windows-gnu on linux host)
        println!("cargo:rustc-link-arg-bin=hyperlight_surrogate=-nostartfiles");
        println!("cargo:rustc-link-arg-bin=hyperlight_surrogate=-Wl,-e,mainCRTStartup");
        println!("cargo:rustc-link-arg-bin=hyperlight_surrogate=-Wl,--subsystem,console");
    } else {
        println!("cargo:rustc-link-arg-bin=hyperlight_surrogate=/ENTRY:mainCRTStartup");
        println!("cargo:rustc-link-arg-bin=hyperlight_surrogate=/SUBSYSTEM:CONSOLE");
    }
}
