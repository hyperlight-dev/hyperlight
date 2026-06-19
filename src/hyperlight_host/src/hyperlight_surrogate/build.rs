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
