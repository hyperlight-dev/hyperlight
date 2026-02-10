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

use hyperlight_host::func::HostFunction;
use hyperlight_host::sandbox::SandboxConfiguration;
use hyperlight_host::{GuestBinary, MultiUseSandbox, UninitializedSandbox};
use hyperlight_testing::{c_simple_guest_as_string, simple_guest_as_string};

/// Returns the path to the Rust simple guest binary.
fn rust_guest_path() -> String {
    simple_guest_as_string().unwrap()
}

/// Returns the path to the C simple guest binary.
fn c_guest_path() -> String {
    c_simple_guest_as_string().unwrap()
}

/// Creates a new Rust guest MultiUseSandbox.
pub fn new_rust_sandbox() -> MultiUseSandbox {
    UninitializedSandbox::new(GuestBinary::FilePath(rust_guest_path()), None)
        .unwrap()
        .evolve()
        .unwrap()
}

/// Creates a new Rust guest UninitializedSandbox.
pub fn new_rust_uninit_sandbox() -> UninitializedSandbox {
    UninitializedSandbox::new(GuestBinary::FilePath(rust_guest_path()), None).unwrap()
}

// =============================================================================
// Rust guest helpers
// =============================================================================

/// Runs a test with a Rust guest MultiUseSandbox.
pub fn with_rust_sandbox<F>(f: F)
where
    F: FnOnce(MultiUseSandbox),
{
    let sandbox = UninitializedSandbox::new(GuestBinary::FilePath(rust_guest_path()), None)
        .unwrap()
        .evolve()
        .unwrap();
    f(sandbox);
}

/// Runs a test with a Rust guest MultiUseSandbox using custom configuration.
pub fn with_rust_sandbox_cfg<F>(cfg: SandboxConfiguration, f: F)
where
    F: FnOnce(MultiUseSandbox),
{
    let sandbox = UninitializedSandbox::new(GuestBinary::FilePath(rust_guest_path()), Some(cfg))
        .unwrap()
        .evolve()
        .unwrap();
    f(sandbox);
}

/// Runs a test with a Rust guest UninitializedSandbox.
pub fn with_rust_uninit_sandbox<F>(f: F)
where
    F: FnOnce(UninitializedSandbox),
{
    let sandbox =
        UninitializedSandbox::new(GuestBinary::FilePath(rust_guest_path()), None).unwrap();
    f(sandbox);
}

// =============================================================================
// C guest helpers
// =============================================================================

/// Runs a test with a C guest MultiUseSandbox.
pub fn with_c_sandbox<F>(f: F)
where
    F: FnOnce(MultiUseSandbox),
{
    let sandbox = UninitializedSandbox::new(GuestBinary::FilePath(c_guest_path()), None)
        .unwrap()
        .evolve()
        .unwrap();
    f(sandbox);
}

/// Runs a test with a C guest UninitializedSandbox.
pub fn with_c_uninit_sandbox<F>(f: F)
where
    F: FnOnce(UninitializedSandbox),
{
    let sandbox = UninitializedSandbox::new(GuestBinary::FilePath(c_guest_path()), None).unwrap();
    f(sandbox);
}

// =============================================================================
// Both guests helpers (run test with Rust AND C guests)
// =============================================================================

/// Runs a test with both Rust and C guest MultiUseSandboxes.
pub fn with_all_sandboxes<F>(f: F)
where
    F: Fn(MultiUseSandbox),
{
    for path in [rust_guest_path(), c_guest_path()] {
        let sandbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None)
            .unwrap()
            .evolve()
            .unwrap();
        f(sandbox);
    }
}

/// Runs a test with both Rust and C guest UninitializedSandboxes.
pub fn with_all_uninit_sandboxes<F>(f: F)
where
    F: Fn(UninitializedSandbox),
{
    for path in [rust_guest_path(), c_guest_path()] {
        let sandbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
        f(sandbox);
    }
}

/// Runs a test with both Rust and C guest MultiUseSandboxes, with a print writer.
pub fn with_all_sandboxes_with_writer<F>(writer: HostFunction<i32, (String,)>, f: F)
where
    F: Fn(MultiUseSandbox),
{
    for path in [rust_guest_path(), c_guest_path()] {
        let mut sandbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
        sandbox.register_print(writer.clone()).unwrap();
        let sandbox = sandbox.evolve().unwrap();
        f(sandbox);
    }
}
