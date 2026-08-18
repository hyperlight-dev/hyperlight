// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use std::path::PathBuf;

use hyperlight_host::{MultiUseSandbox, SandboxBuilder};
use hyperlight_testing::{c_simple_guest_as_pathbuf, simple_guest_as_pathbuf};

/// Returns the path to the Rust simple guest binary.
fn rust_guest_path() -> PathBuf {
    simple_guest_as_pathbuf()
}

/// Returns the path to the C simple guest binary.
fn c_guest_path() -> PathBuf {
    c_simple_guest_as_pathbuf()
}

// =============================================================================
// Rust guest helpers
// =============================================================================

/// Builds a Rust guest MultiUseSandbox from `builder`.
pub fn build_rust_sandbox(builder: SandboxBuilder) -> MultiUseSandbox {
    builder.build_from_file(rust_guest_path()).unwrap()
}

/// Creates a new Rust guest MultiUseSandbox.
pub fn new_rust_sandbox() -> MultiUseSandbox {
    build_rust_sandbox(SandboxBuilder::new())
}

/// Runs a test with a Rust guest MultiUseSandbox.
pub fn with_rust_sandbox<F>(f: F)
where
    F: FnOnce(MultiUseSandbox),
{
    f(new_rust_sandbox());
}

/// Runs a test with a Rust guest MultiUseSandbox built from `builder`.
pub fn with_rust_sandbox_from<F>(builder: SandboxBuilder, f: F)
where
    F: FnOnce(MultiUseSandbox),
{
    f(build_rust_sandbox(builder));
}

// =============================================================================
// C guest helpers
// =============================================================================

/// Builds a C guest MultiUseSandbox from `builder`.
pub fn build_c_sandbox(builder: SandboxBuilder) -> MultiUseSandbox {
    builder.build_from_file(c_guest_path()).unwrap()
}

/// Runs a test with a C guest MultiUseSandbox.
pub fn with_c_sandbox<F>(f: F)
where
    F: FnOnce(MultiUseSandbox),
{
    f(build_c_sandbox(SandboxBuilder::new()));
}

/// Runs a test with a C guest MultiUseSandbox built from `builder`.
pub fn with_c_sandbox_from<F>(builder: SandboxBuilder, f: F)
where
    F: FnOnce(MultiUseSandbox),
{
    f(build_c_sandbox(builder));
}

// =============================================================================
// Both guests helpers (run test with Rust AND C guests)
// =============================================================================

/// Runs a test once per guest binary, passing the path to it.
///
/// Use this when the test needs to configure the sandbox itself, for instance
/// to register a host function that owns per-guest state.
pub fn with_all_guests<F>(f: F)
where
    F: Fn(PathBuf),
{
    for path in [rust_guest_path(), c_guest_path()] {
        f(path);
    }
}

/// Runs a test with both Rust and C guest MultiUseSandboxes.
pub fn with_all_sandboxes<F>(f: F)
where
    F: Fn(MultiUseSandbox),
{
    with_all_guests(|path| {
        f(SandboxBuilder::new().build_from_file(path).unwrap());
    });
}
