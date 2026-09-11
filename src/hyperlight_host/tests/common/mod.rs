// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use std::path::PathBuf;

use hyperlight_host::sandbox::SandboxConfiguration;
use hyperlight_host::{GuestBinary, MultiUseSandbox, SandboxBuilder, UninitializedSandbox};
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

/// Builds a Rust guest MultiUseSandbox, applying `configure` to the builder.
pub fn build_rust_sandbox<C>(configure: C) -> MultiUseSandbox
where
    C: FnOnce(SandboxBuilder) -> SandboxBuilder,
{
    configure(SandboxBuilder::from_file(rust_guest_path()))
        .build()
        .unwrap()
}

/// Creates a new Rust guest MultiUseSandbox.
pub fn new_rust_sandbox() -> MultiUseSandbox {
    build_rust_sandbox(|builder| builder)
}

/// Runs a test with a Rust guest MultiUseSandbox.
pub fn with_rust_sandbox<F>(f: F)
where
    F: FnOnce(MultiUseSandbox),
{
    f(new_rust_sandbox());
}

/// Runs a test with a Rust guest MultiUseSandbox built with `configure`.
pub fn with_rust_sandbox_from<C, F>(configure: C, f: F)
where
    C: FnOnce(SandboxBuilder) -> SandboxBuilder,
    F: FnOnce(MultiUseSandbox),
{
    f(build_rust_sandbox(configure));
}

/// Runs a test with a Rust guest UninitializedSandbox.
pub fn with_rust_uninit_sandbox<F>(f: F)
where
    F: FnOnce(UninitializedSandbox),
{
    with_rust_uninit_sandbox_cfg(SandboxConfiguration::default(), f);
}

/// Runs a test with a Rust guest UninitializedSandbox using custom configuration.
pub fn with_rust_uninit_sandbox_cfg<F>(cfg: SandboxConfiguration, f: F)
where
    F: FnOnce(UninitializedSandbox),
{
    let sandbox =
        UninitializedSandbox::new(GuestBinary::FilePath(rust_guest_path()), Some(cfg)).unwrap();
    f(sandbox);
}

// =============================================================================
// C guest helpers
// =============================================================================

/// Builds a C guest MultiUseSandbox, applying `configure` to the builder.
pub fn build_c_sandbox<C>(configure: C) -> MultiUseSandbox
where
    C: FnOnce(SandboxBuilder) -> SandboxBuilder,
{
    configure(SandboxBuilder::from_file(c_guest_path()))
        .build()
        .unwrap()
}

/// Runs a test with a C guest MultiUseSandbox.
pub fn with_c_sandbox<F>(f: F)
where
    F: FnOnce(MultiUseSandbox),
{
    f(build_c_sandbox(|builder| builder));
}

/// Runs a test with a C guest MultiUseSandbox built with `configure`.
pub fn with_c_sandbox_from<C, F>(configure: C, f: F)
where
    C: FnOnce(SandboxBuilder) -> SandboxBuilder,
    F: FnOnce(MultiUseSandbox),
{
    f(build_c_sandbox(configure));
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
        f(SandboxBuilder::from_file(path).build().unwrap());
    });
}
