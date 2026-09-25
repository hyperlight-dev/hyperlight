// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.
//! Holds one sandbox alive and then idles.
//!
//! A vCPU created without an in-kernel LAPIC bumps the kernel's
//! `kvm_has_noapic_vcpu` static key, and teardown drops it again. Each
//! transition through zero patches kernel text, which IPIs every core.
//! Keeping one sandbox resident holds the count above zero, so a benchmark
//! that creates and drops sandboxes never crosses that boundary.
//! Parks after startup, so it consumes no CPU while a benchmark runs.

use std::io::Read;

use hyperlight_host::SandboxBuilder;

fn main() -> hyperlight_host::Result<()> {
    let _sandbox =
        SandboxBuilder::from_file(hyperlight_testing::simple_guest_as_pathbuf()).build()?;

    // Readers wait for this line before starting to measure.
    println!("ballast ready");

    // Stdin reaches EOF when the parent closes it or dies, so the sandbox never
    // outlives the run that asked for it.
    let mut discard = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut discard);

    Ok(())
}
