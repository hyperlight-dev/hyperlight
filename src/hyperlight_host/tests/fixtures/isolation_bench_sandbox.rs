// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! The verified program image selects callback placement, never host authority.

use hyperlight_host::process::{ProcessHostFunctions, ProcessStartup, SandboxHost};
use hyperlight_host::{Result, new_error};

mod isolation_bench_contracts;
use isolation_bench_contracts::{ADD, ECHO, add, echo};

fn main() -> Result<()> {
    // SAFETY: capture is the first operation, before threads or environment access.
    // The production launcher owns and supplies the one-shot inherited resources.
    let startup = unsafe { ProcessStartup::capture() }?
        .ok_or_else(|| new_error!("Production sandbox startup resources are required"))?;
    let executable = std::env::current_exe()?;
    let image = executable
        .parent()
        .ok_or_else(|| new_error!("Executable has no image directory"))?;
    let mode = std::fs::read(image.join("isolation-bench-mode"))?;
    let mut functions = ProcessHostFunctions::default();
    match mode.as_slice() {
        b"local" => {
            functions.bind(ECHO, echo)?;
            functions.bind(ADD, add)?;
        }
        b"remote" => {}
        _ => return Err(new_error!("Invalid verified benchmark placement")),
    }
    SandboxHost::new(functions).run(startup)?;
    Ok(())
}
