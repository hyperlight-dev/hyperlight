// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Stateless benchmark callbacks. Only the production launcher supplies startup.

use hyperlight_host::process::{ProcessHostFunctions, ProcessStartup};
use hyperlight_host::{Result, new_error};

mod isolation_bench_contracts;
use isolation_bench_contracts::{ADD, ECHO, add, echo};

fn main() -> Result<()> {
    // SAFETY: capture is the first operation, before threads or environment access.
    // The production launcher owns and supplies the one-shot inherited resources.
    let startup = unsafe { ProcessStartup::capture() }?
        .ok_or_else(|| new_error!("Production worker startup resources are required"))?;
    let mut functions = ProcessHostFunctions::default();
    functions.bind(ECHO, echo)?;
    functions.bind(ADD, add)?;
    functions.run(startup)?;
    Ok(())
}
