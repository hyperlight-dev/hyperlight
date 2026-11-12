// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use hyperlight_host::process::{self, HostFunctionContract, Idempotency};
use hyperlight_host::{Result, new_error};

const PRINT: HostFunctionContract<(String,), i32> =
    HostFunctionContract::new("HostPrint", Idempotency::Idempotent);
const ADD: HostFunctionContract<(i32, i32), i32> =
    HostFunctionContract::new("HostAdd", Idempotency::NonIdempotent);

fn main() -> Result<()> {
    // SAFETY: the trusted test launcher supplies the invitation. No threads,
    // tracing, environment access or subprocesses precede this one-shot capture.
    let startup = unsafe { process::ProcessStartup::capture() }?
        .ok_or_else(|| new_error!("Sandbox startup resources are required"))?;
    let mut functions = process::ProcessHostFunctions::default();
    functions.bind(PRINT, |message: String| {
        if message == "__exit_sandbox" {
            std::process::exit(87);
        }
        std::process::id() as i32
    })?;
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [] => {}
        [mode] if mode == "--local-add" => {
            let mut calls = 0;
            functions.bind(ADD, move |a: i32, b: i32| {
                calls += 1;
                a + b + calls
            })?;
        }
        _ => return Err(new_error!("Unknown sandbox fixture arguments")),
    }
    process::SandboxHost::new(functions).run(startup)?;
    Ok(())
}
