// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::io::Write;

use hyperlight_host::{Result, new_error, process};

mod process_contracts;

fn main() -> Result<()> {
    // SAFETY: this fixture is entered only by the trusted launcher, before threads.
    let startup = unsafe { process::ProcessStartup::capture() }?
        .ok_or_else(|| new_error!("Worker startup resources are required"))?;
    let args: Vec<_> = std::env::args().skip(1).collect();
    if let [mode, marker] = args.as_slice()
        && mode == "--block-before-run"
    {
        block(marker);
    }
    let mode = args.first().cloned().unwrap_or_default();
    let marker = args.get(1).cloned();
    let idempotency = match args.get(2).map(String::as_str) {
        None => process::Idempotency::Idempotent,
        Some("unmarked") => process::Idempotency::Unspecified,
        Some("non-idempotent") => process::Idempotency::NonIdempotent,
        _ => return Err(new_error!("Unknown fixture contract")),
    };
    if !matches!(
        mode.as_str(),
        "" | "--block-native" | "--crash-once" | "--crash-always"
    ) {
        return Err(new_error!("Unknown fixture arguments"));
    }
    let mut functions = process::ProcessHostFunctions::default();
    let add = if idempotency == process::Idempotency::Idempotent {
        process_contracts::ADD
    } else {
        process::HostFunctionContract::<(i32, i32), i32>::new("HostAdd", idempotency)
    };
    functions.bind(add, move |a: i32, b: i32| {
        if let Some(marker) = &marker {
            if mode == "--block-native" {
                block(marker);
            }
            let existed = std::path::Path::new(marker).exists();
            let mut record = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(marker)
                .expect("Unable to open dispatch record");
            record
                .write_all(b"dispatched\n")
                .expect("Unable to record dispatch");
            record
                .sync_all()
                .expect("Unable to persist dispatch record");
            if mode == "--crash-always" || (mode == "--crash-once" && !existed) {
                // Exit after an observable effect but before the RPC reply.
                std::process::exit(86);
            }
        }
        a + b
    })?;
    functions.bind(process_contracts::PID, std::process::id)?;
    functions.run(startup)?;
    Ok(())
}

fn block(marker: &str) -> ! {
    std::fs::write(marker, b"entered").expect("Unable to publish fixture entry");
    loop {
        std::thread::park();
    }
}
