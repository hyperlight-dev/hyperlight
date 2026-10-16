// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Generates C# host bindings for a WIT world.
//!
//! Usage: `csharp_bindgen <wit path> <namespace> <output file>`

use std::path::Path;
use std::process::ExitCode;

use hyperlight_component_csharp::generate_from_path;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [wit, namespace, out] = args.as_slice() else {
        eprintln!("usage: csharp_bindgen <wit path> <namespace> <output file>");
        return ExitCode::FAILURE;
    };
    let result = generate_from_path(Path::new(wit), None, namespace)
        .map_err(|e| e.to_string())
        .and_then(|cs| std::fs::write(out, cs).map_err(|e| format!("{out}: {e}")));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
