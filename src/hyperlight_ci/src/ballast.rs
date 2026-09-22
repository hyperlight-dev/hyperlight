// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.
//! A resident VM held for the duration of a benchmark run.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};

use anyhow::{Context, bail};

/// Line the helper prints once its sandbox is live.
const READY: &str = "ballast ready";

/// A sandbox held alive for a whole benchmark run.
///
/// Benchmarks that create and drop sandboxes leave the host with no resident
/// VM between iterations. Crossing that boundary toggles a kernel static key,
/// and each toggle patches kernel text and IPIs every core. That cost lands on
/// whichever benchmark happens to trigger it, so holding one sandbox resident
/// keeps it out of the measurements.
pub(crate) struct Ballast {
    child: Child,
    /// The helper exits when this closes, which the OS does for us if this
    /// process is killed before [`Drop`] can run.
    _stdin: ChildStdin,
}

impl Ballast {
    /// Build the helper, start it, and wait until its sandbox is live.
    pub(crate) fn start() -> anyhow::Result<Self> {
        let exe = build().context("Failed to build the ballast helper")?;

        let mut child = Command::new(&exe)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .with_context(|| format!("Failed to start the ballast helper {}", exe.display()))?;

        let stdin = child.stdin.take().expect("stdin is piped");
        let stdout = child.stdout.take().expect("stdout is piped");
        let mut line = String::new();
        BufReader::new(stdout)
            .read_line(&mut line)
            .context("Failed to read readiness from the ballast helper")?;

        if line.trim() != READY {
            bail!("Ballast helper did not become ready");
        }

        Ok(Self {
            child,
            _stdin: stdin,
        })
    }
}

impl Drop for Ballast {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Build the ballast example and return the executable cargo produced.
fn build() -> anyhow::Result<PathBuf> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    let output = Command::new(cargo)
        .args([
            "build",
            "--release",
            "--package",
            "hyperlight-host",
            "--example",
            "ballast",
            "--message-format=json-render-diagnostics",
        ])
        .stderr(Stdio::inherit())
        .output()?;

    if !output.status.success() {
        bail!("cargo build failed for the ballast helper");
    }

    for line in output.stdout.as_slice().lines() {
        let Ok(line) = line else { continue };
        let Ok(msg) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        if msg["reason"] == "compiler-artifact" && msg["target"]["name"] == "ballast" {
            if let Some(exe) = msg["executable"].as_str() {
                return Ok(PathBuf::from(exe));
            }
        }
    }

    bail!("cargo reported no executable for the ballast helper")
}
